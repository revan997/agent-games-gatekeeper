// Core Proof Gatekeeper logic — transport-independent.
// handleRequest({ method, rawBody, headers }) -> { status, body, headers }
// - Verifies HMAC over the RAW body BEFORE parsing JSON.
// - Preflight -> { ok:true, protocolVersion:"v1" }.
// - Task -> deterministic rule checks -> Groth16 proof (local, snarkjs).
// - Every response is signed with x-agent-games-signature over the raw body.
// - Fail closed: any error / uncertainty / timeout -> REJECT, never APPROVE.
// - Idempotent: a retried task_id returns the byte-identical cached response.
// - PROOF_REUSED answers WITHOUT a proof (per spec; excluded from proof bonus).
//
// Check order when several traps fire at once (unspecified by the docs;
// documented here so behaviour is deterministic): PROOF_REUSED, then
// VK_SUBSTITUTION, EXPIRED_CONDITION, RECIPIENT_MISMATCH, THRESHOLD_MISMATCH,
// AMOUNT_OVERFLOW. Trap tasks in practice carry exactly one trap.
const fs = require('fs');
const path = require('path');
const hmac = require('./hmac');
const proofLib = require('./proof');

const SIGNATURE_HEADER = 'x-agent-games-signature';
const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';

// In-memory state. NOTE (serverless): this does not survive cold starts and
// is not shared across instances. SEEN_STORE_PATH (optional env) persists it
// to a JSON file for single-instance/local use. For production on Vercel,
// back this with an external store (Vercel KV / Upstash) — see README.
const seenProofTx = new Set(); // normalised (lowercased) proof_tx values
const taskCache = new Map(); // task_id -> { status, body } (body = exact string sent)
let stateLoaded = false;

function storePath() {
  return process.env.SEEN_STORE_PATH || null;
}

function loadState() {
  if (stateLoaded) return;
  stateLoaded = true;
  const p = storePath();
  if (!p) return;
  try {
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    (data.seenProofTx || []).forEach((x) => seenProofTx.add(x));
    Object.entries(data.taskCache || {}).forEach(([k, v]) => taskCache.set(k, v));
  } catch {
    // No prior state file — start empty. Corrupt file is ignored (fail open
    // only for the cache; decisions themselves still fail closed).
  }
}

function saveState() {
  const p = storePath();
  if (!p) return;
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const data = {
      seenProofTx: [...seenProofTx].slice(-5000),
      taskCache: Object.fromEntries([...taskCache.entries()].slice(-1000)),
    };
    fs.writeFileSync(p, JSON.stringify(data));
  } catch {
    // Persistence is best-effort; a failed save must not fail the response.
  }
}

function normHex(v) {
  return String(v || '').trim().toLowerCase();
}

function toBigIntDecimal(v, field) {
  if (v === undefined || v === null || v === '') throw new Error(`Missing field: ${field}`);
  try {
    return BigInt(String(v).trim());
  } catch {
    throw new Error(`Invalid numeric field: ${field}`);
  }
}

// Deterministic rule checks. Returns { decision, reason_code }.
// Throws on malformed input (caller turns it into a fail-closed REJECT).
function decide(input) {
  if (!input || typeof input !== 'object') throw new Error('Missing input');
  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer', 'proof_tx'];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null || input[f] === '') {
      throw new Error(`Missing field: ${f}`);
    }
  }
  const proofTx = normHex(input.proof_tx);
  if (seenProofTx.has(proofTx)) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  if (normHex(input.proof_vk) !== normHex(input.registered_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (toBigIntDecimal(input.current_block, 'current_block')
      >= toBigIntDecimal(input.expiry_block, 'expiry_block')) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (normHex(input.recipient) !== normHex(input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (toBigIntDecimal(input.public_balance, 'public_balance')
      < toBigIntDecimal(input.minimum, 'minimum')) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (toBigIntDecimal(input.amount, 'amount')
      > toBigIntDecimal(input.max_transfer, 'max_transfer')) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function signResponse(status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  const sig = hmac.sign(body);
  if (sig) headers[SIGNATURE_HEADER] = sig;
  return { status, body, headers };
}

// The 60s deadline is enforced as: never START a proof when less than 5s
// of the platform deadline remain (proof takes ~3-6s warm, ~10-17s cold).
function timeLeftMs(task) {
  if (!task.deadline_at) return Infinity;
  const d = Date.parse(task.deadline_at);
  if (Number.isNaN(d)) return Infinity;
  return d - Date.now();
}

async function handleTask(task) {
  const taskId = task.task_id || '';
  loadState();
  if (taskId && taskCache.has(taskId)) {
    const cached = taskCache.get(taskId);
    return cached; // byte-identical retry
  }
  const input = task.input || null;
  let outcome;
  try {
    outcome = decide(input);
  } catch (e) {
    // Malformed task: fail closed, no proof.
    const res = signResponse(200, {
      decision: 'REJECT', reason_code: 'INVALID_TASK',
      ...(input && input.proof_tx ? { proof_tx: input.proof_tx } : {}),
    });
    if (taskId) { taskCache.set(taskId, res); saveState(); }
    return res;
  }

  const proofTx = normHex(input.proof_tx);

  // PROOF_REUSED: answer WITHOUT a proof, per spec.
  if (outcome.reason_code === 'PROOF_REUSED') {
    const res = signResponse(200, {
      decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: input.proof_tx,
    });
    if (taskId) { taskCache.set(taskId, res); saveState(); }
    return res;
  }

  // Fail closed on a (near-)expired deadline: answer REJECT without spending
  // time on a proof that cannot arrive in time. TIMEOUT is a local
  // fail-closed code (not a trap code) — the task is already lost either way.
  if (timeLeftMs(task) < 5000) {
    const res = signResponse(200, {
      decision: 'REJECT', reason_code: 'TIMEOUT', proof_tx: input.proof_tx,
    });
    seenProofTx.add(proofTx);
    if (taskId) { taskCache.set(taskId, res); saveState(); }
    return res;
  }

  // Generate the Groth16 proof for the decision. The circuit enforces
  // decision == verdict: a wrong decision cannot produce a witness, so a
  // proof failure here means our decision disagrees with the circuit.
  try {
    const { proof, publicSignals } = await proofLib.prove(
      { ...input, task_id: taskId }, outcome.decision);
    seenProofTx.add(proofTx);
    const res = signResponse(200, {
      decision: outcome.decision,
      reason_code: outcome.reason_code,
      proof,
      public_signals: publicSignals,
      proof_tx: input.proof_tx,
    });
    if (taskId) { taskCache.set(taskId, res); saveState(); }
    return res;
  } catch (e) {
    // Proof failed: fail closed. Keep the REJECT decision if we were
    // rejecting (decision still correct, only the proof bonus is lost);
    // if we were approving, flip to REJECT — never approve without a proof.
    // PROOF_FAILED is a non-spec fallback code, used only in this path.
    const res = signResponse(200, {
      decision: 'REJECT',
      reason_code: outcome.decision === 'APPROVE' ? 'PROOF_FAILED' : outcome.reason_code,
      proof_tx: input.proof_tx,
    });
    seenProofTx.add(proofTx);
    if (taskId) { taskCache.set(taskId, res); saveState(); }
    return res;
  }
}

async function handleRequest({ method, rawBody, headers }) {
  loadState();
  const sigHeader = headers[SIGNATURE_HEADER] || headers['X-Agent-Games-Signature'];

  // Health check (GET): no signature required; sign if a secret is configured.
  if (method === 'GET') {
    return signResponse(200, {
      ok: true, service: 'agent-games-gatekeeper', protocolVersion: 'v1',
    });
  }
  if (method !== 'POST') {
    return signResponse(405, { error: 'method_not_allowed' });
  }

  // No secret configured -> cannot verify or sign: fail closed.
  if (!hmac.getSecret()) {
    return { status: 500, body: JSON.stringify({ error: 'hmac_secret_not_configured' }), headers: { 'content-type': 'application/json' } };
  }

  // Verify HMAC over the RAW body BEFORE parsing JSON.
  if (!hmac.verify(rawBody, sigHeader)) {
    return signResponse(401, { error: 'invalid_signature' });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return signResponse(200, { decision: 'REJECT', reason_code: 'INVALID_TASK' });
  }

  if (payload && payload.type === PREFLIGHT_TYPE) {
    return signResponse(200, { ok: true, protocolVersion: 'v1' });
  }
  if (payload && payload.type === TASK_TYPE) {
    return handleTask(payload);
  }
  return signResponse(200, { decision: 'REJECT', reason_code: 'INVALID_TASK' });
}

module.exports = { handleRequest, decide, signResponse, _internals: { seenProofTx, taskCache } };
