// Groth16 proof generation for the official gatekeeper circuit (snarkjs 0.7.6).
//
// Circuit input signal names (13) — VERIFIED by this build, not just copied:
//   * Names come from a third-party wasm probe (Medium @dickycan42) — the
//     official /build page does not list them.
//   * Verified here by trial fullProve against the official wasm/zkey:
//     - valid scenario proves OK and `groth16.verify` returns true;
//     - wrong APPROVE (decision=1 on a trap) fails witness generation;
//     - wrong REJECT (decision=0 on valid inputs) fails witness generation;
//     - trap REJECT (decision=0 on a trap) proves OK.
//   * Value encodings verified the same way (publicSignals match exactly):
//     - registeredVkHash / proofVkHash: BigInt(hex) mod BN128 scalar field prime
//       (raw vk hash 0x6b79... exceeds the field prime, snarkjs reduces it;
//       we reduce explicitly). Verified: publicSignals[1] == publicSignals[2]
//       == 4836144126773920907502496244340012141761656471453348073975163706578152814510.
//     - recipient / conditionRecipient: BigInt(address).
//     - minimum / publicBalance / amount / maxTransfer: decimal strings as-is.
//     - expiryBlock / currentBlock: integers as-is.
//     - decision: "1" approve / "0" reject.
//     - taskId: ASCII bytes of the task_id string as a BigInt
//       (verified: "gk_8d31_test" -> 32006760739351017058025698164 == publicSignals[12]).
//       NOTE (2026-11-19, R06 post-mortem): that encoding is WRONG for
//       competition tasks. Practice verification passes with ANY taskId
//       encoding (it only re-runs groth16.verify), but competition
//       verification ALSO binds publicSignals[12] to the task_id — and the
//       platform recomputes it as the UUID at the end of the task_id,
//       dashes stripped, read as hex, mod p. Evidence: the one agent
//       found with verified competition proofs (urutericcc/GLO-GATE,
//       379.3 pts, ~30/30 verified) uses exactly that encoding; every
//       other encoding tried in competition — raw UTF-8 (us, 0/8 in R06),
//       SHA-256 (BAOK-GK R03-R04), Keccak-256 (BAOK-GK mid-R04, mangkarones
//       ~2/24) — scores 0 verified. Kurier on-chain submission does NOT
//       fix it either (BAOK-GK 0/24 in R03-R05 despite ProofVerified
//       events on Subscan). Fallback: if the task_id has no trailing UUID,
//       keep the old ASCII encoding so proving never fails outright on an
//       unknown id format (practice tasks always carry a UUID, so the
//       fallback only fires for unrecognised formats).
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function taskIdToField(taskId) {
  const m = String(taskId || '').match(UUID_RE);
  if (m) return (BigInt('0x' + m[0].replaceAll('-', '')) % FIELD_P).toString();
  return asciiToField(taskId);
}
//     - salt: PRIVATE input (not a public signal). publicSignals[0] is a
//       circuit output commitment that changes with the salt (verified:
//       salt 12345 / 99999 / 0 give different publicSignals[0]).
//       We derive the salt DETERMINISTICALLY as SHA-256(task_id) mod p so a
//       retried task_id reproduces a byte-identical proof (idempotency).
//
// Public-signal order returned by fullProve (13 values):
//   [0]=commitment(salt,...), [1]=registeredVkHash, [2]=proofVkHash,
//   [3]=minimum, [4]=publicBalance, [5]=expiryBlock, [6]=currentBlock,
//   [7]=recipient, [8]=conditionRecipient, [9]=amount, [10]=maxTransfer,
//   [11]=decision, [12]=taskId
// The agent returns publicSignals exactly as fullProve returns them; the
// platform re-verifies against its own verification key.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = path.join(__dirname, '..', 'circuits', 'verification_key.json');

let cachedVk = null;
function getVerificationKey() {
  if (!cachedVk) cachedVk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  return cachedVk;
}

// Hex string ("0x...") or decimal string -> field element (decimal string).
function hexToField(hex) {
  return (BigInt(hex) % FIELD_P).toString();
}

function asciiToField(str) {
  if (!str) return '0';
  return (BigInt('0x' + Buffer.from(String(str), 'utf8').toString('hex')) % FIELD_P).toString();
}

// Deterministic private salt: SHA-256(task_id) mod p.
function saltForTask(taskId) {
  const digest = crypto.createHash('sha256').update(String(taskId)).digest('hex');
  return (BigInt('0x' + digest) % FIELD_P).toString();
}

function buildCircuitInput(input, decision) {
  return {
    registeredVkHash: hexToField(input.registered_vk),
    proofVkHash: hexToField(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: hexToField(input.recipient),
    conditionRecipient: hexToField(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(input.task_id || ''),
    salt: saltForTask(input.task_id || ''),
  };
}

async function doProve(input, decision) {
  const circuitInput = buildCircuitInput(input, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

// Serialised proving: witness generation is heavy single-threaded work, so
// concurrent fullProve calls (e.g. warm-up + a real task) only contend for
// the same CPU and make both slower. Chain all proves through one queue;
// a task arriving during warm-up waits for the warm-up prove, then runs fast.
let proveChain = Promise.resolve();
function prove(input, decision) {
  const run = proveChain.then(() => doProve(input, decision));
  proveChain = run.catch(() => {});
  return run;
}

async function verifyLocally(proof, publicSignals) {
  return snarkjs.groth16.verify(getVerificationKey(), publicSignals, proof);
}

// Warm-up: the FIRST fullProve in a process is far slower than later ones
// (measured locally: first ~11-43s vs ~6-9s warm — wasm compile + zkey load,
// worse under CPU contention). Pre-compile it in the background at startup
// so the first real task is fast. Fire-and-forget: never blocks a response,
// errors swallowed. Safe to call repeatedly (single shared promise).
// NOTE: on Vercel the CPU may freeze after a response returns, so a warm-up
// started at module load may not finish before the first task — the agent
// still works, just slower on that first task. See README § "Latency".
let warmupPromise = null;
function warmup() {
  if (warmupPromise) return warmupPromise;
  warmupPromise = (async () => {
    try {
      await prove({
        registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
        proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
        minimum: '1000', public_balance: '1460',
        expiry_block: '8430000', current_block: '8420000',
        recipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f901234',
        condition_recipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f901234',
        amount: '500', max_transfer: '1000',
        task_id: 'warmup',
      }, 'APPROVE');
    } catch {
      // Warm-up is best-effort only.
    }
  })();
  return warmupPromise;
}

module.exports = {
  FIELD_P, buildCircuitInput, prove, verifyLocally, getVerificationKey,
  hexToField, asciiToField, taskIdToField, saltForTask, warmup,
};
