# Proof Gatekeeper Agent — zkVerify Agent Games Season 01

Node.js agent (no framework) for the **Proof Gatekeeper** track. The platform
POSTs signed task envelopes; the agent verifies the HMAC, runs deterministic
rule checks, generates a local Groth16 proof with snarkjs + the official
gatekeeper circuit, and answers signed JSON within the 60-second deadline.

## Deploy (Vercel, free tier)

```bash
cd gatekeeper
vercel deploy            # or connect the repo in the Vercel dashboard
```

Then in the Vercel dashboard, set the environment variable (from the Agent
Games dashboard → agent settings → "Rotate Secret", shown once):

- `AGENT_GAMES_HMAC_SECRET` — the 32-byte per-agent secret. **Only ever from
  env. No secret is hardcoded anywhere in this repo; there is no `.env` file
  committed (see `.gitignore`).**

Optional env vars:

- `HMAC_FORMAT=hex|base64` (default `hex`) — encoding of the
  `x-agent-games-signature` header. See "Unconfirmed" below.
- `WARMUP=1` — run a background warm-up proof at cold start (off by default
  on Vercel so preflight/health stay responsive; on for the local server).
- `SEEN_STORE_PATH=./data/state.json` — persist the seen-`proof_tx` set +
  task cache to a file (single-instance use only).

Register the endpoint in the Agent Games dashboard as
`https://<your-app>.vercel.app/agent` (the `/agent` path is rewritten to the
serverless function by `vercel.json`). Then run **preflight** from the
dashboard, then a **practice task**.

Local run:

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET
npm install
npm start              # http://localhost:3000/agent
npm test               # 12/12 end-to-end tests (see TESTS.md)
```

## Protocol (as documented on the official /build page)

- `POST /agent`, header `x-agent-games-signature` = HMAC over the **raw**
  request body, verified **before** parsing JSON. Bad/missing signature → 401.
- Preflight `{"type":"agent-games.preflight.v1",...}` →
  `{"ok":true,"protocolVersion":"v1"}`, signed.
- Task `{"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_...",
  "mode":"competition","issued_at":"...","deadline_at":"...",
  "input":{registered_vk, proof_vk, minimum, public_balance, expiry_block,
  current_block, recipient, condition_recipient, amount, max_transfer,
  proof_tx}}` (amounts are decimal strings).
- Answer: `{"decision":"APPROVE"|"REJECT","reason_code":...,
  "proof":{...},"public_signals":[...],"proof_tx":"..."}` — every response
  signed with `x-agent-games-signature` over the raw response body.
- Deadline 60s; fail closed (any error/uncertainty/timeout → REJECT).

## Decision rules (one failure → REJECT)

Checked in this order (the docs don't specify precedence when several traps
fire at once; the order is documented here so behaviour is deterministic):

| # | reason_code | Rule |
|---|---|---|
| 1 | `PROOF_REUSED` | `proof_tx` already seen (local seen-set). Answered **without** a proof. |
| 2 | `VK_SUBSTITUTION` | `proof_vk != registered_vk` |
| 3 | `EXPIRED_CONDITION` | `current_block > expiry_block` |
| 4 | `RECIPIENT_MISMATCH` | `recipient != condition_recipient` |
| 5 | `THRESHOLD_MISMATCH` | `public_balance < minimum` |
| 6 | `AMOUNT_OVERFLOW` | `amount > max_transfer` |
| — | `VALID_CONDITION` | All pass → `APPROVE` |

All comparisons use `BigInt` (amounts are decimal strings; addresses/VKs are
compared case-insensitively). Idempotency: a retried `task_id` returns the
byte-identical cached response. Local fail-closed codes (not trap codes, only
used when the agent itself cannot proceed): `INVALID_TASK` (malformed
envelope), `TIMEOUT` (deadline already past), `PROOF_FAILED` (proof
generation failed on an otherwise valid APPROVE — flipped to REJECT),
`INTERNAL_ERROR` (last-resort handler catch).

## Proof (Groth16, local, snarkjs 0.7.6)

Circuit: official `gatekeeper.wasm` + `gatekeeper_final.zkey` (hashes verified
against the recon report: wasm `be00aefe…92764f`, zkey `adfe95a4…af80d`;
vkHash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).

**Circuit input signal names (13) — verified by trial proving, not guessed:**
`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
taskId, salt`. The official /build page does **not** list them; the names were
first published by a third-party wasm probe (Medium @dickycan42) and were
confirmed here by successful `fullProve` + `groth16.verify` (see TESTS.md for
the evidence, including the exact public-signal values). Encodings:
vk hashes as `BigInt(hex) mod p` (raw hash exceeds the BN128 field prime);
addresses as `BigInt(address)`; `taskId` as ASCII bytes of the task_id string
as a BigInt; `salt` is a **private** input, derived deterministically as
SHA-256(task_id) mod p so retries reproduce byte-identical proofs.
The circuit enforces decision == verdict: a wrong APPROVE or a wrong REJECT
cannot even produce a witness (verified in probes).

Warm proofs take ~4–9s locally; the first proof in a fresh process takes
~11–43s (wasm compile + zkey load, worse under CPU load). See TESTS.md
"Latency notes".

## Files

```
gatekeeper/
├── package.json          # deps: snarkjs 0.7.6 only; scripts: start, test
├── vercel.json           # /agent -> /api/agent; maxDuration 60, memory 1024
├── .env.example          # env template (no secrets)
├── .gitignore            # .env, node_modules, data/
├── index.js              # local dev server (loads .env, port 3000)
├── api/agent.js          # Vercel serverless handler (raw body, bodyParser off)
├── lib/
│   ├── gatekeeper.js     # core: HMAC gate, preflight, decide, prove, cache
│   ├── hmac.js           # HMAC-SHA256 sign/verify (hex|base64), timing-safe
│   └── proof.js          # circuit input encoding, fullProve, warm-up, queue
├── circuits/
│   ├── gatekeeper.wasm            # official, 1,755,820 bytes
│   ├── gatekeeper_final.zkey      # official, 309,750 bytes
│   └── verification_key.json      # exported from the zkey (for tests)
├── test/run-tests.cjs    # 12 end-to-end tests (see TESTS.md)
├── TESTS.md              # test results + circuit verification evidence
└── README.md             # this file
```

## Unconfirmed / must verify against the live platform

1. **HMAC algorithm + encoding.** The official docs never state them.
   Implementation: HMAC-SHA256, hex (community convention). If the real
   preflight fails with a signature error, try `HMAC_FORMAT=base64` first.
2. **Response shape.** The docs show a minimal example
   (`decision`/`reason_code`/`proof_tx`) in one place and the full form
   (`+ proof`/`public_signals`) in another. This agent sends the full form;
   confirm with one practice task.
3. **Kurier on-chain submission is NOT implemented.** It is optional /
   best-effort per the brief and needs a Kurier mainnet API key (none exists).
   The agent returns the proof in the response; the platform re-verifies it.
   If on-chain submission turns out to be required, that is a follow-up task.

## Limitations

- **Seen-set is in-memory by default** — on Vercel serverless it does not
  survive cold starts and is not shared across instances, so `PROOF_REUSED`
  detection can miss a reuse after a cold start. Use `SEEN_STORE_PATH`
  (single instance) or, for production, an external store (Vercel KV /
  Upstash Redis) before relying on it.
- **Vercel `maxDuration: 60` needs a Pro plan** — the Hobby plan caps
  functions at 10s, which a cold first proof (~11–43s) can exceed. If
  deploying on Hobby, the first task after a cold start risks a function
  timeout (the platform scores it −2, the agent itself still fails closed).
  A long-lived server (VPS / Railway) with the warm-up does not have this
  problem. No purchase was made; this is a deployment note for the parent.
- Proving starves the Node event loop while it runs; concurrent tasks queue
  behind the single proving queue (fine — tasks arrive spread over hours).
- No Kurier submission, no on-chain writes, no wallet keys involved at all.
  The agent never touches `keypair.json` or any wallet.
