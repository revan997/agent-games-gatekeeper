# Gatekeeper — Test Results

**Last full run: 2026-11-15 ~23:07 WIB — 12/12 PASS.**
Command: `npm test` (runs `node test/run-tests.cjs`: starts the local server on
port 3457 with a test HMAC secret, posts signed tasks, verifies every
generated proof with `snarkjs groth16.verify` against
`circuits/verification_key.json`, which was exported from the official zkey).
An earlier run at ~22:58 WIB also passed 12/12 (first proof 42.7s under heavy
parallel CPU load; see latency notes below).

Shared base input for all task tests (unless a row overrides a field):

```json
{
  "registered_vk": "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  "proof_vk": "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  "minimum": "1000", "public_balance": "1460",
  "expiry_block": 8430000, "current_block": 8420000,
  "recipient": "0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f901234",
  "condition_recipient": "0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f901234",
  "amount": "500", "max_transfer": "1000",
  "proof_tx": "0xaaa111"
}
```

## Results (run 2026-11-15 ~23:07 WIB)

| # | Test | Input | Expected | Actual | Result |
|---|---|---|---|---|---|
| 01 | Preflight | `{"type":"agent-games.preflight.v1","agent_id":"agt_test","nonce":"abc123"}` signed HMAC-SHA256 hex | HTTP 200 `{"ok":true,"protocolVersion":"v1"}` + valid response signature | 200, exact body, response signature verified | ✅ PASS |
| 02 | Valid task → APPROVE | Base input, `task_id=gk_test_valid_1`, `proof_tx=0xaaa111` | `APPROVE` / `VALID_CONDITION` + Groth16 proof that verifies locally + signed response | `APPROVE` / `VALID_CONDITION`, `snarkjs groth16.verify` = true, response signature valid (31.3s — first proof in process, includes background warm-up) | ✅ PASS |
| 03 | VK_SUBSTITUTION | `proof_vk=0x13aaa…` (≠ registered) | `REJECT` / `VK_SUBSTITUTION` + decision-0 proof verifies + signed | `REJECT` / `VK_SUBSTITUTION`, proof verifies true, signed (9.4s) | ✅ PASS |
| 04 | EXPIRED_CONDITION | `current_block=8430001` (> expiry 8430000) | `REJECT` / `EXPIRED_CONDITION` + decision-0 proof verifies + signed | `REJECT` / `EXPIRED_CONDITION`, proof verifies true, signed (6.6s) | ✅ PASS |
| 05 | RECIPIENT_MISMATCH | `recipient=0x1111…` (≠ condition) | `REJECT` / `RECIPIENT_MISMATCH` + decision-0 proof verifies + signed | `REJECT` / `RECIPIENT_MISMATCH`, proof verifies true, signed (5.5s) | ✅ PASS |
| 06 | THRESHOLD_MISMATCH | `public_balance=999` (< minimum 1000) | `REJECT` / `THRESHOLD_MISMATCH` + decision-0 proof verifies + signed | `REJECT` / `THRESHOLD_MISMATCH`, proof verifies true, signed (4.0s) | ✅ PASS |
| 07 | AMOUNT_OVERFLOW | `amount=1001` (> max_transfer 1000) | `REJECT` / `AMOUNT_OVERFLOW` + decision-0 proof verifies + signed | `REJECT` / `AMOUNT_OVERFLOW`, proof verifies true, signed (4.8s) | ✅ PASS |
| 08 | Bad HMAC | Valid task body, signature `deadbeef…` | HTTP 401, no decision work done | HTTP 401 | ✅ PASS |
| 09 | Replay (same task 2×) | Exact raw body of test 02 re-POSTed twice | Byte-identical cached `APPROVE` response both times (not a reuse REJECT) | Both replays `APPROVE`, bodies + signatures byte-identical | ✅ PASS |
| 10 | PROOF_REUSED | New `task_id=gk_test_reuse_1`, same `proof_tx=0xaaa111` as test 02 | `REJECT` / `PROOF_REUSED` with NO `proof` / `public_signals` fields + signed | `REJECT` / `PROOF_REUSED`, no proof fields, signed | ✅ PASS |
| 11 | Timeout / fail-closed | Valid task, `deadline_at` 60s in the past | `REJECT`, no proof, no approve | `REJECT` / `TIMEOUT` (local fail-closed code), no proof | ✅ PASS |
| 12 | Malformed / fail-closed | `input` contains only `registered_vk` (all other fields missing) | `REJECT`, no approve | `REJECT` / `INVALID_TASK` | ✅ PASS |

**Total: 12/12 PASS.**

## Circuit verification (pre-build probes, same day)

Before writing the agent, the 13 circuit input signal names and their value
encodings were verified by trial `fullProve` against the official
`gatekeeper.wasm` / `gatekeeper_final.zkey` (hashes match the recon report:
wasm `be00aefe…92764f`, zkey `adfe95a4…af80d`):

- Signal names: `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId, salt` (names first found by a third-party
  wasm probe — Medium @dickycan42 — and confirmed here by successful proving).
- `snarkjs.zKey.exportVerificationKey` → Groth16/BN128, **nPublic = 13**,
  IC length 14.
- Encodings confirmed via the returned `publicSignals`:
  - `registeredVkHash` / `proofVkHash` = `BigInt(vkHex) mod p` → publicSignals[1]
    = publicSignals[2] =
    `4836144126773920907502496244340012141761656471453348073975163706578152814510`
    (the raw vk hash `0x6b79…` exceeds the BN128 field prime, so it must be
    reduced; snarkjs also reduces it automatically — the agent reduces
    explicitly).
  - `taskId` = ASCII bytes of the task_id string as a BigInt → e.g.
    `"gk_8d31_test"` → `32006760739351017058025698164` = publicSignals[12].
  - `salt` is a PRIVATE input: publicSignals[0] is a circuit output commitment
    that changes with the salt (salt 12345 / 99999 / 0 gave three different
    publicSignals[0]). The agent derives the salt deterministically as
    SHA-256(task_id) mod p, so a retried task_id reproduces a byte-identical proof.
- Circuit semantics confirmed (witness generation fails = the circuit refuses):
  - valid inputs + decision=1 → proves, `groth16.verify` = true.
  - recipient mismatch + decision=1 → fullProve FAILS (`Assert Failed…
    GatekeeperEvaluation_79 line: 102`).
  - valid inputs + decision=0 → fullProve FAILS (same assert).
  - recipient mismatch + decision=0 → proves, verify = true.
  - I.e. the circuit enforces decision == verdict (approve iff all checks pass).

## Latency notes (honest)

- Warm proofs (steady state, local VM): **~4–9s** per task — well inside the
  60s deadline.
- First proof in a fresh process (wasm compile + zkey load): **~11–43s**
  measured (10.7s and 16.8s in isolated probes; 31–43s when the VM was under
  heavy parallel load). Still inside 60s, but with little margin under load.
- Mitigations in place: background warm-up prove at startup of the local
  server (`index.js`); proves serialised through one queue so a warm-up and a
  real task never contend for CPU; on Vercel the warm-up is opt-in
  (`WARMUP=1`) so a cold start never delays preflight/health responses.
- Proving is CPU-heavy and starves the Node event loop while it runs — the
  server cannot answer a second request mid-proof. Tasks arrive spread over
  hours in practice, so this is acceptable; concurrent tasks would queue.

## Known gaps (not covered by these tests)

- **HMAC algorithm/encoding is unconfirmed** (official docs never state it).
  Tests use HMAC-SHA256 hex, the community convention. If the real preflight
  rejects it, set `HMAC_FORMAT=base64` (or as the dashboard indicates) — no
  code change needed. This must be confirmed against the live preflight.
- **Seen-set / task cache are in-memory by default.** On Vercel serverless
  they do not survive cold starts and are not shared across instances, so
  `PROOF_REUSED` detection can miss a reuse after a cold start. `SEEN_STORE_PATH`
  persists them to a file for single-instance use; production should use an
  external store (Vercel KV / Upstash). See README.
- **Kurier on-chain submission is NOT implemented** (optional/best-effort per
  brief; no API key exists). The response carries `proof` + `public_signals`
  + `proof_tx`; the platform re-verifies the proof itself.
- Live preflight / practice task against the real platform have NOT been run
  (they need a registered agent + dashboard + the real HMAC secret).
