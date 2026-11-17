// Vercel serverless handler for the Proof Gatekeeper agent.
// Route: POST /agent (rewritten to /api/agent by vercel.json).
// Reads the RAW body (bodyParser disabled) so the HMAC can be verified
// over the exact bytes the platform signed.
const { handleRequest } = require('../lib/gatekeeper');
const { warmup } = require('../lib/proof');

// Background warm-up of the proving stack (non-blocking; see lib/proof.js).
// Opt-in on Vercel (WARMUP=1): proving is CPU-heavy and starves the event
// loop while it runs, so a cold-start warm-up would delay the first
// preflight/health response. The first real task's proof (~11-43s worst case
// measured locally) still fits the 60s deadline without it.
if (process.env.WARMUP === '1') warmup();

module.exports = async function handler(req, res) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers || {})) headers[k.toLowerCase()] = v;
  try {
    const result = await handleRequest({ method: req.method, rawBody, headers });
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (e) {
    // Last-resort fail closed: never leak a stack, never approve.
    console.error('gatekeeper handler error:', e);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }));
  }
};

module.exports.config = { api: { bodyParser: false } };
