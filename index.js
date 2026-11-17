// Local dev server: `npm start` (loads .env if present) or `node index.js`.
// Same core handler as the Vercel deployment (lib/gatekeeper.js).
const http = require('http');
const fs = require('fs');
const path = require('path');
const { handleRequest } = require('./lib/gatekeeper');

// Minimal .env loader (no dependency). Real deployments use real env vars.
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

const PORT = Number(process.env.PORT || 3000);
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      const result = await handleRequest({ method: req.method, rawBody, headers: req.headers });
      res.writeHead(result.status, result.headers);
      res.end(result.body);
    } catch (e) {
      console.error('handler error:', e);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`gatekeeper listening on http://localhost:${PORT}/agent`);
  console.log(`HMAC secret configured: ${!!process.env.AGENT_GAMES_HMAC_SECRET} (format=${process.env.HMAC_FORMAT || 'hex'})`);
  // Background warm-up of the proving stack (non-blocking; see lib/proof.js).
  require('./lib/proof').warmup();
});
