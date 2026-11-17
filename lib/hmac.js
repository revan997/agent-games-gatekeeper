// HMAC helpers for the Agent Games protocol.
//
// UNCONFIRMED (official docs never state it): the algorithm/encoding of the
// `x-agent-games-signature` header. Primary implementation: HMAC-SHA256, hex
// encoding of the raw body. HMAC_FORMAT=hex|base64 switches the encoding.
// If the real preflight rejects this, flip the env var — no code change needed.
const crypto = require('crypto');

function getFormat() {
  const f = (process.env.HMAC_FORMAT || 'hex').trim().toLowerCase();
  if (f !== 'hex' && f !== 'base64') throw new Error(`Unsupported HMAC_FORMAT: ${f}`);
  return f;
}

function getSecret() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  return s && s.length > 0 ? s : null;
}

// Sign raw bytes (Buffer|string) -> header value in the configured encoding.
function sign(rawBody) {
  const secret = getSecret();
  if (!secret) return null;
  const h = crypto.createHmac('sha256', secret);
  h.update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody));
  return getFormat() === 'base64' ? h.digest('base64') : h.digest('hex');
}

// Constant-time comparison of the presented header against the expected value.
// Tolerates an optional "sha256=" prefix. Returns false on any mismatch,
// including wrong length / wrong encoding.
function verify(rawBody, presented) {
  const secret = getSecret();
  if (!secret || typeof presented !== 'string') return false;
  let p = presented.trim();
  if (p.toLowerCase().startsWith('sha256=')) p = p.slice(7);
  const expected = sign(rawBody);
  if (!expected) return false;
  let a;
  let b;
  try {
    if (getFormat() === 'base64') {
      a = Buffer.from(p, 'base64');
      b = Buffer.from(expected, 'base64');
    } else {
      // Hex: reject non-hex / odd length instead of silently coercing.
      if (!/^[0-9a-fA-F]+$/.test(p) || p.length % 2 !== 0) return false;
      a = Buffer.from(p.toLowerCase(), 'hex');
      b = Buffer.from(expected.toLowerCase(), 'hex');
    }
  } catch {
    return false;
  }
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { sign, verify, getSecret, getFormat };
