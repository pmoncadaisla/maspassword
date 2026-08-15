// ============================================================
// Sésamo — RFC 6238 TOTP (dependency-free)
//
// Uses the Web Crypto API (crypto.subtle) HMAC-SHA1, available in
// extension popups and in Node v22. No external dependencies.
// ============================================================

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Decode an RFC 4648 base32 string into bytes. Case-insensitive,
// tolerant of spaces, padding (`=`) and separators (e.g. dashes),
// which are simply skipped.
export function base32Decode(str) {
  if (typeof str !== 'string') return new Uint8Array(0);
  const clean = str.toUpperCase().replace(/[=\s]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) continue; // skip anything outside the alphabet
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// 8-byte big-endian counter (RFC 4226 moving factor).
function counterBytes(counter) {
  const buf = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  return buf;
}

// Generate the current TOTP code.
//   secret : base32-encoded shared secret
//   period : time step in seconds (default 30)
//   digits : number of output digits (default 6)
//   t      : "current" time in ms (default Date.now())
// Returns { code: zero-padded string, remaining: seconds left in step }.
export async function generateTOTP(secret, { period = 30, digits = 6, t = Date.now() } = {}) {
  const keyBytes = base32Decode(secret);
  const seconds = Math.floor(t / 1000);
  const counter = Math.floor(seconds / period);

  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(counter)));

  // RFC 4226 dynamic truncation.
  const offset = sig[sig.length - 1] & 0x0f;
  const bin =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  const code = String(bin % (10 ** digits)).padStart(digits, '0');
  const remaining = period - (seconds % period);
  return { code, remaining };
}

// Defensive global exposure for non-module consumers.
if (typeof self !== 'undefined') {
  self.MP_totp = { base32Decode, generateTOTP };
}
