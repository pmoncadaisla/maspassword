// ============================================================
// Vault Internal — Password generator (dependency-free)
//
// Cryptographically secure: uses crypto.getRandomValues with
// rejection sampling so there is NO modulo bias across the pool.
// ============================================================

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}<>?.,;:',
};

// Unbiased integer in [0, max) via rejection sampling over uint32.
function randomIndex(max) {
  // Largest multiple of `max` that fits in a uint32; values at or
  // above it are rejected so every residue is equally likely.
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

// Build a password from the selected character classes.
export function generatePassword(opts = {}) {
  const {
    length = 20,
    lower = true,
    upper = true,
    digits = true,
    symbols = true,
  } = opts;

  let pool = '';
  if (lower) pool += SETS.lower;
  if (upper) pool += SETS.upper;
  if (digits) pool += SETS.digits;
  if (symbols) pool += SETS.symbols;
  if (!pool) pool = SETS.lower; // never allow an empty pool

  const len = Math.max(1, Math.min(128, Math.floor(length) || 20));
  let out = '';
  for (let i = 0; i < len; i++) {
    out += pool[randomIndex(pool.length)];
  }
  return out;
}

// Defensive global exposure for non-module consumers.
if (typeof self !== 'undefined') {
  self.MP_generator = { generatePassword };
}
