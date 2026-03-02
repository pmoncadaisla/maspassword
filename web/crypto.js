// Client-side AES-256-GCM encryption using Web Crypto API
// All encryption/decryption happens here — the server never sees plaintext

// Derive a 256-bit AES key from master password + email using PBKDF2
export async function deriveKey(password, email) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('vault-internal:' + email), iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt plaintext string → base64(iv + ciphertext)
export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  // Prepend IV to ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

// Decrypt base64(iv + ciphertext) → plaintext string
export async function decrypt(key, encoded) {
  const combined = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

// Generate a random password
export function generatePassword(length = 20) {
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % chars.length]).join('');
}

// --- RSA-OAEP Key Pair (4096-bit) for shared vault encryption ---

// Generate RSA-OAEP key pair → { publicKeyJwk, privateKeyJwk }
export async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  return { publicKeyJwk, privateKeyJwk };
}

// Encrypt private key JWK with AES encKey → base64 string
export async function encryptPrivateKey(encKey, privateKeyJwk) {
  return encrypt(encKey, JSON.stringify(privateKeyJwk));
}

// Decrypt encrypted private key → private CryptoKey
export async function decryptPrivateKey(encKey, encrypted) {
  const json = await decrypt(encKey, encrypted);
  const jwk = JSON.parse(json);
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

// Encrypt data with RSA public key (JWK string from server) → base64
export async function encryptWithPublicKey(pubKeyJwk, data) {
  const pubKey = await crypto.subtle.importKey('jwk', pubKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
}

// Decrypt data with RSA private CryptoKey → string
export async function decryptWithPrivateKey(privKey, encoded) {
  const ciphertext = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// --- Vault Key (AES-256) for shared vaults ---

// Generate a random AES-256 vault key → base64 string of raw key bytes
export async function generateVaultKey() {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Import a base64 vault key string → CryptoKey
export async function importVaultKey(base64) {
  const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// --- TOTP (Time-based One-Time Password, RFC 6238) ---

function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  str = str.replace(/[\s=-]+/g, '').toUpperCase();
  let bits = '';
  for (const c of str) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

// Generate a 6-digit TOTP code from a Base32-encoded secret
// Returns { code: "123456", remaining: seconds_left_in_period }
export async function generateTOTP(secret, period = 30) {
  const keyBytes = base32Decode(secret);
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  const remaining = period - (now % period);

  // Counter as 8-byte big-endian
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(4, counter, false);

  // HMAC-SHA1
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, counterBuf);
  const hmac = new Uint8Array(sig);

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const code = (binary % 1000000).toString().padStart(6, '0');
  return { code, remaining };
}
