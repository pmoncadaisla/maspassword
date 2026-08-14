// sharelink.js — client-side crypto for one-time share links.
//
// Zero-knowledge invariant: the random AES key NEVER leaves the browser except
// inside the URL FRAGMENT ('#/share/<id>/<key>'). Fragments are not sent to the
// server in HTTP requests, so the server only ever stores the opaque encrypted
// payload and can never read the shared item.
//
// Format:
//   payloadB64 = base64( iv(12 bytes) || AES-GCM ciphertext )   -> stored server-side
//   keyB64     = base64url( raw 32-byte key ), no padding        -> URL fragment only

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(s) {
  let b64 = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return base64ToBytes(b64);
}

/**
 * Encrypt a plain item-data object for sharing.
 * Generates a fresh 256-bit AES-GCM key and a 12-byte IV via
 * crypto.getRandomValues, encrypts JSON(itemData), and returns:
 *   { payloadB64, keyB64 }
 * payloadB64 = base64(iv || ciphertext)  — safe to send to the server.
 * keyB64     = base64url(raw key), unpadded — put it ONLY in the URL fragment.
 */
export async function createSharePayload(itemData) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const plaintext = textEncoder.encode(JSON.stringify(itemData));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));

  const payload = new Uint8Array(iv.length + ciphertext.length);
  payload.set(iv, 0);
  payload.set(ciphertext, iv.length);

  return {
    payloadB64: bytesToBase64(payload),
    keyB64: bytesToBase64Url(keyBytes),
  };
}

/**
 * Inverse of createSharePayload. Throws (rejects) on any tampering — AES-GCM
 * authentication fails — or on malformed input.
 */
export async function decryptSharePayload(payloadB64, keyB64) {
  const payload = base64ToBytes(payloadB64);
  if (payload.length < 13) throw new Error('invalid-payload');
  const iv = payload.subarray(0, 12);
  const ciphertext = payload.subarray(12);
  const keyBytes = base64UrlToBytes(keyB64);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(textDecoder.decode(plaintext));
}

/**
 * Build the share URL. The key travels in the fragment, never in path/query.
 */
export function buildShareUrl(origin, id, keyB64) {
  return `${origin}/#/share/${id}/${keyB64}`;
}

/**
 * Parse a location.hash of the form '#/share/<id>/<key>'.
 * Returns { id, key } or null when the hash is not a share link.
 */
export function parseShareHash(hash) {
  if (typeof hash !== 'string') return null;
  const m = hash.match(/^#\/share\/([^/]+)\/([^/]+)$/);
  if (!m) return null;
  return { id: m[1], key: m[2] };
}
