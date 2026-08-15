// ============================================================
// Sésamo — WebAuthn provider primitives
//
// The pieces a software passkey authenticator needs: minimal CBOR
// encoding (registration responses are CBOR), COSE public keys,
// authenticatorData layout, ECDSA P-256 signing with raw→DER
// conversion, and RP ID validation.
//
// Pure module, same contract as domain.js: works as an ES module in
// the MV3 service worker and in Node (`node --test`). All crypto is
// WebCrypto (`crypto.subtle`), available in both.
// ============================================================

import { registrableDomain } from './domain.js';

// AAGUID identifying Sésamo (né MasPassword) as a passkey provider. Constant across
// installs (that is how provider-identification lists work); spells
// "masp/as/sw/or/dpkv01" in ASCII hex.
export const AAGUID = new Uint8Array([
  0x6d, 0x61, 0x73, 0x70, 0x61, 0x73, 0x73, 0x77,
  0x6f, 0x72, 0x64, 0x70, 0x6b, 0x76, 0x30, 0x31,
]);

// authenticatorData flag bits (WebAuthn §6.1)
export const FLAG_UP = 0x01; // user present
export const FLAG_UV = 0x04; // user verified
export const FLAG_BE = 0x08; // backup eligible (synced credential)
export const FLAG_BS = 0x10; // backed up
export const FLAG_AT = 0x40; // attested credential data included

export const ALG_ES256 = -7;

// --- base64url ---
export function b64urlEncode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// --- CBOR (encoder only, the subset attestation objects need) ---
// Supported values: non-negative/negative integers, Uint8Array (byte
// string), string (text string), Array, and Map (entries emitted in
// insertion order — callers insert in CTAP2 canonical order).
function cborHead(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value <= 0xff) return Uint8Array.of((major << 5) | 24, value);
  if (value <= 0xffff) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
  if (value <= 0xffffffff) {
    return Uint8Array.of((major << 5) | 26,
      (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  }
  throw new Error('CBOR: value too large');
}

export function cborEncode(value) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('CBOR: only integers');
    return value >= 0 ? cborHead(0, value) : cborHead(1, -value - 1);
  }
  if (value instanceof Uint8Array) {
    return concatBytes(cborHead(2, value.length), value);
  }
  if (typeof value === 'string') {
    const utf8 = new TextEncoder().encode(value);
    return concatBytes(cborHead(3, utf8.length), utf8);
  }
  if (Array.isArray(value)) {
    return concatBytes(cborHead(4, value.length), ...value.map(cborEncode));
  }
  if (value instanceof Map) {
    const parts = [cborHead(5, value.size)];
    for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
    return concatBytes(...parts);
  }
  throw new Error('CBOR: unsupported type ' + typeof value);
}

// COSE_Key for an EC2 P-256 public key (kty:EC2, alg:ES256, crv:P-256).
// Keys in CTAP2 canonical order: 1, 3, -1, -2, -3.
export function coseEc2Key(x, y) {
  if (x.length !== 32 || y.length !== 32) throw new Error('COSE: x/y must be 32 bytes');
  const m = new Map();
  m.set(1, 2);          // kty: EC2
  m.set(3, ALG_ES256);  // alg: ES256
  m.set(-1, 1);         // crv: P-256
  m.set(-2, x);
  m.set(-3, y);
  return cborEncode(m);
}

// --- authenticatorData ---
// rpIdHash(32) || flags(1) || signCount(4, big-endian).
// Synced (multi-device) credentials keep signCount at 0 forever: any
// per-device increment would trip RP clone detection when the same
// vault is used from two devices. BE|BS mark the credential as synced.
export function buildAuthData(rpIdHash, flags, attestedCredentialData) {
  const counter = new Uint8Array(4); // always 0
  return attestedCredentialData
    ? concatBytes(rpIdHash, Uint8Array.of(flags), counter, attestedCredentialData)
    : concatBytes(rpIdHash, Uint8Array.of(flags), counter);
}

// attestedCredentialData: AAGUID(16) || credIdLen(2, BE) || credId || COSE key
export function buildAttestedCredentialData(credentialId, cosePublicKey) {
  const len = Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff);
  return concatBytes(AAGUID, len, credentialId, cosePublicKey);
}

// attestationObject with fmt "none" (the format every passkey provider
// uses: iCloud Keychain, Google PM, 1Password, Bitwarden). Map entries
// in canonical order: fmt, attStmt, authData.
export function buildAttestationObject(authData) {
  const m = new Map();
  m.set('fmt', 'none');
  m.set('attStmt', new Map());
  m.set('authData', authData);
  return cborEncode(m);
}

// --- ECDSA signature raw (r||s, 64 bytes) → ASN.1 DER, as WebAuthn requires ---
function derInteger(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.slice(i);
  if (v[0] & 0x80) v = concatBytes(Uint8Array.of(0), v);
  return concatBytes(Uint8Array.of(0x02, v.length), v);
}

export function rawSigToDer(raw) {
  if (raw.length !== 64) throw new Error('signature: expected 64 bytes r||s');
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32));
  const body = concatBytes(r, s);
  return concatBytes(Uint8Array.of(0x30, body.length), body);
}

// --- RP ID validation (WebAuthn §5.1.3/5.1.4) ---
// The RP ID must be a registrable-domain suffix of the caller origin's
// effective domain: for login.app.example.com the valid RP IDs are
// login.app.example.com, app.example.com and example.com — never "com".
export function rpIdValidFor(hostname, rpId) {
  if (!hostname || !rpId) return false;
  const h = String(hostname).toLowerCase().replace(/\.$/, '');
  const r = String(rpId).toLowerCase().replace(/\.$/, '');
  if (h !== r && !h.endsWith('.' + r)) return false;
  if (h === r) return true;
  const rd = registrableDomain(h);
  return r === rd || r.endsWith('.' + rd);
}

// --- WebCrypto helpers ---
export async function sha256(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// Generate a P-256 keypair for a new passkey. The private key is stored
// as a JWK inside the item's encrypted blob (same treatment as a
// password); x/y feed the COSE key in the registration response.
export async function generatePasskeyKeypair() {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return {
    privateKeyJwk,
    x: b64urlDecode(privateKeyJwk.x),
    y: b64urlDecode(privateKeyJwk.y),
  };
}

// SPKI DER of the public half (AuthenticatorAttestationResponse.getPublicKey()).
export async function spkiFromPrivateJwk(privateKeyJwk) {
  const pubJwk = { kty: 'EC', crv: 'P-256', x: privateKeyJwk.x, y: privateKeyJwk.y };
  const pub = await crypto.subtle.importKey(
    'jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}

// Sign authenticatorData || sha256(clientDataJSON) with the passkey's
// private key. Returns the DER signature RPs verify.
export async function signAssertion(privateKeyJwk, authData, clientDataHash) {
  const key = await crypto.subtle.importKey(
    'jwk', privateKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const payload = concatBytes(authData, clientDataHash);
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, payload));
  return rawSigToDer(raw);
}

export function randomCredentialId() {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  return id;
}
