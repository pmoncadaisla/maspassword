// Regenerates the cross-implementation vectors embedded in
// core/src/test/kotlin/com/maspassword/core/WebVectors.kt by running the REAL
// web client crypto (web/crypto.js) under Node >= 18 (WebCrypto).
//
//   node android/core/scripts/gen-web-vectors.mjs > vectors.json
//
// Then transcribe the values into WebVectors.kt (or regenerate it with any
// script — the constants map 1:1 to the JSON keys). Because the RSA keypair
// and the AES-GCM IVs are random, every run produces different ciphertexts;
// all of them are equally valid vectors.
import * as C from '../../../web/crypto.js';
import { pbkdf2Sync } from 'node:crypto';

const password = 'pässwörd-🔐 correct horse';
const email = 'ana.garcía@example.com';

// Independent PBKDF2 expectation (same parameters deriveKey uses).
const derivedHex = pbkdf2Sync(password, 'vault-internal:' + email, 600000, 32, 'sha256').toString('hex');

const key = await C.deriveKey(password, email);

// Personal-vault item encrypted with the derived key.
const itemJson = JSON.stringify({
  type: 'login', title: 'Ejemplo S.A.', username: 'ana', password: 's3cret!ñ€',
  url: 'https://app.example.co.uk/login', notes: 'línea1\nlínea2',
  totp_secret: 'JBSWY3DPEHPK3PXP', tags: ['work', 'ütf-8'], favorite: true,
  customFields: [{ label: 'PIN', value: '1234', hidden: true }],
  attachments: [{ name: 'a.txt', type: 'text/plain', size: 5, data: 'aGVsbG8=' }],
  icon: '🔑', pwChangedAt: 1723620000000,
});
const encItem = await C.encrypt(key, itemJson);
const encVaultName = await C.encrypt(key, 'Personal');

// Shared-vault chain: RSA-4096 JWK -> encrypted private key -> wrapped vault key.
const { publicKeyJwk, privateKeyJwk } = await C.generateKeyPair();
const encPrivKey = await C.encryptPrivateKey(key, privateKeyJwk);
const vaultKeyB64 = await C.generateVaultKey();
const encVaultKey = await C.encryptWithPublicKey(publicKeyJwk, vaultKeyB64);
const vk = await C.importVaultKey(vaultKeyB64);
const sharedItemJson = JSON.stringify({ type: 'note', title: 'Nota compartida', notes: 'secreto' });
const encSharedItem = await C.encrypt(vk, sharedItemJson);

// Pairing QR payload, byte-for-byte like web/app.js renderDevicePairing.
const tok = 'mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_wY0yhq0kQXfYtEZO4Q0z0eBUn_-o3O9y5m0eXk3vJqE';
const payload = JSON.stringify({ v: 1, srv: 'https://vault.example.com', email, tok });
const qrB64url = btoa(String.fromCharCode(...new TextEncoder().encode(payload)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

console.log(JSON.stringify({
  password, email, derivedHex,
  itemJson, encItem, encVaultName,
  encPrivKey, vaultKeyB64, encVaultKey, sharedItemJson, encSharedItem,
  tok, qrB64url,
}, null, 2));
