import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createSharePayload,
  decryptSharePayload,
  buildShareUrl,
  parseShareHash,
} from '../sharelink.js';

const SAMPLE = {
  type: 'login',
  title: 'GitHub',
  username: 'ana@example.com',
  password: 'S3cr3t!ñ€🔑',
  url: 'https://github.com/login',
  notes: 'línea 1\nlínea 2',
  tags: ['work', 'code'],
};

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function bytesToB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

test('roundtrip: createSharePayload -> decryptSharePayload restores the object', async () => {
  const { payloadB64, keyB64 } = await createSharePayload(SAMPLE);
  const restored = await decryptSharePayload(payloadB64, keyB64);
  assert.deepEqual(restored, SAMPLE);
});

test('keyB64 is unpadded base64url of a 256-bit key', async () => {
  const { keyB64 } = await createSharePayload({ a: 1 });
  assert.match(keyB64, /^[A-Za-z0-9_-]+$/, 'base64url alphabet only, no padding');
  assert.equal(keyB64.length, 43, '32 raw bytes -> 43 base64url chars');
});

test('payloadB64 is base64 of iv(12) || ciphertext(plaintext+16 tag)', async () => {
  const data = { x: 'y' };
  const { payloadB64 } = await createSharePayload(data);
  const payload = b64ToBytes(payloadB64);
  const plaintextLen = new TextEncoder().encode(JSON.stringify(data)).length;
  assert.equal(payload.length, 12 + plaintextLen + 16);
});

test('every share uses a fresh key and IV', async () => {
  const a = await createSharePayload(SAMPLE);
  const b = await createSharePayload(SAMPLE);
  assert.notEqual(a.keyB64, b.keyB64);
  assert.notEqual(a.payloadB64, b.payloadB64);
});

test('tamper detection: flipping a ciphertext byte makes decryption throw', async () => {
  const { payloadB64, keyB64 } = await createSharePayload(SAMPLE);
  const payload = b64ToBytes(payloadB64);
  payload[payload.length - 1] ^= 0x01; // corrupt the GCM tag
  await assert.rejects(decryptSharePayload(bytesToB64(payload), keyB64));
});

test('tamper detection: flipping an IV byte makes decryption throw', async () => {
  const { payloadB64, keyB64 } = await createSharePayload(SAMPLE);
  const payload = b64ToBytes(payloadB64);
  payload[0] ^= 0xff;
  await assert.rejects(decryptSharePayload(bytesToB64(payload), keyB64));
});

test('decryption with the wrong key throws', async () => {
  const a = await createSharePayload(SAMPLE);
  const b = await createSharePayload({ other: true });
  await assert.rejects(decryptSharePayload(a.payloadB64, b.keyB64));
});

test('decryption of malformed payloads throws', async () => {
  const { keyB64 } = await createSharePayload(SAMPLE);
  await assert.rejects(decryptSharePayload('AAAA', keyB64)); // too short
});

test('buildShareUrl puts the key in the fragment only', () => {
  const url = buildShareUrl('https://vault.example.com', 'abc123', 'kEy_-42');
  assert.equal(url, 'https://vault.example.com/#/share/abc123/kEy_-42');
  const parsed = new URL(url);
  assert.equal(parsed.pathname, '/');
  assert.ok(!parsed.search.includes('kEy_-42'), 'key must not be in the query string');
  assert.ok(parsed.hash.includes('kEy_-42'), 'key must be in the fragment');
});

test('parseShareHash / buildShareUrl are symmetric', async () => {
  const { payloadB64, keyB64 } = await createSharePayload(SAMPLE);
  const url = buildShareUrl('https://vault.example.com', 'id-42', keyB64);
  const { hash } = new URL(url);
  const parsed = parseShareHash(hash);
  assert.deepEqual(parsed, { id: 'id-42', key: keyB64 });
  // and the parsed key still decrypts the payload
  const restored = await decryptSharePayload(payloadB64, parsed.key);
  assert.deepEqual(restored, SAMPLE);
});

test('parseShareHash returns null for anything that is not a share hash', () => {
  assert.equal(parseShareHash(null), null);
  assert.equal(parseShareHash(undefined), null);
  assert.equal(parseShareHash(''), null);
  assert.equal(parseShareHash('#/'), null);
  assert.equal(parseShareHash('#/share/'), null);
  assert.equal(parseShareHash('#/share/only-id'), null);
  assert.equal(parseShareHash('#/share/id/'), null);
  assert.equal(parseShareHash('#/vault/v1/item/i1'), null);
  assert.equal(parseShareHash('#/share/a/b/c'), null);
  assert.equal(parseShareHash('/share/a/b'), null); // missing '#'
});
