import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AAGUID, ALG_ES256, FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT,
  b64urlEncode, b64urlDecode, concatBytes, cborEncode, coseEc2Key,
  buildAuthData, buildAttestedCredentialData, buildAttestationObject,
  rawSigToDer, rpIdValidFor, sha256, generatePasskeyKeypair,
  spkiFromPrivateJwk, signAssertion, randomCredentialId,
} from './webauthn.js';

const hex = bytes => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

// Minimal CBOR decoder — test-side only, to verify what the encoder emits.
function cborDecode(bytes) {
  let pos = 0;
  function readLen(info) {
    if (info < 24) return info;
    if (info === 24) return bytes[pos++];
    if (info === 25) { const v = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; return v; }
    if (info === 26) {
      const v = (bytes[pos] * 2 ** 24) + (bytes[pos + 1] << 16) + (bytes[pos + 2] << 8) + bytes[pos + 3];
      pos += 4; return v;
    }
    throw new Error('decoder: unsupported length');
  }
  function item() {
    const b = bytes[pos++];
    const major = b >> 5, info = b & 0x1f;
    const len = readLen(info);
    if (major === 0) return len;
    if (major === 1) return -1 - len;
    if (major === 2) { const v = bytes.slice(pos, pos + len); pos += len; return v; }
    if (major === 3) { const v = new TextDecoder().decode(bytes.slice(pos, pos + len)); pos += len; return v; }
    if (major === 4) { const a = []; for (let i = 0; i < len; i++) a.push(item()); return a; }
    if (major === 5) { const m = new Map(); for (let i = 0; i < len; i++) { const k = item(); m.set(k, item()); } return m; }
    throw new Error('decoder: unsupported major ' + major);
  }
  const v = item();
  return { value: v, consumed: pos };
}

test('b64url: roundtrip and alphabet', () => {
  const bytes = Uint8Array.of(0xfb, 0xef, 0xff, 0x3e, 0x00);
  const s = b64urlEncode(bytes);
  assert.ok(!/[+/=]/.test(s), 'no +, / or padding');
  assert.deepEqual(b64urlDecode(s), bytes);
  assert.deepEqual(b64urlDecode(b64urlEncode(new Uint8Array(0))), new Uint8Array(0));
});

test('cbor: integer encodings match RFC 8949 vectors', () => {
  assert.equal(hex(cborEncode(0)), '00');
  assert.equal(hex(cborEncode(23)), '17');
  assert.equal(hex(cborEncode(24)), '1818');
  assert.equal(hex(cborEncode(255)), '18ff');
  assert.equal(hex(cborEncode(256)), '190100');
  assert.equal(hex(cborEncode(65536)), '1a00010000');
  assert.equal(hex(cborEncode(-1)), '20');
  assert.equal(hex(cborEncode(-7)), '26');   // ES256 alg identifier
  assert.equal(hex(cborEncode(-257)), '390100'); // RS256, for reference
});

test('cbor: strings, byte strings, arrays, maps', () => {
  assert.equal(hex(cborEncode('fmt')), '63666d74');
  assert.equal(hex(cborEncode(Uint8Array.of(1, 2, 3))), '43010203');
  assert.equal(hex(cborEncode([1, 2])), '820102');
  const m = new Map([[1, 2], [-1, 'a']]);
  assert.equal(hex(cborEncode(m)), 'a20102206161');
});

test('cbor: 256-byte string uses 2-byte length header', () => {
  const big = new Uint8Array(256).fill(7);
  const enc = cborEncode(big);
  assert.equal(hex(enc.slice(0, 3)), '590100');
  assert.equal(enc.length, 3 + 256);
});

test('coseEc2Key: canonical field order and values', () => {
  const x = new Uint8Array(32).fill(0xaa);
  const y = new Uint8Array(32).fill(0xbb);
  const { value: m } = cborDecode(coseEc2Key(x, y));
  assert.deepEqual([...m.keys()], [1, 3, -1, -2, -3]);
  assert.equal(m.get(1), 2);          // kty EC2
  assert.equal(m.get(3), ALG_ES256);  // alg ES256
  assert.equal(m.get(-1), 1);         // crv P-256
  assert.deepEqual(m.get(-2), x);
  assert.deepEqual(m.get(-3), y);
  assert.throws(() => coseEc2Key(new Uint8Array(31), y));
});

test('authData: assertion layout (37 bytes, zero counter, synced flags)', async () => {
  const rpIdHash = await sha256('example.com');
  const flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
  const ad = buildAuthData(rpIdHash, flags);
  assert.equal(ad.length, 37);
  assert.deepEqual(ad.slice(0, 32), rpIdHash);
  assert.equal(ad[32], 0x1d);
  assert.deepEqual(ad.slice(33), new Uint8Array(4)); // signCount always 0
});

test('authData: registration layout parses back to AAGUID, credId and COSE key', async () => {
  const rpIdHash = await sha256('example.com');
  const credId = randomCredentialId();
  assert.equal(credId.length, 16);
  const x = new Uint8Array(32).fill(1), y = new Uint8Array(32).fill(2);
  const acd = buildAttestedCredentialData(credId, coseEc2Key(x, y));
  const flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;
  const ad = buildAuthData(rpIdHash, flags, acd);

  assert.equal(ad[32], 0x5d);
  assert.deepEqual(ad.slice(37, 53), AAGUID);
  const idLen = (ad[53] << 8) | ad[54];
  assert.equal(idLen, 16);
  assert.deepEqual(ad.slice(55, 55 + idLen), credId);
  const { value: cose } = cborDecode(ad.slice(55 + idLen));
  assert.deepEqual(cose.get(-2), x);
});

test('attestationObject: fmt none with empty attStmt, canonical key order', async () => {
  const ad = buildAuthData(await sha256('example.com'), FLAG_UP);
  const { value: att, consumed } = cborDecode(buildAttestationObject(ad));
  assert.deepEqual([...att.keys()], ['fmt', 'attStmt', 'authData']);
  assert.equal(att.get('fmt'), 'none');
  assert.equal(att.get('attStmt').size, 0);
  assert.deepEqual(att.get('authData'), ad);
  assert.equal(consumed, buildAttestationObject(ad).length, 'no trailing bytes');
});

test('rawSigToDer: minimal integers, high-bit zero padding', () => {
  // r starts with high bit set -> 0x00 pad; s has leading zeros -> trimmed.
  const r = new Uint8Array(32); r[0] = 0x80; r[31] = 0x01;
  const s = new Uint8Array(32); s[31] = 0x02;
  const der = rawSigToDer(concatBytes(r, s));
  // SEQUENCE { INTEGER 0x00 0x80.. (33 bytes), INTEGER 0x02 (1 byte) }
  assert.equal(der[0], 0x30);
  assert.equal(der[2], 0x02);           // first INTEGER tag
  assert.equal(der[3], 33);             // padded length
  assert.equal(der[4], 0x00);           // pad byte
  assert.equal(der[5], 0x80);
  const sOff = 4 + 33;
  assert.equal(der[sOff], 0x02);        // second INTEGER tag
  assert.equal(der[sOff + 1], 1);       // trimmed to one byte
  assert.equal(der[sOff + 2], 0x02);
  assert.throws(() => rawSigToDer(new Uint8Array(63)));
});

test('rpIdValidFor: registrable-domain suffix rule', () => {
  assert.ok(rpIdValidFor('example.com', 'example.com'));
  assert.ok(rpIdValidFor('login.example.com', 'example.com'));
  assert.ok(rpIdValidFor('a.b.example.com', 'b.example.com'));
  assert.ok(rpIdValidFor('localhost', 'localhost'));
  assert.ok(rpIdValidFor('app.example.co.uk', 'example.co.uk'));

  assert.ok(!rpIdValidFor('login.example.com', 'com'), 'public suffix rejected');
  assert.ok(!rpIdValidFor('example.co.uk', 'co.uk'), 'multi-part suffix rejected');
  assert.ok(!rpIdValidFor('evil.com', 'example.com'), 'unrelated domain');
  assert.ok(!rpIdValidFor('notexample.com', 'example.com'), 'suffix needs dot boundary');
  assert.ok(!rpIdValidFor('example.com', 'login.example.com'), 'rpId more specific than host');
  assert.ok(!rpIdValidFor('example.com', ''));
  assert.ok(!rpIdValidFor('', 'example.com'));
});

test('end to end: registration output verifies an assertion signature', async () => {
  const { privateKeyJwk, x, y } = await generatePasskeyKeypair();
  const rpIdHash = await sha256('example.com');

  // Registration: COSE key inside attested credential data.
  const credId = randomCredentialId();
  const acd = buildAttestedCredentialData(credId, coseEc2Key(x, y));
  const regAuthData = buildAuthData(rpIdHash, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, acd);
  const { value: att } = cborDecode(buildAttestationObject(regAuthData));
  const cose = cborDecode(att.get('authData').slice(55 + credId.length)).value;

  // RP side: rebuild the public key from the COSE coordinates.
  const pubJwk = {
    kty: 'EC', crv: 'P-256',
    x: b64urlEncode(cose.get(-2)), y: b64urlEncode(cose.get(-3)),
  };
  const pubKey = await crypto.subtle.importKey(
    'jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

  // Assertion: sign authData || sha256(clientDataJSON), verify DER→raw.
  const clientDataJSON = JSON.stringify({
    type: 'webauthn.get', challenge: b64urlEncode(randomCredentialId()),
    origin: 'https://example.com', crossOrigin: false,
  });
  const assertAuthData = buildAuthData(rpIdHash, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
  const clientDataHash = await sha256(clientDataJSON);
  const der = await signAssertion(privateKeyJwk, assertAuthData, clientDataHash);

  // DER → raw r||s for WebCrypto verify.
  function derToRaw(sig) {
    let p = 2;
    function int() {
      assert.equal(sig[p], 0x02); p++;
      let len = sig[p++];
      let v = sig.slice(p, p + len); p += len;
      while (v.length > 32) v = v.slice(1);
      const out = new Uint8Array(32); out.set(v, 32 - v.length);
      return out;
    }
    return concatBytes(int(), int());
  }
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, pubKey, derToRaw(der),
    concatBytes(assertAuthData, clientDataHash));
  assert.ok(ok, 'assertion signature verifies against registered public key');

  // SPKI export is a valid P-256 key too.
  const spki = await spkiFromPrivateJwk(privateKeyJwk);
  await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
});
