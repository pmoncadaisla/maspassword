import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  buildKdbx,
  buildCsv,
  buildJson,
  itemsToKdbxEntries,
  chachaStream,
  bytesToB64,
} from '../export.js';

// ---------------------------------------------------------------------------
// Independent KDBX 4 reader built on node:crypto — deliberately NOT sharing
// primitives with the writer. AES-KDF is recomputed with literal sequential
// AES-ECB rounds (validating the writer's CBC-over-zeros trick against the
// real thing) and protected values are decrypted with node's native chacha20.
// ---------------------------------------------------------------------------

function aesKdfEcb(composite, seed, rounds) {
  let left = composite.subarray(0, 16);
  let right = composite.subarray(16, 32);
  for (let i = 0; i < rounds; i++) {
    const c = crypto.createCipheriv('aes-256-ecb', seed, null);
    c.setAutoPadding(false);
    const out = Buffer.concat([c.update(Buffer.concat([left, right])), c.final()]);
    left = out.subarray(0, 16);
    right = out.subarray(16, 32);
  }
  return crypto.createHash('sha256').update(Buffer.concat([left, right])).digest();
}

function readKdbx(fileBytes, password) {
  const buf = Buffer.from(fileBytes);
  let off = 0;
  const u32 = () => { const v = buf.readUInt32LE(off); off += 4; return v; };

  assert.equal(u32(), 0x9aa2d903, 'signature 1');
  assert.equal(u32(), 0xb54bfb67, 'signature 2');
  assert.equal(u32() & 0xffff0000, 0x00040000, 'KDBX major version 4');

  const fields = {};
  for (;;) {
    const id = buf.readUInt8(off); off += 1;
    const len = buf.readInt32LE(off); off += 4;
    const data = buf.subarray(off, off + len); off += len;
    if (id === 0) break;
    fields[id] = data;
  }
  const headerBytes = buf.subarray(0, off);

  // KDF parameters (VariantDictionary)
  const kdf = {};
  {
    const d = fields[11];
    let p = 2; // version
    for (;;) {
      const type = d.readUInt8(p); p += 1;
      if (type === 0) break;
      const klen = d.readInt32LE(p); p += 4;
      const key = d.subarray(p, p + klen).toString('utf8'); p += klen;
      const vlen = d.readInt32LE(p); p += 4;
      const val = d.subarray(p, p + vlen); p += vlen;
      kdf[key] = { type, val };
    }
  }
  assert.equal(kdf['$UUID'].val.toString('hex'), 'c9d9f39a628a4460bf740d08c18a4fea', 'AES-KDF uuid');
  const rounds = Number(kdf.R.val.readBigUInt64LE(0));

  // Keys
  const pwHash = crypto.createHash('sha256').update(password, 'utf8').digest();
  const composite = crypto.createHash('sha256').update(pwHash).digest();
  const transformed = aesKdfEcb(composite, kdf.S.val, rounds);
  const masterSeed = fields[4];
  const cipherKey = crypto.createHash('sha256')
    .update(Buffer.concat([masterSeed, transformed])).digest();
  const hmacBase = crypto.createHash('sha512')
    .update(Buffer.concat([masterSeed, transformed, Buffer.from([0x01])])).digest();

  // Header integrity
  const headerSha = buf.subarray(off, off + 32); off += 32;
  const headerHmac = buf.subarray(off, off + 32); off += 32;
  assert.deepEqual(headerSha, crypto.createHash('sha256').update(headerBytes).digest(), 'header sha256');
  const idxMax = Buffer.alloc(8, 0xff);
  const headerHmacKey = crypto.createHash('sha512').update(Buffer.concat([idxMax, hmacBase])).digest();
  assert.deepEqual(headerHmac,
    crypto.createHmac('sha256', headerHmacKey).update(headerBytes).digest(), 'header hmac');

  // HMAC block stream
  const chunks = [];
  for (let index = 0n; ; index++) {
    const hmac = buf.subarray(off, off + 32); off += 32;
    const len = buf.readInt32LE(off); off += 4;
    const data = buf.subarray(off, off + len); off += len;
    const idx = Buffer.alloc(8);
    idx.writeBigUInt64LE(index);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeInt32LE(len);
    const blockKey = crypto.createHash('sha512').update(Buffer.concat([idx, hmacBase])).digest();
    const expect = crypto.createHmac('sha256', blockKey)
      .update(Buffer.concat([idx, lenBuf, data])).digest();
    assert.deepEqual(hmac, expect, `block ${index} hmac`);
    if (len === 0) break;
    chunks.push(data);
  }
  assert.equal(off, buf.length, 'no trailing bytes');

  // Decrypt payload (node handles PKCS7)
  const dec = crypto.createDecipheriv('aes-256-cbc', cipherKey, fields[7]);
  const payload = Buffer.concat([dec.update(Buffer.concat(chunks)), dec.final()]);

  // Inner header
  let p = 0;
  const inner = {};
  for (;;) {
    const id = payload.readUInt8(p); p += 1;
    const len = payload.readInt32LE(p); p += 4;
    const data = payload.subarray(p, p + len); p += len;
    if (id === 0) break;
    inner[id] = data;
  }
  assert.equal(inner[1].readUInt32LE(0), 3, 'inner stream is ChaCha20');
  const xml = payload.subarray(p).toString('utf8');

  // Protected values: one continuous ChaCha20 keystream in document order.
  const streamHash = crypto.createHash('sha512').update(inner[2]).digest();
  const iv = Buffer.concat([Buffer.alloc(4), streamHash.subarray(32, 44)]); // counter 0 || nonce
  const cipher = crypto.createCipheriv('chacha20', streamHash.subarray(0, 32), iv);
  const protectedValues = [];
  const re = /<Value Protected="True">([^<]*)<\/Value>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const ct = Buffer.from(m[1], 'base64');
    protectedValues.push(cipher.update(ct).toString('utf8'));
  }
  return { xml, protectedValues, rounds };
}

// ---------------------------------------------------------------------------

const sampleItems = [
  {
    data: {
      type: 'login', title: 'Correo & <Cía>', username: 'ana@example.com',
      password: 'S3creta"única"', url: 'https://mail.example.com',
      notes: 'línea 1\nlínea 2', totp_secret: 'JBSWY3DPEHPK3PXP',
      tags: ['trabajo', 'email'],
      customFields: [
        { label: 'PIN', value: '1234', hidden: true },
        { label: 'Password', value: 'colisiona', hidden: false },
      ],
    },
    created_at: '2026-08-01T10:00:00Z',
    updated_at: '2026-08-15T09:30:00Z',
  },
  {
    data: {
      type: 'card', title: 'Visa personal', card_holder: 'Ana García',
      card_number: '4111111111111111', card_brand: 'Visa',
      card_exp: '12/28', card_cvv: '123', card_pin: '9876', notes: '',
    },
    created_at: '2026-08-02T10:00:00Z',
    updated_at: '2026-08-02T10:00:00Z',
  },
];

test('KDBX round-trip: an independent reader recovers every field', async () => {
  const entries = itemsToKdbxEntries(sampleItems);
  const file = await buildKdbx({
    vaultName: 'Caja «personal»',
    entries,
    password: 'contraseña-de-export!',
    rounds: 1000, // keep the test fast; the format is identical
  });

  const { xml, protectedValues, rounds } = readKdbx(file, 'contraseña-de-export!');
  assert.equal(rounds, 1000);

  // Unprotected fields land escaped in the XML.
  assert.match(xml, /<DatabaseName>Caja «personal»<\/DatabaseName>/);
  assert.match(xml, /<Key>Title<\/Key><Value>Correo &amp; &lt;Cía&gt;<\/Value>/);
  assert.match(xml, /<Key>UserName<\/Key><Value>ana@example.com<\/Value>/);
  assert.match(xml, /<Key>URL<\/Key><Value>https:\/\/mail.example.com<\/Value>/);
  assert.match(xml, /<Tags>trabajo;email<\/Tags>/);
  assert.match(xml, /<Key>Card Holder<\/Key><Value>Ana García<\/Value>/);
  // The custom field colliding with the standard Password key gets suffixed.
  assert.match(xml, /<Key>Password \(2\)<\/Key><Value>colisiona<\/Value>/);

  // Protected values decrypt in document order: entry 1's password, otp and
  // custom PIN, then entry 2's card number, CVV and PIN.
  assert.deepEqual(protectedValues, [
    'S3creta"única"',
    'otpauth://totp/Correo%20%26%20%3CC%C3%ADa%3E?secret=JBSWY3DPEHPK3PXP',
    '1234',
    '4111111111111111',
    '123',
    '9876',
  ]);

  // KDBX4 times are base64(uint64le(seconds since 0001-01-01)).
  const tMatch = xml.match(/<CreationTime>([^<]+)<\/CreationTime>/g);
  assert.ok(tMatch.length >= 2);
  const secs = Buffer.from(tMatch[1].replace(/<\/?CreationTime>/g, ''), 'base64').readBigUInt64LE(0);
  const expected = BigInt(Math.floor(Date.parse('2026-08-01T10:00:00Z') / 1000) + 62135596800);
  assert.equal(secs, expected);
});

test('KDBX: wrong password fails the header HMAC, not something later', async () => {
  const file = await buildKdbx({
    vaultName: 'V', entries: itemsToKdbxEntries(sampleItems.slice(0, 1)),
    password: 'correcta', rounds: 500,
  });
  assert.throws(() => readKdbx(file, 'incorrecta'), /header hmac/);
});

test('chachaStream XORs like node crypto chacha20 and is an involution', () => {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const data = crypto.randomBytes(300); // crosses block boundaries

  const mine = chachaStream(new Uint8Array(key), new Uint8Array(nonce)).xor(new Uint8Array(data));
  const iv = Buffer.concat([Buffer.alloc(4), nonce]);
  const theirs = crypto.createCipheriv('chacha20', key, iv).update(data);
  assert.deepEqual(Buffer.from(mine), theirs);

  const stream2 = chachaStream(new Uint8Array(key), new Uint8Array(nonce));
  const back = stream2.xor(mine.subarray(0, 300));
  assert.deepEqual(Buffer.from(back), data);
});

test('CSV: quoting, BOM, notes folding and tags', () => {
  const csv = buildCsv(sampleItems);
  assert.ok(csv.startsWith('﻿'), 'starts with BOM');
  const lines = csv.slice(1).split('\r\n');
  assert.equal(lines[0], 'type,title,username,password,url,notes,totp,tags');
  // Quoted fields with embedded quotes/newlines survive.
  assert.match(lines[1], /"S3creta""única"""/);
  assert.match(csv, /"línea 1\nlínea 2\nPIN: 1234\nPassword: colisiona"/);
  assert.match(csv, /trabajo;email/);
  // Card fields fold into notes.
  assert.match(csv, /Card Number: 4111111111111111/);
});

test('JSON export keeps full fidelity', () => {
  const json = JSON.parse(buildJson('Personal', sampleItems));
  assert.equal(json.format, 'sesamo-vault');
  assert.equal(json.vault, 'Personal');
  assert.equal(json.items.length, 2);
  assert.equal(json.items[0].password, 'S3creta"única"');
  assert.equal(json.items[0].customFields[0].label, 'PIN');
  assert.equal(json.items[1].card_number, '4111111111111111');
  assert.equal(json.items[0].created_at, '2026-08-01T10:00:00Z');
});

test('itemsToKdbxEntries: otpauth passthrough and empty fields dropped', () => {
  const [entry] = itemsToKdbxEntries([{
    data: { type: 'login', title: 'X', totp_secret: 'otpauth://totp/ya?secret=ABC', password: '' },
  }]);
  const otp = entry.fields.find(f => f.key === 'otp');
  assert.equal(otp.value, 'otpauth://totp/ya?secret=ABC');
  assert.ok(otp.protected);
  // Password is empty → the XML builder drops it; ensure mapping kept it as ''
  const pw = entry.fields.find(f => f.key === 'Password');
  assert.equal(pw.value, '');
});

test('bytesToB64 handles large buffers without call-stack overflow', () => {
  const big = new Uint8Array(300000).fill(65);
  const b64 = bytesToB64(big);
  assert.equal(Buffer.from(b64, 'base64').length, 300000);
});
