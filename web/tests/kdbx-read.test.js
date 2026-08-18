// Tests for the KDBX reader.
//
// The crypto primitives are validated against vectors generated with
// independent implementations: hashlib (BLAKE2b), pycryptodome (Salsa20) and
// argon2-cffi (Argon2d/Argon2id). The fixture files under fixtures/ were
// written by pykeepass (KDBX 4: Argon2d, Argon2id and ChaCha20 outer cipher)
// and by a standalone pycryptodome script (KDBX 3.1), so every read path is
// exercised against bytes a real KeePass implementation produced or accepts.
// Argon2 costs in the fixtures are lowered (1 MiB, t=2) to keep this fast.

import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { blake2b, argon2, salsaStream, parseXml, readKdbx, kdbxEntriesToItems } from '../kdbx-read.js';
import { buildKdbx, itemsToKdbxEntries } from '../export.js';

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const utf8 = (s) => new TextEncoder().encode(s);
const fixture = (name) => new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const FIXTURE_PASSWORD = 'contraseña-fixture';

// --- primitives ---

test('blake2b matches hashlib on multiple lengths and block boundaries', () => {
  assert.equal(hex(blake2b(utf8('abc'), 64)),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
  assert.equal(hex(blake2b(new Uint8Array(0), 64)),
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
  assert.equal(hex(blake2b(Uint8Array.from({ length: 256 }, (_, i) => i), 32)),
    '39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835');
  assert.equal(hex(blake2b(utf8('abc'), 20)), '384264f676f39536840523f284921cdc68b6846b');
  const long = Uint8Array.from({ length: 1280 }, (_, i) => i & 0xff);
  assert.equal(hex(blake2b(long, 64)),
    'a86b784c748f990b998e6d30d71e20cc95228d2b08dd85e29f63e4de8d8839bdf935f4291537af5014fe44c0b578a073e4c9217c7b05542d0c450784c30bac8a');
});

test('salsa20 keystream matches pycryptodome (KeePass fixed nonce)', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.equal(hex(salsaStream(key).xor(new Uint8Array(128))),
    '58538c4e383a24951f6f5a9c814a5fa7a757d4102897a9ba29ba58c295874138a55afd231a4c908892d661fcb536d654'
    + '98e100e02615a237675e4623b39b8fa46958318605e8c8f61e9169c3a4e94388c82f143ad128fbf0f4c678f49e6085c'
    + 'd70a9d559992be4c9307a177074ad04d7f3eab8d932a142c862cc1b3990a05263');
});

test('argon2d and argon2id match argon2-cffi', async () => {
  const password = utf8('sesamo-password');
  const salt = utf8('salt-16-bytes-ok');
  // [variant, passes, memKiB, lanes] → tag. m=41/p=3 exercises the m' truncation.
  const vectors = [
    [0, 3, 32, 4, 'c839415d47e1ca290c4f58c4fe1345506801c545ab1e9f544752a6baa6deaeab'],
    [0, 2, 64, 1, 'fe74716ee245a2c2f25e9abd090a4127fbec25b0b4ef27d1c0754272ffe024fc'],
    [0, 1, 41, 3, '7555ff1a1a7b06b18c0847090d2ca541cd5b90f73fed89ec670f1297862608d3'],
    [2, 3, 32, 4, 'c73b35bec45cebc59b13a4813cb67d9f1ae77d919299db2bd5faa13edf8b0886'],
    [2, 2, 64, 1, '6c5eb5777dffddd2e5c3454de2b72ee6aeaf897ee519a9bb98c386787c4e7c3a'],
    [2, 1, 41, 3, '0142f5777b40660d1839199c563fccd1c1342e7c8864d5d14ea073b5546ac60a'],
  ];
  for (const [variant, passes, memKiB, lanes, want] of vectors) {
    const got = await argon2({ variant, password, salt, passes, memKiB, lanes });
    assert.equal(hex(got), want, `argon2 variant=${variant} t=${passes} m=${memKiB} p=${lanes}`);
  }
});

test('parseXml handles entities, CDATA, self-closing tags and attributes', () => {
  const doc = parseXml('<?xml version="1.0"?><!-- c --><KeePassFile><A x="1 &amp; 2">a&lt;b&#233;</A>'
    + '<B/><C><![CDATA[<raw>]]></C></KeePassFile>');
  assert.equal(doc.tag, 'KeePassFile');
  assert.equal(doc.children.length, 3);
  assert.equal(doc.children[0].attrs.x, '1 & 2');
  assert.equal(doc.children[0].text, 'a<bé');
  assert.equal(doc.children[1].children.length, 0);
  assert.equal(doc.children[2].text, '<raw>');
});

// --- fixture files from real implementations ---

test('reads a KDBX 4 Argon2d database written by pykeepass', async () => {
  const db = await readKdbx(fixture('argon2d.kdbx'), FIXTURE_PASSWORD);
  const items = kdbxEntriesToItems(db.entries);
  assert.equal(items.length, 2, 'recycle-bin entry is skipped');

  const gh = items.find((i) => i.title === 'GitHub «Cía»');
  // 'S3creta-v2' is the value AFTER the history snapshot: proves protected
  // values consume the inner stream across <History> entries in document order.
  assert.equal(gh.password, 'S3creta-v2');
  assert.equal(gh.username, 'ana@example.com');
  assert.equal(gh.url, 'https://github.com');
  assert.equal(gh.notes, 'línea 1\nlínea 2');
  assert.equal(gh.totp_secret, 'JBSWY3DPEHPK3PXP');
  // The entry has login credentials, so the Card Number custom key must NOT
  // coerce it to a card (whose layout hides username/password/TOTP) — it stays
  // a login with the card number as a hidden custom field.
  assert.equal(gh.type, 'login');
  assert.equal(gh.card_number, undefined);
  assert.deepEqual(gh.customFields, [
    { label: 'PIN', value: '1234', hidden: true },
    { label: 'Card Number', value: '4111111111111111', hidden: true },
  ]);
  assert.deepEqual(gh.tags, ['trabajo', 'email', 'Trabajo'], 'entry tags then group path');

  const simple = items.find((i) => i.title === 'Simple');
  assert.equal(simple.password, 'pass2');
  assert.equal(simple.tags, undefined, 'root-group entries carry no group tag');
});

test('reads a KDBX 4 Argon2id database written by pykeepass', async () => {
  const db = await readKdbx(fixture('argon2id.kdbx'), FIXTURE_PASSWORD);
  const items = kdbxEntriesToItems(db.entries);
  assert.equal(items.length, 2);
  assert.equal(items.find((i) => i.title === 'GitHub «Cía»').password, 'S3creta-v2');
});

test('reads a KDBX 4 database with the ChaCha20 outer cipher', async () => {
  const db = await readKdbx(fixture('chacha-outer.kdbx'), FIXTURE_PASSWORD);
  const items = kdbxEntriesToItems(db.entries);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'ChaChaEntry');
  assert.equal(items[0].password, 'pass-cc');
});

test('reads a KDBX 3.1 database (AES-KDF, Salsa20, gzip, hashed blocks)', async () => {
  const db = await readKdbx(fixture('kdbx31.kdbx'), FIXTURE_PASSWORD);
  assert.equal(db.name, 'Base31');
  const items = kdbxEntriesToItems(db.entries);
  assert.equal(items.length, 2);

  const correo = items.find((i) => i.title === 'Correo');
  assert.equal(correo.password, 'pw-31-«ñ»');
  assert.equal(correo.notes, 'nota & más', 'XML entities decode');
  assert.deepEqual(correo.customFields, [{ label: 'Secreto interno', value: 'ss-31', hidden: true }]);
  assert.deepEqual(correo.tags, ['a', 'b']);

  const sub = items.find((i) => i.title === 'Nota simple');
  assert.equal(sub.password, 'p2');
  assert.deepEqual(sub.tags, ['Sub'], 'subgroup name becomes a tag');
});

test('wrong password fails cleanly on both container versions', async () => {
  for (const name of ['argon2d.kdbx', 'kdbx31.kdbx']) {
    await assert.rejects(readKdbx(fixture(name), 'incorrecta'),
      (err) => err.code === 'bad-password', name);
  }
});

test('rejects garbage and truncated files without throwing raw TypeErrors', async () => {
  await assert.rejects(readKdbx(utf8('not a kdbx at all'), 'x'), (err) => err.code === 'not-kdbx');
  await assert.rejects(readKdbx(new Uint8Array(4), 'x'), (err) => err.code === 'not-kdbx');
  const cut = fixture('argon2d.kdbx').slice(0, 200);
  await assert.rejects(readKdbx(cut, FIXTURE_PASSWORD), (err) => typeof err.code === 'string');
});

test('a flipped ciphertext byte is detected, not silently misread', async () => {
  const bytes = fixture('argon2d.kdbx');
  bytes[bytes.length - 100] ^= 0xff;
  await assert.rejects(readKdbx(bytes, FIXTURE_PASSWORD),
    (err) => err.code === 'corrupt' || err.code === 'bad-password');
});

// --- round trip with our own writer ---

test('a Sésamo export re-imports with typed items intact', async () => {
  const source = [
    {
      data: {
        type: 'card', title: 'Visa', card_holder: 'Ana García', card_number: '4111111111111111',
        card_brand: 'Visa', card_exp: '12/28', card_cvv: '123', card_pin: '9876',
        tags: ['banco'], customFields: [{ label: 'Nota interna', value: 'x', hidden: true }],
      },
      created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-02T10:00:00Z',
    },
    {
      data: {
        type: 'login', title: 'Mail', username: 'u@example.com', password: 'p«»',
        url: 'https://mail.example.com', notes: 'n1\nn2', totp_secret: 'JBSWY3DPEHPK3PXP',
      },
    },
    {
      data: { type: 'identity', title: 'Yo', id_fullname: 'Ana García', id_email: 'ana@example.com' },
    },
  ];
  const kdbx = await buildKdbx({
    vaultName: 'RT', password: 'rt-pass', rounds: 60000,
    entries: itemsToKdbxEntries(source),
  });
  const db = await readKdbx(kdbx, 'rt-pass');
  assert.equal(db.name, 'RT');
  const items = kdbxEntriesToItems(db.entries);
  assert.equal(items.length, 3);

  const card = items.find((i) => i.title === 'Visa');
  assert.equal(card.type, 'card');
  assert.equal(card.card_holder, 'Ana García');
  assert.equal(card.card_number, '4111111111111111');
  assert.equal(card.card_cvv, '123');
  assert.equal(card.card_pin, '9876');
  assert.deepEqual(card.tags, ['banco']);
  assert.deepEqual(card.customFields, [{ label: 'Nota interna', value: 'x', hidden: true }]);

  const login = items.find((i) => i.title === 'Mail');
  assert.equal(login.type, 'login');
  assert.equal(login.password, 'p«»');
  assert.equal(login.notes, 'n1\nn2');
  assert.equal(login.totp_secret, 'JBSWY3DPEHPK3PXP');

  const id = items.find((i) => i.title === 'Yo');
  assert.equal(id.type, 'identity');
  assert.equal(id.id_fullname, 'Ana García');
  assert.equal(id.id_email, 'ana@example.com');
});

// --- mapper details ---

test('typed reconstruction only applies to credential-less entries', () => {
  const items = kdbxEntriesToItems([
    {
      // card fields alone → card item (the Sésamo→KDBX→Sésamo round trip)
      fields: [{ key: 'Title', value: 'Visa' }, { key: 'Card Number', value: '4111', protected: true },
        { key: 'Card Holder', value: 'Ana' }],
      tags: [], group: [],
    },
    {
      // login credentials + card key → stays login, card key becomes custom
      fields: [{ key: 'Title', value: 'Mixta' }, { key: 'UserName', value: 'u' },
        { key: 'Password', value: 'p', protected: true }, { key: 'Card Number', value: '4111', protected: true }],
      tags: [], group: [],
    },
    {
      // Full Name alone → identity
      fields: [{ key: 'Title', value: 'Yo' }, { key: 'Full Name', value: 'Ana García' }],
      tags: [], group: [],
    },
  ]);
  assert.equal(items[0].type, 'card');
  assert.equal(items[0].card_number, '4111');
  assert.equal(items[1].type, 'login');
  assert.equal(items[1].card_number, undefined);
  assert.deepEqual(items[1].customFields, [{ label: 'Card Number', value: '4111', hidden: true }]);
  assert.equal(items[2].type, 'identity');
  assert.equal(items[2].id_fullname, 'Ana García');
});

test('kdbxEntriesToItems maps otp variants and skips empty entries', () => {
  const items = kdbxEntriesToItems([
    {
      fields: [
        { key: 'Title', value: 'Otp URI' },
        { key: 'otp', value: 'otpauth://totp/x?secret=ABCDEFGH&period=30', protected: true },
      ],
      tags: [], group: [],
    },
    {
      fields: [{ key: 'Title', value: 'Seed' }, { key: 'TOTP Seed', value: 'JBSWY3DP' },
        { key: 'TOTP Settings', value: '30;6' }],
      tags: [], group: [],
    },
    { fields: [{ key: 'Title', value: '' }], tags: [], group: [] },
    { fields: [{ key: 'UserName', value: 'only-user' }], tags: [], group: [] },
  ]);
  assert.equal(items.length, 3, 'the all-empty entry is dropped');
  assert.equal(items[0].totp_secret, 'ABCDEFGH');
  assert.equal(items[1].totp_secret, 'JBSWY3DP');
  assert.equal(items[1].customFields, undefined, 'TOTP Settings metadata is not a custom field');
  assert.equal(items[2].title, 'only-user', 'title falls back to username');
});
