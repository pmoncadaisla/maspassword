// Vault export builders: KDBX 4 (KeePass), CSV and JSON.
//
// Everything here runs on ALREADY-DECRYPTED item data and produces bytes for a
// local download — nothing ever leaves the device, so the zero-knowledge model
// is untouched. The functions are pure (no DOM) so they run under node:test.
//
// The KDBX writer targets KDBX 4.0 exactly as KeePass 2.x defines it:
// AES-256-CBC outer cipher, AES-KDF key derivation, ChaCha20 inner stream for
// protected values, HMAC-SHA256 block stream. AES-KDF instead of Argon2 is a
// deliberate choice: WebCrypto has no Argon2, and N sequential AES-ECB rounds
// collapse into ONE native AES-CBC call over N zero blocks (CBC with IV=X over
// zeros yields E^N(X) as its last block), so derivation stays native-fast
// without shipping a WASM blob. KeePass/KeePassXC open AES-KDF KDBX4 files.

const subtle = globalThis.crypto.subtle;

// --- small buffer helpers ---

function u8(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64le(lo, hi = 0) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, lo >>> 0, true);
  dv.setUint32(4, hi >>> 0, true);
  return b;
}

function u64leBig(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function utf8(s) { return new TextEncoder().encode(s); }

export function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

async function sha256(data) { return new Uint8Array(await subtle.digest('SHA-256', data)); }
async function sha512(data) { return new Uint8Array(await subtle.digest('SHA-512', data)); }

async function hmacSha256(keyBytes, data) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, data));
}

// --- ChaCha20 (RFC 8439) — inner stream cipher for protected values ---

function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }

function chachaBlock(key, counter, nonce) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  const kv = new DataView(key.buffer, key.byteOffset, 32);
  for (let i = 0; i < 8; i++) st[4 + i] = kv.getUint32(i * 4, true);
  st[12] = counter >>> 0;
  const nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
  st[13] = nv.getUint32(0, true); st[14] = nv.getUint32(4, true); st[15] = nv.getUint32(8, true);

  const w = Uint32Array.from(st);
  const qr = (a, b, c, d) => {
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl(w[d] ^ w[a], 16);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl(w[b] ^ w[c], 12);
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl(w[d] ^ w[a], 8);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl(w[b] ^ w[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, (w[i] + st[i]) >>> 0, true);
  return out;
}

// Stateful keystream: protected values consume it sequentially in document
// order, which is exactly how KeePass expects them to be recoverable.
export function chachaStream(key, nonce) {
  let counter = 0;
  let block = null;
  let pos = 64;
  return {
    xor(data) {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        if (pos === 64) { block = chachaBlock(key, counter++, nonce); pos = 0; }
        out[i] = data[i] ^ block[pos++];
      }
      return out;
    },
  };
}

// --- AES-KDF via the CBC-over-zeros trick ---
//
// CBC with IV=X over all-zero plaintext blocks gives C1=E(X), C2=E(C1), ... so
// the last real block is E^rounds(X): the AES-KDF transform of one half, in a
// single native call (chunked to bound memory). WebCrypto appends a PKCS7
// padding block, which we simply ignore.
async function aesKdfHalf(cbcKey, half, rounds) {
  let iv = half;
  const CHUNK_BLOCKS = 1 << 18; // 4 MiB of zeros per call
  let remaining = rounds;
  while (remaining > 0) {
    const blocks = Math.min(remaining, CHUNK_BLOCKS);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-CBC', iv }, cbcKey, new Uint8Array(blocks * 16)));
    iv = ct.slice((blocks - 1) * 16, blocks * 16);
    remaining -= blocks;
  }
  return iv;
}

export async function aesKdf(compositeKey, seed, rounds) {
  const cbcKey = await subtle.importKey('raw', seed, { name: 'AES-CBC' }, false, ['encrypt']);
  const [left, right] = await Promise.all([
    aesKdfHalf(cbcKey, compositeKey.slice(0, 16), rounds),
    aesKdfHalf(cbcKey, compositeKey.slice(16, 32), rounds),
  ]);
  return sha256(u8(left, right));
}

// --- KDBX structures ---

const KDBX_SIG1 = 0x9aa2d903;
const KDBX_SIG2 = 0xb54bfb67;
const KDBX_VERSION_4 = 0x00040000;
const CIPHER_AES256 = new Uint8Array([0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff]);
const KDF_AES = new Uint8Array([0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea]);
export const AES_KDF_ROUNDS = 1000000;

function headerField(id, data) {
  return u8(new Uint8Array([id]), u32le(data.length), data);
}

function variantDict(entries) {
  const parts = [new Uint8Array([0x00, 0x01])]; // version 0x0100 LE
  for (const [key, type, value] of entries) {
    const k = utf8(key);
    parts.push(new Uint8Array([type]), u32le(k.length), k, u32le(value.length), value);
  }
  parts.push(new Uint8Array([0x00]));
  return u8(...parts);
}

// KeePass stores KDBX4 times as base64(uint64le(seconds since 0001-01-01)).
const DOTNET_EPOCH_OFFSET = 62135596800;
function kdbxTime(msEpoch) {
  const secs = Math.floor(msEpoch / 1000) + DOTNET_EPOCH_OFFSET;
  return bytesToB64(u64leBig(secs));
}

function xmlEsc(s) {
  // Control chars are invalid in XML 1.0 and KeePass rejects them.
  return String(s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function randomUuidB64() {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return bytesToB64(b);
}

// Entry: { title, fields: [{key, value, protected}], tags: [], created, modified }
function entryXml(entry, stream) {
  const strings = entry.fields
    .filter(f => f.value !== undefined && f.value !== null && f.value !== '')
    .map(f => {
      if (f.protected) {
        const enc = bytesToB64(stream.xor(utf8(String(f.value))));
        return `<String><Key>${xmlEsc(f.key)}</Key><Value Protected="True">${enc}</Value></String>`;
      }
      return `<String><Key>${xmlEsc(f.key)}</Key><Value>${xmlEsc(f.value)}</Value></String>`;
    })
    .join('');
  const tags = entry.tags && entry.tags.length ? `<Tags>${xmlEsc(entry.tags.join(';'))}</Tags>` : '';
  const created = kdbxTime(entry.created || Date.now());
  const modified = kdbxTime(entry.modified || entry.created || Date.now());
  return `<Entry><UUID>${randomUuidB64()}</UUID>${tags}` +
    `<Times><CreationTime>${created}</CreationTime><LastModificationTime>${modified}</LastModificationTime>` +
    `<LastAccessTime>${modified}</LastAccessTime><ExpiryTime>${modified}</ExpiryTime>` +
    `<Expires>False</Expires></Times>${strings}</Entry>`;
}

function databaseXml(vaultName, entries, stream) {
  const now = kdbxTime(Date.now());
  const entriesXml = entries.map(e => entryXml(e, stream)).join('');
  return '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<KeePassFile><Meta><Generator>Sésamo</Generator>' +
    `<DatabaseName>${xmlEsc(vaultName)}</DatabaseName><DatabaseNameChanged>${now}</DatabaseNameChanged>` +
    '<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName>' +
    '<ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes>' +
    '</MemoryProtection></Meta><Root>' +
    `<Group><UUID>${randomUuidB64()}</UUID><Name>${xmlEsc(vaultName)}</Name>` +
    `<Times><CreationTime>${now}</CreationTime><LastModificationTime>${now}</LastModificationTime>` +
    `<LastAccessTime>${now}</LastAccessTime><ExpiryTime>${now}</ExpiryTime><Expires>False</Expires></Times>` +
    `${entriesXml}</Group></Root></KeePassFile>`;
}

// Build a complete KDBX 4.0 file protected by `password`.
// entries: [{ title, fields, tags, created, modified }] — see entryXml.
export async function buildKdbx({ vaultName, entries, password, rounds = AES_KDF_ROUNDS }) {
  const rnd = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };
  const masterSeed = rnd(32);
  const encryptionIV = rnd(16);
  const kdfSeed = rnd(32);
  const innerKey = rnd(64);

  // Outer header
  const kdfParams = variantDict([
    ['$UUID', 0x42, KDF_AES],
    ['R', 0x05, u64leBig(rounds)],
    ['S', 0x42, kdfSeed],
  ]);
  const header = u8(
    u32le(KDBX_SIG1), u32le(KDBX_SIG2), u32le(KDBX_VERSION_4),
    headerField(2, CIPHER_AES256),
    headerField(3, u32le(0)), // no compression
    headerField(4, masterSeed),
    headerField(7, encryptionIV),
    headerField(11, kdfParams),
    headerField(0, new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a])),
  );

  // Keys
  const composite = await sha256(await sha256(utf8(password)));
  const transformed = await aesKdf(composite, kdfSeed, rounds);
  const cipherKeyBytes = await sha256(u8(masterSeed, transformed));
  const hmacKeyBase = await sha512(u8(masterSeed, transformed, new Uint8Array([0x01])));

  const headerHash = await sha256(header);
  const headerHmacKey = await sha512(u8(u64le(0xffffffff, 0xffffffff), hmacKeyBase));
  const headerHmac = await hmacSha256(headerHmacKey, header);

  // Plaintext payload: inner header + XML (protected values consume the
  // ChaCha20 keystream as the XML is generated, in document order).
  const streamKeyHash = await sha512(innerKey);
  const stream = chachaStream(streamKeyHash.slice(0, 32), streamKeyHash.slice(32, 44));
  const xml = databaseXml(vaultName, entries, stream);
  const innerHeader = u8(
    headerField(1, u32le(3)), // InnerRandomStreamID = ChaCha20
    headerField(2, innerKey),
    headerField(0, new Uint8Array(0)),
  );
  const payload = u8(innerHeader, utf8(xml));

  // Encrypt, then wrap the ciphertext in the HMAC block stream.
  const cipherKey = await subtle.importKey('raw', cipherKeyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: encryptionIV }, cipherKey, payload));

  const blocks = [];
  const BLOCK = 1 << 20;
  let index = 0;
  for (let off = 0; off < ciphertext.length; off += BLOCK, index++) {
    const data = ciphertext.subarray(off, Math.min(off + BLOCK, ciphertext.length));
    const blockKey = await sha512(u8(u64leBig(index), hmacKeyBase));
    const hmac = await hmacSha256(blockKey, u8(u64leBig(index), u32le(data.length), data));
    blocks.push(u8(hmac, u32le(data.length), data));
  }
  const endKey = await sha512(u8(u64leBig(index), hmacKeyBase));
  const endHmac = await hmacSha256(endKey, u8(u64leBig(index), u32le(0)));
  blocks.push(u8(endHmac, u32le(0)));

  return u8(header, headerHash, headerHmac, ...blocks);
}

// --- Mapping Sésamo items to export rows/entries ---

function otpauthUri(item) {
  const s = (item.totp_secret || '').trim();
  if (!s) return '';
  if (s.startsWith('otpauth://')) return s;
  const label = encodeURIComponent(item.title || 'Sesamo');
  return `otpauth://totp/${label}?secret=${encodeURIComponent(s.replace(/\s/g, ''))}`;
}

// Type-specific fields, used by both the KDBX entry builder and the CSV notes
// fallback. [key, value, protected]
function extraFields(d) {
  switch (d.type) {
    case 'card': return [
      ['Card Holder', d.card_holder, false],
      ['Card Number', d.card_number, true],
      ['Card Brand', d.card_brand, false],
      ['Card Expiry', d.card_exp, false],
      ['Card CVV', d.card_cvv, true],
      ['Card PIN', d.card_pin, true],
    ];
    case 'identity': return [
      ['Full Name', d.id_fullname, false],
      ['Email', d.id_email, false],
      ['Phone', d.id_phone, false],
      ['Address', d.id_address, false],
      ['Company', d.id_company, false],
    ];
    default: return [];
  }
}

// items: [{ data: <decrypted _data>, created_at, updated_at }]
export function itemsToKdbxEntries(items) {
  return items.map(({ data: d, created_at, updated_at }) => {
    const fields = [
      { key: 'Title', value: d.title },
      { key: 'UserName', value: d.username },
      { key: 'Password', value: d.password, protected: true },
      { key: 'URL', value: d.url },
      { key: 'Notes', value: d.notes },
    ];
    const otp = otpauthUri(d);
    if (otp) fields.push({ key: 'otp', value: otp, protected: true });
    const used = new Set(fields.map(f => f.key));
    for (const [key, value, prot] of extraFields(d)) {
      fields.push({ key, value, protected: prot });
      used.add(key);
    }
    for (const cf of d.customFields || []) {
      if (!cf.label && !cf.value) continue;
      let key = cf.label || 'Field';
      let n = 2;
      while (used.has(key)) key = `${cf.label || 'Field'} (${n++})`;
      used.add(key);
      fields.push({ key, value: cf.value, protected: !!cf.hidden });
    }
    return {
      title: d.title || '',
      fields,
      tags: d.tags || [],
      created: created_at ? Date.parse(created_at) : Date.now(),
      modified: updated_at ? Date.parse(updated_at) : Date.now(),
    };
  });
}

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// Simple interoperable CSV: one row per item, login fields as columns and
// type-specific/custom fields folded into notes as "Label: value" lines.
// The BOM keeps Excel from mangling accents.
export function buildCsv(items) {
  const header = ['type', 'title', 'username', 'password', 'url', 'notes', 'totp', 'tags'];
  const rows = [header.join(',')];
  for (const { data: d } of items) {
    let notes = d.notes || '';
    const extras = extraFields(d).filter(([, v]) => v);
    for (const cf of d.customFields || []) {
      if (cf.label || cf.value) extras.push([cf.label || 'Field', cf.value]);
    }
    if (extras.length) {
      const lines = extras.map(([k, v]) => `${k}: ${v}`).join('\n');
      notes = notes ? `${notes}\n${lines}` : lines;
    }
    rows.push([
      d.type || 'login', d.title || '', d.username || '', d.password || '',
      d.url || '', notes, d.totp_secret || '', (d.tags || []).join(';'),
    ].map(csvCell).join(','));
  }
  return '\ufeff' + rows.join('\r\n') + '\r\n';
}

// Full-fidelity dump: every decrypted field as stored, including attachments
// and custom fields. This is the format that can round-trip everything.
export function buildJson(vaultName, items) {
  return JSON.stringify({
    format: 'sesamo-vault',
    version: 1,
    exported_at: new Date().toISOString(),
    vault: vaultName,
    items: items.map(({ data, created_at, updated_at }) => ({
      ...data, created_at, updated_at,
    })),
  }, null, 2);
}
