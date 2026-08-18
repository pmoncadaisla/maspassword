// KDBX reader (KeePass 2.x databases): KDBX 3.1 and 4.x.
//
// Like the writer in export.js, everything runs locally — the file is decrypted
// in the browser and the resulting plaintext items are re-encrypted with the
// vault key before they ever touch the network, so zero-knowledge holds.
//
// Reading real-world files needs three primitives WebCrypto doesn't have, all
// implemented here in pure JS and validated against independent
// implementations (hashlib, argon2-cffi, pycryptodome) in the tests:
//  - BLAKE2b (RFC 7693), because Argon2 is built on it.
//  - Argon2d/Argon2id (RFC 9106), the default KDF of KDBX 4 files written by
//    KeePass 2.x and KeePassXC. The writer avoids Argon2 by choosing AES-KDF,
//    but the reader has no such luxury: it must take whatever the file uses.
//  - Salsa20, the inner stream cipher of KDBX 3.1 protected values.
// AES-KDF files reuse the fast CBC-over-zeros trick from export.js, and the
// ChaCha20 in export.js covers both the KDBX 4 inner stream and the (rare)
// ChaCha20 outer cipher.
//
// Deliberately unsupported: keyfiles, Twofish outer cipher, and attachments
// (binaries are skipped and counted). Errors carry a `code` so the UI can
// translate them: not-kdbx | bad-password | unsupported | corrupt.

import { chachaStream, aesKdf } from './export.js';

const subtle = globalThis.crypto.subtle;

// --- small helpers ---

function u8cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function le32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function utf8(s) { return new TextEncoder().encode(s); }
function utf8dec(b) { return new TextDecoder().decode(b); }

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(data) { return new Uint8Array(await subtle.digest('SHA-256', data)); }
async function sha512(data) { return new Uint8Array(await subtle.digest('SHA-512', data)); }

async function hmacSha256(keyBytes, data) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', key, data));
}

function kdbxError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

async function gunzip(data) {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// --- BLAKE2b (RFC 7693) ---
//
// 64-bit words live as little-endian (lo, hi) uint32 pairs: word w of an array
// occupies indices 2w and 2w+1. All the rotation amounts BLAKE2b uses (32, 24,
// 16, 63) have cheap two-word forms, so no BigInt is needed anywhere.

const B2B_IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

const B2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

function b2bG(v, m, a, b, c, d, x, y) {
  let al = v[2 * a], ah = v[2 * a + 1], bl = v[2 * b], bh = v[2 * b + 1];
  let cl = v[2 * c], ch = v[2 * c + 1], dl = v[2 * d], dh = v[2 * d + 1];
  let lo = al + bl + m[2 * x];
  al = lo >>> 0; ah = (ah + bh + m[2 * x + 1] + Math.floor(lo / 0x100000000)) >>> 0;
  let xl = dl ^ al, xh = dh ^ ah;
  // XOR yields SIGNED int32 — normalize before these feed additions.
  dl = xh >>> 0; dh = xl >>> 0; // rotr 32
  lo = cl + dl;
  cl = lo >>> 0; ch = (ch + dh + Math.floor(lo / 0x100000000)) >>> 0;
  xl = bl ^ cl; xh = bh ^ ch;
  bl = ((xl >>> 24) | (xh << 8)) >>> 0; bh = ((xh >>> 24) | (xl << 8)) >>> 0; // rotr 24
  lo = al + bl + m[2 * y];
  al = lo >>> 0; ah = (ah + bh + m[2 * y + 1] + Math.floor(lo / 0x100000000)) >>> 0;
  xl = dl ^ al; xh = dh ^ ah;
  dl = ((xl >>> 16) | (xh << 16)) >>> 0; dh = ((xh >>> 16) | (xl << 16)) >>> 0; // rotr 16
  lo = cl + dl;
  cl = lo >>> 0; ch = (ch + dh + Math.floor(lo / 0x100000000)) >>> 0;
  xl = bl ^ cl; xh = bh ^ ch;
  bl = ((xl << 1) | (xh >>> 31)) >>> 0; bh = ((xh << 1) | (xl >>> 31)) >>> 0; // rotr 63
  v[2 * a] = al; v[2 * a + 1] = ah; v[2 * b] = bl; v[2 * b + 1] = bh;
  v[2 * c] = cl; v[2 * c + 1] = ch; v[2 * d] = dl; v[2 * d + 1] = dh;
}

function b2bCompress(h, v, m, tLo, tHi, last) {
  for (let i = 0; i < 16; i++) v[i] = h[i];
  for (let i = 0; i < 16; i++) v[16 + i] = B2B_IV[i];
  v[24] ^= tLo; v[25] ^= tHi;
  if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
  for (let r = 0; r < 12; r++) {
    const s = B2B_SIGMA[r % 10];
    b2bG(v, m, 0, 4, 8, 12, s[0], s[1]); b2bG(v, m, 1, 5, 9, 13, s[2], s[3]);
    b2bG(v, m, 2, 6, 10, 14, s[4], s[5]); b2bG(v, m, 3, 7, 11, 15, s[6], s[7]);
    b2bG(v, m, 0, 5, 10, 15, s[8], s[9]); b2bG(v, m, 1, 6, 11, 12, s[10], s[11]);
    b2bG(v, m, 2, 7, 8, 13, s[12], s[13]); b2bG(v, m, 3, 4, 9, 14, s[14], s[15]);
  }
  for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[16 + i];
}

export function blake2b(data, outLen) {
  const h = Uint32Array.from(B2B_IV);
  h[0] ^= 0x01010000 ^ outLen;
  const v = new Uint32Array(32);
  const m = new Uint32Array(32);
  let tLo = 0, tHi = 0;
  const blockCount = Math.max(1, Math.ceil(data.length / 128));
  for (let bi = 0; bi < blockCount; bi++) {
    const off = bi * 128;
    const chunkLen = Math.min(128, data.length - off);
    tLo += chunkLen;
    if (tLo > 0xffffffff) { tLo -= 0x100000000; tHi++; }
    m.fill(0);
    for (let i = 0; i < chunkLen; i++) m[i >> 2] |= data[off + i] << ((i & 3) * 8);
    b2bCompress(h, v, m, tLo, tHi, bi === blockCount - 1);
  }
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) out[i] = (h[i >> 2] >>> ((i & 3) * 8)) & 0xff;
  return out;
}

// Argon2's variable-length hash H': chains BLAKE2b, taking 32 bytes per link.
// The final link is a reduced-length digest — its outLen parameter changes the
// hash, so it can't be a truncation of a 64-byte one.
function hPrime(input, outLen) {
  if (outLen <= 64) return blake2b(u8cat(le32(outLen), input), outLen);
  const out = new Uint8Array(outLen);
  let v = blake2b(u8cat(le32(outLen), input), 64);
  let pos = 0;
  while (outLen - pos > 64) {
    out.set(v.subarray(0, 32), pos);
    pos += 32;
    const rem = outLen - pos;
    v = blake2b(v, rem > 64 ? 64 : rem);
  }
  out.set(v, pos);
  return out;
}

// --- Argon2d / Argon2id (RFC 9106) ---
//
// The compression function G is BLAKE2b's round with the multiply-hardened
// BlaMka mix f(a,b) = a + b + 2·lo32(a)·lo32(b). The 32×32→64 multiply is done
// exactly with 16-bit limbs — every intermediate stays under 2^53, so plain
// doubles are exact and no BigInt enters the hot loop.

const AG_S = new Uint32Array(32); // P permutation scratch: 16 u64 as pairs
let fmLo = 0, fmHi = 0;

function fBlaMka(al, ah, bl, bh) {
  const x0 = al & 0xffff, x1 = al >>> 16, y0 = bl & 0xffff, y1 = bl >>> 16;
  const mid = x1 * y0 + x0 * y1;
  const tl = x0 * y0 + (mid % 65536) * 65536;
  const th = (x1 * y1 + Math.floor(mid / 65536) + Math.floor(tl / 0x100000000)) >>> 0;
  const pl = tl >>> 0;
  const dl = (pl << 1) >>> 0, dh = ((th << 1) | (pl >>> 31)) >>> 0;
  const lo = al + bl + dl;
  fmLo = lo >>> 0;
  fmHi = (ah + bh + dh + Math.floor(lo / 0x100000000)) >>> 0;
}

function bmG(a, b, c, d) {
  const S = AG_S;
  let al = S[2 * a], ah = S[2 * a + 1], bl = S[2 * b], bh = S[2 * b + 1];
  let cl = S[2 * c], ch = S[2 * c + 1], dl = S[2 * d], dh = S[2 * d + 1];
  fBlaMka(al, ah, bl, bh); al = fmLo; ah = fmHi;
  let xl = dl ^ al, xh = dh ^ ah;
  dl = xh >>> 0; dh = xl >>> 0; // rotr 32 — normalize the signed XOR
  fBlaMka(cl, ch, dl, dh); cl = fmLo; ch = fmHi;
  xl = bl ^ cl; xh = bh ^ ch;
  bl = ((xl >>> 24) | (xh << 8)) >>> 0; bh = ((xh >>> 24) | (xl << 8)) >>> 0;
  fBlaMka(al, ah, bl, bh); al = fmLo; ah = fmHi;
  xl = dl ^ al; xh = dh ^ ah;
  dl = ((xl >>> 16) | (xh << 16)) >>> 0; dh = ((xh >>> 16) | (xl << 16)) >>> 0;
  fBlaMka(cl, ch, dl, dh); cl = fmLo; ch = fmHi;
  xl = bl ^ cl; xh = bh ^ ch;
  bl = ((xl << 1) | (xh >>> 31)) >>> 0; bh = ((xh << 1) | (xl >>> 31)) >>> 0;
  S[2 * a] = al; S[2 * a + 1] = ah; S[2 * b] = bl; S[2 * b + 1] = bh;
  S[2 * c] = cl; S[2 * c + 1] = ch; S[2 * d] = dl; S[2 * d + 1] = dh;
}

const AG_OFFS = new Int32Array(16);

function pApply(v) {
  const S = AG_S, offs = AG_OFFS;
  for (let k = 0; k < 16; k++) { S[2 * k] = v[offs[k]]; S[2 * k + 1] = v[offs[k] + 1]; }
  bmG(0, 4, 8, 12); bmG(1, 5, 9, 13); bmG(2, 6, 10, 14); bmG(3, 7, 11, 15);
  bmG(0, 5, 10, 15); bmG(1, 6, 11, 12); bmG(2, 7, 8, 13); bmG(3, 4, 9, 14);
  for (let k = 0; k < 16; k++) { v[offs[k]] = S[2 * k]; v[offs[k] + 1] = S[2 * k + 1]; }
}

function agPermute(q) {
  const offs = AG_OFFS;
  for (let r = 0; r < 8; r++) {
    for (let k = 0; k < 16; k++) offs[k] = 32 * r + 2 * k;
    pApply(q);
  }
  for (let c = 0; c < 8; c++) {
    for (let k = 0; k < 16; k++) offs[k] = 4 * c + 32 * (k >> 1) + 2 * (k & 1);
    pApply(q);
  }
}

// out = G(x, y), optionally XORed over the previous contents (Argon2 v1.3
// second and later passes). x/y/out are u32 offsets into B; R and Q are
// caller-provided 256-word scratch blocks.
function agCompress(B, xOff, yOff, outOff, withXor, R, Q) {
  for (let i = 0; i < 256; i++) { const r = B[xOff + i] ^ B[yOff + i]; R[i] = r; Q[i] = r; }
  agPermute(Q);
  if (withXor) for (let i = 0; i < 256; i++) B[outOff + i] ^= Q[i] ^ R[i];
  else for (let i = 0; i < 256; i++) B[outOff + i] = Q[i] ^ R[i];
}

// floor(a*a / 2^32) for u32 a, exact.
function umulHi(a) {
  const x0 = a & 0xffff, x1 = a >>> 16;
  const mid = x1 * x0 * 2;
  const tl = x0 * x0 + (mid % 65536) * 65536;
  return (x1 * x1 + Math.floor(mid / 65536) + Math.floor(tl / 0x100000000)) >>> 0;
}

// variant: 0 = Argon2d, 2 = Argon2id (1 = Argon2i works but KeePass never uses it).
// Yields to the event loop after each slice so a long derivation doesn't freeze
// the UI; onProgress gets a 0..1 fraction.
export async function argon2({ variant, version = 0x13, password, salt, passes, memKiB, lanes, tagLen = 32, onProgress }) {
  if (version !== 0x13 && version !== 0x10) throw kdbxError('unsupported', `Argon2 version ${version} not supported`);
  let mPrime = 4 * lanes * Math.floor(memKiB / (4 * lanes));
  if (mPrime < 8 * lanes) mPrime = 8 * lanes;
  const q = mPrime / lanes, segLen = q / 4;

  const h0 = blake2b(u8cat(
    le32(lanes), le32(tagLen), le32(memKiB), le32(passes), le32(version), le32(variant),
    le32(password.length), password, le32(salt.length), salt, le32(0), le32(0),
  ), 64);

  const B = new Uint32Array(mPrime * 256);
  const seed = new Uint8Array(72);
  seed.set(h0, 0);
  for (let lane = 0; lane < lanes; lane++) {
    for (let j = 0; j < 2; j++) {
      seed.set(le32(j), 64);
      seed.set(le32(lane), 68);
      const blk = hPrime(seed, 1024);
      const dv = new DataView(blk.buffer);
      const base = (lane * q + j) * 256;
      for (let i = 0; i < 256; i++) B[base + i] = dv.getUint32(i * 4, true);
    }
  }

  const R = new Uint32Array(256), Q = new Uint32Array(256);
  const addrBlock = new Uint32Array(256);
  // agCompress reads x and y straight out of B, so give the address-generation
  // scratch blocks a window at the end of one shared buffer.
  const scratch = new Uint32Array(256 * 3);
  const SC_ZERO = 0, SC_IN = 256, SC_TMP = 512;

  for (let pass = 0; pass < passes; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        const dataIndependent = variant === 1 || (variant === 2 && pass === 0 && slice < 2);
        let addrCounter = 0;
        const startIdx = (pass === 0 && slice === 0) ? 2 : 0;
        for (let idx = startIdx; idx < segLen; idx++) {
          const curIdx = slice * segLen + idx;
          const prevIdx = (curIdx - 1 + q) % q;
          const curOff = (lane * q + curIdx) * 256;
          const prevOff = (lane * q + prevIdx) * 256;

          let J1, J2;
          if (dataIndependent) {
            const k = idx % 128;
            if (k === 0 || (idx === startIdx && addrCounter === 0)) {
              addrCounter = Math.floor(idx / 128) + 1;
              scratch.fill(0, SC_ZERO, SC_IN);
              scratch.fill(0, SC_IN, SC_TMP);
              scratch[SC_IN] = pass; scratch[SC_IN + 2] = lane; scratch[SC_IN + 4] = slice;
              scratch[SC_IN + 6] = mPrime; scratch[SC_IN + 8] = passes; scratch[SC_IN + 10] = variant;
              scratch[SC_IN + 12] = addrCounter;
              agCompress(scratch, SC_ZERO, SC_IN, SC_TMP, false, R, Q);
              // addrBlock = G(zero, G(zero, input)) — reuse the input slot as output
              agCompress(scratch, SC_ZERO, SC_TMP, SC_IN, false, R, Q);
              addrBlock.set(scratch.subarray(SC_IN, SC_IN + 256));
            }
            J1 = addrBlock[2 * k]; J2 = addrBlock[2 * k + 1];
          } else {
            J1 = B[prevOff]; J2 = B[prevOff + 1];
          }

          const refLane = (pass === 0 && slice === 0) ? lane : J2 % lanes;
          const sameLane = refLane === lane;
          let refArea;
          if (pass === 0) {
            if (slice === 0) refArea = idx - 1;
            else if (sameLane) refArea = slice * segLen + idx - 1;
            else refArea = slice * segLen + (idx === 0 ? -1 : 0);
          } else if (sameLane) {
            refArea = q - segLen + idx - 1;
          } else {
            refArea = q - segLen + (idx === 0 ? -1 : 0);
          }
          const rel = refArea - 1 - Math.floor(refArea * umulHi(J1) / 0x100000000);
          const startPos = pass === 0 ? 0 : ((slice + 1) % 4) * segLen;
          const refOff = (refLane * q + (startPos + rel) % q) * 256;

          agCompress(B, prevOff, refOff, curOff, pass > 0 && version === 0x13, R, Q);
        }
      }
      if (onProgress) onProgress((pass * 4 + slice + 1) / (passes * 4));
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  const final = new Uint32Array(256);
  for (let lane = 0; lane < lanes; lane++) {
    const off = (lane * q + q - 1) * 256;
    for (let i = 0; i < 256; i++) final[i] ^= B[off + i];
  }
  const finalBytes = new Uint8Array(1024);
  const fv = new DataView(finalBytes.buffer);
  for (let i = 0; i < 256; i++) fv.setUint32(i * 4, final[i], true);
  return hPrime(finalBytes, tagLen);
}

// --- Salsa20 — KDBX ≤3.1 inner stream cipher ---

const SALSA_NONCE = new Uint8Array([0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a]);

function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }

function salsaBlock(key, counter) {
  const kv = new DataView(key.buffer, key.byteOffset, 32);
  const nv = new DataView(SALSA_NONCE.buffer);
  const st = new Uint32Array(16);
  st[0] = 0x61707865;
  for (let i = 0; i < 4; i++) st[1 + i] = kv.getUint32(i * 4, true);
  st[5] = 0x3320646e;
  st[6] = nv.getUint32(0, true); st[7] = nv.getUint32(4, true);
  st[8] = counter >>> 0; st[9] = Math.floor(counter / 0x100000000) >>> 0;
  st[10] = 0x79622d32;
  for (let i = 0; i < 4; i++) st[11 + i] = kv.getUint32(16 + i * 4, true);
  st[15] = 0x6b206574;
  const w = Uint32Array.from(st);
  for (let r = 0; r < 10; r++) {
    w[4] ^= rotl((w[0] + w[12]) >>> 0, 7); w[8] ^= rotl((w[4] + w[0]) >>> 0, 9);
    w[12] ^= rotl((w[8] + w[4]) >>> 0, 13); w[0] ^= rotl((w[12] + w[8]) >>> 0, 18);
    w[9] ^= rotl((w[5] + w[1]) >>> 0, 7); w[13] ^= rotl((w[9] + w[5]) >>> 0, 9);
    w[1] ^= rotl((w[13] + w[9]) >>> 0, 13); w[5] ^= rotl((w[1] + w[13]) >>> 0, 18);
    w[14] ^= rotl((w[10] + w[6]) >>> 0, 7); w[2] ^= rotl((w[14] + w[10]) >>> 0, 9);
    w[6] ^= rotl((w[2] + w[14]) >>> 0, 13); w[10] ^= rotl((w[6] + w[2]) >>> 0, 18);
    w[3] ^= rotl((w[15] + w[11]) >>> 0, 7); w[7] ^= rotl((w[3] + w[15]) >>> 0, 9);
    w[11] ^= rotl((w[7] + w[3]) >>> 0, 13); w[15] ^= rotl((w[11] + w[7]) >>> 0, 18);
    w[1] ^= rotl((w[0] + w[3]) >>> 0, 7); w[2] ^= rotl((w[1] + w[0]) >>> 0, 9);
    w[3] ^= rotl((w[2] + w[1]) >>> 0, 13); w[0] ^= rotl((w[3] + w[2]) >>> 0, 18);
    w[6] ^= rotl((w[5] + w[4]) >>> 0, 7); w[7] ^= rotl((w[6] + w[5]) >>> 0, 9);
    w[4] ^= rotl((w[7] + w[6]) >>> 0, 13); w[5] ^= rotl((w[4] + w[7]) >>> 0, 18);
    w[11] ^= rotl((w[10] + w[9]) >>> 0, 7); w[8] ^= rotl((w[11] + w[10]) >>> 0, 9);
    w[9] ^= rotl((w[8] + w[11]) >>> 0, 13); w[10] ^= rotl((w[9] + w[8]) >>> 0, 18);
    w[12] ^= rotl((w[15] + w[14]) >>> 0, 7); w[13] ^= rotl((w[12] + w[15]) >>> 0, 9);
    w[14] ^= rotl((w[13] + w[12]) >>> 0, 13); w[15] ^= rotl((w[14] + w[13]) >>> 0, 18);
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, (w[i] + st[i]) >>> 0, true);
  return out;
}

export function salsaStream(key) {
  let counter = 0, block = null, pos = 64;
  return {
    xor(data) {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        if (pos === 64) { block = salsaBlock(key, counter++); pos = 0; }
        out[i] = data[i] ^ block[pos++];
      }
      return out;
    },
  };
}

// ARC4, the ancient KDBX inner stream nobody should still have. Cheap to keep.
function arc4Stream(key) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  let x = 0, y = 0;
  return {
    xor(data) {
      const out = new Uint8Array(data.length);
      for (let k = 0; k < data.length; k++) {
        x = (x + 1) & 0xff; y = (y + s[x]) & 0xff;
        [s[x], s[y]] = [s[y], s[x]];
        out[k] = data[k] ^ s[(s[x] + s[y]) & 0xff];
      }
      return out;
    },
  };
}

// --- minimal XML parser ---
//
// KeePass XML is machine-generated and well-formed; this parses exactly that
// dialect (elements, attributes, entities, CDATA, comments) into
// { tag, attrs, children, text } nodes, preserving document order — protected
// values must consume the inner stream in exactly that order, history entries
// included.

const XML_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function xmlDecode(s) {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (match, ent) => {
    if (ent[0] === '#') {
      const cp = ent[1] === 'x' || ent[1] === 'X' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      return Number.isNaN(cp) ? match : String.fromCodePoint(cp);
    }
    return XML_ENTITIES[ent] ?? match;
  });
}

export function parseXml(text) {
  const root = { tag: null, attrs: {}, children: [], text: '' };
  const stack = [root];
  let i = 0;
  while (i < text.length) {
    const lt = text.indexOf('<', i);
    if (lt === -1) break;
    if (lt > i) stack[stack.length - 1].text += xmlDecode(text.slice(i, lt));
    if (text.startsWith('<!--', lt)) {
      const end = text.indexOf('-->', lt);
      if (end === -1) throw kdbxError('corrupt', 'unterminated XML comment');
      i = end + 3;
      continue;
    }
    if (text.startsWith('<![CDATA[', lt)) {
      const end = text.indexOf(']]>', lt);
      if (end === -1) throw kdbxError('corrupt', 'unterminated CDATA');
      stack[stack.length - 1].text += text.slice(lt + 9, end);
      i = end + 3;
      continue;
    }
    if (text[lt + 1] === '?' || text[lt + 1] === '!') {
      const end = text.indexOf('>', lt);
      if (end === -1) throw kdbxError('corrupt', 'unterminated XML declaration');
      i = end + 1;
      continue;
    }
    const gt = text.indexOf('>', lt);
    if (gt === -1) throw kdbxError('corrupt', 'unterminated XML tag');
    let body = text.slice(lt + 1, gt);
    i = gt + 1;
    if (body[0] === '/') {
      if (stack.length > 1) stack.pop();
      continue;
    }
    const selfClose = body.endsWith('/');
    if (selfClose) body = body.slice(0, -1);
    const sp = body.search(/\s/);
    const el = { tag: sp === -1 ? body : body.slice(0, sp), attrs: {}, children: [], text: '' };
    if (sp !== -1) {
      const re = /([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
      let m;
      const rest = body.slice(sp);
      while ((m = re.exec(rest))) el.attrs[m[1]] = xmlDecode(m[2] ?? m[3]);
    }
    stack[stack.length - 1].children.push(el);
    if (!selfClose) stack.push(el);
  }
  const doc = root.children.find((c) => c.tag === 'KeePassFile');
  if (!doc) throw kdbxError('corrupt', 'no KeePassFile element');
  return doc;
}

function childEl(el, tag) { return el.children.find((c) => c.tag === tag); }
function childText(el, tag) { return childEl(el, tag)?.text ?? ''; }

// --- KDBX container parsing ---

const CIPHER_AES = '31c1f2e6bf714350be5805216afc5aff';
const CIPHER_CHACHA20 = 'd6038a2b8b6f4cb5a524339a31dbb59a';
const CIPHER_TWOFISH = 'ad68f29f576f4bb9a36ad47af965346c';
const KDF_AES_UUID = 'c9d9f39a628a4460bf740d08c18a4fea';
const KDF_ARGON2D_UUID = 'ef636ddf8c29444b91f7a9a403e30a0c';
const KDF_ARGON2ID_UUID = '9e298b1956db4773b23dfc3ec6f0a1e6';

// Header fields are [u8 id][len][data]; the length is u16 in KDBX ≤3.1 and u32
// in KDBX 4. Returns { fields, end } with the last occurrence of each id.
function parseHeaderFields(bytes, start, wideLen) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const fields = new Map();
  let pos = start;
  for (;;) {
    if (pos + (wideLen ? 5 : 3) > bytes.length) throw kdbxError('corrupt', 'truncated header');
    const id = bytes[pos];
    const len = wideLen ? dv.getUint32(pos + 1, true) : dv.getUint16(pos + 1, true);
    pos += wideLen ? 5 : 3;
    if (pos + len > bytes.length) throw kdbxError('corrupt', 'truncated header field');
    const data = bytes.slice(pos, pos + len);
    pos += len;
    if (id === 0) return { fields, end: pos };
    fields.set(id, data);
  }
}

function parseVariantDict(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const out = new Map();
  let pos = 2; // u16 version
  for (;;) {
    const type = bytes[pos];
    pos += 1;
    if (type === 0) return out;
    const klen = dv.getUint32(pos, true);
    const key = utf8dec(bytes.subarray(pos + 4, pos + 4 + klen));
    pos += 4 + klen;
    const vlen = dv.getUint32(pos, true);
    const raw = bytes.slice(pos + 4, pos + 4 + vlen);
    pos += 4 + vlen;
    const rdv = new DataView(raw.buffer, raw.byteOffset, raw.length);
    let value = raw;
    if (type === 0x04) value = rdv.getUint32(0, true);
    else if (type === 0x0c) value = rdv.getInt32(0, true);
    else if (type === 0x05 || type === 0x0d) value = Number(rdv.getBigUint64(0, true));
    else if (type === 0x08) value = raw[0] !== 0;
    else if (type === 0x18) value = utf8dec(raw);
    out.set(key, value);
  }
}

function innerStreamFor(id, keyHashes) {
  if (id === 3) return chachaStream(keyHashes.h512.slice(0, 32), keyHashes.h512.slice(32, 44));
  if (id === 2) return salsaStream(keyHashes.h256);
  if (id === 1) return arc4Stream(keyHashes.raw);
  return { xor: (d) => d }; // 0 = plain
}

async function deriveTransformed(kdfParams, composite, onProgress) {
  const uuid = bytesHex(kdfParams.get('$UUID'));
  if (uuid === KDF_AES_UUID) {
    return new Uint8Array(await aesKdf(composite, kdfParams.get('S'), kdfParams.get('R')));
  }
  if (uuid === KDF_ARGON2D_UUID || uuid === KDF_ARGON2ID_UUID) {
    return argon2({
      variant: uuid === KDF_ARGON2D_UUID ? 0 : 2,
      version: kdfParams.get('V'),
      password: composite,
      salt: kdfParams.get('S'),
      passes: kdfParams.get('I'),
      memKiB: Math.floor(kdfParams.get('M') / 1024),
      lanes: kdfParams.get('P'),
      onProgress,
    });
  }
  throw kdbxError('unsupported', `unsupported KDF ${uuid}`);
}

async function decryptOuter(cipherUuid, key, iv, ciphertext) {
  const hex = bytesHex(cipherUuid);
  if (hex === CIPHER_AES) {
    const k = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
    try {
      return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, k, ciphertext));
    } catch {
      throw kdbxError('bad-password', 'decryption failed');
    }
  }
  if (hex === CIPHER_CHACHA20) return chachaStream(key, iv).xor(ciphertext);
  if (hex === CIPHER_TWOFISH) throw kdbxError('unsupported', 'Twofish outer cipher not supported');
  throw kdbxError('unsupported', `unsupported cipher ${hex}`);
}

async function readKdbx4(bytes, headerEnd, password, onProgress) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const { fields } = parseHeaderFields(bytes, 12, true);
  const header = bytes.subarray(0, headerEnd);
  const storedHash = bytes.subarray(headerEnd, headerEnd + 32);
  const storedHmac = bytes.subarray(headerEnd + 32, headerEnd + 64);
  const actualHash = await sha256(header);
  if (bytesHex(actualHash) !== bytesHex(storedHash)) throw kdbxError('corrupt', 'header hash mismatch');

  const composite = await sha256(await sha256(utf8(password)));
  const masterSeed = fields.get(4);
  const kdfParams = parseVariantDict(fields.get(11));
  const transformed = await deriveTransformed(kdfParams, composite, onProgress);
  const hmacKeyBase = await sha512(u8cat(masterSeed, transformed, new Uint8Array([0x01])));
  const cipherKey = await sha256(u8cat(masterSeed, transformed));

  const ff = new Uint8Array(8).fill(0xff);
  const headerHmacKey = await sha512(u8cat(ff, hmacKeyBase));
  const expectHmac = await hmacSha256(headerHmacKey, header);
  if (bytesHex(expectHmac) !== bytesHex(storedHmac)) throw kdbxError('bad-password', 'header HMAC mismatch');

  // HMAC block stream: [32B hmac][u32 len][data]…, terminated by len 0.
  const chunks = [];
  let pos = headerEnd + 64;
  for (let index = 0; ; index++) {
    if (pos + 36 > bytes.length) throw kdbxError('corrupt', 'truncated block stream');
    const hmac = bytes.subarray(pos, pos + 32);
    const len = dv.getUint32(pos + 32, true);
    const data = bytes.subarray(pos + 36, pos + 36 + len);
    if (data.length !== len) throw kdbxError('corrupt', 'truncated block');
    const idxBytes = new Uint8Array(8);
    new DataView(idxBytes.buffer).setBigUint64(0, BigInt(index), true);
    const blockKey = await sha512(u8cat(idxBytes, hmacKeyBase));
    const expect = await hmacSha256(blockKey, u8cat(idxBytes, le32(len), data));
    if (bytesHex(expect) !== bytesHex(hmac)) throw kdbxError('corrupt', 'block HMAC mismatch');
    pos += 36 + len;
    if (len === 0) break;
    chunks.push(data);
  }

  let payload = await decryptOuter(fields.get(2), cipherKey, fields.get(7), u8cat(...chunks));
  const compression = fields.get(3) ? new DataView(fields.get(3).buffer, fields.get(3).byteOffset).getUint32(0, true) : 0;
  if (compression === 1) payload = await gunzip(payload);

  // Inner header: same shape as the outer one (u32 lengths), then the XML.
  const pdv = new DataView(payload.buffer, payload.byteOffset, payload.length);
  let ipos = 0, streamId = 0, streamKey = null, binaries = 0;
  for (;;) {
    const id = payload[ipos];
    const len = pdv.getUint32(ipos + 1, true);
    const data = payload.subarray(ipos + 5, ipos + 5 + len);
    ipos += 5 + len;
    if (id === 0) break;
    if (id === 1) streamId = new DataView(data.buffer, data.byteOffset).getUint32(0, true);
    else if (id === 2) streamKey = data.slice();
    else if (id === 3) binaries++;
  }

  const keyHashes = {
    raw: streamKey,
    h256: streamKey ? await sha256(streamKey) : null,
    h512: streamKey ? await sha512(streamKey) : null,
  };
  const xml = utf8dec(payload.subarray(ipos));
  return { xml, stream: innerStreamFor(streamId, keyHashes), binaries };
}

async function readKdbx3(bytes, headerEnd, password) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const { fields } = parseHeaderFields(bytes, 12, false);
  const header = bytes.subarray(0, headerEnd);

  const composite = await sha256(await sha256(utf8(password)));
  const roundsDv = fields.get(6);
  const rounds = Number(new DataView(roundsDv.buffer, roundsDv.byteOffset).getBigUint64(0, true));
  const transformed = new Uint8Array(await aesKdf(composite, fields.get(5), rounds));
  const masterKey = await sha256(u8cat(fields.get(4), transformed));

  const payload = await decryptOuter(fields.get(2), masterKey, fields.get(7), bytes.subarray(headerEnd));
  const ssb = fields.get(9);
  if (bytesHex(payload.subarray(0, ssb.length)) !== bytesHex(ssb)) {
    throw kdbxError('bad-password', 'stream start bytes mismatch');
  }

  // Hashed block stream: [u32 index][32B sha256][u32 len][data]…, terminated by len 0.
  const chunks = [];
  let pos = ssb.length;
  const pdv = new DataView(payload.buffer, payload.byteOffset, payload.length);
  for (;;) {
    if (pos + 40 > payload.length) throw kdbxError('corrupt', 'truncated block stream');
    const hash = payload.subarray(pos + 4, pos + 36);
    const len = pdv.getUint32(pos + 36, true);
    const data = payload.subarray(pos + 40, pos + 40 + len);
    pos += 40 + len;
    if (len === 0) break;
    if (data.length !== len) throw kdbxError('corrupt', 'truncated block');
    if (bytesHex(await sha256(data)) !== bytesHex(hash)) throw kdbxError('corrupt', 'block hash mismatch');
    chunks.push(data);
  }

  let xmlBytes = u8cat(...chunks);
  const compDv = fields.get(3);
  const compression = compDv ? new DataView(compDv.buffer, compDv.byteOffset).getUint32(0, true) : 0;
  if (compression === 1) xmlBytes = await gunzip(xmlBytes);

  const streamKey = fields.get(8);
  const streamIdDv = fields.get(10);
  const streamId = streamIdDv ? new DataView(streamIdDv.buffer, streamIdDv.byteOffset).getUint32(0, true) : 2;
  const keyHashes = {
    raw: streamKey,
    h256: streamKey ? await sha256(streamKey) : null,
    h512: streamKey ? await sha512(streamKey) : null,
  };
  const xml = utf8dec(xmlBytes);
  return { xml, stream: innerStreamFor(streamId, keyHashes), binaries: 0, headerBytes: header };
}

// KDBX ≤3.1 stores times as ISO 8601 strings, KDBX 4 as
// base64(uint64le(seconds since 0001-01-01)).
const DOTNET_EPOCH_OFFSET = 62135596800;

function parseKdbxTime(s) {
  if (!s) return null;
  if (s.includes('-') || s.includes(':')) {
    const t = Date.parse(s);
    return Number.isNaN(t) ? null : t;
  }
  try {
    const b = b64ToBytes(s);
    if (b.length < 8) return null;
    const secs = Number(new DataView(b.buffer, b.byteOffset).getBigUint64(0, true));
    return (secs - DOTNET_EPOCH_OFFSET) * 1000;
  } catch {
    return null;
  }
}

function isTrue(v) { return typeof v === 'string' && v.toLowerCase() === 'true'; }

// Decrypt every <Value Protected="True"> in document order — the stream is
// stateful and history entries consume it too, so this must happen over the
// whole tree before any extraction.
function unprotectAll(el, stream) {
  if (el.tag === 'Value' && isTrue(el.attrs.Protected)) {
    const enc = el.text.trim();
    el.text = enc ? utf8dec(stream.xor(b64ToBytes(enc))) : '';
  }
  for (const c of el.children) unprotectAll(c, stream);
}

function entryFromXml(el, groupPath) {
  const fields = [];
  let tags = [], created = null, modified = null;
  for (const c of el.children) {
    if (c.tag === 'String') {
      const valEl = childEl(c, 'Value');
      fields.push({
        key: childText(c, 'Key'),
        value: valEl ? valEl.text : '',
        protected: !!valEl && isTrue(valEl.attrs.Protected),
      });
    } else if (c.tag === 'Times') {
      created = parseKdbxTime(childText(c, 'CreationTime'));
      modified = parseKdbxTime(childText(c, 'LastModificationTime'));
    } else if (c.tag === 'Tags') {
      tags = c.text.split(/[;,]/).map((s) => s.trim()).filter(Boolean);
    }
  }
  return { fields, tags, created, modified, group: groupPath };
}

// Parse a KDBX file. Returns { name, entries, binariesSkipped } where entries
// carry raw KeePass fields; kdbxEntriesToItems maps them to Sésamo items.
export async function readKdbx(bytes, password, { onProgress } = {}) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  if (bytes.length < 12) throw kdbxError('not-kdbx', 'file too short');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  if (dv.getUint32(0, true) !== 0x9aa2d903 || dv.getUint32(4, true) !== 0xb54bfb67) {
    throw kdbxError('not-kdbx', 'not a KDBX (KeePass 2.x) file');
  }
  const major = dv.getUint16(10, true);
  let result;
  if (major === 4) {
    const { end } = parseHeaderFields(bytes, 12, true);
    result = await readKdbx4(bytes, end, password, onProgress);
  } else if (major === 3 || major === 2) {
    const { end } = parseHeaderFields(bytes, 12, false);
    result = await readKdbx3(bytes, end, password);
  } else {
    throw kdbxError('unsupported', `KDBX ${major}.x not supported`);
  }

  const doc = parseXml(result.xml);
  unprotectAll(doc, result.stream);

  const meta = childEl(doc, 'Meta');
  // KDBX ≤3.1 authenticates the header through Meta/HeaderHash.
  if (result.headerBytes && meta) {
    const declared = childText(meta, 'HeaderHash').trim();
    if (declared) {
      const actual = await sha256(result.headerBytes);
      if (bytesToB64ForCompare(actual) !== declared) throw kdbxError('corrupt', 'header hash mismatch');
    }
  }
  const recycleUuid = meta ? childText(meta, 'RecycleBinUUID').trim() : '';

  const entries = [];
  const walkGroup = (group, path) => {
    for (const c of group.children) {
      if (c.tag === 'Group') {
        if (recycleUuid && childText(c, 'UUID').trim() === recycleUuid) continue;
        walkGroup(c, [...path, childText(c, 'Name').trim()]);
      } else if (c.tag === 'Entry') {
        entries.push(entryFromXml(c, path)); // History children are not Entry siblings, so old revisions never land here
      }
    }
  };
  const root = childEl(doc, 'Root');
  if (root) for (const g of root.children) if (g.tag === 'Group') walkGroup(g, []);

  return {
    name: meta ? childText(meta, 'DatabaseName') : '',
    entries,
    binariesSkipped: result.binaries,
  };
}

function bytesToB64ForCompare(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// --- Mapping KeePass entries to Sésamo items ---
//
// Mirror of itemsToKdbxEntries in export.js: the field names below must stay
// in sync with extraFields there so a Sésamo→KDBX→Sésamo round trip
// reconstructs typed items instead of piling everything into customFields.

const CARD_KEYS = {
  'Card Holder': 'card_holder', 'Card Number': 'card_number', 'Card Brand': 'card_brand',
  'Card Expiry': 'card_exp', 'Card CVV': 'card_cvv', 'Card PIN': 'card_pin',
};
const IDENTITY_KEYS = {
  'Full Name': 'id_fullname', 'Email': 'id_email', 'Phone': 'id_phone',
  'Address': 'id_address', 'Company': 'id_company',
};
const STANDARD_KEYS = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes']);

function totpSecretFrom(value) {
  const v = (value || '').trim();
  if (!v) return '';
  if (v.startsWith('otpauth://')) {
    try {
      const secret = new URL(v).searchParams.get('secret');
      if (secret) return secret;
    } catch { /* fall through to regex */ }
    const m = v.match(/[?&]secret=([A-Za-z2-7=]+)/i);
    return m ? m[1] : '';
  }
  return v;
}

export function kdbxEntriesToItems(entries) {
  const items = [];
  for (const entry of entries) {
    const byKey = new Map(entry.fields.map((f) => [f.key, f]));
    const val = (k) => byKey.get(k)?.value ?? '';

    const item = { type: 'login', title: val('Title').trim() };
    for (const [key, prop] of [['UserName', 'username'], ['Password', 'password'], ['URL', 'url'], ['Notes', 'notes']]) {
      const v = val(key);
      if (v) item[prop] = v;
    }
    if (!item.title && !item.username && !item.password && !item.url) continue;
    if (!item.title) item.title = item.username || item.url || 'KeePass';

    const consumed = new Set(STANDARD_KEYS);
    // Reconstruct a typed item only when the entry carries no login
    // credentials: Sésamo's card/identity layouts don't render
    // username/password, so an entry that has both stays a login and keeps
    // the Card */identity keys as (hidden) custom fields instead.
    if (!item.username && !item.password) {
      if (byKey.has('Card Number') || byKey.has('Card Holder')) {
        item.type = 'card';
        for (const [key, prop] of Object.entries(CARD_KEYS)) {
          if (byKey.has(key)) { item[prop] = val(key); consumed.add(key); }
        }
      } else if (byKey.has('Full Name')) {
        item.type = 'identity';
        for (const [key, prop] of Object.entries(IDENTITY_KEYS)) {
          if (byKey.has(key)) { item[prop] = val(key); consumed.add(key); }
        }
      }
    }

    const otpField = byKey.get('otp') || byKey.get('TOTP Seed');
    if (otpField) {
      const secret = totpSecretFrom(otpField.value);
      if (secret) item.totp_secret = secret;
      consumed.add(otpField.key);
    }
    consumed.add('TOTP Settings'); // KeeTrayTOTP metadata, meaningless without the plugin

    const customFields = [];
    for (const f of entry.fields) {
      if (consumed.has(f.key) || !f.value) continue;
      customFields.push({ label: f.key, value: f.value, hidden: f.protected });
    }
    if (customFields.length) item.customFields = customFields;

    const tags = [...entry.tags];
    for (const g of entry.group || []) if (g && !tags.includes(g)) tags.push(g);
    if (tags.length) item.tags = tags;

    items.push(item);
  }
  return items;
}
