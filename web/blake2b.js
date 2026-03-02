// BLAKE2b-256 implementation (pure JS, no dependencies)
// Based on RFC 7693 - BLAKE2b with 256-bit output

(function(root) {
  'use strict';

  const BLAKE2B_IV = [
    0xF3BCC908n, 0x6A09E667n,
    0x84CAA73Bn, 0xBB67AE85n,
    0xFE94F82Bn, 0x3C6EF372n,
    0x5F1D36F1n, 0xA54FF53An,
    0xADE682D1n, 0x510E527Fn,
    0x2B3E6C1Fn, 0x9B05688Cn,
    0xFB41BD6Bn, 0x1F83D9ABn,
    0x137E2179n, 0x5BE0CD19n,
  ];

  const SIGMA = [
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
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  ];

  function LOAD64(buf, offset) {
    let lo = 0n;
    for (let i = 7; i >= 4; i--) lo = (lo << 8n) | BigInt(buf[offset + i]);
    let hi = 0n;
    for (let i = 3; i >= 0; i--) hi = (hi << 8n) | BigInt(buf[offset + i]);
    return (lo << 32n) | hi;
  }

  function STORE64(out, offset, val) {
    for (let i = 0; i < 8; i++) {
      out[offset + i] = Number(val & 0xFFn);
      val >>= 8n;
    }
  }

  const MASK64 = (1n << 64n) - 1n;

  function ADD64(a, b) { return (a + b) & MASK64; }

  function ROTR64(x, n) {
    return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
  }

  function G(v, a, b, c, d, x, y) {
    v[a] = ADD64(ADD64(v[a], v[b]), x);
    v[d] = ROTR64(v[d] ^ v[a], 32);
    v[c] = ADD64(v[c], v[d]);
    v[b] = ROTR64(v[b] ^ v[c], 24);
    v[a] = ADD64(ADD64(v[a], v[b]), y);
    v[d] = ROTR64(v[d] ^ v[a], 16);
    v[c] = ADD64(v[c], v[d]);
    v[b] = ROTR64(v[b] ^ v[c], 63);
  }

  function compress(ctx, last) {
    const v = new Array(16);
    const m = new Array(16);

    for (let i = 0; i < 8; i++) v[i] = ctx.h[i];
    for (let i = 0; i < 8; i++) v[8 + i] = (BLAKE2B_IV[i * 2 + 1] << 32n) | BLAKE2B_IV[i * 2];
    v[12] ^= ctx.t & MASK64;
    v[13] ^= (ctx.t >> 64n) & MASK64;
    if (last) v[14] = ~v[14] & MASK64;

    for (let i = 0; i < 16; i++) {
      m[i] = LOAD64(ctx.b, i * 8);
    }

    for (let i = 0; i < 12; i++) {
      const s = SIGMA[i];
      G(v, 0, 4, 8,  12, m[s[0]],  m[s[1]]);
      G(v, 1, 5, 9,  13, m[s[2]],  m[s[3]]);
      G(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
      G(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
      G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
      G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(v, 2, 7, 8,  13, m[s[12]], m[s[13]]);
      G(v, 3, 4, 9,  14, m[s[14]], m[s[15]]);
    }

    for (let i = 0; i < 8; i++) {
      ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 8];
    }
  }

  function blake2bInit(outlen) {
    const ctx = {
      h: new Array(8),
      b: new Uint8Array(128),
      c: 0,
      t: 0n,
      outlen: outlen,
    };
    for (let i = 0; i < 8; i++) {
      ctx.h[i] = (BLAKE2B_IV[i * 2 + 1] << 32n) | BLAKE2B_IV[i * 2];
    }
    ctx.h[0] ^= BigInt(0x01010000 ^ outlen);
    return ctx;
  }

  function blake2bUpdate(ctx, input) {
    for (let i = 0; i < input.length; i++) {
      if (ctx.c === 128) {
        ctx.t += 128n;
        compress(ctx, false);
        ctx.c = 0;
      }
      ctx.b[ctx.c++] = input[i];
    }
  }

  function blake2bFinal(ctx) {
    ctx.t += BigInt(ctx.c);
    while (ctx.c < 128) ctx.b[ctx.c++] = 0;
    compress(ctx, true);

    const out = new Uint8Array(ctx.outlen);
    for (let i = 0; i < ctx.outlen; i++) {
      out[i] = Number((ctx.h[i >> 3] >> BigInt(8 * (i & 7))) & 0xFFn);
    }
    return out;
  }

  function blake2b256(data) {
    if (typeof data === 'string') {
      data = new TextEncoder().encode(data);
    }
    const ctx = blake2bInit(32);
    blake2bUpdate(ctx, data);
    return blake2bFinal(ctx);
  }

  function blake2b256Hex(data) {
    const hash = blake2b256(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Multi-input hash: blake2b(a || b || c ...)
  function blake2b256Multi(...inputs) {
    const ctx = blake2bInit(32);
    for (const input of inputs) {
      if (typeof input === 'string') {
        blake2bUpdate(ctx, new TextEncoder().encode(input));
      } else {
        blake2bUpdate(ctx, input);
      }
    }
    return blake2bFinal(ctx);
  }

  root.blake2b256 = blake2b256;
  root.blake2b256Hex = blake2b256Hex;
  root.blake2b256Multi = blake2b256Multi;

})(typeof globalThis !== 'undefined' ? globalThis : window);
