// qr.js — clean-room QR Code encoder (model 2, byte mode, error correction M).
//
// Pure ES module, zero dependencies, no build step. Implements the ISO/IEC
// 18004 pipeline end to end: byte-mode segmentation, Reed-Solomon ECC over
// GF(256) (polynomial 0x11D), block interleaving, all 8 mask patterns with
// standard penalty evaluation, BCH-protected format info and (v7+) version
// info. Supports versions 1..15 (up to 412 bytes at level M) — plenty for the
// device-linking payload (~180-250 chars) with headroom.
//
// Exports:
//   qrMatrix(text)            -> boolean[][] (true = dark). Throws if too long.
//   qrSvg(text, opts)         -> standalone <svg> string with crisp squares.
//
// SECURITY NOTE: this module only ever renders what it is given. The
// device-linking payload it displays contains server origin, email and the
// device API token — never any encryption key material (zero-knowledge).

const ECC_M = 0; // format-info bit pattern for level M is 0b00

// --- GF(256) arithmetic (primitive polynomial x^8+x^4+x^3+x^2+1 = 0x11D) ---
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

// Generator polynomial Π(x - α^i) for i = 0..degree-1, MSB-first, leading 1.
function rsGenerator(degree) {
  let g = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j]; // × x
      next[j + 1] ^= gfMul(g[j], GF_EXP[i]); // × α^i
    }
    g = next;
  }
  return g;
}

// Remainder of data(x)·x^degree ÷ generator(x) — the ECC codewords.
function rsRemainder(data, degree) {
  const gen = rsGenerator(degree);
  const rem = new Uint8Array(degree);
  for (const b of data) {
    const factor = b ^ rem[0];
    rem.copyWithin(0, 1);
    rem[degree - 1] = 0;
    if (factor !== 0) {
      for (let i = 0; i < degree; i++) rem[i] ^= gfMul(gen[i + 1], factor);
    }
  }
  return rem;
}

// --- Version tables (level M), versions 1..15 -------------------------------
// [totalCodewords, eccPerBlock, group1Blocks, group1DataCW, group2Blocks, group2DataCW]
const VERSIONS = [
  null,
  [26, 10, 1, 16, 0, 0],
  [44, 16, 1, 28, 0, 0],
  [70, 26, 1, 44, 0, 0],
  [100, 18, 2, 32, 0, 0],
  [134, 24, 2, 43, 0, 0],
  [172, 16, 4, 27, 0, 0],
  [196, 18, 4, 31, 0, 0],
  [242, 22, 2, 38, 2, 39],
  [292, 22, 3, 36, 2, 37],
  [346, 26, 4, 43, 1, 44],
  [404, 30, 1, 50, 4, 51],
  [466, 22, 6, 36, 2, 37],
  [532, 22, 8, 37, 1, 38],
  [581, 24, 4, 40, 5, 41],
  [655, 24, 5, 41, 5, 42],
];
const MAX_VERSION = 15;

// Alignment pattern centre coordinates per version.
const ALIGN = [
  null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
  [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70],
];

function dataCodewords(version) {
  const [, ecc, g1n, g1d, g2n, g2d] = VERSIONS[version];
  void ecc;
  return g1n * g1d + g2n * g2d;
}

// Byte-mode character capacity: data bits minus mode (4) and count (8/16) bits.
function byteCapacity(version) {
  return dataCodewords(version) - (version <= 9 ? 2 : 3);
}

// --- Bit buffer --------------------------------------------------------------
class BitBuffer {
  constructor() { this.bits = []; }
  push(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  get length() { return this.bits.length; }
  toBytes() {
    const out = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, i) => { out[i >> 3] |= bit << (7 - (i & 7)); });
    return out;
  }
}

// --- Encoding: text -> interleaved codewords ---------------------------------
function encodeText(text) {
  const bytes = new TextEncoder().encode(String(text));
  let version = 0;
  for (let v = 1; v <= MAX_VERSION; v++) {
    if (byteCapacity(v) >= bytes.length) { version = v; break; }
  }
  if (!version) {
    throw new Error(`qr: input too long (${bytes.length} bytes, max ${byteCapacity(MAX_VERSION)} at version ${MAX_VERSION}-M)`);
  }

  const dataCW = dataCodewords(version);
  const bb = new BitBuffer();
  bb.push(0b0100, 4); // byte mode
  bb.push(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) bb.push(b, 8);
  // Terminator (up to 4 zero bits), then pad to a byte boundary.
  bb.push(0, Math.min(4, dataCW * 8 - bb.length));
  if (bb.length % 8 !== 0) bb.push(0, 8 - (bb.length % 8));
  // Alternating pad codewords to fill capacity.
  const PADS = [0xec, 0x11];
  for (let i = 0; bb.length < dataCW * 8; i++) bb.push(PADS[i % 2], 8);

  return { version, codewords: interleave(bb.toBytes(), version) };
}

// Split into RS blocks, compute ECC per block, interleave data then ECC.
function interleave(data, version) {
  const [total, eccLen, g1n, g1d, g2n, g2d] = VERSIONS[version];
  const blocks = [];
  let off = 0;
  for (let i = 0; i < g1n; i++) { blocks.push(data.subarray(off, off + g1d)); off += g1d; }
  for (let i = 0; i < g2n; i++) { blocks.push(data.subarray(off, off + g2d)); off += g2d; }
  const eccBlocks = blocks.map((b) => rsRemainder(b, eccLen));

  const out = new Uint8Array(total);
  let k = 0;
  const maxData = Math.max(g1d, g2d);
  for (let i = 0; i < maxData; i++) {
    for (const b of blocks) if (i < b.length) out[k++] = b[i];
  }
  for (let i = 0; i < eccLen; i++) {
    for (const e of eccBlocks) out[k++] = e[i];
  }
  return out;
}

// --- Matrix construction ------------------------------------------------------
function buildMatrix(version, codewords) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));

  const set = (row, col, dark) => {
    modules[row][col] = dark;
    isFunction[row][col] = true;
  };

  // Timing patterns (row 6 / col 6).
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }

  // Finder patterns + separators at three corners.
  const drawFinder = (r, c) => {
    for (let dr = -4; dr <= 4; dr++) {
      for (let dc = -4; dc <= 4; dc++) {
        const rr = r + dr, cc = c + dc;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const dist = Math.max(Math.abs(dr), Math.abs(dc));
        set(rr, cc, dist !== 2 && dist !== 4); // rings: dark, light, dark core; light separator
      }
    }
  };
  drawFinder(3, 3);
  drawFinder(3, size - 4);
  drawFinder(size - 4, 3);

  // Alignment patterns (skip the three overlapping the finders).
  const centers = ALIGN[version];
  const last = centers.length - 1;
  for (let i = 0; i < centers.length; i++) {
    for (let j = 0; j < centers.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      const r = centers[i], c = centers[j];
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  // Reserve format-info cells (real bits are drawn per-mask later).
  drawFormatBits(modules, isFunction, size, 0, set);

  // Version info blocks for v7+ (18 bits: 6 data + 12 BCH remainder, gen 0x1F25).
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(b, a, bit); // top-right 6×3 block
      set(a, b, bit); // bottom-left 3×6 block
    }
  }

  // Zigzag data placement over the non-function area.
  let bitIndex = 0;
  const totalBits = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // vertical timing column is skipped entirely
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const upward = ((right + 1) & 2) === 0;
        const row = upward ? size - 1 - vert : vert;
        if (!isFunction[row][col] && bitIndex < totalBits) {
          modules[row][col] = ((codewords[bitIndex >> 3] >>> (7 - (bitIndex & 7))) & 1) === 1;
          bitIndex++;
        }
        // Remainder modules stay light and get masked like data (per spec).
      }
    }
  }

  // Try all 8 masks; keep the one with the lowest penalty. XOR is involutory,
  // so applying the same mask twice restores the previous state.
  let bestMask = 0;
  let bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(modules, isFunction, size, mask);
    drawFormatBits(modules, isFunction, size, mask, set);
    const p = penaltyScore(modules, size);
    if (p < bestPenalty) { bestPenalty = p; bestMask = mask; }
    applyMask(modules, isFunction, size, mask); // undo
  }
  applyMask(modules, isFunction, size, bestMask);
  drawFormatBits(modules, isFunction, size, bestMask, set);

  return modules;
}

// Format info: 5 bits (ECC level M=00 + mask) protected by BCH(15,5)
// (generator 0x537), XOR-masked with 0x5412, drawn in both standard copies.
function drawFormatBits(modules, isFunction, size, mask, set) {
  const data = (ECC_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) === 1;

  // First copy, around the top-left finder.
  for (let i = 0; i <= 5; i++) set(i, 8, bit(i));
  set(7, 8, bit(6));
  set(8, 8, bit(7));
  set(8, 7, bit(8));
  for (let i = 9; i < 15; i++) set(8, 14 - i, bit(i));

  // Second copy, split between bottom-left and top-right.
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(i));
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, bit(i));
  set(size - 8, 8, true); // dark module
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function applyMask(modules, isFunction, size, mask) {
  const fn = MASKS[mask];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunction[r][c] && fn(r, c)) modules[r][c] = !modules[r][c];
    }
  }
}

// Standard penalty rules N1..N4.
function penaltyScore(modules, size) {
  let score = 0;

  // N1: runs of >=5 same-coloured modules in a row/column: 3 + (len - 5).
  for (let r = 0; r < size; r++) {
    for (const line of [modules[r], modules.map((row) => row[r])]) {
      let run = 1;
      for (let i = 1; i <= size; i++) {
        if (i < size && line[i] === line[i - 1]) {
          run++;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
    }
  }

  // N2: each 2×2 block of a single colour: +3.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = modules[r][c];
      if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) score += 3;
    }
  }

  // N3: finder-like 1:1:3:1:1 pattern with 4 light modules on one side: +40.
  const PAT_A = [true, false, true, true, true, false, true, false, false, false, false];
  const PAT_B = [false, false, false, false, true, false, true, true, true, false, true];
  const matches = (line, i, pat) => pat.every((p, k) => line[i + k] === p);
  for (let r = 0; r < size; r++) {
    const row = modules[r];
    const col = modules.map((rw) => rw[r]);
    for (let i = 0; i + 11 <= size; i++) {
      if (matches(row, i, PAT_A) || matches(row, i, PAT_B)) score += 40;
      if (matches(col, i, PAT_A) || matches(col, i, PAT_B)) score += 40;
    }
  }

  // N4: deviation of the dark-module proportion from 50%, in 5% steps: ×10.
  let dark = 0;
  for (const row of modules) for (const m of row) if (m) dark++;
  const percent = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

// --- Public API ---------------------------------------------------------------

/**
 * Encode text as a QR module matrix (model 2, byte mode, ECC level M,
 * version auto-selected in 1..15). Returns boolean[][] where true = dark.
 * Throws when the UTF-8 encoding of `text` exceeds the version-15 capacity.
 */
export function qrMatrix(text) {
  const { version, codewords } = encodeText(text);
  return buildMatrix(version, codewords);
}

/**
 * Render text as a standalone SVG string of crisp squares.
 * opts: { size = 224, margin = 2 (modules), dark = '#000', light = '#fff' }.
 */
export function qrSvg(text, { size = 224, margin = 2, dark = '#000', light = '#fff' } = {}) {
  const matrix = qrMatrix(text);
  const n = matrix.length;
  const dim = n + margin * 2;

  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (matrix[r][c]) d += `M${c + margin} ${r + margin}h1v1h-1z`;
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${size}" height="${size}" shape-rendering="crispEdges" role="img">` +
    `<rect width="${dim}" height="${dim}" fill="${light}"/>` +
    `<path d="${d}" fill="${dark}"/>` +
    `</svg>`;
}
