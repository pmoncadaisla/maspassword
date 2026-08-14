import { test } from 'node:test';
import assert from 'node:assert/strict';
import { qrMatrix, qrSvg } from '../qr.js';

// Expected symbol size for a QR version: 4v + 17.
const sizeFor = (version) => version * 4 + 17;

// Asserts the concentric finder pattern (dark border, light ring, dark 3×3
// core) at the 7×7 block whose top-left module is (top, left).
function assertFinder(m, top, left, corner) {
  for (let r = 0; r < 7; r++) {
    for (let c = 0; c < 7; c++) {
      const dist = Math.max(Math.abs(r - 3), Math.abs(c - 3));
      const expected = dist !== 2; // dark at core (0,1) and outer border (3)
      assert.equal(m[top + r][left + c], expected,
        `${corner} finder module (${top + r},${left + c}) should be ${expected ? 'dark' : 'light'}`);
    }
  }
}

test('qrMatrix returns a square boolean matrix', () => {
  const m = qrMatrix('hello world');
  assert.ok(Array.isArray(m));
  assert.ok(m.length >= 21);
  for (const row of m) {
    assert.equal(row.length, m.length, 'matrix must be square');
    for (const cell of row) assert.equal(typeof cell, 'boolean');
  }
});

test('short input fits version 1 (21×21)', () => {
  assert.equal(qrMatrix('a').length, sizeFor(1));
  assert.equal(qrMatrix('x'.repeat(14)).length, sizeFor(1)); // exact v1-M byte capacity
});

test('finder patterns sit at three corners with light separators', () => {
  const m = qrMatrix('device-linking');
  const n = m.length;
  assertFinder(m, 0, 0, 'top-left');
  assertFinder(m, 0, n - 7, 'top-right');
  assertFinder(m, n - 7, 0, 'bottom-left');
  // Separators: the row/col just past each finder is all light.
  for (let i = 0; i < 8; i++) {
    assert.equal(m[7][i], false, 'top-left separator row');
    assert.equal(m[i][7], false, 'top-left separator col');
    assert.equal(m[7][n - 1 - i], false, 'top-right separator row');
    assert.equal(m[n - 8][i], false, 'bottom-left separator row');
  }
  // No finder in the fourth corner: its 7×7 block can't be the exact pattern.
  let fourthCornerMatches = true;
  for (let r = 0; r < 7 && fourthCornerMatches; r++) {
    for (let c = 0; c < 7; c++) {
      const dist = Math.max(Math.abs(r - 3), Math.abs(c - 3));
      if (m[n - 7 + r][n - 7 + c] !== (dist !== 2)) { fourthCornerMatches = false; break; }
    }
  }
  assert.equal(fourthCornerMatches, false, 'bottom-right corner must not contain a finder');
});

test('timing patterns alternate along row/col 6', () => {
  const m = qrMatrix('timing check payload');
  const n = m.length;
  for (let i = 8; i < n - 8; i++) {
    assert.equal(m[6][i], i % 2 === 0, `horizontal timing at col ${i}`);
    assert.equal(m[i][6], i % 2 === 0, `vertical timing at row ${i}`);
  }
});

test('dark module is always set at (size-8, 8)', () => {
  for (const text of ['a', 'x'.repeat(60), 'x'.repeat(220)]) {
    const m = qrMatrix(text);
    assert.equal(m[m.length - 8][8], true);
  }
});

test('encoding is deterministic', () => {
  const payload = JSON.stringify({ v: 1, srv: 'https://vault.example.com', email: 'ana@example.com', tok: 'mpd_x_y' });
  assert.deepEqual(qrMatrix(payload), qrMatrix(payload));
  assert.equal(qrSvg(payload), qrSvg(payload));
});

test('version scales with input length (auto version 1..15)', () => {
  assert.equal(qrMatrix('x'.repeat(10)).length, sizeFor(1));
  assert.equal(qrMatrix('x'.repeat(15)).length, sizeFor(2)); // just past v1 capacity
  assert.equal(qrMatrix('x'.repeat(100)).length, sizeFor(6));
  assert.equal(qrMatrix('x'.repeat(181)).length, sizeFor(10)); // past v9 (180)
  assert.equal(qrMatrix('x'.repeat(250)).length, sizeFor(11)); // device payload upper bound
  assert.equal(qrMatrix('x'.repeat(412)).length, sizeFor(15)); // exact v15-M capacity
});

test('capacity is counted in UTF-8 bytes, not characters', () => {
  assert.equal(qrMatrix('é'.repeat(7)).length, sizeFor(1)); // 14 bytes: still v1
  assert.equal(qrMatrix('é'.repeat(8)).length, sizeFor(2)); // 16 bytes: v2
});

test('throws beyond version-15 capacity', () => {
  assert.throws(() => qrMatrix('x'.repeat(413)), /too long/);
  assert.throws(() => qrMatrix('é'.repeat(210)), /too long/); // 420 UTF-8 bytes
});

test('a realistic device-linking payload (~250 chars) encodes fine', () => {
  const json = JSON.stringify({
    v: 1,
    srv: 'https://vault.masorange.es',
    email: 'pablo.moncada@masorange.es',
    tok: 'mpd_0d4c2a9e-7f13-4b58-a1c2-2f9e8d7c6b5a_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY',
  });
  const b64url = Buffer.from(json).toString('base64url');
  assert.ok(b64url.length >= 180 && b64url.length <= 250, `payload length ${b64url.length}`);
  const m = qrMatrix(b64url);
  assert.ok(m.length >= sizeFor(9) && m.length <= sizeFor(11), `matrix ${m.length}`);
});

test('qrSvg produces expected dimensions and crisp rendering hints', () => {
  const svg = qrSvg('svg dims test');
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.ok(svg.includes('width="224"'), 'default size 224');
  assert.ok(svg.includes('height="224"'));
  assert.ok(svg.includes('viewBox="0 0 25 25"'), '21 modules + 2×2 margin'); // v1
  assert.ok(svg.includes('shape-rendering="crispEdges"'));
  assert.ok(svg.includes('fill="#fff"'), 'default light');
  assert.ok(svg.includes('fill="#000"'), 'default dark');
  assert.ok(svg.includes('<path '), 'modules drawn as one path');
});

test('qrSvg honours size, margin and colors', () => {
  const svg = qrSvg('svg opts test', { size: 320, margin: 4, dark: '#111827', light: '#f8fafc' });
  assert.ok(svg.includes('width="320"'));
  assert.ok(svg.includes('height="320"'));
  assert.ok(svg.includes('viewBox="0 0 29 29"'), '21 modules + 2×4 margin');
  assert.ok(svg.includes('fill="#111827"'));
  assert.ok(svg.includes('fill="#f8fafc"'));
});

test('qrSvg throws for oversized input too', () => {
  assert.throws(() => qrSvg('x'.repeat(2000)), /too long/);
});
