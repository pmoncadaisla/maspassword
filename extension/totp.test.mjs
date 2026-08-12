import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, generateTOTP } from './totp.js';

// RFC 6238 test-vector secret: ASCII "12345678901234567890".
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('base32Decode: decodes RFC 6238 secret to ASCII 12345678901234567890', () => {
  const bytes = base32Decode(SECRET);
  assert.equal(new TextDecoder().decode(bytes), '12345678901234567890');
});

test('generateTOTP: RFC 6238 vector at t=59s, 8 digits -> 94287082', async () => {
  const { code } = await generateTOTP(SECRET, { t: 59000, digits: 8 });
  assert.equal(code, '94287082');
});

test('generateTOTP: RFC 6238 vector at t=59s, 6 digits -> 287082', async () => {
  const { code } = await generateTOTP(SECRET, { t: 59000, digits: 6 });
  assert.equal(code, '287082');
});

test('generateTOTP: remaining seconds are within the step', async () => {
  const { remaining } = await generateTOTP(SECRET, { t: 59000, period: 30 });
  // At t=59s the step boundary is 60s, so 1s remains.
  assert.equal(remaining, 1);
});

test('generateTOTP: default digits is 6', async () => {
  const { code } = await generateTOTP(SECRET, { t: 59000 });
  assert.equal(code.length, 6);
  assert.equal(code, '287082');
});
