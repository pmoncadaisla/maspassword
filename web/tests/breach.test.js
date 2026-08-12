import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha1Hex, checkPwnedCount } from '../breach.js';

// SHA-1('password') = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PW = 'password';
const PW_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
const PW_PREFIX = PW_HASH.slice(0, 5);   // 5BAA6
const PW_SUFFIX = PW_HASH.slice(5);      // 1E4C9B93F3F0682250B6CF8331B7EE68FD8

test('sha1Hex returns an uppercase 40-char hex digest', async () => {
  const h = await sha1Hex(PW);
  assert.equal(h, PW_HASH);
  assert.match(h, /^[0-9A-F]{40}$/);
});

test('checkPwnedCount returns the count for a matching suffix', async () => {
  const body = [
    '003D68EB55068C33ACE09247EE4C639306B:3',
    `${PW_SUFFIX}:3730471`,
    '11EDD52C8E80B4F0B0EF7B9C6C0E9E9F0F0:99',
  ].join('\r\n');

  let requestedUrl = '';
  const fetchImpl = async (url) => {
    requestedUrl = url;
    return { text: async () => body };
  };

  const count = await checkPwnedCount(PW, { fetchImpl });
  assert.equal(count, 3730471);

  // k-anonymity: only the 5-char prefix may appear in the request path.
  // (Note: the host "pwnedpasswords.com" itself contains the word "password",
  //  so the privacy check is made against the URL *path*, which carries the
  //  secret-derived data.)
  const path = new URL(requestedUrl).pathname;
  assert.equal(path, `/range/${PW_PREFIX}`, 'path carries only the 5-char prefix');
  assert.ok(path.includes(PW_PREFIX), 'path contains the 5-char prefix');
  assert.ok(!path.includes(PW_SUFFIX), 'path must not contain the suffix');
  assert.ok(!path.includes(PW_HASH), 'path must not contain the full hash');
  assert.ok(!path.toLowerCase().includes(PW.toLowerCase()), 'path must not contain the password');
  assert.equal(requestedUrl, `https://api.pwnedpasswords.com/range/${PW_PREFIX}`);
});

test('checkPwnedCount returns 0 when no suffix matches', async () => {
  const body = [
    '11111111111111111111111111111111111:5',
    '22222222222222222222222222222222222:7',
  ].join('\r\n');

  const fetchImpl = async () => ({ text: async () => body });
  const count = await checkPwnedCount(PW, { fetchImpl });
  assert.equal(count, 0);
});

test('suffix matching is case-insensitive', async () => {
  const body = `${PW_SUFFIX.toLowerCase()}:42`;
  const fetchImpl = async () => ({ text: async () => body });
  const count = await checkPwnedCount(PW, { fetchImpl });
  assert.equal(count, 42);
});

test('the requested URL never leaks more than the 5-char prefix', async () => {
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    return { text: async () => '' };
  };

  await checkPwnedCount('correct horse battery staple', { fetchImpl });
  assert.equal(urls.length, 1);
  const url = urls[0];
  const fullHash = await sha1Hex('correct horse battery staple');
  assert.ok(url.endsWith(fullHash.slice(0, 5)));
  assert.ok(!url.includes(fullHash.slice(5)));
  assert.ok(!url.toLowerCase().includes('correct horse'));
});
