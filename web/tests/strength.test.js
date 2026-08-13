import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateStrength } from '../strength.js';

test("'password' scores 0 and is flagged", () => {
  const r = estimateStrength('password');
  assert.equal(r.score, 0);
  assert.equal(r.label, 'very weak');
  assert.ok(r.warnings.length > 0);
  assert.ok(
    r.warnings.some((w) => /common/i.test(w)),
    'blacklist warning present',
  );
});

test("'123456' scores 0 and is flagged", () => {
  const r = estimateStrength('123456');
  assert.equal(r.score, 0);
  assert.ok(r.warnings.length > 0);
  assert.ok(r.warnings.some((w) => /common/i.test(w)));
});

test('a long random mixed string scores 4', () => {
  const r = estimateStrength('4G$k9T!m2P#w7R@b5X&n3L%q8Z!v6M');
  assert.equal(r.score, 4);
  assert.equal(r.label, 'very strong');
  assert.ok(r.entropyBits >= 128);
});

test('score is always an integer within 0..4', () => {
  const samples = ['', 'a', 'abc', 'aaaa', 'password1', 'Xy9$mQ2!vZ', '4G$k9T!m2P#w7R@b5X&n3L%q8Z!v6M'];
  for (const p of samples) {
    const r = estimateStrength(p);
    assert.ok(Number.isInteger(r.score));
    assert.ok(r.score >= 0 && r.score <= 4, `score in range for ${JSON.stringify(p)}`);
  }
});

test('crackTimeSeconds increases with stronger input', () => {
  const weak = estimateStrength('abc');
  const medium = estimateStrength('Xy9$mQ2!vZ');
  const strong = estimateStrength('7xK#mQ2!vZ9pLw4Ng@Rt');
  assert.ok(medium.crackTimeSeconds > weak.crackTimeSeconds);
  assert.ok(strong.crackTimeSeconds > medium.crackTimeSeconds);
});

test('estimateStrength is pure/deterministic for the same input', () => {
  const a = estimateStrength('SomeP@ssw0rd!23xyz');
  const b = estimateStrength('SomeP@ssw0rd!23xyz');
  assert.deepEqual(a, b);
});

test('estimateStrength returns the full result shape', () => {
  const r = estimateStrength('Xy9$mQ2!vZ');
  for (const key of ['score', 'entropyBits', 'crackTimeSeconds', 'crackTimeDisplay', 'label', 'warnings', 'suggestions']) {
    assert.ok(key in r, `has key ${key}`);
  }
  assert.equal(typeof r.entropyBits, 'number');
  assert.equal(typeof r.crackTimeSeconds, 'number');
  assert.equal(typeof r.crackTimeDisplay, 'string');
  assert.ok(Array.isArray(r.warnings));
  assert.ok(Array.isArray(r.suggestions));
});
