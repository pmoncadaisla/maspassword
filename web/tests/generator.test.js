import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePassword,
  generatePassphrase,
  passwordEntropyBits,
} from '../generator.js';

test('generatePassword respects the requested length', () => {
  for (const length of [1, 4, 8, 12, 20, 64, 128]) {
    assert.equal(generatePassword({ length }).length, length);
  }
});

test('generatePassword only emits characters from enabled classes', () => {
  const lowerOnly = generatePassword({
    length: 100, upper: false, lower: true, digits: false, symbols: false,
  });
  assert.match(lowerOnly, /^[a-z]+$/);

  const digitsOnly = generatePassword({
    length: 100, upper: false, lower: false, digits: true, symbols: false,
  });
  assert.match(digitsOnly, /^[0-9]+$/);

  const upperOnly = generatePassword({
    length: 100, upper: true, lower: false, digits: false, symbols: false,
  });
  assert.match(upperOnly, /^[A-Z]+$/);

  const noSymbols = generatePassword({
    length: 200, upper: true, lower: true, digits: true, symbols: false,
  });
  assert.match(noSymbols, /^[a-zA-Z0-9]+$/);
});

test('generatePassword includes at least one char from each enabled class', () => {
  // Length comfortably larger than the number of classes.
  for (let i = 0; i < 25; i++) {
    const pw = generatePassword({ length: 12 });
    assert.match(pw, /[a-z]/, 'has lowercase');
    assert.match(pw, /[A-Z]/, 'has uppercase');
    assert.match(pw, /[0-9]/, 'has digit');
    assert.match(pw, /[^a-zA-Z0-9]/, 'has symbol');
  }
});

test('avoidAmbiguous excludes iIlL1oO0', () => {
  for (let i = 0; i < 10; i++) {
    const pw = generatePassword({ length: 200, avoidAmbiguous: true });
    assert.doesNotMatch(pw, /[iIlL1oO0]/);
  }
});

test('generatePassphrase produces the requested word count and separator', () => {
  const phrase = generatePassphrase({ words: 5, separator: '.' });
  const parts = phrase.split('.');
  assert.equal(parts.length, 5);
  for (const p of parts) assert.match(p, /^[a-z]+$/);

  const dashed = generatePassphrase({ words: 3 });
  assert.equal(dashed.split('-').length, 3);
});

test('generatePassphrase capitalize + includeNumber options work', () => {
  const phrase = generatePassphrase({
    words: 4, separator: '-', capitalize: true, includeNumber: true,
  });
  const parts = phrase.split('-');
  assert.equal(parts.length, 4);
  for (const p of parts) assert.match(p, /^[A-Z]/, 'each word title-cased');
  // Exactly one digit was appended somewhere in the phrase.
  const digits = phrase.replace(/[^0-9]/g, '');
  assert.equal(digits.length, 1);
});

test('two generations differ (randomness)', () => {
  assert.notEqual(
    generatePassword({ length: 32 }),
    generatePassword({ length: 32 }),
  );
  assert.notEqual(
    generatePassphrase({ words: 6 }),
    generatePassphrase({ words: 6 }),
  );
});

test('passwordEntropyBits is monotonic with length', () => {
  let prev = -1;
  for (const length of [4, 8, 16, 32, 64]) {
    const bits = passwordEntropyBits('a'.repeat(length));
    assert.ok(bits > prev, `entropy grows at length ${length}`);
    prev = bits;
  }
  // Larger pool at the same length yields more entropy.
  assert.ok(passwordEntropyBits('aA0$aA0$') > passwordEntropyBits('aaaaaaaa'));
});

test('generatePassword throws when no character class is enabled', () => {
  assert.throws(
    () => generatePassword({ upper: false, lower: false, digits: false, symbols: false }),
    /class/i,
  );
});
