import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  ONBOARDING_STEPS,
  _setStorage,
  loadState,
  ensureState,
  markDone,
  setDismissed,
  setWelcomed,
  progress,
  isComplete,
} from '../onboarding.js';

// Fresh in-memory storage per test (localStorage does not exist under Node).
function memStore() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}

const EMAIL = 'Ana@Ejemplo.com';

beforeEach(() => _setStorage(memStore()));

test('loadState returns null for an unseen account', () => {
  assert.equal(loadState(EMAIL), null);
});

test('ensureState creates a live guide for a new account (no vaults)', () => {
  const s = ensureState(EMAIL, { vaultCount: 0 });
  assert.equal(s.dismissed, false);
  assert.equal(s.welcomed, false);
  ONBOARDING_STEPS.forEach(step => assert.equal(s.done[step], false));
});

test('ensureState auto-dismisses for an account that already has vaults', () => {
  const s = ensureState(EMAIL, { vaultCount: 3 });
  assert.equal(s.dismissed, true);
  assert.equal(s.welcomed, true);
});

test('ensureState is idempotent: never resurrects a dismissed guide', () => {
  ensureState(EMAIL, { vaultCount: 0 });
  setDismissed(EMAIL, true);
  const s = ensureState(EMAIL, { vaultCount: 0 });
  assert.equal(s.dismissed, true);
});

test('email key is case/whitespace-insensitive', () => {
  ensureState(EMAIL, { vaultCount: 0 });
  markDone(EMAIL, 'vault');
  const s = loadState('  ana@ejemplo.com ');
  assert.equal(s.done.vault, true);
});

test('markDone marks once and reports change', () => {
  ensureState(EMAIL, { vaultCount: 0 });
  assert.equal(markDone(EMAIL, 'item'), true);
  assert.equal(markDone(EMAIL, 'item'), false); // already done
  assert.equal(loadState(EMAIL).done.item, true);
});

test('markDone rejects unknown steps', () => {
  ensureState(EMAIL, { vaultCount: 0 });
  assert.equal(markDone(EMAIL, 'nope'), false);
  assert.equal(loadState(EMAIL).done.nope, undefined);
});

test('progress and isComplete track the five steps', () => {
  const s0 = ensureState(EMAIL, { vaultCount: 0 });
  assert.deepEqual(progress(s0), { done: 0, total: 5 });
  assert.equal(isComplete(s0), false);

  ONBOARDING_STEPS.forEach(step => markDone(EMAIL, step));
  const s1 = loadState(EMAIL);
  assert.deepEqual(progress(s1), { done: 5, total: 5 });
  assert.equal(isComplete(s1), true);
});

test('setWelcomed persists and survives reloads', () => {
  ensureState(EMAIL, { vaultCount: 0 });
  setWelcomed(EMAIL);
  assert.equal(loadState(EMAIL).welcomed, true);
});

test('corrupt stored JSON degrades to null (fresh start)', () => {
  const store = memStore();
  _setStorage(store);
  store.setItem('mp-onboarding:ana@ejemplo.com', '{not json');
  assert.equal(loadState(EMAIL), null);
});

test('unknown persisted step keys are dropped, missing ones default to false', () => {
  const store = memStore();
  _setStorage(store);
  store.setItem('mp-onboarding:ana@ejemplo.com',
    JSON.stringify({ welcomed: 1, done: { vault: true, legacy: true } }));
  const s = loadState(EMAIL);
  assert.equal(s.welcomed, true);
  assert.equal(s.done.vault, true);
  assert.equal(s.done.legacy, undefined);
  assert.equal(s.done.team, false);
});
