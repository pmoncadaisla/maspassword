// onboarding.js — first-run onboarding: welcome dialog + "first steps" checklist.
//
// State is per-account and client-side only, under localStorage
// `mp-onboarding:<email>`:
//   { welcomed: bool, dismissed: bool, done: { vault, item, generator, extension, team } }
//
// New-account detection: no saved state AND zero vaults. An existing account
// seen on a new device gets an auto-dismissed state, so the guide never
// bothers users who are past it.
//
// Pure ES module, no build step, no imports: the UI helpers (t, icon) and the
// step actions are injected via initOnboarding(), which keeps this module
// runnable under Node 22 for tests (storage falls back to an in-memory Map).

export const ONBOARDING_STEPS = ['vault', 'item', 'generator', 'extension', 'team'];

const KEY_PREFIX = 'mp-onboarding:';

// --- Storage (localStorage in the browser, Map fallback under Node) ---
const memoryStore = (() => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
})();

let storage = (typeof localStorage !== 'undefined') ? localStorage : memoryStore;

// Test hook: swap the backing store (pass null to restore the default).
export function _setStorage(s) { storage = s || memoryStore; }

function storageKey(email) {
  return KEY_PREFIX + String(email || '').trim().toLowerCase();
}

function emptyState() {
  const done = {};
  ONBOARDING_STEPS.forEach(s => { done[s] = false; });
  return { welcomed: false, dismissed: false, done };
}

// --- State (pure, testable) ---
export function loadState(email) {
  try {
    const raw = storage.getItem(storageKey(email));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    // Merge over an empty state so missing/new steps default to false.
    const state = emptyState();
    state.welcomed = !!parsed.welcomed;
    state.dismissed = !!parsed.dismissed;
    ONBOARDING_STEPS.forEach(s => { state.done[s] = !!(parsed.done && parsed.done[s]); });
    return state;
  } catch {
    return null;
  }
}

export function saveState(email, state) {
  try { storage.setItem(storageKey(email), JSON.stringify(state)); } catch {}
}

// First contact for an account on this device. New accounts (no vaults yet)
// get a live guide; accounts that already have data get a dismissed one.
export function ensureState(email, { vaultCount = 0 } = {}) {
  let state = loadState(email);
  if (state) return state;
  state = emptyState();
  if (vaultCount > 0) {
    state.dismissed = true;
    state.welcomed = true;
  }
  saveState(email, state);
  return state;
}

// Mark a step done. Returns true when this call changed the state.
export function markDone(email, step) {
  if (!ONBOARDING_STEPS.includes(step)) return false;
  const state = loadState(email) || emptyState();
  if (state.done[step]) return false;
  state.done[step] = true;
  saveState(email, state);
  return true;
}

export function setDismissed(email, dismissed) {
  const state = loadState(email) || emptyState();
  state.dismissed = !!dismissed;
  saveState(email, state);
}

export function setWelcomed(email) {
  const state = loadState(email) || emptyState();
  state.welcomed = true;
  saveState(email, state);
}

export function progress(state) {
  const done = ONBOARDING_STEPS.filter(s => state.done[s]).length;
  return { done, total: ONBOARDING_STEPS.length };
}

export function isComplete(state) {
  return ONBOARDING_STEPS.every(s => state.done[s]);
}

// --- UI (browser only) ---
// initOnboarding wires everything for the logged-in account:
//   email       account email (state key)
//   vaultCount  number of vaults right after login (new-account detection)
//   teamCount   number of teams (auto-completes the team step)
//   deps        { t, icon } from i18n.js / icons.js
//   actions     { vault, item, generator, extension, team } click handlers
let ctx = null;

const STEP_ICONS = { vault: 'vault', item: 'key', generator: 'sparkles', extension: 'download', team: 'team' };

export function initOnboarding({ email, vaultCount = 0, teamCount = 0, deps, actions }) {
  ctx = { email, deps, actions };
  const state = ensureState(email, { vaultCount });
  // Auto-complete what the account already has (e.g. created elsewhere).
  if (vaultCount > 0) markDone(email, 'vault');
  if (teamCount > 0) markDone(email, 'team');
  renderOnboardingCard();
  return state;
}

// Mark a step from app code (vault created, item saved, ...) and re-render.
export function onboardingStepDone(step) {
  if (!ctx) return;
  if (markDone(ctx.email, step)) renderOnboardingCard();
}

// Whether the welcome dialog should open for this account, marking it shown.
export function shouldShowWelcome() {
  if (!ctx) return false;
  const state = loadState(ctx.email);
  if (!state || state.welcomed || state.dismissed) return false;
  setWelcomed(ctx.email);
  return true;
}

export function dismissOnboarding() {
  if (!ctx) return;
  setDismissed(ctx.email, true);
  renderOnboardingCard();
}

export function renderOnboardingCard() {
  const card = document.getElementById('onboarding-card');
  if (!card || !ctx) return;
  const { t, icon } = ctx.deps;
  const state = loadState(ctx.email);

  if (!state || state.dismissed) {
    card.style.display = 'none';
    card.innerHTML = '';
    return;
  }

  const { done, total } = progress(state);
  const pct = Math.round((done / total) * 100);

  const rows = ONBOARDING_STEPS.map(step => `
    <button class="onboarding-step${state.done[step] ? ' done' : ''}" data-step="${step}">
      <span class="onboarding-check">${state.done[step] ? icon('check', { size: 12 }) : ''}</span>
      <span class="onboarding-step-icon">${icon(STEP_ICONS[step], { size: 14 })}</span>
      <span class="onboarding-step-label">${t('onboarding.step.' + step)}</span>
    </button>`).join('');

  card.innerHTML = `
    <div class="onboarding-head">
      <span class="onboarding-title">${t('onboarding.title')}</span>
      <span class="onboarding-count">${t('onboarding.progress', { done, total })}</span>
      <button class="onboarding-close" id="onboarding-dismiss" title="${t('onboarding.dismiss')}" aria-label="${t('onboarding.dismiss')}">${icon('x', { size: 13 })}</button>
    </div>
    <div class="onboarding-bar"><div class="onboarding-bar-fill" style="width:${pct}%"></div></div>
    ${isComplete(state) ? `<p class="onboarding-complete">${t('onboarding.complete')}</p>` : rows}
  `;
  card.style.display = 'block';

  card.querySelector('#onboarding-dismiss').addEventListener('click', dismissOnboarding);
  card.querySelectorAll('.onboarding-step').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = ctx.actions[btn.dataset.step];
      if (action) action();
    });
  });
}
