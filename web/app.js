import { SRPClient, generateVerifier } from '/srp.js';
import { deriveKey, encrypt, decrypt, generatePassword, generateKeyPair, encryptPrivateKey, decryptPrivateKey, encryptWithPublicKey, decryptWithPrivateKey, generateVaultKey, importVaultKey, generateTOTP, generateRecoveryKey, deriveRecoveryKey } from '/crypto.js';
import { generatePassword as genAdvanced, generatePassphrase, passwordEntropyBits } from '/generator.js';
import { estimateStrength } from '/strength.js';
import { checkPwnedCount } from '/breach.js';
import { detectFormatAndParse } from '/import.js';
import { initI18n, getLocale, setLocale, t, applyI18n, LOCALES } from '/i18n.js';
import { icon, faviconUrl } from '/icons.js';
import { MAX_ATTACHMENTS, fileToAttachment, attachmentDataUrl, formatSize } from '/attachments.js';
import { createSharePayload, decryptSharePayload, buildShareUrl, parseShareHash } from '/sharelink.js';
import { findDuplicateGroups } from '/duplicates.js';
import { qrSvg } from '/qr.js';

// --- Item types (1Password-style) ---
// Labels are resolved lazily through t() so they follow the active locale.
// `icon` is a flat SVG icon name from icons.js (rendered via icon()).
const ITEM_TYPES = {
  login:    { icon: 'key' },
  card:     { icon: 'card' },
  note:     { icon: 'note' },
  identity: { icon: 'identity' },
};
function itemType(data) { return ITEM_TYPES[data?.type] ? data.type : 'login'; }
function typeLabel(type) { return t('type.' + (ITEM_TYPES[type] ? type : 'login')); }
function typeIconHtml(type, size = 16) { return icon(ITEM_TYPES[ITEM_TYPES[type] ? type : 'login'].icon, { size }); }

// --- State ---
let token = null;
let encKey = null;
let privateKey = null;
let vaults = [];
let currentVault = null;
let items = [];
let currentItem = null;
let editingItem = null;
let teams = [];
let currentTeam = null;
let vaultKeyCache = {};
let totpInterval = null;
let searchQuery = '';
let sidebarMode = 'vaults'; // 'vaults' or 'team'
let decryptedItemsCache = []; // cache of { id, data } for search
let pendingRoute = null; // route to navigate to after login
let navigating = false; // prevent recursive route handling
let iapMode = false; // true when IAP authentication is active
let iapSession = null; // session info from /api/auth/session
let activeTag = null; // tag filter in the item list
let lockContext = null; // { email, encryptedPrivateKey } — lets us re-unlock without a full re-login
let autoLockTimer = null; // inactivity timer handle
let autoLockMinutes = Number(localStorage.getItem('mp-autolock') || 10); // 0 = disabled
let appVersion = ''; // server version from /auth/mode
let vaultSharesCache = {}; // vaultId -> { at, teams: [{team_id,team_name,shared_at}] }
let formAttachments = []; // attachments being edited in the item form (plaintext, in-memory only)
let historyEntries = []; // decrypted history entries for the open history modal
let globalIndex = null; // decrypted cross-vault index for the sidebar global search
let globalIndexAt = 0; // timestamp of globalIndex (cached ~60s)

// --- API ---
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = res.status !== 204 ? await res.json().catch(() => null) : null;
  if (!res.ok) {
    const err = new Error(data?.error?.message || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// --- Navigation ---
function showAuthScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + id).classList.add('active');
  document.getElementById('main-app').style.display = 'none';
  setHash('/' + id);
}

// Show a screen WITHOUT touching the hash (used by the share-link recipient
// screen, where the fragment carries the decryption key and must be preserved).
function showScreenNoHash(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + id).classList.add('active');
  document.getElementById('main-app').style.display = 'none';
}

function showMainApp() {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('main-app').style.display = 'grid';
  refreshAdminUI(); // fire-and-forget: toggles the admin-only sidebar button
}

// --- Routing ---
function setHash(hash) {
  navigating = true;
  location.hash = hash;
  // navigating flag is reset after the hashchange event fires
  setTimeout(() => { navigating = false; }, 0);
}

function currentHash() {
  return location.hash.replace(/^#\/?/, '/');
}

async function handleRoute() {
  // One-time share links come BEFORE any auth check: recipients don't need an
  // account. The decryption key lives only in the fragment and never leaves
  // the browser.
  const share = parseShareHash(location.hash);
  if (share) {
    await renderShareOpen(share);
    return;
  }

  if (navigating) return;
  const hash = currentHash();

  // Locked: keep the lock screen no matter where the hash points.
  // (token is still valid; only the in-memory keys were wiped.)
  if (token && lockContext && !encKey) {
    document.getElementById('lock-email').textContent = lockContext.email || '';
    showAuthScreen('lock');
    return;
  }

  // Auth routes (always accessible)
  if (hash === '/signup') {
    if (token) return; // already logged in, ignore
    showAuthScreen('signup');
    return;
  }
  if (hash === '/recover') {
    if (token) return;
    showAuthScreen('recover');
    return;
  }

  // Not logged in — save route for after login
  if (!token) {
    if (hash !== '/' && hash !== '/login') {
      pendingRoute = location.hash;
    }
    showAuthScreen('login');
    return;
  }

  // Logged in routes
  if (hash === '/login' || hash === '/signup') {
    // Already logged in, go to root
    setHash('/');
    return;
  }

  // Ensure data is loaded
  if (!vaults.length && !teams.length) {
    await Promise.all([loadVaults(), loadTeams()]);
    renderSidebar();
  }

  // Parse route
  const vaultItemMatch = hash.match(/^\/vault\/([^/]+)\/item\/([^/]+)$/);
  const vaultMatch = hash.match(/^\/vault\/([^/]+)$/);
  const teamMatch = hash.match(/^\/team\/([^/]+)$/);

  if (vaultItemMatch) {
    const [, vaultId, itemId] = vaultItemMatch;
    await navigateToVault(vaultId);
    await navigateToItem(itemId);
  } else if (vaultMatch) {
    const [, vaultId] = vaultMatch;
    await navigateToVault(vaultId);
  } else if (teamMatch) {
    const [, teamId] = teamMatch;
    await navigateToTeam(teamId);
  } else {
    // Root or unknown — show main app, no selection
    showMainApp();
  }
}

async function navigateToVault(vaultId) {
  // Ensure the vault exists in our list
  let vault = vaults.find(v => v.id === vaultId);
  if (!vault) {
    // Maybe it's a team vault not yet in the list — reload
    await loadVaults();
    renderSidebar();
    vault = vaults.find(v => v.id === vaultId);
  }
  if (!vault) {
    toast(t('vault.notFound'), true);
    setHash('/');
    return;
  }

  // Only reload if switching vaults
  if (!currentVault || currentVault.id !== vaultId) {
    currentVault = vault;
    currentTeam = null;
    sidebarMode = 'vaults';
    currentItem = null;
    stopTOTP();

    document.getElementById('team-detail-panel').style.display = 'none';
    document.getElementById('item-list').style.display = 'flex';
    document.getElementById('item-list-actions').style.display = 'flex';

    showMainApp();
    await loadItems();
    renderSidebar();
    showDetailEmpty();
    closeMobileSidebar();
    // Lazily fetch which teams this vault is shared with (renders chips under the header).
    loadVaultShares(vault);
  }
}

async function navigateToItem(itemId) {
  if (!currentVault) return;

  // Items should already be loaded by navigateToVault
  const item = items.find(i => i.id === itemId);
  if (!item) {
    toast(t('toast.itemNotFound'), true);
    setHash(`/vault/${currentVault.id}`);
    return;
  }

  await openItemDirect(itemId);
}

async function navigateToTeam(teamId) {
  let team = teams.find(tm => tm.id === teamId);
  if (!team) {
    await loadTeams();
    renderSidebar();
    team = teams.find(tm => tm.id === teamId);
  }
  if (!team) {
    toast(t('teams.notFound'), true);
    setHash('/');
    return;
  }

  if (!currentTeam || currentTeam.id !== teamId) {
    currentTeam = team;
    currentVault = null;
    currentItem = null;
    sidebarMode = 'team';
    stopTOTP();

    document.getElementById('item-list').style.display = 'none';
    document.getElementById('items-empty').style.display = 'none';
    document.getElementById('item-list-actions').style.display = 'none';
    document.getElementById('team-detail-panel').style.display = 'block';
    document.getElementById('vault-shares').style.display = 'none';
    document.getElementById('tag-bar').style.display = 'none';

    showMainApp();
    await Promise.all([loadTeamMembers(), loadTeamVaults()]);
    renderSidebar();
    showDetailEmpty();
    closeMobileSidebar();
    // Process pending vault keys in background (admin only)
    processPendingVaultKeys();
  }
}

// --- Toast ---
function toast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show' + (isError ? ' error' : '');
  setTimeout(() => el.className = 'toast', 2500);
}

// --- Vault decryption key helper ---
async function getVaultDecryptionKey(vault) {
  if (!vault.team_id) {
    return encKey;
  }
  if (vaultKeyCache[vault.id]) {
    return vaultKeyCache[vault.id];
  }
  const resp = await api('GET', `/api/vaults/${vault.id}/key`);
  const vaultKeyBase64 = await decryptWithPrivateKey(privateKey, resp.encrypted_vault_key);
  const vaultCryptoKey = await importVaultKey(vaultKeyBase64);
  vaultKeyCache[vault.id] = vaultCryptoKey;
  return vaultCryptoKey;
}

// --- Auth ---
async function signup() {
  const email = document.getElementById('signup-email').value.trim();
  const pw = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;

  if (!email || !pw) return toast(t('toast.fillAllFields'), true);
  if (pw !== confirm) return toast(t('toast.passwordsMismatch'), true);
  if (pw.length < 8) return toast(t('toast.passwordTooShort'), true);

  const btn = document.getElementById('btn-signup');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    const { verifier, salt } = generateVerifier(email, pw);
    const derivedKey = await deriveKey(pw, email);
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
    const encryptedPrivKey = await encryptPrivateKey(derivedKey, privateKeyJwk);

    // Generate recovery key and encrypt private key with it
    const recoveryKey = generateRecoveryKey();
    const recoveryAesKey = await deriveRecoveryKey(recoveryKey, email);
    const recoveryEncPrivKey = await encrypt(recoveryAesKey, JSON.stringify(privateKeyJwk));

    await api('POST', '/auth/signup', {
      email,
      srp_salt: salt,
      srp_verifier: verifier,
      public_key: JSON.stringify(publicKeyJwk),
      encrypted_private_key: encryptedPrivKey,
      recovery_encrypted_private_key: recoveryEncPrivKey,
    });
    toast(t('toast.accountCreated'));
    showRecoveryKeyScreen(recoveryKey, () => {
      showAuthScreen('login');
      document.getElementById('login-email').value = email;
    });
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = t('auth.signup.title');
  }
}

async function login() {
  const email = document.getElementById('login-email').value.trim();
  const pw = document.getElementById('login-password').value;
  if (!email || !pw) return toast(t('toast.fillAllFields'), true);

  const btn = document.getElementById('btn-login');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    const client = new SRPClient(email, pw);
    const creds = client.credentials();
    const step1 = await api('POST', '/auth/login/step1', { email, client_public: creds });

    const clientProof = client.generate(step1.server_public);
    const step2 = await api('POST', '/auth/login/step2', {
      session_id: step1.session_id,
      client_proof: clientProof,
    });

    if (!client.serverOk(step2.server_proof)) {
      throw new Error('Server verification failed');
    }

    token = step2.token;
    encKey = await deriveKey(pw, email);

    let lockEncPrivKey;
    if (step2.encrypted_private_key) {
      lockEncPrivKey = step2.encrypted_private_key;
      privateKey = await decryptPrivateKey(encKey, step2.encrypted_private_key);
    } else {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
      const encryptedPrivKey = await encryptPrivateKey(encKey, privateKeyJwk);
      await api('POST', '/api/users/keys', {
        public_key: JSON.stringify(publicKeyJwk),
        encrypted_private_key: encryptedPrivKey,
      });
      lockEncPrivKey = encryptedPrivKey;
      privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    lockContext = { email, encryptedPrivateKey: lockEncPrivKey };
    sessionStorage.setItem('token', token);
    startAutoLock();
    toast(t('toast.loggedIn'));
    await Promise.all([loadVaults(), loadTeams()]);

    // Navigate to pending route or show main app
    if (pendingRoute) {
      const route = pendingRoute;
      pendingRoute = null;
      location.hash = route;
      await handleRoute();
    } else {
      showMainApp();
      renderSidebar();
      setHash('/');
    }
  } catch (e) {
    toast(t('toast.loginFailed', { error: e.message }), true);
  } finally {
    btn.disabled = false;
    btn.textContent = t('auth.login');
  }
}

function logout() {
  token = null;
  encKey = null;
  privateKey = null;
  vaults = [];
  items = [];
  teams = [];
  currentVault = null;
  currentItem = null;
  currentTeam = null;
  vaultKeyCache = {};
  decryptedItemsCache = [];
  pendingRoute = null;
  activeTag = null;
  lockContext = null;
  vaultSharesCache = {};
  historyEntries = [];
  wipePlaintextCaches();
  stopAutoLock();
  stopTOTP();
  sessionStorage.clear();
  document.getElementById('login-password').value = '';
  iapSession = null;
  closeCmdPalette();
  showAuthScreen('login');
}

// --- Auto-lock (locks the vault after inactivity; re-unlock needs only the master password) ---
function startAutoLock() {
  stopAutoLock();
  if (!autoLockMinutes || autoLockMinutes <= 0) return;
  const reset = () => {
    clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(lockVault, autoLockMinutes * 60 * 1000);
  };
  startAutoLock._reset = reset;
  ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(evt =>
    document.addEventListener(evt, reset, { passive: true }));
  reset();
}

function stopAutoLock() {
  clearTimeout(autoLockTimer);
  autoLockTimer = null;
  if (startAutoLock._reset) {
    ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(evt =>
      document.removeEventListener(evt, startAutoLock._reset));
    startAutoLock._reset = null;
  }
}

// Wipe every in-memory plaintext cache (global search index, palette index,
// strength memo). Called on lock and logout.
function wipePlaintextCaches() {
  globalIndex = null;
  globalIndexAt = 0;
  cmdIndex = [];
  cmdList = [];
  _strengthMemo.clear();
  hideGlobalSearch(true);
}

// Lock: wipe decryption keys and plaintext caches from memory, show the lock screen.
// The JWT session token is preserved so unlocking is a local key re-derivation.
function lockVault() {
  if (!lockContext) return; // nothing to lock
  encKey = null;
  privateKey = null;
  vaultKeyCache = {};
  decryptedItemsCache = [];
  currentItem = null;
  historyEntries = [];
  wipePlaintextCaches();
  stopAutoLock();
  stopTOTP();
  closeCmdPalette();
  // Dismiss any open overlay (item form, watchtower, generator, history) so it
  // can't float over the lock screen with plaintext still visible.
  document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
  // Scrub decrypted plaintext out of the (about-to-be-hidden) DOM — item titles,
  // usernames, revealed passwords, breach results, tag chips, history entries,
  // attachments and share metadata.
  ['item-list', 'detail-fields', 'detail-meta', 'detail-breach-result', 'tag-bar',
   'history-body', 'share-links-list', 'vault-shares', 'detail-item-icon',
   'custom-fields-list', 'item-attachments-list', 'device-qr-result', 'device-list']
    .forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
  formAttachments = [];
  FORM_FIELDS.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  const extras = document.getElementById('detail-extras');
  if (extras) extras.style.display = 'none';
  const search = document.getElementById('search-input');
  if (search) search.value = '';
  showDetailEmpty();
  document.getElementById('lock-email').textContent = lockContext.email || '';
  document.getElementById('lock-password').value = '';
  showAuthScreen('lock');
}

async function unlockVault() {
  const pw = document.getElementById('lock-password').value;
  if (!pw || !lockContext) return;
  const btn = document.getElementById('btn-unlock');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';
  try {
    const k = await deriveKey(pw, lockContext.email);
    // Verify by decrypting the private key; also restore it for shared-vault access.
    privateKey = await decryptPrivateKey(k, lockContext.encryptedPrivateKey);
    encKey = k;
    startAutoLock();
    showMainApp();
    renderSidebar();
    // Re-render whatever was open and restore the route off of /lock.
    if (currentVault) {
      await loadItems();
      loadVaultShares(currentVault);
      setHash(`/vault/${currentVault.id}`);
    }
    else setHash('/');
    toast(t('toast.unlocked'));
    document.getElementById('lock-password').value = '';
  } catch {
    toast(t('toast.wrongMasterPassword'), true);
    encKey = null;
    privateKey = null;
  } finally {
    btn.disabled = false;
    btn.textContent = t('auth.unlock');
  }
}

// --- Theme (light / dark) ---
function currentTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}
function applyTheme(theme) {
  if (theme === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  else document.documentElement.removeAttribute('data-theme');
  try { localStorage.setItem('mp-theme', theme); } catch {}
  updateMetaThemeColor();
  const btn = document.getElementById('btn-theme');
  if (btn) btn.innerHTML = theme === 'dark'
    ? `${icon('sun', { size: 15 })} <span>${esc(t('sidebar.lightMode'))}</span>`
    : `${icon('moon', { size: 15 })} <span>${esc(t('sidebar.darkMode'))}</span>`;
}
function toggleTheme() {
  applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
}

// --- Skin (user-selectable visual theme) ---
// Two independent dimensions on <html>: data-skin ("orange" or absent = Light)
// and data-theme (dark mode). The Orange skin implements the Orange Design
// System and supports both modes.
// Resolution order: localStorage 'mp-skin' (user choice) → 'mp-skin-default'
// (instance default, cached from every /auth/mode fetch) → 'light'.
const SKINS = ['light', 'orange'];

function currentSkin() {
  return document.documentElement.getAttribute('data-skin') === 'orange' ? 'orange' : 'light';
}

// The PWA chrome color follows both the active skin and the dark mode.
function updateMetaThemeColor() {
  const meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) return;
  const dark = currentTheme() === 'dark';
  meta.setAttribute('content', currentSkin() === 'orange'
    ? (dark ? '#141414' : '#ffffff')
    : (dark ? '#0b0e14' : '#fafbfc'));
}

// Applies a skin WITHOUT persisting it (used for the instance default so the
// user's lack-of-choice keeps following the admin-configured default).
function setSkinAttr(skin) {
  if (skin === 'orange') document.documentElement.setAttribute('data-skin', 'orange');
  else document.documentElement.removeAttribute('data-skin');
  updateMetaThemeColor();
  const sel = document.getElementById('skin-select');
  if (sel) sel.value = currentSkin();
}

// Applies AND persists the user's own skin choice.
function applySkin(skin) {
  if (!SKINS.includes(skin)) skin = 'light';
  setSkinAttr(skin);
  try { localStorage.setItem('mp-skin', skin); } catch {}
}

// Caches the instance-wide default theme (from /auth/mode or an admin save)
// and applies it when the user has not made an explicit choice.
function rememberDefaultSkin(value) {
  const dt = value === 'orange' ? 'orange' : 'light';
  try {
    localStorage.setItem('mp-skin-default', dt);
    if (!localStorage.getItem('mp-skin')) setSkinAttr(dt);
  } catch {}
}

// --- Global settings (admin-only panel) ---
let adminUIToken = null; // token the admin-button visibility was resolved for

// Shows the "Global Settings" sidebar button only when the session is an
// admin (ADMIN_EMAILS server-side). Resolved once per token.
async function refreshAdminUI() {
  const btn = document.getElementById('btn-global-settings');
  if (!btn) return;
  if (!token) { btn.style.display = 'none'; adminUIToken = null; return; }
  if (adminUIToken === token) return;
  adminUIToken = token;
  let isAdmin = false;
  try {
    if (iapSession) {
      isAdmin = iapSession.is_admin === true;
    } else {
      const s = await api('GET', '/api/auth/session');
      isAdmin = s?.is_admin === true;
    }
  } catch {}
  btn.style.display = isAdmin ? '' : 'none';
}

async function openGlobalSettings() {
  const sel = document.getElementById('global-default-theme');
  // Prefill from the cached default, then refresh from the server.
  sel.value = localStorage.getItem('mp-skin-default') === 'orange' ? 'orange' : 'light';
  openModal('modal-global-settings');
  try {
    const s = await api('GET', '/api/admin/settings');
    sel.value = s?.default_theme === 'orange' ? 'orange' : 'light';
  } catch (e) {
    toast(e.message, true);
  }
}

async function saveGlobalSettings() {
  const sel = document.getElementById('global-default-theme');
  const btn = document.getElementById('btn-save-global-settings');
  btn.disabled = true;
  try {
    const saved = await api('PUT', '/api/admin/settings', { default_theme: sel.value });
    rememberDefaultSkin(saved?.default_theme);
    toast(t('toast.saved'));
    closeModal('modal-global-settings');
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
  }
}

// --- Password generator popover ---
// Reads options from the generator UI and produces a password or passphrase.
function readGenOptions() {
  const mode = document.querySelector('input[name="gen-mode"]:checked')?.value || 'password';
  return {
    mode,
    length: Number(document.getElementById('gen-length').value),
    words: Number(document.getElementById('gen-words').value),
    upper: document.getElementById('gen-upper').checked,
    lower: document.getElementById('gen-lower').checked,
    digits: document.getElementById('gen-digits').checked,
    symbols: document.getElementById('gen-symbols').checked,
    avoidAmbiguous: document.getElementById('gen-avoid').checked,
    capitalize: document.getElementById('gen-cap').checked,
    includeNumber: document.getElementById('gen-num').checked,
  };
}

function generateFromOptions() {
  const o = readGenOptions();
  try {
    if (o.mode === 'passphrase') {
      return generatePassphrase({ words: o.words, separator: '-', capitalize: o.capitalize, includeNumber: o.includeNumber });
    }
    return genAdvanced({ length: o.length, upper: o.upper, lower: o.lower, digits: o.digits, symbols: o.symbols, avoidAmbiguous: o.avoidAmbiguous });
  } catch (e) {
    toast(e.message, true);
    return '';
  }
}

function refreshGenerator() {
  const o = readGenOptions();
  document.getElementById('gen-password-controls').style.display = o.mode === 'passphrase' ? 'none' : 'block';
  document.getElementById('gen-passphrase-controls').style.display = o.mode === 'passphrase' ? 'block' : 'none';
  document.getElementById('gen-length-label').textContent = o.length;
  document.getElementById('gen-words-label').textContent = o.words;
  const pw = generateFromOptions();
  const out = document.getElementById('gen-output');
  if (out) out.textContent = pw;
  renderStrengthInto('gen-strength', pw);
  return pw;
}

// --- Password strength meter ---
const STRENGTH_KEYS = ['strength.veryWeak', 'strength.weak', 'strength.fair', 'strength.strong', 'strength.veryStrong'];

function renderStrengthInto(containerId, password) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!password) { el.innerHTML = ''; return; }
  const s = estimateStrength(password);
  const pct = Math.max(6, Math.round((s.score + 1) / 5 * 100));
  const cls = ['vw', 'w', 'f', 's', 'vs'][s.score] || 'w';
  const detail = s.crackTimeDisplay ? `· ${esc(t('strength.cracksIn', { time: s.crackTimeDisplay }))}` : '';
  el.innerHTML = `
    <div class="strength-bar"><div class="strength-fill strength-${cls}" style="width:${pct}%"></div></div>
    <div class="strength-label">${esc(t(STRENGTH_KEYS[s.score] || STRENGTH_KEYS[1]))} <span class="strength-detail">${esc(t('strength.bits', { bits: Math.round(s.entropyBits) }))} ${detail}</span></div>`;
}

// Memoized strength score used for the per-row weak-password badge.
const _strengthMemo = new Map();
function strengthScore(pw) {
  if (_strengthMemo.has(pw)) return _strengthMemo.get(pw);
  let score = 4;
  try { score = estimateStrength(pw).score; } catch {}
  if (_strengthMemo.size > 500) _strengthMemo.clear();
  _strengthMemo.set(pw, score);
  return score;
}

// --- Version ---
function renderVersion() {
  const label = appVersion ? `MasPassword ${appVersion}` : 'MasPassword';
  ['app-version-login', 'app-version-sidebar', 'app-version-share'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = label;
  });
}

// --- Relative time ("hace 5 min") in the active locale ---
function formatRelative(ts) {
  const time = new Date(ts).getTime();
  if (!isFinite(time)) return '';
  const diff = time - Date.now();
  let rtf;
  try { rtf = new Intl.RelativeTimeFormat(getLocale(), { numeric: 'auto' }); }
  catch { rtf = new Intl.RelativeTimeFormat('es', { numeric: 'auto' }); }
  const abs = Math.abs(diff);
  const MIN = 60e3, HOUR = 3600e3, DAY = 86400e3;
  if (abs < 45e3) return rtf.format(Math.round(diff / 1e3), 'second');
  if (abs < 45 * MIN) return rtf.format(Math.round(diff / MIN), 'minute');
  if (abs < 22 * HOUR) return rtf.format(Math.round(diff / HOUR), 'hour');
  if (abs < 26 * DAY) return rtf.format(Math.round(diff / DAY), 'day');
  if (abs < 335 * DAY) return rtf.format(Math.round(diff / (30 * DAY)), 'month');
  return rtf.format(Math.round(diff / (365 * DAY)), 'year');
}

// --- IAP Authentication ---
async function detectAuthMode() {
  try {
    const res = await fetch('/auth/mode');
    const data = await res.json();
    appVersion = data.version || '';
    renderVersion();
    rememberDefaultSkin(data.default_theme);
    return data.iap_enabled === true;
  } catch {
    return false;
  }
}

async function initIAPSession() {
  try {
    const res = await fetch('/api/auth/session');
    if (!res.ok) return false;
    iapSession = await res.json();
    token = iapSession.token;
    sessionStorage.setItem('token', token);

    if (iapSession.encryption_setup) {
      // Encryption already set up — show unlock screen
      showAuthScreen('iap-unlock');
      document.getElementById('iap-unlock-email').textContent = iapSession.email;
    } else {
      // First time — show setup screen
      showAuthScreen('iap-setup');
      document.getElementById('iap-setup-email').textContent = iapSession.email;
    }
    return true;
  } catch {
    return false;
  }
}

async function iapUnlock() {
  const pw = document.getElementById('iap-unlock-password').value;
  if (!pw) return toast(t('toast.enterMasterPassword'), true);

  const btn = document.getElementById('btn-iap-unlock');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    encKey = await deriveKey(pw, iapSession.email);

    // Try to decrypt private key to verify password
    privateKey = await decryptPrivateKey(encKey, iapSession.encrypted_private_key);

    lockContext = { email: iapSession.email, encryptedPrivateKey: iapSession.encrypted_private_key };
    startAutoLock();
    toast(t('toast.unlocked'));
    await Promise.all([loadVaults(), loadTeams()]);
    showMainApp();
    renderSidebar();
    setHash('/');
  } catch (e) {
    toast(t('toast.wrongMasterPassword'), true);
    encKey = null;
    privateKey = null;
  } finally {
    btn.disabled = false;
    btn.textContent = t('auth.unlock');
  }
}

async function iapSetup() {
  const pw = document.getElementById('iap-setup-password').value;
  const confirm = document.getElementById('iap-setup-confirm').value;

  if (!pw) return toast(t('toast.enterMasterPassword'), true);
  if (pw !== confirm) return toast(t('toast.passwordsMismatch'), true);
  if (pw.length < 8) return toast(t('toast.passwordTooShort'), true);

  const btn = document.getElementById('btn-iap-setup');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    encKey = await deriveKey(pw, iapSession.email);

    // Generate RSA keypair
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
    const encryptedPrivKey = await encryptPrivateKey(encKey, privateKeyJwk);

    // Generate SRP verifier for future SRP login
    const { verifier, salt } = generateVerifier(iapSession.email, pw);

    // Generate recovery key and encrypt private key with it
    const recoveryKey = generateRecoveryKey();
    const recoveryAesKey = await deriveRecoveryKey(recoveryKey, iapSession.email);
    const recoveryEncPrivKey = await encrypt(recoveryAesKey, JSON.stringify(privateKeyJwk));

    // Send setup to server
    await api('POST', '/api/auth/setup-encryption', {
      srp_salt: salt,
      srp_verifier: verifier,
      public_key: JSON.stringify(publicKeyJwk),
      encrypted_private_key: encryptedPrivKey,
      recovery_encrypted_private_key: recoveryEncPrivKey,
    });

    // Import private key for use
    privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);

    lockContext = { email: iapSession.email, encryptedPrivateKey: encryptedPrivKey };
    startAutoLock();
    toast(t('toast.encryptionSetup'));
    await Promise.all([loadVaults(), loadTeams()]);

    showRecoveryKeyScreen(recoveryKey, () => {
      showMainApp();
      renderSidebar();
      setHash('/');
    });
  } catch (e) {
    toast(t('toast.setupFailed', { error: e.message }), true);
  } finally {
    btn.disabled = false;
    btn.textContent = t('auth.iap.setupTitle');
  }
}

// --- Recovery Key ---
let recoveryKeyContinueCallback = null;

function showRecoveryKeyScreen(recoveryKey, onContinue) {
  document.getElementById('recovery-key-display').textContent = recoveryKey;
  document.getElementById('recovery-key-saved-checkbox').checked = false;
  document.getElementById('btn-recovery-key-continue').disabled = true;
  recoveryKeyContinueCallback = onContinue;
  showAuthScreen('show-recovery-key');
}

async function recover() {
  const email = document.getElementById('recover-email').value.trim();
  const recoveryKeyInput = document.getElementById('recover-key').value.trim();
  const pw = document.getElementById('recover-password').value;
  const confirm = document.getElementById('recover-confirm').value;

  if (!email || !recoveryKeyInput || !pw) return toast(t('toast.fillAllFields'), true);
  if (pw !== confirm) return toast(t('toast.passwordsMismatch'), true);
  if (pw.length < 8) return toast(t('toast.passwordTooShort'), true);

  const btn = document.getElementById('btn-recover');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    // 1. Get recovery data from server
    const recoveryData = await api('GET', `/auth/recovery/${encodeURIComponent(email)}`);

    // 2. Derive recovery AES key and decrypt private key
    const recoveryAesKey = await deriveRecoveryKey(recoveryKeyInput, email);
    let privateKeyJwk;
    try {
      const json = await decrypt(recoveryAesKey, recoveryData.recovery_encrypted_private_key);
      privateKeyJwk = JSON.parse(json);
    } catch {
      throw new Error(t('toast.invalidRecoveryKey'));
    }

    // 2b. Prove possession of the recovery key to the server: decrypt a nonce the
    // server encrypts to our stored public key. Without this the server would reset
    // credentials for any email (account takeover).
    const recoveryPrivKey = await crypto.subtle.importKey(
      'jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
    );
    const challenge = await api('POST', '/auth/recover/challenge', { email });
    const nonce = await decryptWithPrivateKey(recoveryPrivKey, challenge.encrypted_nonce);

    // 3. Re-encrypt private key with new master password
    const newEncKey = await deriveKey(pw, email);
    const newEncryptedPrivKey = await encryptPrivateKey(newEncKey, privateKeyJwk);

    // 4. Generate new SRP verifier
    const { verifier, salt } = generateVerifier(email, pw);

    // 5. Generate new recovery key and encrypt private key with it
    const newRecoveryKey = generateRecoveryKey();
    const newRecoveryAesKey = await deriveRecoveryKey(newRecoveryKey, email);
    const newRecoveryEncPrivKey = await encrypt(newRecoveryAesKey, JSON.stringify(privateKeyJwk));

    // 6. Send recovery request (with proof-of-possession from step 2b)
    await api('POST', '/auth/recover', {
      email,
      challenge_id: challenge.challenge_id,
      nonce,
      srp_salt: salt,
      srp_verifier: verifier,
      encrypted_private_key: newEncryptedPrivKey,
      recovery_encrypted_private_key: newRecoveryEncPrivKey,
    });

    toast(t('toast.passwordResetSuccess'));
    showRecoveryKeyScreen(newRecoveryKey, () => {
      showAuthScreen('login');
      document.getElementById('login-email').value = email;
    });
  } catch (e) {
    toast(t('toast.recoveryFailed', { error: e.message }), true);
  } finally {
    btn.disabled = false;
    btn.textContent = t('recover.submit');
  }
}

// --- Sidebar ---
async function renderSidebar() {
  const vaultList = document.getElementById('sidebar-vault-list');
  const teamList = document.getElementById('sidebar-team-list');

  // Render vaults
  const vaultCards = [];
  for (const v of vaults) {
    let name = 'Vault';
    try {
      const key = await getVaultDecryptionKey(v);
      name = await decrypt(key, v.name_encrypted);
    } catch {}
    const sharedBadge = v.team_id ? `<span class="badge-shared" title="${escAttr(t('vault.shared'))}">${icon('users', { size: 12 })}</span>` : '';
    const activeClass = currentVault && currentVault.id === v.id && sidebarMode === 'vaults' ? ' active' : '';
    vaultCards.push(`<button class="sidebar-item${activeClass}" data-vault-id="${v.id}">
      <span class="sidebar-item-icon">${icon('vault', { size: 16 })}</span>
      <span class="sidebar-item-name">${esc(name)}</span>
      ${sharedBadge}
    </button>`);
  }
  vaultList.innerHTML = vaultCards.join('');
  vaultList.querySelectorAll('.sidebar-item').forEach(btn => {
    btn.addEventListener('click', () => selectVault(btn.dataset.vaultId));
  });

  // Render teams
  const teamCards = teams.map(tm => {
    const activeClass = currentTeam && currentTeam.id === tm.id && sidebarMode === 'team' ? ' active' : '';
    return `<button class="sidebar-item${activeClass}" data-team-id="${tm.id}">
      <span class="sidebar-item-icon">${icon('users', { size: 16 })}</span>
      <span class="sidebar-item-name">${esc(tm.name)}</span>
    </button>`;
  }).join('');
  teamList.innerHTML = teamCards;
  teamList.querySelectorAll('.sidebar-item').forEach(btn => {
    btn.addEventListener('click', () => selectTeam(btn.dataset.teamId));
  });
}

async function selectVault(id) {
  setHash(`/vault/${id}`);
  await navigateToVault(id);
}

async function selectTeam(id) {
  setHash(`/team/${id}`);
  await navigateToTeam(id);
}

// --- Vaults ---
async function loadVaults() {
  vaults = (await api('GET', '/api/vaults')) || [];
}

async function createVault() {
  const nameInput = document.getElementById('vault-name-input');
  const name = nameInput.value.trim();
  if (!name) return toast(t('toast.enterName'), true);

  try {
    const nameEnc = await encrypt(encKey, name);
    const newVault = await api('POST', '/api/vaults', { name_encrypted: nameEnc });
    closeModal('modal-vault');
    nameInput.value = '';
    await loadVaults();
    renderSidebar();
    toast(t('vault.created'));
    if (newVault?.id) await selectVault(newVault.id);
  } catch (e) {
    toast(e.message, true);
  }
}

// --- Vault shares (which teams a vault is shared with) ---
async function loadVaultShares(vault) {
  const el = document.getElementById('vault-shares');
  if (!el || !vault) return;
  el.style.display = 'none';
  el.innerHTML = '';
  let entry = vaultSharesCache[vault.id];
  if (!entry || Date.now() - entry.at > 60000) {
    let shares = [];
    try { shares = (await api('GET', `/api/vaults/${vault.id}/shares`)) || []; } catch {}
    entry = { at: Date.now(), teams: shares };
    vaultSharesCache[vault.id] = entry;
  }
  // The user may have navigated away while we were fetching.
  if (!currentVault || currentVault.id !== vault.id || sidebarMode !== 'vaults') return;
  if (!entry.teams.length) return;
  el.innerHTML = `<span class="vault-shares-label">${icon('users', { size: 12 })} ${esc(t('vault.sharedWith'))}</span>` +
    entry.teams.map(s => `<span class="team-chip">${esc(s.team_name)}</span>`).join('');
  el.style.display = 'flex';
}

// --- Items ---
async function loadItems() {
  activeTag = null;
  items = (await api('GET', `/api/vaults/${currentVault.id}/items`)) || [];
  await renderItems();
}

async function renderItems() {
  const list = document.getElementById('item-list');
  const empty = document.getElementById('items-empty');

  if (!items.length) {
    list.innerHTML = '';
    empty.style.display = 'flex';
    decryptedItemsCache = [];
    renderTagBar();
    return;
  }

  empty.style.display = 'none';
  const key = await getVaultDecryptionKey(currentVault);
  decryptedItemsCache = [];
  for (const item of items) {
    let data = {};
    try { data = JSON.parse(await decrypt(key, item.data_encrypted)); } catch {}
    decryptedItemsCache.push({ id: item.id, data });
  }

  renderTagBar();
  renderFilteredItems();
}

function itemSubtitle(data) {
  const ty = itemType(data);
  if (ty === 'card') return data.card_number ? '•••• ' + data.card_number.replace(/\s/g, '').slice(-4) : typeLabel('card');
  if (ty === 'identity') return data.id_email || data.id_fullname || typeLabel('identity');
  if (ty === 'note') return typeLabel('note');
  return data.username || '';
}

// Item icon, in priority: custom emoji (data.icon) -> site favicon -> flat type icon.
// The favicon <img> falls back to the type icon on load error.
function itemIconHtml(data, size = 16) {
  const typeIco = typeIconHtml(itemType(data), size);
  if (data && data.icon) {
    return `<span class="item-emoji">${esc(String(data.icon).slice(0, 8))}</span>`;
  }
  const fav = data && data.url ? faviconUrl(data.url, 32) : null;
  if (fav) {
    return `<img class="favicon-img" src="${escAttr(fav)}" width="${size}" height="${size}" alt="" loading="lazy"
      onerror="this.style.display='none';if(this.nextElementSibling)this.nextElementSibling.style.display='inline-flex';">` +
      `<span class="item-type-fallback" style="display:none;">${typeIco}</span>`;
  }
  return typeIco;
}

// Small tag chips shown on list rows (max 3 + '+N').
function rowTagsHtml(tags) {
  if (!tags || !tags.length) return '';
  const shown = tags.slice(0, 3).map(tg => `<span class="row-tag">${esc(tg)}</span>`).join('');
  const more = tags.length > 3 ? `<span class="row-tag more">+${tags.length - 3}</span>` : '';
  return `<div class="row-tags">${shown}${more}</div>`;
}

// Render the favorites/tags filter chips above the item list.
function renderTagBar() {
  const bar = document.getElementById('tag-bar');
  if (!bar) return;
  const tagSet = new Set();
  let hasFav = false;
  for (const { data } of decryptedItemsCache) {
    if (data.favorite) hasFav = true;
    (data.tags || []).forEach(tg => tagSet.add(tg));
  }
  const chips = [];
  if (hasFav) chips.push(`<button class="filter-chip${activeTag === '__fav__' ? ' active' : ''}" data-tag="__fav__">${icon('starFilled', { size: 11 })} ${esc(t('items.favorites'))}</button>`);
  for (const tg of [...tagSet].sort()) {
    chips.push(`<button class="filter-chip${activeTag === tg ? ' active' : ''}" data-tag="${escAttr(tg)}">${esc(tg)}</button>`);
  }
  bar.innerHTML = chips.join('');
  bar.style.display = chips.length ? 'flex' : 'none';
  bar.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      activeTag = (activeTag === chip.dataset.tag) ? null : chip.dataset.tag;
      renderTagBar();
      renderFilteredItems();
    });
  });
}

function renderFilteredItems() {
  const list = document.getElementById('item-list');
  const empty = document.getElementById('items-empty');
  const query = searchQuery.toLowerCase();

  let filtered = decryptedItemsCache;
  if (activeTag === '__fav__') filtered = filtered.filter(i => i.data.favorite);
  else if (activeTag) filtered = filtered.filter(i => (i.data.tags || []).includes(activeTag));
  if (query) filtered = filtered.filter(i =>
    (i.data.title || '').toLowerCase().includes(query) ||
    (i.data.username || '').toLowerCase().includes(query) ||
    (i.data.url || '').toLowerCase().includes(query) ||
    (i.data.tags || []).some(tg => tg.toLowerCase().includes(query)));

  // Favorites first, then alphabetical by title.
  filtered = [...filtered].sort((a, b) =>
    (b.data.favorite ? 1 : 0) - (a.data.favorite ? 1 : 0) ||
    (a.data.title || '').localeCompare(b.data.title || ''));

  if (!filtered.length) {
    list.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }
  empty.style.display = 'none';

  const cards = filtered.map(({ id, data }) => {
    const activeClass = currentItem && currentItem.id === id ? ' active' : '';
    const totpDot = data.totp_secret ? `<span class="totp-indicator" title="${escAttr(t('items.hasTotp'))}"></span>` : '';
    const favDot = data.favorite ? `<span class="fav-indicator" title="${escAttr(t('items.favorite'))}">${icon('starFilled', { size: 12 })}</span>` : '';
    const weakDot = (itemType(data) === 'login' && data.password && strengthScore(data.password) <= 1)
      ? `<span class="weak-indicator" title="${escAttr(t('watchtower.weak'))}">${icon('alert', { size: 13 })}</span>` : '';
    return `<div class="item-card${activeClass}" data-id="${id}">
      <div class="card-icon">${itemIconHtml(data, 18)}</div>
      <div class="card-info">
        <h3>${esc(data.title || t('items.untitled'))}</h3>
        <p>${esc(itemSubtitle(data))}</p>
        ${rowTagsHtml(data.tags)}
      </div>
      ${weakDot}${favDot}${totpDot}
    </div>`;
  });
  list.innerHTML = cards.join('');
  list.querySelectorAll('.item-card').forEach(card => {
    card.addEventListener('click', () => openItem(card.dataset.id));
  });
}

async function openItem(id) {
  if (currentVault) {
    setHash(`/vault/${currentVault.id}/item/${id}`);
  }
  await openItemDirect(id);
}

// Build a single detail field row. Copy/reveal use event delegation (see wireCopyReveal).
function fieldRow(label, value, opts = {}) {
  if (value == null || value === '') return '';
  const { mono = false, masked = false, url = false } = opts;
  const enc = encodeURIComponent(value);
  let valHtml;
  if (url) {
    const href = /^https?:\/\//i.test(value) ? value : 'https://' + value;
    valHtml = `<a class="field-value link" href="${escAttr(href)}" target="_blank" rel="noopener noreferrer">${esc(value)}</a>`;
  } else {
    valHtml = `<div class="field-value ${mono ? 'mono' : ''} ${masked ? 'masked' : ''}" data-raw="${enc}">${masked ? '••••••••••' : esc(value)}</div>`;
  }
  const reveal = masked ? `<button class="btn-icon js-reveal" title="${escAttr(t('actions.show'))}">${icon('eye', { size: 15 })}</button>` : '';
  const copy = `<button class="btn-icon js-copy" data-copy="${enc}" title="${escAttr(t('actions.copy'))}">${icon('copy', { size: 15 })}</button>`;
  return `<div class="field"><div class="field-main"><div class="field-label">${esc(label)}</div>${valHtml}</div><div class="field-actions">${reveal}${copy}</div></div>`;
}

function totpFieldHtml() {
  return `<div class="field" id="totp-field-container">
    <div class="field-main">
      <div class="field-label">${esc(t('fields.totp'))}</div>
      <div class="totp-display">
        <span class="totp-code" id="detail-totp-code"></span>
        <svg class="totp-countdown" viewBox="0 0 36 36">
          <circle class="totp-countdown-bg" cx="18" cy="18" r="16" fill="none" stroke-width="2"/>
          <circle class="totp-countdown-fg" cx="18" cy="18" r="16" fill="none" stroke-width="2"
            stroke-dasharray="100.53" stroke-dashoffset="0" id="totp-countdown-circle"/>
          <text x="18" y="19" class="totp-countdown-text" id="totp-countdown-text" dominant-baseline="central" text-anchor="middle"></text>
        </svg>
      </div>
    </div>
    <div class="field-actions">
      <button class="btn-icon js-copy" data-copy="totp" title="${escAttr(t('totp.copyCode'))}">${icon('copy', { size: 15 })}</button>
    </div>
  </div>`;
}

// One attachment row (used in detail view and in the shared-item view).
function attachmentRowHtml(att) {
  const name = att.name || 'file';
  return `<div class="attachment-row">
    <span class="attachment-icon">${icon('attachment', { size: 15 })}</span>
    <span class="attachment-name">${esc(name)}</span>
    <span class="attachment-size">${esc(formatSize(att.size))}</span>
    <a class="btn-icon" href="${escAttr(attachmentDataUrl(att))}" download="${escAttr(name)}" title="${escAttr(t('Descargar'))}">${icon('download', { size: 15 })}</a>
  </div>`;
}

// Render the detail panel for any item type.
function renderDetail(data) {
  const type = itemType(data);
  document.getElementById('detail-empty').style.display = 'none';
  document.getElementById('detail-content').style.display = 'block';
  document.getElementById('detail-title').textContent = data.title || t('items.untitled');
  document.getElementById('detail-item-icon').innerHTML = itemIconHtml(data, 20);

  const favBtn = document.getElementById('btn-fav-item');
  favBtn.innerHTML = icon(data.favorite ? 'starFilled' : 'star', { size: 17 });
  favBtn.classList.toggle('active', !!data.favorite);

  const tags = (data.tags || []).map(tg => `<button class="tag-chip" data-tag="${escAttr(tg)}">${esc(tg)}</button>`).join('');
  let metaHtml = `<span class="type-badge">${typeIconHtml(type, 12)} ${esc(typeLabel(type))}</span>${tags}`;
  // "Last edited by X, 5 min ago" — uses display_name with email fallback.
  if (currentItem && currentItem.updated_at) {
    const by = currentItem.updated_by_name || currentItem.updated_by_email;
    if (by) {
      metaHtml += `<span class="detail-edited">${icon('clock', { size: 12 })} ${esc(t('items.lastEdited', { name: by, when: formatRelative(currentItem.updated_at) }))}</span>`;
    }
  }
  document.getElementById('detail-meta').innerHTML = metaHtml;

  let html = '';
  if (type === 'login') {
    html += fieldRow(t('fields.username'), data.username);
    html += fieldRow(t('fields.password'), data.password, { mono: true, masked: true });
    if (data.totp_secret) html += totpFieldHtml();
    html += fieldRow(t('fields.website'), data.url, { url: true });
    html += fieldRow(t('fields.notes'), data.notes);
  } else if (type === 'card') {
    html += fieldRow(t('fields.cardholder'), data.card_holder);
    html += fieldRow(t('fields.cardNumber'), data.card_number, { mono: true, masked: true });
    html += fieldRow(t('fields.cardBrand'), data.card_brand);
    html += fieldRow(t('fields.cardExpiry'), data.card_exp, { mono: true });
    html += fieldRow(t('fields.cvv'), data.card_cvv, { mono: true, masked: true });
    html += fieldRow(t('fields.pin'), data.card_pin, { mono: true, masked: true });
    html += fieldRow(t('fields.notes'), data.notes);
  } else if (type === 'identity') {
    html += fieldRow(t('fields.fullName'), data.id_fullname);
    html += fieldRow(t('fields.email'), data.id_email);
    html += fieldRow(t('fields.phone'), data.id_phone);
    html += fieldRow(t('fields.address'), data.id_address);
    html += fieldRow(t('fields.company'), data.id_company);
    html += fieldRow(t('fields.notes'), data.notes);
  } else {
    html += fieldRow(t('fields.notes'), data.notes) ||
      `<div class="field"><div class="field-main"><div class="field-label">${esc(t('fields.notes'))}</div><div class="field-value">-</div></div></div>`;
  }

  // Custom fields (inside the encrypted blob): hidden ones masked with reveal toggle.
  const cfs = data.customFields || [];
  if (cfs.length) {
    html += `<div class="detail-section-title">${esc(t('items.customFields'))}</div>`;
    for (const cf of cfs) {
      html += fieldRow(cf.label || t('items.customFields.label'), cf.value, { masked: !!cf.hidden, mono: !!cf.hidden });
    }
  }

  // Attachments (inside the encrypted blob): download as data URLs, nothing leaves the device.
  const atts = data.attachments || [];
  if (atts.length) {
    html += `<div class="detail-section-title">${esc(t('items.attachments'))}</div>`;
    html += atts.map(att => attachmentRowHtml(att)).join('');
  }

  document.getElementById('detail-fields').innerHTML = html;

  const extras = document.getElementById('detail-extras');
  if (type === 'login' && data.password) {
    extras.style.display = 'block';
    renderStrengthInto('detail-pw-strength', data.password);
    document.getElementById('detail-breach-result').innerHTML = '';
  } else {
    extras.style.display = 'none';
  }
}

async function openItemDirect(id) {
  currentItem = items.find(i => i.id === id);
  if (!currentItem) return;

  const key = await getVaultDecryptionKey(currentVault);
  let data = {};
  try { data = JSON.parse(await decrypt(key, currentItem.data_encrypted)); } catch {}
  currentItem._data = data;

  renderDetail(data);

  // TOTP live updates
  stopTOTP();
  if (data.totp_secret) {
    await updateTOTP(data.totp_secret);
    totpInterval = setInterval(() => updateTOTP(data.totp_secret), 1000);
  }

  renderFilteredItems();
  document.querySelector('.detail-panel').classList.add('mobile-open');
}

// Toggle favorite on the currently open item.
async function toggleFavorite() {
  if (!currentItem || !currentItem._data) return;
  const data = { ...currentItem._data, favorite: !currentItem._data.favorite };
  const key = await getVaultDecryptionKey(currentVault);
  const dataEnc = await encrypt(key, JSON.stringify(data));
  try {
    await api('PUT', `/api/vaults/${currentVault.id}/items/${currentItem.id}`, {
      data_encrypted: dataEnc, version: currentItem.version,
    });
    toast(data.favorite ? t('toast.favoriteAdded') : t('toast.favoriteRemoved'));
    globalIndex = null;
    await loadItems();
    await openItem(currentItem.id);
  } catch (e) { toast(e.message, true); }
}

// Delete the currently open item (uses the DELETE endpoint).
async function deleteCurrentItem() {
  if (!currentItem) return;
  if (!confirm(t('toast.deleteConfirm'))) return;
  try {
    await api('DELETE', `/api/vaults/${currentVault.id}/items/${currentItem.id}`);
    toast(t('toast.itemDeleted'));
    currentItem = null;
    globalIndex = null;
    await loadItems();
    showDetailEmpty();
    setHash(`/vault/${currentVault.id}`);
  } catch (e) { toast(e.message, true); }
}

// --- Item history (server-stored encrypted versions, decrypted locally) ---
// Each entry shows version + author + date, with "view" (read-only mini detail)
// and "restore" (prefills the edit form; saving creates a new version).
async function showItemHistory() {
  if (!currentItem) return;
  try {
    const history = await api('GET', `/api/vaults/${currentVault.id}/items/${currentItem.id}/history`) || [];
    const key = await getVaultDecryptionKey(currentVault);
    historyEntries = [];
    for (const h of history) {
      let d = {};
      try { d = JSON.parse(await decrypt(key, h.data_encrypted)); } catch {}
      historyEntries.push({
        version: h.version,
        by: h.changed_by_name || h.changed_by_email || '',
        createdAt: h.created_at,
        data: d,
      });
    }
    renderHistoryEntries();
    openModal('modal-history');
  } catch (e) { toast(e.message, true); }
}

function renderHistoryEntries() {
  const body = document.getElementById('history-body');
  if (!historyEntries.length) {
    body.innerHTML = `<p class="empty-text">${esc(t('history.empty'))}</p>`;
    return;
  }
  body.innerHTML = historyEntries.map((h, i) => {
    const when = new Date(h.createdAt).toLocaleString(getLocale());
    const by = h.by ? ` · ${esc(h.by)}` : '';
    return `<div class="history-row">
      <div class="history-line">
        <div class="history-meta">${icon('history', { size: 13 })} <strong>v${Number(h.version) || 0}</strong>${by} · ${esc(when)}</div>
        <div class="history-actions">
          <button class="btn-icon js-hist-view" data-i="${i}" title="${escAttr(t('actions.show'))}">${icon('eye', { size: 15 })}</button>
          <button class="btn-icon js-hist-restore" data-i="${i}" title="${escAttr(t('Restaurar'))}">${icon('refresh', { size: 15 })}</button>
        </div>
      </div>
      <div class="history-mini" data-mini="${i}" style="display:none;"></div>
    </div>`;
  }).join('');
}

// Read-only compact rendering of an item's decrypted data (history view,
// shared-item view). Values are copyable; sensitive ones start masked.
function miniDetailHtml(data) {
  const rows = [];
  const add = (label, value, masked = false) => {
    if (value == null || value === '') return;
    const enc = encodeURIComponent(value);
    const revealBtn = masked ? `<button class="btn-icon js-reveal" title="${escAttr(t('actions.show'))}">${icon('eye', { size: 14 })}</button>` : '';
    rows.push(`<div class="mini-field">
      <span class="mini-label">${esc(label)}</span>
      <span class="mini-value${masked ? ' masked' : ''}" data-raw="${enc}">${masked ? '••••••••' : esc(value)}</span>
      <span class="mini-actions">${revealBtn}<button class="btn-icon js-copy" data-copy="${enc}" title="${escAttr(t('actions.copy'))}">${icon('copy', { size: 14 })}</button></span>
    </div>`);
  };
  const type = itemType(data);
  if (type === 'login') {
    add(t('fields.username'), data.username);
    add(t('fields.password'), data.password, true);
    add(t('fields.website'), data.url);
    if (data.totp_secret) add(t('fields.totpSecret'), data.totp_secret, true);
  } else if (type === 'card') {
    add(t('fields.cardholder'), data.card_holder);
    add(t('fields.cardNumber'), data.card_number, true);
    add(t('fields.cardBrand'), data.card_brand);
    add(t('fields.cardExpiry'), data.card_exp);
    add(t('fields.cvv'), data.card_cvv, true);
    add(t('fields.pin'), data.card_pin, true);
  } else if (type === 'identity') {
    add(t('fields.fullName'), data.id_fullname);
    add(t('fields.email'), data.id_email);
    add(t('fields.phone'), data.id_phone);
    add(t('fields.address'), data.id_address);
    add(t('fields.company'), data.id_company);
  }
  add(t('fields.notes'), data.notes);
  for (const cf of data.customFields || []) {
    add(cf.label || t('items.customFields.label'), cf.value, !!cf.hidden);
  }
  return rows.join('') || `<p class="empty-text">-</p>`;
}

// Check the current password against Have I Been Pwned (k-anonymity: only a hash prefix leaves the device).
async function checkCurrentBreach() {
  if (!currentItem?._data?.password) return;
  const out = document.getElementById('detail-breach-result');
  out.innerHTML = `<span class="strength-detail">${esc(t('breach.checking'))}</span>`;
  try {
    const count = await checkPwnedCount(currentItem._data.password);
    out.innerHTML = count > 0
      ? `<span class="breach-bad">${icon('alert', { size: 13 })} ${esc(t('breach.found', { count: count.toLocaleString(getLocale()) }))}</span>`
      : `<span class="breach-ok">${icon('check', { size: 13 })} ${esc(t('breach.notFound'))}</span>`;
  } catch {
    out.innerHTML = `<span class="strength-detail">${esc(t('breach.unavailable'))}</span>`;
  }
}

function showDetailEmpty() {
  document.getElementById('detail-empty').style.display = 'flex';
  document.getElementById('detail-content').style.display = 'none';
  currentItem = null;
  stopTOTP();

  // Mobile: hide detail
  const detailPanel = document.querySelector('.detail-panel');
  detailPanel.classList.remove('mobile-open');
}

// --- TOTP ---
async function updateTOTP(secret) {
  try {
    const { code, remaining } = await generateTOTP(secret);
    const formatted = code.slice(0, 3) + ' ' + code.slice(3);
    document.getElementById('detail-totp-code').textContent = formatted;

    // Update countdown circle
    const circumference = 2 * Math.PI * 16; // r=16
    const offset = circumference * (1 - remaining / 30);
    document.getElementById('totp-countdown-circle').setAttribute('stroke-dashoffset', offset);
    document.getElementById('totp-countdown-text').textContent = remaining;
  } catch {
    document.getElementById('detail-totp-code').textContent = t('totp.invalid');
    document.getElementById('totp-countdown-text').textContent = '-';
  }
}

function stopTOTP() {
  if (totpInterval) {
    clearInterval(totpInterval);
    totpInterval = null;
  }
}

// --- Item CRUD ---
let itemFormType = 'login';

function setItemFormType(type) {
  itemFormType = ITEM_TYPES[type] ? type : 'login';
  document.querySelectorAll('#item-type-selector .type-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.type === itemFormType);
  });
  document.querySelectorAll('#modal-item [data-type-fields]').forEach(sec => {
    sec.style.display = sec.dataset.typeFields === itemFormType ? 'block' : 'none';
  });
}

const val = id => (document.getElementById(id)?.value ?? '').trim();

// --- Item form: attachments (kept in memory, embedded in the blob before encryption) ---
function renderFormAttachments() {
  const list = document.getElementById('item-attachments-list');
  if (!list) return;
  list.innerHTML = formAttachments.map((att, i) => `
    <div class="attachment-row">
      <span class="attachment-icon">${icon('attachment', { size: 14 })}</span>
      <span class="attachment-name">${esc(att.name)}</span>
      <span class="attachment-size">${esc(formatSize(att.size))}</span>
      <button type="button" class="btn-icon btn-icon-danger js-remove-att" data-i="${i}" title="${escAttr(t('actions.delete'))}">${icon('x', { size: 14 })}</button>
    </div>`).join('');
}

async function addFormAttachments(fileList) {
  for (const f of fileList) {
    if (formAttachments.length >= MAX_ATTACHMENTS) {
      toast(t('Máximo {n} adjuntos por elemento', { n: MAX_ATTACHMENTS }), true);
      break;
    }
    try {
      formAttachments.push(await fileToAttachment(f));
    } catch (err) {
      if (err && err.message === 'too-big') toast(t('items.attachments.tooBig'), true);
      else toast(err?.message || 'Error', true);
    }
  }
  renderFormAttachments();
}

// --- Item form: custom fields (state lives in the DOM rows) ---
function addCustomFieldRow(cf = { label: '', value: '', hidden: false }) {
  const list = document.getElementById('custom-fields-list');
  if (!list) return;
  const row = document.createElement('div');
  row.className = 'cf-row';
  row.innerHTML = `
    <input type="text" class="cf-label" placeholder="${escAttr(t('items.customFields.label'))}" autocomplete="off">
    <input type="text" class="cf-value" placeholder="${escAttr(t('items.customFields.value'))}" autocomplete="off">
    <label class="cf-hidden-toggle" title="${escAttr(t('actions.hide'))}"><input type="checkbox" class="cf-hidden">${icon('eyeOff', { size: 14 })}</label>
    <button type="button" class="btn-icon btn-icon-danger cf-remove" title="${escAttr(t('actions.delete'))}">${icon('x', { size: 14 })}</button>`;
  row.querySelector('.cf-label').value = cf.label || '';
  row.querySelector('.cf-value').value = cf.value || '';
  row.querySelector('.cf-hidden').checked = !!cf.hidden;
  row.querySelector('.cf-remove').addEventListener('click', () => row.remove());
  list.appendChild(row);
}

function readCustomFields() {
  return [...document.querySelectorAll('#custom-fields-list .cf-row')].map(row => ({
    label: row.querySelector('.cf-label').value.trim(),
    value: row.querySelector('.cf-value').value,
    hidden: row.querySelector('.cf-hidden').checked,
  })).filter(cf => cf.label || cf.value);
}

async function saveItem() {
  const title = val('item-title-input');
  if (!title) return toast(t('toast.enterTitle'), true);

  const tags = val('item-tags-input').split(',').map(s => s.trim()).filter(Boolean);
  const favorite = document.getElementById('item-fav-input').checked;

  const dataObj = { type: itemFormType, title, favorite, notes: val('item-notes-input') };
  if (tags.length) dataObj.tags = tags;

  if (itemFormType === 'login') {
    dataObj.username = val('item-user-input');
    dataObj.password = document.getElementById('item-pw-input').value;
    dataObj.url = val('item-url-input');
    const totp = val('item-totp-input');
    if (totp) dataObj.totp_secret = totp;
    // Track when the password last changed (for the security dashboard "old password" check).
    const prev = editingItem?._data || {};
    dataObj.pwChangedAt = (dataObj.password && dataObj.password !== prev.password)
      ? Date.now() : (prev.pwChangedAt || (dataObj.password ? Date.now() : undefined));
  } else if (itemFormType === 'card') {
    dataObj.card_holder = val('item-card-holder');
    dataObj.card_number = val('item-card-number');
    dataObj.card_brand = val('item-card-brand');
    dataObj.card_exp = val('item-card-exp');
    dataObj.card_cvv = val('item-card-cvv');
    dataObj.card_pin = val('item-card-pin');
  } else if (itemFormType === 'identity') {
    dataObj.id_fullname = val('item-id-fullname');
    dataObj.id_email = val('item-id-email');
    dataObj.id_phone = val('item-id-phone');
    dataObj.id_address = val('item-id-address');
    dataObj.id_company = val('item-id-company');
  }

  // Common extras — ALL stored inside the encrypted blob (zero-knowledge).
  const iconVal = val('item-icon-input');
  if (iconVal) dataObj.icon = [...iconVal].slice(0, 4).join('');
  const customFields = readCustomFields();
  if (customFields.length) dataObj.customFields = customFields;
  if (formAttachments.length) dataObj.attachments = formAttachments;

  const key = await getVaultDecryptionKey(currentVault);
  const dataEnc = await encrypt(key, JSON.stringify(dataObj));

  try {
    let savedItemId = null;
    if (editingItem) {
      await api('PUT', `/api/vaults/${currentVault.id}/items/${editingItem.id}`, {
        data_encrypted: dataEnc,
        version: editingItem.version,
      });
      savedItemId = editingItem.id;
      toast(t('toast.itemUpdated'));
    } else {
      const newItem = await api('POST', `/api/vaults/${currentVault.id}/items`, { data_encrypted: dataEnc });
      if (newItem?.id) savedItemId = newItem.id;
      toast(t('toast.itemSaved'));
    }
    closeModal('modal-item');
    clearItemForm();
    globalIndex = null;
    await loadItems();
    if (savedItemId) {
      const item = items.find(i => i.id === savedItemId);
      if (item) await openItem(item.id);
    }
  } catch (e) {
    toast(e.message, true);
  }
}

const FORM_FIELDS = [
  'item-title-input', 'item-user-input', 'item-pw-input', 'item-url-input',
  'item-totp-input', 'item-notes-input', 'item-tags-input', 'item-icon-input',
  'item-card-holder', 'item-card-number', 'item-card-brand', 'item-card-exp',
  'item-card-cvv', 'item-card-pin',
  'item-id-fullname', 'item-id-email', 'item-id-phone', 'item-id-address', 'item-id-company',
];

function clearItemForm() {
  FORM_FIELDS.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  document.getElementById('item-fav-input').checked = false;
  formAttachments = [];
  renderFormAttachments();
  document.getElementById('custom-fields-list').innerHTML = '';
  renderStrengthInto('item-pw-strength', '');
  setItemFormType('login');
  editingItem = null;
}

// Populate the modal from an existing item's decrypted data (used by the Edit button).
function fillItemForm(data) {
  setItemFormType(itemType(data));
  document.getElementById('item-title-input').value = data.title || '';
  document.getElementById('item-notes-input').value = data.notes || '';
  document.getElementById('item-tags-input').value = (data.tags || []).join(', ');
  document.getElementById('item-fav-input').checked = !!data.favorite;
  document.getElementById('item-icon-input').value = data.icon || '';
  document.getElementById('item-user-input').value = data.username || '';
  document.getElementById('item-pw-input').value = data.password || '';
  document.getElementById('item-url-input').value = data.url || '';
  document.getElementById('item-totp-input').value = data.totp_secret || '';
  document.getElementById('item-card-holder').value = data.card_holder || '';
  document.getElementById('item-card-number').value = data.card_number || '';
  document.getElementById('item-card-brand').value = data.card_brand || '';
  document.getElementById('item-card-exp').value = data.card_exp || '';
  document.getElementById('item-card-cvv').value = data.card_cvv || '';
  document.getElementById('item-card-pin').value = data.card_pin || '';
  document.getElementById('item-id-fullname').value = data.id_fullname || '';
  document.getElementById('item-id-email').value = data.id_email || '';
  document.getElementById('item-id-phone').value = data.id_phone || '';
  document.getElementById('item-id-address').value = data.id_address || '';
  document.getElementById('item-id-company').value = data.id_company || '';
  formAttachments = [...(data.attachments || [])];
  renderFormAttachments();
  document.getElementById('custom-fields-list').innerHTML = '';
  (data.customFields || []).forEach(cf => addCustomFieldRow(cf));
  renderStrengthInto('item-pw-strength', data.password || '');
}

// --- Teams ---
async function loadTeams() {
  teams = (await api('GET', '/api/teams')) || [];
}

async function createTeam() {
  const nameInput = document.getElementById('team-name-input');
  const name = nameInput.value.trim();
  if (!name) return toast(t('toast.enterTeamName'), true);

  try {
    await api('POST', '/api/teams', { name });
    closeModal('modal-team');
    nameInput.value = '';
    await loadTeams();
    renderSidebar();
    toast(t('toast.teamCreated'));
  } catch (e) {
    toast(e.message, true);
  }
}

async function loadTeamMembers() {
  const members = (await api('GET', `/api/teams/${currentTeam.id}/members`)) || [];
  const list = document.getElementById('member-list');

  if (!members.length) {
    list.innerHTML = `<p class="empty-text">${esc(t('teams.noMembers'))}</p>`;
    return;
  }

  const myId = getCurrentUserId();
  const myMember = members.find(m => m.user_id === myId);
  const isAdmin = myMember && myMember.role === 'admin';
  const ownerId = currentTeam.owner_id;

  list.innerHTML = members.map(m => {
    const isOwner = m.user_id === ownerId;
    const displayName = m.display_name || m.email;
    let actions = '';
    if (isAdmin && !isOwner) {
      if (m.role === 'member') {
        actions += `<button class="btn-icon btn-promote" data-user-id="${m.user_id}" title="${escAttr(t('teams.promote'))}">${icon('chevronDown', { size: 14, cls: 'icon-up' })}</button>`;
      } else if (m.role === 'admin') {
        actions += `<button class="btn-icon btn-demote" data-user-id="${m.user_id}" title="${escAttr(t('teams.demote'))}">${icon('chevronDown', { size: 14 })}</button>`;
      }
      actions += `<button class="btn-icon btn-remove-member" data-user-id="${m.user_id}" title="${escAttr(t('teams.removeMember'))}">${icon('x', { size: 14 })}</button>`;
    }
    const roleBadge = `<span class="badge-role badge-${escAttr(m.role)}">${esc(t('teams.role.' + m.role))}</span>`;
    const ownerBadge = isOwner ? ` <span class="badge-role badge-owner">${esc(t('teams.role.owner'))}</span>` : '';
    const pendingBadge = !m.has_public_key ? ` <span class="badge-role badge-pending">${esc(t('teams.role.pending'))}</span>` : '';
    return `<div class="member-card">
      <div class="card-info">
        <h3><span class="member-name">${esc(displayName)}</span> ${roleBadge}${ownerBadge}${pendingBadge}</h3>
        <p class="member-email">${esc(m.email)}</p>
      </div>
      <div class="member-actions">${actions}</div>
    </div>`;
  }).join('');

  list.querySelectorAll('.btn-promote').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await api('PUT', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}/role`, { role: 'admin' });
        toast(t('toast.promoted'));
        await loadTeamMembers();
      } catch (e) { toast(e.message, true); }
    });
  });

  list.querySelectorAll('.btn-demote').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await api('PUT', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}/role`, { role: 'member' });
        toast(t('toast.demoted'));
        await loadTeamMembers();
      } catch (e) { toast(e.message, true); }
    });
  });

  list.querySelectorAll('.btn-remove-member').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm(t('teams.removeConfirm'))) return;
      try {
        await api('DELETE', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}`);
        toast(t('toast.memberRemoved'));
        await loadTeamMembers();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

async function loadTeamVaults() {
  const teamVaults = (await api('GET', `/api/teams/${currentTeam.id}/vaults`)) || [];
  const list = document.getElementById('team-vault-list');

  if (!teamVaults.length) {
    list.innerHTML = `<p class="empty-text">${esc(t('teams.noVaults'))}</p>`;
    return;
  }

  const cards = [];
  for (const v of teamVaults) {
    let name = 'Vault';
    try {
      const key = await getVaultDecryptionKey(v);
      name = await decrypt(key, v.name_encrypted);
    } catch {}
    cards.push(`<div class="vault-card" data-id="${v.id}">
      <div class="card-icon">${icon('vault', { size: 16 })}</div>
      <div class="card-info">
        <h3>${esc(name)}</h3>
        <p>${new Date(v.created_at).toLocaleDateString(getLocale())}</p>
      </div>
    </div>`);
  }
  list.innerHTML = cards.join('');
  list.querySelectorAll('.vault-card').forEach(card => {
    card.addEventListener('click', () => {
      let vault = vaults.find(v => v.id === card.dataset.id);
      if (!vault) {
        vault = teamVaults.find(v => v.id === card.dataset.id);
        if (vault) vaults.push(vault);
      }
      selectVault(card.dataset.id);
    });
  });
}

async function processPendingVaultKeys() {
  if (!currentTeam || !privateKey) return;
  try {
    const resp = await api('GET', `/api/teams/${currentTeam.id}/pending-vault-keys`);
    if (!resp.pending?.length) return;

    // Group by vault_id
    const byVault = {};
    for (const p of resp.pending) {
      if (!byVault[p.vault_id]) byVault[p.vault_id] = [];
      byVault[p.vault_id].push(p);
    }

    for (const [vaultId, members] of Object.entries(byVault)) {
      try {
        const vkResp = await api('GET', `/api/vaults/${vaultId}/key`);
        const vaultKeyBase64 = await decryptWithPrivateKey(privateKey, vkResp.encrypted_vault_key);

        const vaultKeys = [];
        for (const m of members) {
          const pubKeyJwk = JSON.parse(m.public_key);
          const encVaultKey = await encryptWithPublicKey(pubKeyJwk, vaultKeyBase64);
          vaultKeys.push({ user_id: m.user_id, encrypted_vault_key: encVaultKey });
        }

        await api('POST', `/api/vaults/${vaultId}/share`, { vault_keys: vaultKeys });
      } catch (e) {
        console.warn('Could not share vault keys for vault', vaultId, e);
      }
    }

    // Refresh member list to update pending badges
    await loadTeamMembers();
  } catch (e) {
    // Non-admin users will get 403, that's expected
    console.debug('processPendingVaultKeys:', e.message);
  }
}

async function addTeamMember() {
  const emailInput = document.getElementById('member-email-input');
  const email = emailInput.value.trim();
  if (!email) return toast(t('toast.enterEmail'), true);

  try {
    const member = await api('POST', `/api/teams/${currentTeam.id}/members`, { email });

    let shared = false;
    try {
      const pubKeyResp = await api('GET', `/api/users/${member.user_id}/public-key`);
      const pubKeyJwk = JSON.parse(pubKeyResp.public_key);

      const teamVaults = (await api('GET', `/api/teams/${currentTeam.id}/vaults`)) || [];
      for (const v of teamVaults) {
        try {
          const vkResp = await api('GET', `/api/vaults/${v.id}/key`);
          const vaultKeyBase64 = await decryptWithPrivateKey(privateKey, vkResp.encrypted_vault_key);
          const encVaultKey = await encryptWithPublicKey(pubKeyJwk, vaultKeyBase64);
          await api('POST', `/api/vaults/${v.id}/share`, {
            vault_keys: [{ user_id: member.user_id, encrypted_vault_key: encVaultKey }],
          });
        } catch (e) {
          console.warn('Could not share vault', v.id, e);
        }
      }
      shared = true;
    } catch (e) {
      // Member has no public key yet (pending signup)
      console.warn('Member has no public key, vault keys will be shared later:', e);
    }

    closeModal('modal-add-member');
    emailInput.value = '';
    await loadTeamMembers();
    toast(shared ? t('toast.memberAdded') : t('toast.memberInvited'));
  } catch (e) {
    toast(e.message, true);
  }
}

async function createTeamVault() {
  const nameInput = document.getElementById('team-vault-name-input');
  const name = nameInput.value.trim();
  if (!name) return toast(t('toast.enterName'), true);

  try {
    const vaultKeyBase64 = await generateVaultKey();
    const members = (await api('GET', `/api/teams/${currentTeam.id}/members`)) || [];
    const vaultKeys = [];

    for (const m of members) {
      try {
        const pubResp = await api('GET', `/api/users/${m.user_id}/public-key`);
        const pubKeyJwk = JSON.parse(pubResp.public_key);
        const encVaultKey = await encryptWithPublicKey(pubKeyJwk, vaultKeyBase64);
        vaultKeys.push({ user_id: m.user_id, encrypted_vault_key: encVaultKey });
      } catch (e) {
        console.warn('Skipping member without public key:', m.user_id);
      }
    }

    const vaultCryptoKey = await importVaultKey(vaultKeyBase64);
    const nameEnc = await encrypt(vaultCryptoKey, name);

    await api('POST', `/api/teams/${currentTeam.id}/vaults`, {
      name_encrypted: nameEnc,
      vault_keys: vaultKeys,
    });

    closeModal('modal-team-vault');
    nameInput.value = '';
    await Promise.all([loadTeamVaults(), loadVaults()]);
    renderSidebar();
    toast(t('toast.teamVaultCreated'));
  } catch (e) {
    toast(e.message, true);
  }
}

// --- One-time share links -------------------------------------------------
// The item's decrypted data is re-encrypted client-side with a fresh random
// key (sharelink.js); the server stores only opaque ciphertext. The key
// travels exclusively in the URL fragment, which browsers never send.

function openShareModal() {
  if (!currentItem || !currentItem._data || !currentVault) return;
  document.getElementById('share-result').style.display = 'none';
  document.getElementById('share-url-input').value = '';
  document.getElementById('share-links-list').innerHTML = '';
  openModal('modal-share');
  loadShareLinks();
}

async function createShareLink() {
  if (!currentItem || !currentItem._data || !currentVault) return;
  const hours = Number(document.getElementById('share-expiry-select').value) || 24;
  const btn = document.getElementById('btn-create-share');
  btn.disabled = true;
  try {
    const { payloadB64, keyB64 } = await createSharePayload(currentItem._data);
    const resp = await api('POST', `/api/vaults/${currentVault.id}/items/${currentItem.id}/share-link`, {
      payload_encrypted: payloadB64,
      expires_in_hours: hours,
    });
    const url = buildShareUrl(location.origin, resp.id, keyB64);
    const input = document.getElementById('share-url-input');
    input.value = url;
    document.getElementById('share-result').style.display = 'block';
    input.focus();
    input.select();
    loadShareLinks();
  } catch (e) {
    if (e.status === 403) toast(t('Solo el propietario o un administrador puede crear enlaces'), true);
    else toast(e.message, true);
  } finally {
    btn.disabled = false;
  }
}

async function loadShareLinks() {
  const list = document.getElementById('share-links-list');
  if (!currentItem || !currentVault) { list.innerHTML = ''; return; }
  let links = [];
  try {
    links = (await api('GET', `/api/vaults/${currentVault.id}/items/${currentItem.id}/share-links`)) || [];
  } catch {
    list.innerHTML = '';
    return;
  }
  if (!links.length) { list.innerHTML = ''; return; }
  const now = Date.now();
  list.innerHTML = links.map(l => {
    let state;
    if (l.redeemed_at) {
      state = `<span class="share-state share-used">${esc(t('Usado'))} · ${esc(formatRelative(l.redeemed_at))}</span>`;
    } else if (new Date(l.expires_at).getTime() < now) {
      state = `<span class="share-state share-expired">${esc(t('Caducado'))}</span>`;
    } else {
      state = `<span class="share-state share-active">${esc(t('share.expires'))} ${esc(formatRelative(l.expires_at))}</span>`;
    }
    return `<div class="share-link-row">
      <span class="share-link-icon">${icon('link', { size: 14 })}</span>
      <span class="share-link-info">
        <span class="share-link-date">${esc(new Date(l.created_at).toLocaleString(getLocale()))}</span>
        ${state}
      </span>
      <button class="btn-icon btn-icon-danger js-revoke-share" data-share-id="${escAttr(l.id)}" title="${escAttr(t('actions.delete'))}">${icon('trash', { size: 14 })}</button>
    </div>`;
  }).join('');
}

// --- Share link recipient flow (public, no login) ---
async function renderShareOpen(share) {
  showScreenNoHash('share-open');
  renderVersion();
  const body = document.getElementById('share-open-body');
  body.innerHTML = `<div class="cmd-loading">${esc(t('breach.checking'))}</div>`;
  let status = 'gone';
  try {
    // Public endpoint; intentionally plain fetch (no Authorization header needed).
    const res = await fetch(`/auth/share-links/${encodeURIComponent(share.id)}/status`);
    if (res.ok) status = (await res.json())?.status || 'gone';
  } catch {}
  if (status !== 'available') {
    body.innerHTML = `<div class="share-gone">${icon('alert', { size: 16 })} ${esc(t('share.open.gone'))}</div>`;
    return;
  }
  body.innerHTML = `
    <p class="share-open-hint">${icon('alert', { size: 13 })} ${esc(t('share.oneUse'))}</p>
    <button class="btn btn-primary" id="btn-open-share">${esc(t('share.open.title'))}</button>`;
  document.getElementById('btn-open-share').addEventListener('click', () => redeemShare(share));
}

async function redeemShare(share) {
  const btn = document.getElementById('btn-open-share');
  const body = document.getElementById('share-open-body');
  if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>'; }
  try {
    const res = await fetch(`/auth/share-links/${encodeURIComponent(share.id)}/redeem`, { method: 'POST' });
    if (!res.ok) throw new Error('gone');
    const resp = await res.json();
    // The key comes from the URL fragment and is used ONLY here, locally.
    const data = await decryptSharePayload(resp.payload_encrypted, share.key);
    renderSharedItem(data);
  } catch {
    body.innerHTML = `<div class="share-gone">${icon('alert', { size: 16 })} ${esc(t('share.open.gone'))}</div>`;
  }
}

function renderSharedItem(data) {
  const body = document.getElementById('share-open-body');
  let html = `<div class="share-item-card">
    <div class="share-item-title">${itemIconHtml(data, 20)}<h3>${esc(data.title || t('items.untitled'))}</h3>
      <span class="type-badge">${typeIconHtml(itemType(data), 12)} ${esc(typeLabel(itemType(data)))}</span></div>
    <div class="share-item-fields">${miniDetailHtml(data)}</div>`;
  const atts = data.attachments || [];
  if (atts.length) {
    html += `<div class="detail-section-title">${esc(t('items.attachments'))}</div>` + atts.map(att => attachmentRowHtml(att)).join('');
  }
  html += '</div>';
  body.innerHTML = html;
  wireCopyReveal(body);
}

// --- Linked devices (QR pairing for the mobile apps) -----------------------
// The pairing QR carries ONLY { v, srv, email, tok } as base64url JSON — the
// server origin, the account email and the device API token. NEVER any key
// material: the phone asks for the master password locally and derives the
// encryption keys on-device (zero-knowledge, same as the web client).

function currentUserEmail() {
  return lockContext?.email || iapSession?.email || '';
}

// Restore the modal to its initial state: create form visible, QR/token gone.
function resetDevicesModal() {
  const form = document.getElementById('device-create-form');
  if (form) form.style.display = '';
  const result = document.getElementById('device-qr-result');
  if (result) result.innerHTML = '';
  const name = document.getElementById('device-name-input');
  if (name) name.value = '';
}

function openDevicesModal() {
  resetDevicesModal();
  openModal('modal-devices');
  loadDevices();
}

async function createDevice() {
  const name = document.getElementById('device-name-input').value.trim();
  if (!name) return toast(t('toast.enterName'), true);
  const btn = document.getElementById('btn-create-device');
  btn.disabled = true;
  try {
    const resp = await api('POST', '/api/devices', { name });
    renderDevicePairing(resp.token); // token is shown exactly ONCE
    loadDevices();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
  }
}

// Replaces the create form with the pairing QR + one-time token readout.
function renderDevicePairing(deviceToken) {
  const payload = JSON.stringify({ v: 1, srv: location.origin, email: currentUserEmail(), tok: deviceToken });
  const b64url = btoa(String.fromCharCode(...new TextEncoder().encode(payload)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  document.getElementById('device-create-form').style.display = 'none';
  const box = document.getElementById('device-qr-result');
  // QR stays black-on-white in every theme/skin: scanners need the contrast.
  box.innerHTML = `
    <div class="device-qr">${qrSvg(b64url, { size: 208, margin: 2 })}</div>
    <p class="device-scan-hint">${esc(t('devices.scanHint'))}</p>
    <div class="share-url-row">
      <input type="text" id="device-token-output" readonly spellcheck="false" value="${escAttr(deviceToken)}">
      <button class="btn-icon" id="btn-copy-device-token" title="${escAttr(t('actions.copy'))}">${icon('copy', { size: 15 })}</button>
    </div>
    <p class="share-warning">${icon('alert', { size: 14 })} <span>${esc(t('devices.tokenOnce'))}</span></p>`;
  document.getElementById('btn-copy-device-token').addEventListener('click', () => {
    navigator.clipboard.writeText(deviceToken)
      .then(() => toast(t('toast.copied')))
      .catch(() => toast(t('toast.copyFailed'), true));
  });
  const out = document.getElementById('device-token-output');
  out.addEventListener('focus', () => out.select());
}

async function loadDevices() {
  const list = document.getElementById('device-list');
  let devices = [];
  try {
    devices = (await api('GET', '/api/devices')) || [];
  } catch {
    list.innerHTML = '';
    return;
  }
  if (!devices.length) { list.innerHTML = ''; return; }
  list.innerHTML = devices.map(d => {
    const revoked = !!d.revoked_at;
    const used = d.last_used_at
      ? `${esc(t('devices.lastUsed'))} ${esc(formatRelative(d.last_used_at))}`
      : esc(t('devices.never'));
    return `<div class="device-row${revoked ? ' device-row-revoked' : ''}">
      <span class="device-row-icon">${icon('link', { size: 14 })}</span>
      <span class="device-row-info">
        <span class="device-row-name">${esc(d.name)}${revoked ? ` <span class="device-badge-revoked">${esc(t('devices.revoked'))}</span>` : ''}</span>
        <span class="device-row-meta">${esc(t('devices.created'))} ${esc(formatRelative(d.created_at))} · ${used}</span>
      </span>
      ${revoked ? '' : `<button class="btn-icon btn-icon-danger js-revoke-device" data-device-id="${escAttr(d.id)}" data-device-name="${escAttr(d.name)}" title="${escAttr(t('devices.revoke'))}">${icon('trash', { size: 14 })}</button>`}
    </div>`;
  }).join('');
}

// --- Modals ---
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

// --- Mobile sidebar ---
function openMobileSidebar() {
  document.querySelector('.sidebar').classList.add('mobile-open');
  const overlay = document.getElementById('sidebar-overlay');
  if (overlay) overlay.classList.add('active');
}

function closeMobileSidebar() {
  document.querySelector('.sidebar').classList.remove('mobile-open');
  const overlay = document.getElementById('sidebar-overlay');
  if (overlay) overlay.classList.remove('active');
}

function closeMobileDetail() {
  document.querySelector('.detail-panel').classList.remove('mobile-open');
  currentItem = null;
  if (currentVault) {
    setHash(`/vault/${currentVault.id}`);
  } else if (currentTeam) {
    setHash(`/team/${currentTeam.id}`);
  }
}

// --- Helpers ---
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

// esc() for attribute values: also neutralizes quotes so user-controlled
// strings can't break out of href/title/data-* attributes.
function escAttr(s) {
  return esc(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getCurrentUserId() {
  if (iapSession && iapSession.user_id) return iapSession.user_id;
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.user_id || null;
  } catch { return null; }
}

window.copyField = function(id) {
  const el = document.getElementById(id);
  const text = el.textContent.replace(/\s/g, ''); // strip spaces (TOTP formatting)
  navigator.clipboard.writeText(text).then(() => toast(t('toast.copied')));
};

// --- Import (1Password CSV + 1PIF) ---
// Pure parsers live in /import.js (unit-tested); importItems below
// handles the DOM + per-item encryption/upload.

async function importItems(parsedItems) {
  if (!currentVault) return toast(t('toast.selectVaultFirst'), true);
  if (!parsedItems.length) return;

  // Show progress step
  document.getElementById('import-step-select').style.display = 'none';
  document.getElementById('import-step-progress').style.display = 'block';

  const total = parsedItems.length;
  let imported = 0;
  const errors = [];

  try {
    const key = await getVaultDecryptionKey(currentVault);

    for (let i = 0; i < total; i++) {
      try {
        const dataEnc = await encrypt(key, JSON.stringify(parsedItems[i]));
        await api('POST', `/api/vaults/${currentVault.id}/items`, { data_encrypted: dataEnc });
        imported++;
      } catch (err) {
        errors.push({ title: parsedItems[i].title, error: err.message });
      }

      // Update progress
      const pct = Math.round(((i + 1) / total) * 100);
      document.getElementById('import-progress-bar').style.width = pct + '%';
      document.getElementById('import-progress-text').textContent =
        t('import.progress', { done: i + 1, total });
    }
  } catch (err) {
    toast(t('import.failed', { error: err.message }), true);
    resetImportModal();
    closeModal('modal-import');
    return;
  }

  // Show results step
  document.getElementById('import-step-progress').style.display = 'none';
  document.getElementById('import-step-results').style.display = 'block';

  let summary = t('import.summary', { imported, total });
  if (errors.length) {
    summary += '\n' + t('import.errors', { count: errors.length });
  }
  document.getElementById('import-results-summary').textContent = summary;

  if (errors.length) {
    const errContainer = document.getElementById('import-results-errors');
    errContainer.style.display = 'block';
    errContainer.innerHTML = errors.map(e =>
      `<div class="import-error-item">${esc(e.title)}: ${esc(e.error)}</div>`
    ).join('');
  }

  // Refresh items list
  globalIndex = null;
  await loadItems();
}

function resetImportModal() {
  document.getElementById('import-step-select').style.display = 'block';
  document.getElementById('import-step-progress').style.display = 'none';
  document.getElementById('import-step-results').style.display = 'none';
  document.getElementById('import-file-input').value = '';
  document.getElementById('import-file-label-text').textContent = t('import.chooseFile');
  document.getElementById('import-file-label').classList.remove('has-file');
  document.getElementById('import-preview').style.display = 'none';
  document.getElementById('import-errors-preview').style.display = 'none';
  document.getElementById('import-errors-preview').textContent = '';
  document.getElementById('import-progress-bar').style.width = '0%';
  document.getElementById('import-progress-text').textContent = t('import.progress', { done: 0, total: 0 });
  document.getElementById('import-results-summary').textContent = '';
  document.getElementById('import-results-errors').style.display = 'none';
  document.getElementById('import-results-errors').innerHTML = '';
  document.getElementById('btn-start-import').disabled = true;
}

// --- Global index (all vaults), used by command palette, global search and
// the security dashboard. Decrypts every item across every accessible vault.
// Zero-knowledge preserved: all decryption happens locally with keys already
// in memory.
async function collectAllItems() {
  const out = [];
  for (const v of vaults) {
    let key, vname = 'Vault';
    try {
      key = await getVaultDecryptionKey(v);
      vname = await decrypt(key, v.name_encrypted);
    } catch { continue; }
    let vitems = [];
    try { vitems = (await api('GET', `/api/vaults/${v.id}/items`)) || []; } catch { continue; }
    for (const it of vitems) {
      let data = {};
      try { data = JSON.parse(await decrypt(key, it.data_encrypted)); } catch {}
      out.push({ vaultId: v.id, vaultName: vname, id: it.id, version: it.version, data });
    }
  }
  return out;
}

async function openVaultItem(vaultId, itemId) {
  setHash(`/vault/${vaultId}/item/${itemId}`);
  await navigateToVault(vaultId);
  await navigateToItem(itemId);
}

// --- Global search (sidebar): searches across ALL vaults, cached ~60s ---
let gsToken = 0;

async function getGlobalIndex() {
  if (!encKey) return [];
  if (globalIndex && Date.now() - globalIndexAt < 60000) return globalIndex;
  globalIndex = await collectAllItems();
  globalIndexAt = Date.now();
  return globalIndex;
}

function hideGlobalSearch(clear = false) {
  gsToken++;
  const results = document.getElementById('global-search-results');
  if (results) { results.style.display = 'none'; results.innerHTML = ''; }
  if (clear) {
    const input = document.getElementById('global-search-input');
    if (input) input.value = '';
  }
}

async function runGlobalSearch(query) {
  const my = ++gsToken;
  const results = document.getElementById('global-search-results');
  results.style.display = 'block';
  results.innerHTML = `<div class="cmd-loading">${esc(t('cmd.indexing'))}</div>`;
  let index = [];
  try { index = await getGlobalIndex(); } catch {}
  if (my !== gsToken) return; // a newer query or a hide superseded us

  const q = query.toLowerCase();
  const matches = index.filter(e =>
    (e.data.title || '').toLowerCase().includes(q) ||
    (e.data.username || '').toLowerCase().includes(q) ||
    (e.data.url || '').toLowerCase().includes(q) ||
    (e.vaultName || '').toLowerCase().includes(q)).slice(0, 20);

  if (!matches.length) {
    results.innerHTML = `<div class="cmd-empty">${esc(t('cmd.noMatches'))}</div>`;
    return;
  }
  results.innerHTML = matches.map(e => `
    <div class="gs-row" data-vault="${escAttr(e.vaultId)}" data-item="${escAttr(e.id)}">
      <span class="gs-icon">${itemIconHtml(e.data, 14)}</span>
      <span class="gs-main">
        <span class="gs-title">${esc(e.data.title || t('items.untitled'))}</span>
        <span class="gs-sub">${esc(e.vaultName)}${e.data.username ? ' · ' + esc(e.data.username) : ''}</span>
      </span>
    </div>`).join('');
  results.querySelectorAll('.gs-row').forEach(row => {
    // pointerdown fires before the input's blur, so the click isn't lost.
    row.addEventListener('pointerdown', (ev) => {
      ev.preventDefault();
      hideGlobalSearch(true);
      openVaultItem(row.dataset.vault, row.dataset.item);
    });
  });
}

// --- Command palette (Cmd/Ctrl+K) ---
let cmdIndex = [];   // cached { vaultId, vaultName, id, data } across all vaults
let cmdList = [];     // currently visible palette rows
let cmdSel = 0;

function cmdActions() {
  return [
    { kind: 'action', icon: icon('plus', { size: 15 }), label: t('form.newItem'), run: () => { closeCmdPalette(); document.getElementById('btn-add-item').click(); } },
    { kind: 'action', icon: icon('vault', { size: 15 }), label: t('vault.new'), run: () => { closeCmdPalette(); openModal('modal-vault'); } },
    { kind: 'action', icon: icon('shield', { size: 15 }), label: t('sidebar.watchtower'), run: () => { closeCmdPalette(); openWatchtower(); } },
    { kind: 'action', icon: icon('sparkles', { size: 15 }), label: t('sidebar.generator'), run: () => { closeCmdPalette(); openGenerator(); } },
    { kind: 'action', icon: icon('moon', { size: 15 }), label: t('cmd.toggleTheme'), run: () => { toggleTheme(); } },
    { kind: 'action', icon: icon('lock', { size: 15 }), label: t('sidebar.lockVault'), run: () => { closeCmdPalette(); lockVault(); } },
  ];
}

async function openCmdPalette() {
  const overlay = document.getElementById('cmd-palette');
  if (!overlay || !encKey) return;
  overlay.classList.add('active');
  const input = document.getElementById('cmd-input');
  input.value = '';
  document.getElementById('cmd-results').innerHTML = `<div class="cmd-loading">${esc(t('cmd.indexing'))}</div>`;
  cmdIndex = await collectAllItems();
  renderCmdResults('');
  input.focus();
}

function closeCmdPalette() {
  const overlay = document.getElementById('cmd-palette');
  if (overlay) overlay.classList.remove('active');
}

function renderCmdResults(query) {
  const q = query.trim().toLowerCase();
  const matches = (q
    ? cmdIndex.filter(e =>
        (e.data.title || '').toLowerCase().includes(q) ||
        (e.data.username || '').toLowerCase().includes(q) ||
        (e.data.url || '').toLowerCase().includes(q) ||
        (e.vaultName || '').toLowerCase().includes(q))
    : cmdIndex.slice(0, 8)
  ).slice(0, 25);

  const itemRows = matches.map(e => ({
    kind: 'item',
    icon: typeIconHtml(itemType(e.data), 15),
    title: e.data.title || t('items.untitled'),
    sub: e.vaultName + (e.data.username ? ' · ' + e.data.username : ''),
    run: () => { closeCmdPalette(); openVaultItem(e.vaultId, e.id); },
  }));
  const actions = cmdActions().filter(a => !q || a.label.toLowerCase().includes(q));
  cmdList = [...itemRows, ...actions];
  cmdSel = 0;
  paintCmd();
}

function paintCmd() {
  const results = document.getElementById('cmd-results');
  if (!cmdList.length) { results.innerHTML = `<div class="cmd-empty">${esc(t('cmd.noMatches'))}</div>`; return; }
  results.innerHTML = cmdList.map((e, i) => `
    <div class="cmd-row${i === cmdSel ? ' active' : ''}" data-i="${i}">
      <span class="cmd-icon">${e.icon || '•'}</span>
      <span class="cmd-main"><span class="cmd-title">${esc(e.title || e.label)}</span>${e.sub ? `<span class="cmd-sub">${esc(e.sub)}</span>` : ''}</span>
      ${e.kind === 'action' ? `<span class="cmd-tag">${esc(t('cmd.action'))}</span>` : ''}
    </div>`).join('');
  results.querySelectorAll('.cmd-row').forEach(row => {
    const i = Number(row.dataset.i);
    row.addEventListener('click', () => { cmdSel = i; cmdList[i].run(); });
    row.addEventListener('mousemove', () => { if (cmdSel !== i) { cmdSel = i; paintCmd(); } });
  });
  const active = results.querySelector('.cmd-row.active');
  if (active) active.scrollIntoView({ block: 'nearest' });
}

function cmdKeydown(e) {
  if (e.key === 'ArrowDown') { e.preventDefault(); cmdSel = Math.min(cmdSel + 1, cmdList.length - 1); paintCmd(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); cmdSel = Math.max(cmdSel - 1, 0); paintCmd(); }
  else if (e.key === 'Enter') { e.preventDefault(); if (cmdList[cmdSel]) cmdList[cmdSel].run(); }
  else if (e.key === 'Escape') { closeCmdPalette(); }
}

// --- Security dashboard (Watchtower-style) ---
async function openWatchtower() {
  if (!encKey) return;
  openModal('modal-watchtower');
  const body = document.getElementById('watchtower-body');
  body.innerHTML = `<div class="cmd-loading">${esc(t('watchtower.scanning'))}</div>`;

  const all = await collectAllItems();
  const logins = all.filter(e => itemType(e.data) === 'login' && e.data.password);

  const byPw = {};
  for (const e of logins) (byPw[e.data.password] = byPw[e.data.password] || []).push(e);
  const reused = Object.values(byPw).filter(g => g.length > 1);

  const weak = logins.filter(e => estimateStrength(e.data.password).score <= 1);

  const YEAR = 365 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const stale = logins.filter(e => e.data.pwChangedAt && (now - e.data.pwChangedAt) > YEAR);

  // Duplicate items (same title + username + site) across all vaults.
  const dups = findDuplicateGroups(all);

  renderWatchtower({ total: logins.length, weak, reused, stale, dups });
  checkWatchtowerBreaches(logins);
}

function wtItemRow(e, extra = '') {
  return `<div class="wt-item" data-vault="${e.vaultId}" data-item="${e.id}">
    <span class="cmd-icon">${itemIconHtml(e.data, 14)}</span>
    <span class="cmd-main"><span class="cmd-title">${esc(e.data.title || t('items.untitled'))}</span>
      <span class="cmd-sub">${esc(e.vaultName)}${e.data.username ? ' · ' + esc(e.data.username) : ''}${extra}</span></span>
  </div>`;
}

function wtSection(title, entries, severity, note) {
  if (!entries.length) return '';
  return `<div class="wt-section wt-${severity}">
    <div class="wt-head"><span class="wt-badge">${entries.length}</span> ${esc(title)}<span class="wt-note">${esc(note || '')}</span></div>
    <div class="wt-list">${entries.map(e => wtItemRow(e)).join('')}</div>
  </div>`;
}

function wtGroupSection(title, groups, severity, note) {
  if (!groups.length) return '';
  const groupsHtml = groups.map(g =>
    `<div class="wt-group">${g.map(e => wtItemRow(e)).join('')}</div>`).join('');
  return `<div class="wt-section wt-${severity}">
    <div class="wt-head"><span class="wt-badge">${groups.length}</span> ${esc(title)}<span class="wt-note">${esc(note || '')}</span></div>
    ${groupsHtml}</div>`;
}

function renderWatchtower(r) {
  const body = document.getElementById('watchtower-body');
  const clean = !r.weak.length && !r.reused.length && !r.stale.length && !r.dups.length;
  let html = `<div class="wt-summary">${esc(t('watchtower.summary', { logins: r.total, vaults: vaults.length }))}</div>`;
  if (clean) html += `<div class="wt-allclear">${icon('check', { size: 14 })} ${esc(t('watchtower.allClear'))}</div>`;
  html += wtSection(t('watchtower.weak'), r.weak, 'bad', t('watchtower.weak.note'));
  html += wtGroupSection(t('watchtower.reused'), r.reused, 'warn', t('watchtower.reused.note'));
  html += wtSection(t('watchtower.aging'), r.stale, 'warn', t('watchtower.aging.note'));
  html += wtGroupSection(t('watchtower.duplicates'), r.dups, 'warn', t('watchtower.duplicates.note'));
  html += `<div id="wt-breaches"><div class="cmd-loading">${esc(t('watchtower.breaches.checking'))}</div></div>`;
  body.innerHTML = html;
  wireWatchtowerNav(body);
}

async function checkWatchtowerBreaches(logins) {
  const el = document.getElementById('wt-breaches');
  if (!el) return;
  const breached = [];
  const seen = {}; // memoize identical passwords to cut network calls
  for (const e of logins) {
    const p = e.data.password;
    try {
      if (!(p in seen)) seen[p] = await checkPwnedCount(p);
    } catch {
      el.innerHTML = `<div class="wt-note">${esc(t('watchtower.breaches.unavailable'))}</div>`;
      return;
    }
    if (seen[p] > 0) breached.push({ ...e, _count: seen[p] });
  }
  if (!breached.length) {
    el.innerHTML = `<div class="wt-allclear">${icon('check', { size: 14 })} ${esc(t('watchtower.breaches.none'))}</div>`;
    return;
  }
  el.innerHTML = `<div class="wt-section wt-bad">
    <div class="wt-head"><span class="wt-badge">${breached.length}</span> ${esc(t('watchtower.breaches'))}<span class="wt-note">${esc(t('watchtower.breaches.note'))}</span></div>
    <div class="wt-list">${breached.map(e => wtItemRow(e, ' · ' + esc(t('watchtower.breaches.count', { count: e._count.toLocaleString(getLocale()) })))).join('')}</div>
  </div>`;
  wireWatchtowerNav(el);
}

function wireWatchtowerNav(root) {
  root.querySelectorAll('.wt-item').forEach(row => {
    row.addEventListener('click', () => {
      closeModal('modal-watchtower');
      openVaultItem(row.dataset.vault, row.dataset.item);
    });
  });
}

// --- Password generator modal ---
let generatorTarget = null; // input id to fill when opened from a form, else null

function openGenerator(targetId = null) {
  generatorTarget = targetId;
  openModal('modal-generator');
  const useBtn = document.getElementById('btn-gen-use');
  if (useBtn) useBtn.style.display = targetId ? 'flex' : 'none';
  refreshGenerator();
}

function useGenerated() {
  const pw = document.getElementById('gen-output').textContent;
  if (generatorTarget) {
    const el = document.getElementById(generatorTarget);
    if (el) { el.value = pw; renderStrengthInto('item-pw-strength', pw); }
  }
  closeModal('modal-generator');
}

// --- Copy / reveal event delegation (detail panel, history modal, shared item) ---
function wireCopyReveal(root) {
  if (!root || root._copyWired) return;
  root._copyWired = true;
  root.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('.js-copy');
    if (copyBtn) {
      let text;
      if (copyBtn.dataset.copy === 'totp') {
        text = (document.getElementById('detail-totp-code')?.textContent || '').replace(/\s/g, '');
      } else {
        text = decodeURIComponent(copyBtn.dataset.copy || '');
      }
      navigator.clipboard.writeText(text).then(() => toast(t('toast.copied')));
      return;
    }
    const reveal = e.target.closest('.js-reveal');
    if (reveal) {
      const valEl = reveal.closest('.field, .mini-field')?.querySelector('.field-value, .mini-value');
      if (valEl) {
        const sz = reveal.closest('.mini-field') ? 14 : 15;
        if (valEl.classList.contains('masked')) {
          valEl.textContent = decodeURIComponent(valEl.dataset.raw || '');
          valEl.classList.remove('masked');
          reveal.innerHTML = icon('eyeOff', { size: sz });
        } else {
          valEl.textContent = '••••••••••';
          valEl.classList.add('masked');
          reveal.innerHTML = icon('eye', { size: sz });
        }
      }
      return;
    }
    const tag = e.target.closest('.tag-chip');
    if (tag && currentVault) {
      activeTag = tag.dataset.tag;
      renderTagBar();
      renderFilteredItems();
      closeMobileDetail();
    }
  });
}

// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', async () => {
  // i18n first: resolve locale, inject flat SVG icons, translate static markup.
  initI18n();
  document.documentElement.lang = getLocale();
  document.querySelectorAll('[data-icon]').forEach(el => {
    el.innerHTML = icon(el.dataset.icon, { size: Number(el.dataset.iconSize) || 16 });
  });
  applyI18n();

  // Language selector (ES/EN/FR) in the sidebar footer.
  const localeSel = document.getElementById('locale-select');
  LOCALES.forEach(l => {
    const opt = document.createElement('option');
    opt.value = l;
    opt.textContent = l.toUpperCase();
    localeSel.appendChild(opt);
  });
  localeSel.value = getLocale();
  localeSel.addEventListener('change', () => {
    setLocale(localeSel.value);
    location.reload();
  });

  // Skin selector (Light / Orange) in the sidebar footer — applies instantly.
  const skinSel = document.getElementById('skin-select');
  if (skinSel) {
    skinSel.value = currentSkin();
    skinSel.addEventListener('change', () => applySkin(skinSel.value));
  }

  // Global settings (admin-only; the button is unhidden by refreshAdminUI)
  document.getElementById('btn-global-settings').addEventListener('click', openGlobalSettings);
  document.getElementById('btn-save-global-settings').addEventListener('click', saveGlobalSettings);
  document.getElementById('btn-cancel-global-settings').addEventListener('click', () => closeModal('modal-global-settings'));

  renderVersion();
  // Sync the theme button label (translated) with the already-applied theme.
  applyTheme(currentTheme());

  // Auth
  document.getElementById('btn-login').addEventListener('click', login);
  document.getElementById('btn-signup').addEventListener('click', signup);
  document.getElementById('btn-show-signup').addEventListener('click', () => showAuthScreen('signup'));
  document.getElementById('btn-show-login').addEventListener('click', () => showAuthScreen('login'));
  document.getElementById('btn-logout').addEventListener('click', logout);

  // Enter key support
  document.getElementById('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  document.getElementById('signup-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') signup(); });

  // Search (per-vault filter)
  document.getElementById('search-input').addEventListener('input', e => {
    searchQuery = e.target.value;
    if (currentVault && sidebarMode === 'vaults') {
      renderFilteredItems();
    }
  });

  // Global search (all vaults, sidebar)
  const gsInput = document.getElementById('global-search-input');
  gsInput.addEventListener('input', () => {
    const q = gsInput.value.trim();
    if (q.length < 2) { hideGlobalSearch(); return; }
    runGlobalSearch(q);
  });
  gsInput.addEventListener('keydown', e => {
    if (e.key === 'Escape') { hideGlobalSearch(); gsInput.blur(); }
  });
  gsInput.addEventListener('blur', () => setTimeout(() => hideGlobalSearch(), 150));

  // Sidebar add buttons
  document.getElementById('btn-sidebar-add-vault').addEventListener('click', () => openModal('modal-vault'));
  document.getElementById('btn-sidebar-add-team').addEventListener('click', () => openModal('modal-team'));

  // Vault modal
  document.getElementById('btn-save-vault').addEventListener('click', createVault);
  document.getElementById('btn-cancel-vault').addEventListener('click', () => closeModal('modal-vault'));
  document.getElementById('vault-name-input').addEventListener('keydown', e => { if (e.key === 'Enter') createVault(); });

  // Items
  document.getElementById('btn-add-item').addEventListener('click', () => {
    if (!currentVault) return toast(t('toast.selectVaultFirst'), true);
    editingItem = null;
    document.getElementById('modal-item-title').textContent = t('form.newItem');
    clearItemForm();
    openModal('modal-item');
  });
  document.getElementById('btn-save-item').addEventListener('click', saveItem);
  document.getElementById('btn-cancel-item').addEventListener('click', () => { closeModal('modal-item'); clearItemForm(); });
  document.getElementById('btn-gen-pw').addEventListener('click', () => openGenerator('item-pw-input'));

  // Item type selector tabs
  document.querySelectorAll('#item-type-selector .type-tab').forEach(tab => {
    tab.addEventListener('click', () => setItemFormType(tab.dataset.type));
  });
  // Live strength meter while typing a password
  document.getElementById('item-pw-input').addEventListener('input', e => {
    renderStrengthInto('item-pw-strength', e.target.value);
  });

  // Item form: attachments + custom fields
  document.getElementById('item-attachment-input').addEventListener('change', async (e) => {
    const files = [...(e.target.files || [])];
    e.target.value = '';
    await addFormAttachments(files);
  });
  document.getElementById('item-attachments-list').addEventListener('click', (e) => {
    const btn = e.target.closest('.js-remove-att');
    if (!btn) return;
    formAttachments.splice(Number(btn.dataset.i), 1);
    renderFormAttachments();
  });
  document.getElementById('btn-add-custom-field').addEventListener('click', () => addCustomFieldRow());

  // Detail actions (favorite / share / edit / delete / history / breach check)
  wireCopyReveal(document.getElementById('detail-content'));
  document.getElementById('btn-fav-item').addEventListener('click', toggleFavorite);
  document.getElementById('btn-item-history').addEventListener('click', showItemHistory);
  document.getElementById('btn-check-breach').addEventListener('click', checkCurrentBreach);
  document.getElementById('btn-share-item').addEventListener('click', openShareModal);

  document.getElementById('btn-edit-item').addEventListener('click', () => {
    if (!currentItem || !currentItem._data) return;
    editingItem = currentItem;
    document.getElementById('modal-item-title').textContent = t('form.editItem');
    fillItemForm(currentItem._data);
    openModal('modal-item');
  });

  document.getElementById('btn-delete-item').addEventListener('click', deleteCurrentItem);

  // Share modal
  document.getElementById('btn-create-share').addEventListener('click', createShareLink);
  document.getElementById('btn-close-share').addEventListener('click', () => closeModal('modal-share'));
  document.getElementById('btn-copy-share').addEventListener('click', () => {
    const url = document.getElementById('share-url-input').value;
    if (url) navigator.clipboard.writeText(url).then(() => toast(t('toast.copied'))).catch(() => toast(t('toast.copyFailed'), true));
  });
  document.getElementById('share-links-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('.js-revoke-share');
    if (!btn) return;
    try {
      await api('DELETE', `/api/share-links/${btn.dataset.shareId}`);
      toast(t('share.revoked'));
      loadShareLinks();
    } catch (err) { toast(err.message, true); }
  });

  // History modal: view (read-only mini detail) + restore (prefill edit form)
  const historyBody = document.getElementById('history-body');
  wireCopyReveal(historyBody);
  historyBody.addEventListener('click', (e) => {
    const viewBtn = e.target.closest('.js-hist-view');
    if (viewBtn) {
      const i = Number(viewBtn.dataset.i);
      const mini = historyBody.querySelector(`[data-mini="${i}"]`);
      if (mini) {
        if (mini.style.display === 'none') {
          mini.innerHTML = miniDetailHtml(historyEntries[i]?.data || {});
          mini.style.display = 'block';
        } else {
          mini.style.display = 'none';
          mini.innerHTML = '';
        }
      }
      return;
    }
    const restoreBtn = e.target.closest('.js-hist-restore');
    if (restoreBtn) {
      const h = historyEntries[Number(restoreBtn.dataset.i)];
      if (!h || !currentItem) return;
      editingItem = currentItem;
      document.getElementById('modal-item-title').textContent = t('form.editItem');
      fillItemForm(h.data);
      closeModal('modal-history');
      openModal('modal-item');
    }
  });
  document.getElementById('btn-close-history').addEventListener('click', () => {
    closeModal('modal-history');
    historyEntries = [];
    historyBody.innerHTML = '';
  });

  // Generator modal
  document.querySelectorAll('input[name="gen-mode"]').forEach(r => r.addEventListener('change', refreshGenerator));
  ['gen-length', 'gen-words'].forEach(id => document.getElementById(id).addEventListener('input', refreshGenerator));
  ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols', 'gen-avoid', 'gen-cap', 'gen-num'].forEach(id =>
    document.getElementById(id).addEventListener('change', refreshGenerator));
  document.getElementById('btn-gen-refresh').addEventListener('click', refreshGenerator);
  document.getElementById('btn-gen-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('gen-output').textContent).then(() => toast(t('toast.copied')));
  });
  document.getElementById('btn-gen-use').addEventListener('click', useGenerated);
  document.getElementById('btn-gen-close').addEventListener('click', () => closeModal('modal-generator'));

  // Sidebar tools: generator, security dashboard, theme, lock
  document.getElementById('btn-tool-generator').addEventListener('click', () => openGenerator());
  document.getElementById('btn-tool-watchtower').addEventListener('click', openWatchtower);
  document.getElementById('btn-theme').addEventListener('click', toggleTheme);
  document.getElementById('btn-lock').addEventListener('click', lockVault);

  // Linked devices modal (QR pairing)
  document.getElementById('btn-link-device').addEventListener('click', openDevicesModal);
  document.getElementById('btn-create-device').addEventListener('click', createDevice);
  document.getElementById('device-name-input').addEventListener('keydown', e => { if (e.key === 'Enter') createDevice(); });
  document.getElementById('btn-close-devices').addEventListener('click', () => {
    closeModal('modal-devices');
    resetDevicesModal(); // don't leave the one-time token in the DOM
  });
  document.getElementById('device-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('.js-revoke-device');
    if (!btn) return;
    if (!confirm(t('devices.revokeConfirm', { name: btn.dataset.deviceName }))) return;
    try {
      await api('DELETE', `/api/devices/${btn.dataset.deviceId}`);
      toast(t('devices.revoked'));
      loadDevices();
    } catch (err) { toast(err.message, true); }
  });

  // Lock screen unlock
  document.getElementById('btn-unlock').addEventListener('click', unlockVault);
  document.getElementById('lock-password').addEventListener('keydown', e => { if (e.key === 'Enter') unlockVault(); });
  document.getElementById('btn-lock-logout').addEventListener('click', logout);

  // Command palette
  document.getElementById('cmd-input').addEventListener('input', e => renderCmdResults(e.target.value));
  document.getElementById('cmd-input').addEventListener('keydown', cmdKeydown);
  document.getElementById('cmd-palette').addEventListener('click', e => {
    if (e.target.id === 'cmd-palette') closeCmdPalette();
  });
  document.getElementById('btn-watchtower-close').addEventListener('click', () => closeModal('modal-watchtower'));

  // Global shortcuts: Cmd/Ctrl+K opens palette, Escape closes overlays
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      const overlay = document.getElementById('cmd-palette');
      if (overlay.classList.contains('active')) closeCmdPalette(); else openCmdPalette();
    } else if (e.key === 'Escape') {
      closeCmdPalette();
      document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
    }
  });

  // Teams
  document.getElementById('btn-save-team').addEventListener('click', createTeam);
  document.getElementById('btn-cancel-team').addEventListener('click', () => closeModal('modal-team'));
  document.getElementById('team-name-input').addEventListener('keydown', e => { if (e.key === 'Enter') createTeam(); });

  // Team detail
  document.getElementById('btn-team-add-member').addEventListener('click', () => openModal('modal-add-member'));
  document.getElementById('btn-save-member').addEventListener('click', addTeamMember);
  document.getElementById('btn-cancel-member').addEventListener('click', () => closeModal('modal-add-member'));
  document.getElementById('member-email-input').addEventListener('keydown', e => { if (e.key === 'Enter') addTeamMember(); });

  document.getElementById('btn-team-add-vault').addEventListener('click', () => openModal('modal-team-vault'));
  document.getElementById('btn-save-team-vault').addEventListener('click', createTeamVault);
  document.getElementById('btn-cancel-team-vault').addEventListener('click', () => closeModal('modal-team-vault'));
  document.getElementById('team-vault-name-input').addEventListener('keydown', e => { if (e.key === 'Enter') createTeamVault(); });

  // Close modals on overlay click
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) closeModal(overlay.id);
    });
  });

  // Mobile: create sidebar overlay element
  const sidebarOverlay = document.createElement('div');
  sidebarOverlay.id = 'sidebar-overlay';
  sidebarOverlay.className = 'sidebar-overlay';
  sidebarOverlay.addEventListener('click', closeMobileSidebar);
  document.body.appendChild(sidebarOverlay);

  // Mobile: add menu button to item-list header
  const searchHeader = document.querySelector('.item-list-header');
  const menuBtn = document.createElement('button');
  menuBtn.className = 'mobile-menu-btn';
  menuBtn.innerHTML = '&#9776;';
  menuBtn.addEventListener('click', openMobileSidebar);
  searchHeader.insertBefore(menuBtn, searchHeader.firstChild);

  // Mobile: add back button to detail panel
  const detailPanel = document.querySelector('.detail-panel');
  const backRow = document.createElement('div');
  backRow.className = 'mobile-back-row';
  backRow.innerHTML = `<button class="btn-icon" id="btn-mobile-back-detail">&larr;</button><h2>${esc(t('detail.title'))}</h2>`;
  detailPanel.insertBefore(backRow, detailPanel.firstChild);
  document.getElementById('btn-mobile-back-detail').addEventListener('click', closeMobileDetail);

  // Import
  let parsedImportItems = [];

  document.getElementById('btn-import-items').addEventListener('click', () => {
    if (!currentVault) return toast(t('toast.selectVaultFirst'), true);
    resetImportModal();
    openModal('modal-import');
  });

  document.getElementById('import-file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    document.getElementById('import-file-label-text').textContent = file.name;
    document.getElementById('import-file-label').classList.add('has-file');

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const result = detectFormatAndParse(reader.result, file.name);
        parsedImportItems = result;

        if (parsedImportItems.length === 0) {
          document.getElementById('import-preview').style.display = 'block';
          document.getElementById('import-preview-text').textContent = t('import.noItems');
          document.getElementById('btn-start-import').disabled = true;
          return;
        }

        const ext = file.name.split('.').pop().toLowerCase();
        const format = ext === '1pif' ? '1PIF' : 'CSV';
        document.getElementById('import-preview').style.display = 'block';
        document.getElementById('import-preview-text').textContent =
          t('import.found', { count: parsedImportItems.length, format });
        document.getElementById('btn-start-import').disabled = false;
      } catch (err) {
        document.getElementById('import-errors-preview').style.display = 'block';
        document.getElementById('import-errors-preview').textContent = 'Error: ' + err.message;
        document.getElementById('btn-start-import').disabled = true;
        parsedImportItems = [];
      }
    };
    reader.readAsText(file);
  });

  document.getElementById('btn-start-import').addEventListener('click', () => importItems(parsedImportItems));
  document.getElementById('btn-cancel-import').addEventListener('click', () => { closeModal('modal-import'); resetImportModal(); });
  document.getElementById('btn-close-import').addEventListener('click', () => { closeModal('modal-import'); resetImportModal(); });

  // Recovery key buttons
  document.getElementById('btn-show-recover').addEventListener('click', () => showAuthScreen('recover'));
  document.getElementById('btn-recover-back-login').addEventListener('click', () => showAuthScreen('login'));
  document.getElementById('btn-recover').addEventListener('click', recover);
  document.getElementById('recover-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') recover(); });
  document.getElementById('btn-copy-recovery-key').addEventListener('click', () => {
    const key = document.getElementById('recovery-key-display').textContent;
    navigator.clipboard.writeText(key).then(() => toast(t('toast.copied'))).catch(() => toast(t('toast.copyFailed'), true));
  });
  document.getElementById('recovery-key-saved-checkbox').addEventListener('change', e => {
    document.getElementById('btn-recovery-key-continue').disabled = !e.target.checked;
  });
  document.getElementById('btn-recovery-key-continue').addEventListener('click', () => {
    if (recoveryKeyContinueCallback) recoveryKeyContinueCallback();
  });

  // IAP buttons
  document.getElementById('btn-iap-unlock').addEventListener('click', iapUnlock);
  document.getElementById('btn-iap-setup').addEventListener('click', iapSetup);
  document.getElementById('iap-unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') iapUnlock(); });
  document.getElementById('iap-setup-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') iapSetup(); });

  // Register service worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js');
  }

  // Routing: handle hash changes
  window.addEventListener('hashchange', () => handleRoute());

  // Detect auth mode and initialize. Share links (#/share/...) bypass auth
  // entirely — the recipient may have no account.
  iapMode = await detectAuthMode();
  if (parseShareHash(location.hash)) {
    await handleRoute();
  } else if (iapMode) {
    await initIAPSession();
  } else {
    handleRoute();
  }
});
