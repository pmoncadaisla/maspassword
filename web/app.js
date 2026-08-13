import { SRPClient, generateVerifier } from '/srp.js';
import { deriveKey, encrypt, decrypt, generatePassword, generateKeyPair, encryptPrivateKey, decryptPrivateKey, encryptWithPublicKey, decryptWithPrivateKey, generateVaultKey, importVaultKey, generateTOTP, generateRecoveryKey, deriveRecoveryKey } from '/crypto.js';
import { generatePassword as genAdvanced, generatePassphrase, passwordEntropyBits } from '/generator.js';
import { estimateStrength } from '/strength.js';
import { checkPwnedCount } from '/breach.js';
import { detectFormatAndParse } from '/import.js';

// --- Item types (1Password-style) ---
const ITEM_TYPES = {
  login:    { label: 'Login',        icon: '\u{1F511}' },  // 🔑
  card:     { label: 'Credit Card',  icon: '\u{1F4B3}' },  // 💳
  note:     { label: 'Secure Note',  icon: '\u{1F4DD}' },  // 📝
  identity: { label: 'Identity',     icon: '\u{1F464}' },  // 👤
};
function itemType(data) { return ITEM_TYPES[data?.type] ? data.type : 'login'; }

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
  if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
  return data;
}

// --- Navigation ---
function showAuthScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + id).classList.add('active');
  document.getElementById('main-app').style.display = 'none';
  setHash('/' + id);
}

function showMainApp() {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('main-app').style.display = 'grid';
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
    toast('Vault not found', true);
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
  }
}

async function navigateToItem(itemId) {
  if (!currentVault) return;

  // Items should already be loaded by navigateToVault
  const item = items.find(i => i.id === itemId);
  if (!item) {
    toast('Item not found', true);
    setHash(`/vault/${currentVault.id}`);
    return;
  }

  await openItemDirect(itemId);
}

async function navigateToTeam(teamId) {
  let team = teams.find(t => t.id === teamId);
  if (!team) {
    await loadTeams();
    renderSidebar();
    team = teams.find(t => t.id === teamId);
  }
  if (!team) {
    toast('Team not found', true);
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

  if (!email || !pw) return toast('Fill all fields', true);
  if (pw !== confirm) return toast('Passwords do not match', true);
  if (pw.length < 8) return toast('Password must be at least 8 characters', true);

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
    toast('Account created!');
    showRecoveryKeyScreen(recoveryKey, () => {
      showAuthScreen('login');
      document.getElementById('login-email').value = email;
    });
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
}

async function login() {
  const email = document.getElementById('login-email').value.trim();
  const pw = document.getElementById('login-password').value;
  if (!email || !pw) return toast('Fill all fields', true);

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
    toast('Logged in');
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
    toast('Login failed: ' + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Log in';
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

// Lock: wipe decryption keys and plaintext caches from memory, show the lock screen.
// The JWT session token is preserved so unlocking is a local key re-derivation.
function lockVault() {
  if (!lockContext) return; // nothing to lock
  encKey = null;
  privateKey = null;
  vaultKeyCache = {};
  decryptedItemsCache = [];
  currentItem = null;
  stopAutoLock();
  stopTOTP();
  closeCmdPalette();
  // Dismiss any open overlay (item form, watchtower, generator, history) so it
  // can't float over the lock screen with plaintext still visible.
  document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
  // Scrub decrypted plaintext out of the (about-to-be-hidden) DOM — item titles,
  // usernames, revealed passwords, breach results and tag chips.
  ['item-list', 'detail-fields', 'detail-meta', 'detail-breach-result', 'tag-bar']
    .forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
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
    if (currentVault) { await loadItems(); setHash(`/vault/${currentVault.id}`); }
    else setHash('/');
    toast('Unlocked');
    document.getElementById('lock-password').value = '';
  } catch {
    toast('Wrong master password', true);
    encKey = null;
    privateKey = null;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
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
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#0d1117' : '#10a37f');
  const btn = document.getElementById('btn-theme');
  if (btn) btn.textContent = theme === 'dark' ? '☀️ Light mode' : '\u{1F319} Dark mode';
}
function toggleTheme() {
  applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
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
function renderStrengthInto(containerId, password) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!password) { el.innerHTML = ''; return; }
  const s = estimateStrength(password);
  const pct = Math.max(6, Math.round((s.score + 1) / 5 * 100));
  const cls = ['vw', 'w', 'f', 's', 'vs'][s.score] || 'w';
  const detail = s.crackTimeDisplay ? `· cracks in ~${esc(s.crackTimeDisplay)}` : '';
  el.innerHTML = `
    <div class="strength-bar"><div class="strength-fill strength-${cls}" style="width:${pct}%"></div></div>
    <div class="strength-label">${esc(s.label)} <span class="strength-detail">${Math.round(s.entropyBits)} bits ${detail}</span></div>`;
}

// --- IAP Authentication ---
async function detectAuthMode() {
  try {
    const res = await fetch('/auth/mode');
    const data = await res.json();
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
  if (!pw) return toast('Enter your master password', true);

  const btn = document.getElementById('btn-iap-unlock');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';

  try {
    encKey = await deriveKey(pw, iapSession.email);

    // Try to decrypt private key to verify password
    privateKey = await decryptPrivateKey(encKey, iapSession.encrypted_private_key);

    lockContext = { email: iapSession.email, encryptedPrivateKey: iapSession.encrypted_private_key };
    startAutoLock();
    toast('Vault unlocked');
    await Promise.all([loadVaults(), loadTeams()]);
    showMainApp();
    renderSidebar();
    setHash('/');
  } catch (e) {
    toast('Wrong master password', true);
    encKey = null;
    privateKey = null;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

async function iapSetup() {
  const pw = document.getElementById('iap-setup-password').value;
  const confirm = document.getElementById('iap-setup-confirm').value;

  if (!pw) return toast('Enter a master password', true);
  if (pw !== confirm) return toast('Passwords do not match', true);
  if (pw.length < 8) return toast('Password must be at least 8 characters', true);

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
    toast('Encryption set up successfully');
    await Promise.all([loadVaults(), loadTeams()]);

    showRecoveryKeyScreen(recoveryKey, () => {
      showMainApp();
      renderSidebar();
      setHash('/');
    });
  } catch (e) {
    toast('Setup failed: ' + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Set Up Encryption';
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

  if (!email || !recoveryKeyInput || !pw) return toast('Fill all fields', true);
  if (pw !== confirm) return toast('Passwords do not match', true);
  if (pw.length < 8) return toast('Password must be at least 8 characters', true);

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
      throw new Error('Invalid recovery key');
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

    toast('Password reset successful!');
    showRecoveryKeyScreen(newRecoveryKey, () => {
      showAuthScreen('login');
      document.getElementById('login-email').value = email;
    });
  } catch (e) {
    toast('Recovery failed: ' + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Reset Password';
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
    const sharedBadge = v.team_id ? '<span class="badge-shared">&#128101;</span>' : '';
    const activeClass = currentVault && currentVault.id === v.id && sidebarMode === 'vaults' ? ' active' : '';
    vaultCards.push(`<button class="sidebar-item${activeClass}" data-vault-id="${v.id}">
      <span class="sidebar-item-icon">&#128274;</span>
      <span class="sidebar-item-name">${esc(name)}</span>
      ${sharedBadge}
    </button>`);
  }
  vaultList.innerHTML = vaultCards.join('');
  vaultList.querySelectorAll('.sidebar-item').forEach(btn => {
    btn.addEventListener('click', () => selectVault(btn.dataset.vaultId));
  });

  // Render teams
  const teamCards = teams.map(t => {
    const activeClass = currentTeam && currentTeam.id === t.id && sidebarMode === 'team' ? ' active' : '';
    return `<button class="sidebar-item${activeClass}" data-team-id="${t.id}">
      <span class="sidebar-item-icon">&#128101;</span>
      <span class="sidebar-item-name">${esc(t.name)}</span>
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
  if (!name) return toast('Enter a name', true);

  try {
    const nameEnc = await encrypt(encKey, name);
    const newVault = await api('POST', '/api/vaults', { name_encrypted: nameEnc });
    closeModal('modal-vault');
    nameInput.value = '';
    await loadVaults();
    renderSidebar();
    toast('Vault created');
    if (newVault?.id) await selectVault(newVault.id);
  } catch (e) {
    toast(e.message, true);
  }
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
  const t = itemType(data);
  if (t === 'card') return data.card_number ? '•••• ' + data.card_number.replace(/\s/g, '').slice(-4) : 'Card';
  if (t === 'identity') return data.id_email || data.id_fullname || 'Identity';
  if (t === 'note') return 'Secure note';
  return data.username || '';
}

// Render the favorites/tags filter chips above the item list.
function renderTagBar() {
  const bar = document.getElementById('tag-bar');
  if (!bar) return;
  const tagSet = new Set();
  let hasFav = false;
  for (const { data } of decryptedItemsCache) {
    if (data.favorite) hasFav = true;
    (data.tags || []).forEach(t => tagSet.add(t));
  }
  const chips = [];
  if (hasFav) chips.push(`<button class="filter-chip${activeTag === '__fav__' ? ' active' : ''}" data-tag="__fav__">★ Favorites</button>`);
  for (const t of [...tagSet].sort()) {
    chips.push(`<button class="filter-chip${activeTag === t ? ' active' : ''}" data-tag="${esc(t)}">${esc(t)}</button>`);
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
    (i.data.tags || []).some(t => t.toLowerCase().includes(query)));

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
    const totpDot = data.totp_secret ? '<span class="totp-indicator" title="Has TOTP"></span>' : '';
    const favDot = data.favorite ? '<span class="fav-indicator" title="Favorite">★</span>' : '';
    return `<div class="item-card${activeClass}" data-id="${id}">
      <div class="card-icon">${ITEM_TYPES[itemType(data)].icon}</div>
      <div class="card-info">
        <h3>${esc(data.title || 'Untitled')}</h3>
        <p>${esc(itemSubtitle(data))}</p>
      </div>
      ${favDot}${totpDot}
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

// Build a single detail field row. Copy/reveal use event delegation (see wireDetailDelegation).
function fieldRow(label, value, opts = {}) {
  if (value == null || value === '') return '';
  const { mono = false, masked = false, url = false } = opts;
  const enc = encodeURIComponent(value);
  let valHtml;
  if (url) {
    const href = /^https?:\/\//i.test(value) ? value : 'https://' + value;
    valHtml = `<a class="field-value link" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(value)}</a>`;
  } else {
    valHtml = `<div class="field-value ${mono ? 'mono' : ''} ${masked ? 'masked' : ''}" data-raw="${enc}">${masked ? '••••••••••' : esc(value)}</div>`;
  }
  const reveal = masked ? `<button class="btn-icon js-reveal" title="Show">&#128065;</button>` : '';
  const copy = `<button class="btn-icon js-copy" data-copy="${enc}" title="Copy">&#128203;</button>`;
  return `<div class="field"><div class="field-main"><div class="field-label">${esc(label)}</div>${valHtml}</div><div class="field-actions">${reveal}${copy}</div></div>`;
}

function totpFieldHtml() {
  return `<div class="field" id="totp-field-container">
    <div class="field-main">
      <div class="field-label">One-Time Password</div>
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
      <button class="btn-icon js-copy" data-copy="totp" title="Copy code">&#128203;</button>
    </div>
  </div>`;
}

// Render the detail panel for any item type.
function renderDetail(data) {
  const type = itemType(data);
  document.getElementById('detail-empty').style.display = 'none';
  document.getElementById('detail-content').style.display = 'block';
  document.getElementById('detail-title').textContent = data.title || 'Untitled';

  const favBtn = document.getElementById('btn-fav-item');
  favBtn.textContent = data.favorite ? '★' : '☆';
  favBtn.classList.toggle('active', !!data.favorite);

  const tags = (data.tags || []).map(t => `<button class="tag-chip" data-tag="${esc(t)}">${esc(t)}</button>`).join('');
  document.getElementById('detail-meta').innerHTML =
    `<span class="type-badge">${ITEM_TYPES[type].icon} ${esc(ITEM_TYPES[type].label)}</span>${tags}`;

  let html = '';
  if (type === 'login') {
    html += fieldRow('Username', data.username);
    html += fieldRow('Password', data.password, { mono: true, masked: true });
    if (data.totp_secret) html += totpFieldHtml();
    html += fieldRow('Website', data.url, { url: true });
    html += fieldRow('Notes', data.notes);
  } else if (type === 'card') {
    html += fieldRow('Cardholder', data.card_holder);
    html += fieldRow('Card Number', data.card_number, { mono: true, masked: true });
    html += fieldRow('Brand', data.card_brand);
    html += fieldRow('Expires', data.card_exp, { mono: true });
    html += fieldRow('CVV', data.card_cvv, { mono: true, masked: true });
    html += fieldRow('PIN', data.card_pin, { mono: true, masked: true });
    html += fieldRow('Notes', data.notes);
  } else if (type === 'identity') {
    html += fieldRow('Full Name', data.id_fullname);
    html += fieldRow('Email', data.id_email);
    html += fieldRow('Phone', data.id_phone);
    html += fieldRow('Address', data.id_address);
    html += fieldRow('Company', data.id_company);
    html += fieldRow('Notes', data.notes);
  } else {
    html += fieldRow('Note', data.notes) ||
      `<div class="field"><div class="field-main"><div class="field-label">Note</div><div class="field-value">-</div></div></div>`;
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
    toast(data.favorite ? 'Added to favorites' : 'Removed from favorites');
    await loadItems();
    await openItem(currentItem.id);
  } catch (e) { toast(e.message, true); }
}

// Delete the currently open item (uses the DELETE endpoint).
async function deleteCurrentItem() {
  if (!currentItem) return;
  if (!confirm('Delete this item? This cannot be undone.')) return;
  try {
    await api('DELETE', `/api/vaults/${currentVault.id}/items/${currentItem.id}`);
    toast('Item deleted');
    currentItem = null;
    await loadItems();
    showDetailEmpty();
    setHash(`/vault/${currentVault.id}`);
  } catch (e) { toast(e.message, true); }
}

// Show the server-stored password history (prior encrypted versions, decrypted locally).
async function showItemHistory() {
  if (!currentItem) return;
  try {
    const history = await api('GET', `/api/vaults/${currentVault.id}/items/${currentItem.id}/history`) || [];
    const key = await getVaultDecryptionKey(currentVault);
    const rows = [];
    for (const h of history) {
      let d = {};
      try { d = JSON.parse(await decrypt(key, h.data_encrypted)); } catch {}
      const when = new Date(h.created_at).toLocaleString();
      const pw = d.password || '(no password)';
      rows.push(`<div class="history-row">
        <div class="history-meta">v${h.version} · ${esc(when)}</div>
        <div class="history-pw"><span class="mono" data-raw="${encodeURIComponent(pw)}">${esc(pw)}</span>
        <button class="btn-icon js-copy" data-copy="${encodeURIComponent(pw)}" title="Copy">&#128203;</button></div>
      </div>`);
    }
    document.getElementById('history-body').innerHTML = rows.length
      ? rows.join('') : '<p class="empty-text">No previous versions.</p>';
    openModal('modal-history');
  } catch (e) { toast(e.message, true); }
}

// Check the current password against Have I Been Pwned (k-anonymity: only a hash prefix leaves the device).
async function checkCurrentBreach() {
  if (!currentItem?._data?.password) return;
  const out = document.getElementById('detail-breach-result');
  out.innerHTML = '<span class="strength-detail">Checking…</span>';
  try {
    const count = await checkPwnedCount(currentItem._data.password);
    out.innerHTML = count > 0
      ? `<span class="breach-bad">⚠ Found in ${count.toLocaleString()} known breaches — change it.</span>`
      : `<span class="breach-ok">✓ Not found in known breaches.</span>`;
  } catch {
    out.innerHTML = '<span class="strength-detail">Breach check unavailable (offline?)</span>';
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
    document.getElementById('detail-totp-code').textContent = 'Invalid';
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

async function saveItem() {
  const title = val('item-title-input');
  if (!title) return toast('Enter a title', true);

  const tags = val('item-tags-input').split(',').map(t => t.trim()).filter(Boolean);
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
      toast('Item updated');
    } else {
      const newItem = await api('POST', `/api/vaults/${currentVault.id}/items`, { data_encrypted: dataEnc });
      if (newItem?.id) savedItemId = newItem.id;
      toast('Item saved');
    }
    closeModal('modal-item');
    clearItemForm();
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
  'item-totp-input', 'item-notes-input', 'item-tags-input',
  'item-card-holder', 'item-card-number', 'item-card-brand', 'item-card-exp',
  'item-card-cvv', 'item-card-pin',
  'item-id-fullname', 'item-id-email', 'item-id-phone', 'item-id-address', 'item-id-company',
];

function clearItemForm() {
  FORM_FIELDS.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  document.getElementById('item-fav-input').checked = false;
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
  renderStrengthInto('item-pw-strength', data.password || '');
}

// --- Teams ---
async function loadTeams() {
  teams = (await api('GET', '/api/teams')) || [];
}

async function createTeam() {
  const nameInput = document.getElementById('team-name-input');
  const name = nameInput.value.trim();
  if (!name) return toast('Enter a team name', true);

  try {
    await api('POST', '/api/teams', { name });
    closeModal('modal-team');
    nameInput.value = '';
    await loadTeams();
    renderSidebar();
    toast('Team created');
  } catch (e) {
    toast(e.message, true);
  }
}

async function loadTeamMembers() {
  const members = (await api('GET', `/api/teams/${currentTeam.id}/members`)) || [];
  const list = document.getElementById('member-list');

  if (!members.length) {
    list.innerHTML = '<p class="empty-text">No members</p>';
    return;
  }

  const myId = getCurrentUserId();
  const myMember = members.find(m => m.user_id === myId);
  const isAdmin = myMember && myMember.role === 'admin';
  const ownerId = currentTeam.owner_id;

  list.innerHTML = members.map(m => {
    const isOwner = m.user_id === ownerId;
    let actions = '';
    if (isAdmin && !isOwner) {
      if (m.role === 'member') {
        actions += `<button class="btn-icon btn-promote" data-user-id="${m.user_id}" title="Promote to admin">&#8593;</button>`;
      } else if (m.role === 'admin') {
        actions += `<button class="btn-icon btn-demote" data-user-id="${m.user_id}" title="Demote to member">&#8595;</button>`;
      }
      actions += `<button class="btn-icon btn-remove-member" data-user-id="${m.user_id}" title="Remove">&#10005;</button>`;
    }
    return `<div class="member-card">
      <div class="card-info">
        <h3>${esc(m.email)} <span class="badge-role badge-${m.role}">${m.role}</span>${isOwner ? ' <span class="badge-role badge-owner">owner</span>' : ''}${!m.has_public_key ? ' <span class="badge-role badge-pending">pending</span>' : ''}</h3>
      </div>
      ${actions}
    </div>`;
  }).join('');

  list.querySelectorAll('.btn-promote').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await api('PUT', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}/role`, { role: 'admin' });
        toast('Promoted to admin');
        await loadTeamMembers();
      } catch (e) { toast(e.message, true); }
    });
  });

  list.querySelectorAll('.btn-demote').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await api('PUT', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}/role`, { role: 'member' });
        toast('Demoted to member');
        await loadTeamMembers();
      } catch (e) { toast(e.message, true); }
    });
  });

  list.querySelectorAll('.btn-remove-member').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('Remove this member?')) return;
      try {
        await api('DELETE', `/api/teams/${currentTeam.id}/members/${btn.dataset.userId}`);
        toast('Member removed');
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
    list.innerHTML = '<p class="empty-text">No vaults</p>';
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
      <div class="card-icon">&#128274;</div>
      <div class="card-info">
        <h3>${esc(name)}</h3>
        <p>${new Date(v.created_at).toLocaleDateString()}</p>
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
  if (!email) return toast('Enter an email', true);

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
    toast(shared ? 'Member added' : 'Member invited (pending encryption setup)');
  } catch (e) {
    toast(e.message, true);
  }
}

async function createTeamVault() {
  const nameInput = document.getElementById('team-vault-name-input');
  const name = nameInput.value.trim();
  if (!name) return toast('Enter a name', true);

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
    toast('Team vault created');
  } catch (e) {
    toast(e.message, true);
  }
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
  d.textContent = s;
  return d.innerHTML;
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
  navigator.clipboard.writeText(text).then(() => toast('Copied'));
};

// --- Import (1Password CSV + 1PIF) ---
// Pure parsers live in /import.js (unit-tested); importItems below
// handles the DOM + per-item encryption/upload.

async function importItems(parsedItems) {
  if (!currentVault) return toast('Select a vault first', true);
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
        `${i + 1} of ${total} items processed...`;
    }
  } catch (err) {
    toast('Import failed: ' + err.message, true);
    resetImportModal();
    closeModal('modal-import');
    return;
  }

  // Show results step
  document.getElementById('import-step-progress').style.display = 'none';
  document.getElementById('import-step-results').style.display = 'block';

  let summary = `${imported} of ${total} item(s) imported successfully.`;
  if (errors.length) {
    summary += `\n${errors.length} error(s).`;
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
  await loadItems();
}

function resetImportModal() {
  document.getElementById('import-step-select').style.display = 'block';
  document.getElementById('import-step-progress').style.display = 'none';
  document.getElementById('import-step-results').style.display = 'none';
  document.getElementById('import-file-input').value = '';
  document.getElementById('import-file-label-text').textContent = 'Choose file...';
  document.getElementById('import-file-label').classList.remove('has-file');
  document.getElementById('import-preview').style.display = 'none';
  document.getElementById('import-errors-preview').style.display = 'none';
  document.getElementById('import-errors-preview').textContent = '';
  document.getElementById('import-progress-bar').style.width = '0%';
  document.getElementById('import-progress-text').textContent = '0 of 0 items processed...';
  document.getElementById('import-results-summary').textContent = '';
  document.getElementById('import-results-errors').style.display = 'none';
  document.getElementById('import-results-errors').innerHTML = '';
  document.getElementById('btn-start-import').disabled = true;
}

// --- Global index (all vaults), used by command palette + security dashboard ---
// Decrypts every item across every accessible vault. Zero-knowledge preserved:
// all decryption happens locally with keys already in memory.
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

// --- Command palette (Cmd/Ctrl+K) ---
let cmdIndex = [];   // cached { vaultId, vaultName, id, data } across all vaults
let cmdList = [];     // currently visible palette rows
let cmdSel = 0;

function cmdActions() {
  return [
    { kind: 'action', icon: '➕', label: 'New item', run: () => { closeCmdPalette(); document.getElementById('btn-add-item').click(); } },
    { kind: 'action', icon: '\u{1F5C4}️', label: 'New vault', run: () => { closeCmdPalette(); openModal('modal-vault'); } },
    { kind: 'action', icon: '\u{1F6E1}️', label: 'Security dashboard', run: () => { closeCmdPalette(); openWatchtower(); } },
    { kind: 'action', icon: '\u{1F3B2}', label: 'Password generator', run: () => { closeCmdPalette(); openGenerator(); } },
    { kind: 'action', icon: '\u{1F311}', label: 'Toggle dark mode', run: () => { toggleTheme(); } },
    { kind: 'action', icon: '\u{1F512}', label: 'Lock vault', run: () => { closeCmdPalette(); lockVault(); } },
  ];
}

async function openCmdPalette() {
  const overlay = document.getElementById('cmd-palette');
  if (!overlay || !encKey) return;
  overlay.classList.add('active');
  const input = document.getElementById('cmd-input');
  input.value = '';
  document.getElementById('cmd-results').innerHTML = '<div class="cmd-loading">Indexing your vaults…</div>';
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
    icon: ITEM_TYPES[itemType(e.data)].icon,
    title: e.data.title || 'Untitled',
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
  if (!cmdList.length) { results.innerHTML = '<div class="cmd-empty">No matches</div>'; return; }
  results.innerHTML = cmdList.map((e, i) => `
    <div class="cmd-row${i === cmdSel ? ' active' : ''}" data-i="${i}">
      <span class="cmd-icon">${e.icon || '•'}</span>
      <span class="cmd-main"><span class="cmd-title">${esc(e.title || e.label)}</span>${e.sub ? `<span class="cmd-sub">${esc(e.sub)}</span>` : ''}</span>
      ${e.kind === 'action' ? '<span class="cmd-tag">action</span>' : ''}
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
  body.innerHTML = '<div class="cmd-loading">Scanning your vaults…</div>';

  const all = await collectAllItems();
  const logins = all.filter(e => itemType(e.data) === 'login' && e.data.password);

  const byPw = {};
  for (const e of logins) (byPw[e.data.password] = byPw[e.data.password] || []).push(e);
  const reused = Object.values(byPw).filter(g => g.length > 1);

  const weak = logins.filter(e => estimateStrength(e.data.password).score <= 1);

  const YEAR = 365 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const stale = logins.filter(e => e.data.pwChangedAt && (now - e.data.pwChangedAt) > YEAR);

  renderWatchtower({ total: logins.length, weak, reused, stale });
  checkWatchtowerBreaches(logins);
}

function wtItemRow(e, extra = '') {
  return `<div class="wt-item" data-vault="${e.vaultId}" data-item="${e.id}">
    <span class="cmd-icon">${ITEM_TYPES[itemType(e.data)].icon}</span>
    <span class="cmd-main"><span class="cmd-title">${esc(e.data.title || 'Untitled')}</span>
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

function renderWatchtower(r) {
  const body = document.getElementById('watchtower-body');
  const clean = !r.weak.length && !r.reused.length && !r.stale.length;
  let html = `<div class="wt-summary">Scanned ${r.total} login${r.total === 1 ? '' : 's'} across ${vaults.length} vault${vaults.length === 1 ? '' : 's'}.</div>`;
  if (clean) html += '<div class="wt-allclear">✓ No weak, reused, or stale passwords found.</div>';
  html += wtSection('Weak passwords', r.weak, 'bad', 'Easy to guess — strengthen these.');
  if (r.reused.length) {
    const groups = r.reused.map(g =>
      `<div class="wt-group">${g.map(e => wtItemRow(e)).join('')}</div>`).join('');
    html += `<div class="wt-section wt-warn">
      <div class="wt-head"><span class="wt-badge">${r.reused.length}</span> Reused passwords<span class="wt-note">The same password protects multiple items.</span></div>
      ${groups}</div>`;
  }
  html += wtSection('Aging passwords', r.stale, 'warn', 'Unchanged for over a year.');
  html += '<div id="wt-breaches"><div class="cmd-loading">Checking Have I Been Pwned…</div></div>';
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
      el.innerHTML = '<div class="wt-note">Breach check unavailable (offline).</div>';
      return;
    }
    if (seen[p] > 0) breached.push({ ...e, _count: seen[p] });
  }
  if (!breached.length) {
    el.innerHTML = '<div class="wt-allclear">✓ No passwords found in known breaches.</div>';
    return;
  }
  el.innerHTML = `<div class="wt-section wt-bad">
    <div class="wt-head"><span class="wt-badge">${breached.length}</span> Breached passwords<span class="wt-note">Seen in known data breaches — change now.</span></div>
    <div class="wt-list">${breached.map(e => wtItemRow(e, ' · in ' + e._count.toLocaleString() + ' breaches')).join('')}</div>
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

// --- Detail panel event delegation (copy / reveal / tag filter) ---
function wireDetailDelegation() {
  const root = document.getElementById('detail-content');
  if (!root || root._wired) return;
  root._wired = true;
  root.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('.js-copy');
    if (copyBtn) {
      let text;
      if (copyBtn.dataset.copy === 'totp') {
        text = (document.getElementById('detail-totp-code')?.textContent || '').replace(/\s/g, '');
      } else {
        text = decodeURIComponent(copyBtn.dataset.copy || '');
      }
      navigator.clipboard.writeText(text).then(() => toast('Copied'));
      return;
    }
    const reveal = e.target.closest('.js-reveal');
    if (reveal) {
      const val = reveal.closest('.field')?.querySelector('.field-value');
      if (val) {
        if (val.classList.contains('masked')) {
          val.textContent = decodeURIComponent(val.dataset.raw || '');
          val.classList.remove('masked');
          reveal.innerHTML = '&#128584;';
        } else {
          val.textContent = '••••••••••';
          val.classList.add('masked');
          reveal.innerHTML = '&#128065;';
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
  // Auth
  document.getElementById('btn-login').addEventListener('click', login);
  document.getElementById('btn-signup').addEventListener('click', signup);
  document.getElementById('btn-show-signup').addEventListener('click', () => showAuthScreen('signup'));
  document.getElementById('btn-show-login').addEventListener('click', () => showAuthScreen('login'));
  document.getElementById('btn-logout').addEventListener('click', logout);

  // Enter key support
  document.getElementById('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  document.getElementById('signup-confirm').addEventListener('keydown', e => { if (e.key === 'Enter') signup(); });

  // Search
  document.getElementById('search-input').addEventListener('input', e => {
    searchQuery = e.target.value;
    if (currentVault && sidebarMode === 'vaults') {
      renderFilteredItems();
    }
  });

  // Sidebar add buttons
  document.getElementById('btn-sidebar-add-vault').addEventListener('click', () => openModal('modal-vault'));
  document.getElementById('btn-sidebar-add-team').addEventListener('click', () => openModal('modal-team'));

  // Vault modal
  document.getElementById('btn-save-vault').addEventListener('click', createVault);
  document.getElementById('btn-cancel-vault').addEventListener('click', () => closeModal('modal-vault'));
  document.getElementById('vault-name-input').addEventListener('keydown', e => { if (e.key === 'Enter') createVault(); });

  // Items
  document.getElementById('btn-add-item').addEventListener('click', () => {
    if (!currentVault) return toast('Select a vault first', true);
    editingItem = null;
    document.getElementById('modal-item-title').textContent = 'New Item';
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

  // Detail actions (favorite / edit / delete / history / breach check)
  wireDetailDelegation();
  document.getElementById('btn-fav-item').addEventListener('click', toggleFavorite);
  document.getElementById('btn-item-history').addEventListener('click', showItemHistory);
  document.getElementById('btn-check-breach').addEventListener('click', checkCurrentBreach);

  document.getElementById('btn-edit-item').addEventListener('click', () => {
    if (!currentItem || !currentItem._data) return;
    editingItem = currentItem;
    document.getElementById('modal-item-title').textContent = 'Edit Item';
    fillItemForm(currentItem._data);
    openModal('modal-item');
  });

  document.getElementById('btn-delete-item').addEventListener('click', deleteCurrentItem);

  // History modal close
  document.getElementById('btn-close-history').addEventListener('click', () => closeModal('modal-history'));

  // Generator modal
  document.querySelectorAll('input[name="gen-mode"]').forEach(r => r.addEventListener('change', refreshGenerator));
  ['gen-length', 'gen-words'].forEach(id => document.getElementById(id).addEventListener('input', refreshGenerator));
  ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols', 'gen-avoid', 'gen-cap', 'gen-num'].forEach(id =>
    document.getElementById(id).addEventListener('change', refreshGenerator));
  document.getElementById('btn-gen-refresh').addEventListener('click', refreshGenerator);
  document.getElementById('btn-gen-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('gen-output').textContent).then(() => toast('Copied'));
  });
  document.getElementById('btn-gen-use').addEventListener('click', useGenerated);
  document.getElementById('btn-gen-close').addEventListener('click', () => closeModal('modal-generator'));

  // Sidebar tools: generator, security dashboard, theme, lock
  document.getElementById('btn-tool-generator').addEventListener('click', () => openGenerator());
  document.getElementById('btn-tool-watchtower').addEventListener('click', openWatchtower);
  document.getElementById('btn-theme').addEventListener('click', toggleTheme);
  document.getElementById('btn-lock').addEventListener('click', lockVault);

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
  backRow.innerHTML = '<button class="btn-icon" id="btn-mobile-back-detail">&larr;</button><h2>Details</h2>';
  detailPanel.insertBefore(backRow, detailPanel.firstChild);
  document.getElementById('btn-mobile-back-detail').addEventListener('click', closeMobileDetail);

  // Import
  let parsedImportItems = [];

  document.getElementById('btn-import-items').addEventListener('click', () => {
    if (!currentVault) return toast('Select a vault first', true);
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
          document.getElementById('import-preview-text').textContent = 'No items found in file.';
          document.getElementById('btn-start-import').disabled = true;
          return;
        }

        const ext = file.name.split('.').pop().toLowerCase();
        const format = ext === '1pif' ? '1PIF' : 'CSV';
        document.getElementById('import-preview').style.display = 'block';
        document.getElementById('import-preview-text').textContent =
          `Found ${parsedImportItems.length} item(s) — Format: ${format}`;
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
    navigator.clipboard.writeText(key).then(() => toast('Copied!')).catch(() => toast('Copy failed', true));
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

  // Detect auth mode and initialize
  iapMode = await detectAuthMode();
  if (iapMode) {
    await initIAPSession();
  } else {
    handleRoute();
  }
});
