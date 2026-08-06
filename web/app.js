import { SRPClient, generateVerifier } from '/srp.js';
import { deriveKey, encrypt, decrypt, generatePassword, generateKeyPair, encryptPrivateKey, decryptPrivateKey, encryptWithPublicKey, decryptWithPrivateKey, generateVaultKey, importVaultKey, generateTOTP, generateRecoveryKey, deriveRecoveryKey } from '/crypto.js';

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

    if (step2.encrypted_private_key) {
      privateKey = await decryptPrivateKey(encKey, step2.encrypted_private_key);
    } else {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
      const encryptedPrivKey = await encryptPrivateKey(encKey, privateKeyJwk);
      await api('POST', '/api/users/keys', {
        public_key: JSON.stringify(publicKeyJwk),
        encrypted_private_key: encryptedPrivKey,
      });
      privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    sessionStorage.setItem('token', token);
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
  stopTOTP();
  sessionStorage.clear();
  document.getElementById('login-password').value = '';
  iapSession = null;
  showAuthScreen('login');
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

  renderFilteredItems();
}

function renderFilteredItems() {
  const list = document.getElementById('item-list');
  const empty = document.getElementById('items-empty');
  const query = searchQuery.toLowerCase();

  const filtered = query
    ? decryptedItemsCache.filter(i =>
        (i.data.title || '').toLowerCase().includes(query) ||
        (i.data.username || '').toLowerCase().includes(query))
    : decryptedItemsCache;

  if (!filtered.length) {
    list.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }
  empty.style.display = 'none';

  const cards = filtered.map(({ id, data }) => {
    const activeClass = currentItem && currentItem.id === id ? ' active' : '';
    const totpDot = data.totp_secret ? '<span class="totp-indicator" title="Has TOTP"></span>' : '';
    return `<div class="item-card${activeClass}" data-id="${id}">
      <div class="card-icon">&#128273;</div>
      <div class="card-info">
        <h3>${esc(data.title || 'Untitled')}</h3>
        <p>${esc(data.username || '')}</p>
      </div>
      ${totpDot}
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

async function openItemDirect(id) {
  currentItem = items.find(i => i.id === id);
  if (!currentItem) return;

  const key = await getVaultDecryptionKey(currentVault);
  let data = {};
  try { data = JSON.parse(await decrypt(key, currentItem.data_encrypted)); } catch {}

  document.getElementById('detail-empty').style.display = 'none';
  document.getElementById('detail-content').style.display = 'block';

  document.getElementById('detail-title').textContent = data.title || 'Untitled';
  document.getElementById('detail-username').textContent = data.username || '-';
  document.getElementById('detail-password').textContent = '••••••••';
  document.getElementById('detail-password').classList.add('masked');
  document.getElementById('detail-password-raw').textContent = data.password || '';
  document.getElementById('detail-url').textContent = data.url || '-';
  document.getElementById('detail-notes').textContent = data.notes || '-';

  currentItem._data = data;

  // TOTP
  stopTOTP();
  if (data.totp_secret) {
    document.getElementById('totp-field-container').style.display = 'flex';
    await updateTOTP(data.totp_secret);
    totpInterval = setInterval(() => updateTOTP(data.totp_secret), 1000);
  } else {
    document.getElementById('totp-field-container').style.display = 'none';
  }

  // Highlight in list
  renderFilteredItems();

  // Mobile: show detail panel
  const detailPanel = document.querySelector('.detail-panel');
  detailPanel.classList.add('mobile-open');
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
async function saveItem() {
  const title = document.getElementById('item-title-input').value.trim();
  const username = document.getElementById('item-user-input').value.trim();
  const password = document.getElementById('item-pw-input').value;
  const url = document.getElementById('item-url-input').value.trim();
  const totp_secret = document.getElementById('item-totp-input').value.trim();
  const notes = document.getElementById('item-notes-input').value.trim();

  if (!title) return toast('Enter a title', true);

  const key = await getVaultDecryptionKey(currentVault);
  const dataObj = { title, username, password, url, notes };
  if (totp_secret) dataObj.totp_secret = totp_secret;
  const data = JSON.stringify(dataObj);
  const dataEnc = await encrypt(key, data);

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

function clearItemForm() {
  document.getElementById('item-title-input').value = '';
  document.getElementById('item-user-input').value = '';
  document.getElementById('item-pw-input').value = '';
  document.getElementById('item-url-input').value = '';
  document.getElementById('item-totp-input').value = '';
  document.getElementById('item-notes-input').value = '';
  editingItem = null;
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

function parseCSV(text) {
  const rows = [];
  let i = 0;
  const len = text.length;

  function parseField() {
    if (i >= len || text[i] === '\n' || text[i] === '\r') return '';
    if (text[i] === '"') {
      i++; // skip opening quote
      let field = '';
      while (i < len) {
        if (text[i] === '"') {
          if (i + 1 < len && text[i + 1] === '"') {
            field += '"';
            i += 2;
          } else {
            i++; // skip closing quote
            break;
          }
        } else {
          field += text[i];
          i++;
        }
      }
      return field;
    } else {
      let field = '';
      while (i < len && text[i] !== ',' && text[i] !== '\n' && text[i] !== '\r') {
        field += text[i];
        i++;
      }
      return field;
    }
  }

  while (i < len) {
    const row = [];
    while (true) {
      row.push(parseField());
      if (i < len && text[i] === ',') {
        i++; // skip comma
      } else {
        break;
      }
    }
    // Skip line endings
    if (i < len && text[i] === '\r') i++;
    if (i < len && text[i] === '\n') i++;
    rows.push(row);
  }

  return rows;
}

function parse1PIF(text) {
  const lines = text.split('\n');
  const entries = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('***')) continue;
    try {
      const obj = JSON.parse(trimmed);
      // Skip system entries
      if (obj.typeName === 'system.folder.Regular' || obj.typeName === 'system.folder.SavedSearch') continue;
      entries.push(obj);
    } catch {
      // Skip unparseable lines
    }
  }
  return entries;
}

function extractTOTPSecret(otpauthUri) {
  if (!otpauthUri || !otpauthUri.startsWith('otpauth://')) return null;
  try {
    const url = new URL(otpauthUri);
    const secret = url.searchParams.get('secret');
    if (secret) return secret;
  } catch {
    // fallback regex
  }
  const match = otpauthUri.match(/[?&]secret=([A-Za-z2-7=]+)/i);
  return match ? match[1] : null;
}

// 1Password CSV without headers: OTPAuth, Notes, Password, Title, Type, URL, Username
const OP_CSV_COLUMNS = { otpauth: 0, notes: 1, password: 2, title: 3, type: 4, url: 5, username: 6 };
const KNOWN_HEADERS = ['title', 'username', 'password', 'url', 'website', 'notes', 'otpauth', 'type'];
// Types we skip (no useful credentials)
const SKIP_TYPES = ['document'];

function csvHasHeaders(firstRow) {
  const lower = firstRow.map(h => h.trim().toLowerCase());
  // If at least 2 known header names appear, treat as header row
  return lower.filter(h => KNOWN_HEADERS.includes(h)).length >= 2;
}

function mapCSVToItems(rows) {
  if (!rows.length) return [];

  const hasHeaders = csvHasHeaders(rows[0]);

  if (hasHeaders) {
    // Header-based mapping
    if (rows.length < 2) return [];
    const headers = rows[0].map(h => h.trim().toLowerCase());
    const idx = (name) => headers.indexOf(name);
    const titleIdx = idx('title');
    if (titleIdx === -1) throw new Error('CSV missing required "Title" column');

    const usernameIdx = Math.max(idx('username'), idx('email'));
    const passwordIdx = idx('password');
    const urlIdx = Math.max(idx('website'), idx('url'));
    const notesIdx = idx('notes');
    const otpIdx = idx('otpauth');
    const typeIdx = idx('type');

    const items = [];
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      // Skip document types
      if (typeIdx >= 0 && SKIP_TYPES.includes((row[typeIdx] || '').trim().toLowerCase())) continue;
      const title = (row[titleIdx] || '').trim();
      if (!title) continue;

      const item = { title };
      if (usernameIdx >= 0 && row[usernameIdx]) item.username = row[usernameIdx].trim();
      if (passwordIdx >= 0 && row[passwordIdx]) item.password = row[passwordIdx].trim();
      if (urlIdx >= 0 && row[urlIdx]) item.url = row[urlIdx].trim();
      if (notesIdx >= 0 && row[notesIdx]) item.notes = row[notesIdx].trim();
      if (otpIdx >= 0 && row[otpIdx]) {
        const secret = extractTOTPSecret(row[otpIdx].trim());
        if (secret) item.totp_secret = secret;
      }
      items.push(item);
    }
    return items;
  }

  // Headerless 1Password CSV: OTPAuth(0), Notes(1), Password(2), Title(3), Type(4), URL(5), Username(6)
  const C = OP_CSV_COLUMNS;
  const items = [];
  for (const row of rows) {
    // Skip document types
    const type = (row[C.type] || '').trim().toLowerCase();
    if (SKIP_TYPES.includes(type)) continue;
    const title = (row[C.title] || '').trim();
    if (!title) continue;

    const item = { title };
    if (row[C.username]) item.username = row[C.username].trim();
    if (row[C.password]) item.password = row[C.password].trim();
    if (row[C.url]) item.url = row[C.url].trim();
    if (row[C.notes]) item.notes = row[C.notes].trim();
    if (row[C.otpauth]) {
      const secret = extractTOTPSecret(row[C.otpauth].trim());
      if (secret) item.totp_secret = secret;
    }
    items.push(item);
  }
  return items;
}

function map1PIFToItems(entries) {
  const items = [];
  for (const entry of entries) {
    const title = (entry.title || '').trim();
    if (!title) continue;

    const item = { title };
    if (entry.location) item.url = entry.location;

    // Extract username/password from secureContents.fields
    const fields = entry.secureContents?.fields || [];
    for (const f of fields) {
      if (f.designation === 'username' && f.value) item.username = f.value;
      if (f.designation === 'password' && f.value) item.password = f.value;
    }

    // Extract notes
    if (entry.secureContents?.notesPlain) item.notes = entry.secureContents.notesPlain;

    // Extract TOTP from sections
    const sections = entry.secureContents?.sections || [];
    for (const section of sections) {
      for (const sf of (section.fields || [])) {
        const val = sf.v || '';
        if (typeof val === 'string' && val.startsWith('otpauth://')) {
          const secret = extractTOTPSecret(val);
          if (secret) item.totp_secret = secret;
        }
      }
    }

    items.push(item);
  }
  return items;
}

function detectFormatAndParse(text, filename) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  if (ext === '1pif') {
    const entries = parse1PIF(text);
    return map1PIFToItems(entries);
  }
  // Default to CSV
  const rows = parseCSV(text);
  return mapCSVToItems(rows);
}

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
  document.getElementById('btn-gen-pw').addEventListener('click', () => {
    document.getElementById('item-pw-input').value = generatePassword();
  });

  // Detail
  document.getElementById('btn-toggle-pw').addEventListener('click', () => {
    const el = document.getElementById('detail-password');
    const raw = document.getElementById('detail-password-raw').textContent;
    if (el.classList.contains('masked')) {
      el.textContent = raw;
      el.classList.remove('masked');
    } else {
      el.textContent = '••••••••';
      el.classList.add('masked');
    }
  });

  document.getElementById('btn-edit-item').addEventListener('click', () => {
    if (!currentItem || !currentItem._data) return;
    editingItem = currentItem;
    document.getElementById('modal-item-title').textContent = 'Edit Item';
    document.getElementById('item-title-input').value = currentItem._data.title || '';
    document.getElementById('item-user-input').value = currentItem._data.username || '';
    document.getElementById('item-pw-input').value = currentItem._data.password || '';
    document.getElementById('item-url-input').value = currentItem._data.url || '';
    document.getElementById('item-totp-input').value = currentItem._data.totp_secret || '';
    document.getElementById('item-notes-input').value = currentItem._data.notes || '';
    openModal('modal-item');
  });

  document.getElementById('btn-delete-item').addEventListener('click', async () => {
    if (!currentItem) return;
    toast('Delete not implemented yet (server needs DELETE endpoint)');
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
