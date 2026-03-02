// ============================================================
// Vault Internal — Popup Script
// ============================================================

const $ = id => document.getElementById(id);

let allItems = [];
let currentTabUrl = '';

// --- Screens ---
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  $(id).classList.add('active');
}

// --- Init ---
async function init() {
  const status = await chrome.runtime.sendMessage({ type: 'getStatus' });

  // Pre-fill server URL
  if (status.serverUrl) {
    $('server-url').value = status.serverUrl;
  }

  if (status.loggedIn) {
    showScreen('screen-main');
    await loadItems();
  } else {
    showScreen('screen-login');
    $('login-email').focus();
  }
}

// --- Login ---
$('btn-login').addEventListener('click', doLogin);
$('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

async function doLogin() {
  const url = $('server-url').value.trim();
  const email = $('login-email').value.trim();
  const pw = $('login-password').value;

  if (!url) { showError('Enter server URL'); return; }
  if (!email || !pw) { showError('Enter email and password'); return; }

  const btn = $('btn-login');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';
  showError('');

  try {
    await chrome.runtime.sendMessage({ type: 'setServerUrl', url });
    await chrome.runtime.sendMessage({ type: 'login', email, password: pw });
    showScreen('screen-main');
    await loadItems();
  } catch (e) {
    showError(e.message || 'Login failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Log in';
  }
}

function showError(msg) {
  $('login-error').textContent = msg;
}

// --- Logout ---
$('btn-logout').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'logout' });
  showScreen('screen-login');
  $('login-password').value = '';
  $('login-email').focus();
});

// --- Load items ---
async function loadItems() {
  // Get current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabUrl = tab?.url || '';

  const resp = await chrome.runtime.sendMessage({ type: 'getAllItems' });
  allItems = resp?.items || [];

  renderItems('');
}

// --- Search ---
$('search-input').addEventListener('input', e => {
  renderItems(e.target.value);
});

// --- Render items ---
function renderItems(query) {
  const currentSite = $('current-site-section');
  const allSection = $('all-items-section');
  const empty = $('empty-state');
  const q = query.toLowerCase();

  // Get matching items for current site
  let siteItems = [];
  if (currentTabUrl) {
    const domain = extractDomain(currentTabUrl);
    siteItems = allItems.filter(item => {
      const itemDomain = extractDomain(item.data.url || '');
      if (!itemDomain) return false;
      return domain.includes(itemDomain) || itemDomain.includes(domain);
    });
  }

  // Filter by search
  let filteredSite = siteItems;
  let filteredAll = allItems.filter(i => !siteItems.includes(i));

  if (q) {
    const match = i => (i.data.title || '').toLowerCase().includes(q) || (i.data.username || '').toLowerCase().includes(q);
    filteredSite = siteItems.filter(match);
    filteredAll = allItems.filter(i => !siteItems.includes(i)).filter(match);
  }

  // Render
  if (filteredSite.length === 0 && filteredAll.length === 0) {
    currentSite.innerHTML = '';
    allSection.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }

  empty.style.display = 'none';

  if (filteredSite.length > 0) {
    currentSite.innerHTML = `
      <div class="section-label">This site</div>
      ${filteredSite.map(i => itemRow(i)).join('')}
    `;
  } else {
    currentSite.innerHTML = '';
  }

  if (filteredAll.length > 0) {
    allSection.innerHTML = `
      <div class="section-label">All passwords</div>
      ${filteredAll.map(i => itemRow(i)).join('')}
    `;
  } else {
    allSection.innerHTML = '';
  }

  // Attach event listeners
  document.querySelectorAll('.item-row').forEach(row => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.dataset.index);
      const item = allItems[idx];
      if (item) fillItem(item);
    });
  });

  document.querySelectorAll('.item-fill-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.index);
      const item = allItems[idx];
      if (item) fillItem(item);
    });
  });
}

function itemRow(item) {
  const idx = allItems.indexOf(item);
  const initial = (item.data.title || '?')[0].toUpperCase();
  return `
    <div class="item-row" data-index="${idx}">
      <div class="item-icon">${esc(initial)}</div>
      <div class="item-info">
        <div class="item-title">${esc(item.data.title || 'Untitled')}</div>
        <div class="item-user">${esc(item.data.username || '')}</div>
      </div>
      <button class="item-fill-btn" data-index="${idx}">Fill</button>
    </div>
  `;
}

async function fillItem(item) {
  await chrome.runtime.sendMessage({
    type: 'fillCredentials',
    username: item.data.username || '',
    password: item.data.password || '',
  });
  window.close();
}

// --- Generate password ---
$('btn-generate').addEventListener('click', async () => {
  const resp = await chrome.runtime.sendMessage({ type: 'generatePassword' });
  if (resp?.password) {
    const container = $('items-container');
    container.innerHTML = `
      <div style="padding: 8px 0;">
        <div class="section-label">Generated password</div>
        <div class="gen-password">${esc(resp.password)}</div>
        <p class="copy-hint">Click to select, then Ctrl+C to copy</p>
        <button class="btn btn-primary" id="btn-copy-gen" style="margin-top: 12px;">Copy & fill</button>
      </div>
    `;
    $('btn-copy-gen').addEventListener('click', async () => {
      await navigator.clipboard.writeText(resp.password);
      await chrome.runtime.sendMessage({
        type: 'fillCredentials',
        username: '',
        password: resp.password,
      });
      window.close();
    });
  }
});

// --- Refresh ---
$('btn-refresh').addEventListener('click', async () => {
  const btn = $('btn-refresh');
  btn.textContent = 'Refreshing...';
  btn.disabled = true;
  try {
    await chrome.runtime.sendMessage({ type: 'refreshItems' });
    await loadItems();
  } finally {
    btn.textContent = 'Refresh';
    btn.disabled = false;
  }
});

// --- Helpers ---
function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// --- Start ---
init();
