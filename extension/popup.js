// ============================================================
// MasPassword — Popup Script (ES module)
// ============================================================

import { domainsMatch } from './domain.js';
import { generateTOTP } from './totp.js';
import { generatePassword } from './generator.js';

const $ = id => document.getElementById(id);

// --- i18n (es default, en for English browsers) ---
const STRINGS = {
  es: {
    'login.sub': 'Conocimiento cero: tus datos se cifran en tu dispositivo.',
    'login.email': 'Email',
    'login.master': 'Contraseña maestra',
    'login.cta': 'Entrar',
    'login.server': 'Servidor',
    'login.serverHint': 'Déjalo como está para usar el servidor corporativo.',
    'login.errUrl': 'Introduce la URL del servidor',
    'login.errCreds': 'Introduce email y contraseña',
    'login.errLogin': 'No se pudo iniciar sesión',
    'main.search': 'Buscar contraseñas…',
    'main.thisSite': 'Este sitio',
    'main.all': 'Todas las contraseñas',
    'main.empty': 'No hay resultados',
    'main.generator': 'Generador',
    'main.refresh': 'Actualizar',
    'main.lock': 'Bloquear',
    'main.fill': 'Rellenar',
    'detail.back': 'Volver',
    'detail.fill': 'Autocompletar en la página',
    'detail.user': 'Usuario',
    'detail.password': 'Contraseña',
    'detail.totp': 'Código de un solo uso',
    'detail.web': 'Sitio web',
    'detail.notes': 'Notas',
    'actions.copy': 'Copiar',
    'actions.copied': 'Copiado',
    'actions.show': 'Mostrar',
    'actions.hide': 'Ocultar',
    'gen.title': 'Generador de contraseñas',
    'gen.length': 'Longitud',
    'gen.upper': 'Mayúsculas (A-Z)',
    'gen.lower': 'Minúsculas (a-z)',
    'gen.digits': 'Dígitos (0-9)',
    'gen.symbols': 'Símbolos (!@#…)',
    'gen.generate': 'Generar',
    'gen.copy': 'Copiar',
    'gen.regenerate': 'Regenerar',
    'totp.invalid': 'Secreto no válido',
    'untitled': 'Sin título',
  },
  en: {
    'login.sub': 'Zero knowledge: your data is encrypted on your device.',
    'login.email': 'Email',
    'login.master': 'Master password',
    'login.cta': 'Log in',
    'login.server': 'Server',
    'login.serverHint': 'Leave as-is to use the corporate server.',
    'login.errUrl': 'Enter the server URL',
    'login.errCreds': 'Enter email and password',
    'login.errLogin': 'Login failed',
    'main.search': 'Search passwords…',
    'main.thisSite': 'This site',
    'main.all': 'All passwords',
    'main.empty': 'No results',
    'main.generator': 'Generator',
    'main.refresh': 'Refresh',
    'main.lock': 'Lock',
    'main.fill': 'Fill',
    'detail.back': 'Back',
    'detail.fill': 'Autofill on page',
    'detail.user': 'Username',
    'detail.password': 'Password',
    'detail.totp': 'One-time code',
    'detail.web': 'Website',
    'detail.notes': 'Notes',
    'actions.copy': 'Copy',
    'actions.copied': 'Copied',
    'actions.show': 'Show',
    'actions.hide': 'Hide',
    'gen.title': 'Password generator',
    'gen.length': 'Length',
    'gen.upper': 'Uppercase (A-Z)',
    'gen.lower': 'Lowercase (a-z)',
    'gen.digits': 'Digits (0-9)',
    'gen.symbols': 'Symbols (!@#…)',
    'gen.generate': 'Generate',
    'gen.copy': 'Copy',
    'gen.regenerate': 'Regenerate',
    'totp.invalid': 'Invalid secret',
    'untitled': 'Untitled',
  },
};
const LOCALE = (navigator.language || 'es').toLowerCase().startsWith('en') ? 'en' : 'es';
function t(key) {
  return (STRINGS[LOCALE] && STRINGS[LOCALE][key]) || STRINGS.es[key] || key;
}

function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
}

let allItems = [];
let currentTabUrl = '';
let totpTimer = null; // interval id for the live TOTP countdown

// --- Screens ---
function showScreen(id) {
  stopTotp(); // leaving any screen stops the TOTP ticker; callers restart it
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  $(id).classList.add('active');
}

// --- Init ---
async function init() {
  applyI18n();
  $('version').textContent = 'v' + chrome.runtime.getManifest().version;

  const status = await chrome.runtime.sendMessage({ type: 'getStatus' });

  // Pre-fill server URL (defaults to the corporate Cloud Run deployment)
  if (status?.serverUrl) {
    $('server-url').value = status.serverUrl;
  }

  if (status?.loggedIn) {
    showScreen('screen-main');
    $('search-input').focus();
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

  if (!url) { showError(t('login.errUrl')); return; }
  if (!email || !pw) { showError(t('login.errCreds')); return; }

  const btn = $('btn-login');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';
  showError('');

  try {
    await chrome.runtime.sendMessage({ type: 'setServerUrl', url });
    const res = await chrome.runtime.sendMessage({ type: 'login', email, password: pw });
    if (res?.error) throw new Error(res.error);
    $('login-password').value = '';
    showScreen('screen-main');
    $('search-input').focus();
    await loadItems();
  } catch (e) {
    showError(e.message || t('login.errLogin'));
  } finally {
    btn.disabled = false;
    btn.textContent = t('login.cta');
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

  renderItems($('search-input').value || '');
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

  // Items matching the current site — matched by registrable domain
  // (eTLD+1), NOT by substring. Items without a URL never match a
  // site; they only appear in the "all passwords" list / search.
  let siteItems = [];
  if (currentTabUrl) {
    siteItems = allItems.filter(item => {
      const itemUrl = item.data.url || '';
      if (!itemUrl) return false;
      return domainsMatch(currentTabUrl, itemUrl);
    });
  }

  // Filter by search
  let filteredSite = siteItems;
  let filteredAll = allItems.filter(i => !siteItems.includes(i));

  if (q) {
    const match = i =>
      (i.data.title || '').toLowerCase().includes(q) ||
      (i.data.username || '').toLowerCase().includes(q) ||
      (i.data.url || '').toLowerCase().includes(q);
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

  currentSite.innerHTML = filteredSite.length
    ? `<div class="section-label">${t('main.thisSite')}</div>${filteredSite.map(i => itemRow(i)).join('')}`
    : '';

  allSection.innerHTML = filteredAll.length
    ? `<div class="section-label">${t('main.all')}</div>${filteredAll.map(i => itemRow(i)).join('')}`
    : '';

  // Row click opens the detail view; the Fill button fills immediately.
  document.querySelectorAll('.item-row').forEach(row => {
    row.addEventListener('click', () => {
      const item = allItems[parseInt(row.dataset.index)];
      if (item) showItemDetail(item);
    });
  });

  document.querySelectorAll('.item-fill-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const item = allItems[parseInt(btn.dataset.index)];
      if (item) fillItem(item);
    });
  });
}

function itemRow(item) {
  const idx = allItems.indexOf(item);
  const emoji = (item.data.icon || '').trim();
  const avatar = emoji
    ? `<div class="item-icon emoji">${esc(emoji)}</div>`
    : `<div class="item-icon">${esc((item.data.title || '?')[0].toUpperCase())}</div>`;
  const hasTotp = !!extractTotpSecret(item.data);
  return `
    <div class="item-row" data-index="${idx}">
      ${avatar}
      <div class="item-info">
        <div class="item-title">${esc(item.data.title || t('untitled'))}${hasTotp ? ' <span class="item-totp-badge">2FA</span>' : ''}</div>
        <div class="item-user">${esc(item.data.username || '')}</div>
      </div>
      <button class="item-fill-btn" data-index="${idx}">${t('main.fill')}</button>
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

// ============================================================
// Item detail view (with TOTP)
// ============================================================
function showItemDetail(item) {
  const d = item.data;
  const body = $('detail-body');
  body.textContent = '';
  $('detail-title').textContent = d.title || t('untitled');

  if (d.username) body.appendChild(detailRow(t('detail.user'), d.username, { copy: d.username }));
  if (d.password) body.appendChild(passwordRow(d.password));

  const totp = extractTotpSecret(d);
  if (totp) body.appendChild(totpRow());

  if (d.url) body.appendChild(detailRow(t('detail.web'), d.url));
  if (d.notes) body.appendChild(detailRow(t('detail.notes'), d.notes));

  $('btn-detail-fill').onclick = () => fillItem(item);

  showScreen('screen-detail');
  if (totp) startTotp(totp);
}

$('btn-detail-back').addEventListener('click', () => showScreen('screen-main'));

function detailRow(label, value, { copy = null, mono = false } = {}) {
  const row = document.createElement('div');
  row.className = 'detail-row';

  const l = document.createElement('div');
  l.className = 'detail-label';
  l.textContent = label;

  const wrap = document.createElement('div');
  wrap.className = 'detail-value-wrap';

  const v = document.createElement('div');
  v.className = 'detail-value' + (mono ? ' mono' : '');
  v.textContent = value;
  wrap.appendChild(v);

  if (copy !== null) {
    const btn = document.createElement('button');
    btn.className = 'detail-copy-btn';
    btn.textContent = t('actions.copy');
    btn.addEventListener('click', () => copyText(copy, btn));
    wrap.appendChild(btn);
  }

  row.appendChild(l);
  row.appendChild(wrap);
  return row;
}

function passwordRow(password) {
  const row = document.createElement('div');
  row.className = 'detail-row';

  const l = document.createElement('div');
  l.className = 'detail-label';
  l.textContent = t('detail.password');

  const wrap = document.createElement('div');
  wrap.className = 'detail-value-wrap';

  const v = document.createElement('div');
  v.className = 'detail-value mono';
  v.textContent = '••••••••••';

  let revealed = false;
  const reveal = document.createElement('button');
  reveal.className = 'detail-copy-btn';
  reveal.textContent = t('actions.show');
  reveal.addEventListener('click', () => {
    revealed = !revealed;
    v.textContent = revealed ? password : '••••••••••';
    reveal.textContent = revealed ? t('actions.hide') : t('actions.show');
  });

  const copy = document.createElement('button');
  copy.className = 'detail-copy-btn';
  copy.textContent = t('actions.copy');
  copy.addEventListener('click', () => copyText(password, copy));

  wrap.appendChild(v);
  wrap.appendChild(reveal);
  wrap.appendChild(copy);
  row.appendChild(l);
  row.appendChild(wrap);
  return row;
}

function totpRow() {
  const row = document.createElement('div');
  row.className = 'detail-row';

  const l = document.createElement('div');
  l.className = 'detail-label';
  l.textContent = t('detail.totp');

  const wrap = document.createElement('div');
  wrap.className = 'detail-value-wrap';

  const code = document.createElement('div');
  code.className = 'detail-value mono totp-code';
  code.id = 'totp-code';
  code.textContent = '––– –––';

  const cd = document.createElement('span');
  cd.className = 'totp-countdown';
  cd.id = 'totp-countdown';

  const copy = document.createElement('button');
  copy.className = 'detail-copy-btn';
  copy.textContent = t('actions.copy');
  copy.addEventListener('click', () => {
    const raw = code.dataset.raw || '';
    if (raw) copyText(raw, copy);
  });

  wrap.appendChild(code);
  wrap.appendChild(cd);
  wrap.appendChild(copy);
  row.appendChild(l);
  row.appendChild(wrap);
  return row;
}

// Parse a TOTP secret from item data. The web app stores it in
// `data.totp_secret`; also accept a raw base32 secret in `data.totp`,
// or an `otpauth://totp/...?secret=XXX` URI in any of the three.
function extractTotpSecret(data) {
  const raw = (data.totp_secret || data.totp || data.otpauth || '').trim();
  if (!raw) return null;
  if (/^otpauth:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const secret = u.searchParams.get('secret');
      if (!secret) return null;
      return {
        secret,
        period: parseInt(u.searchParams.get('period'), 10) || 30,
        digits: parseInt(u.searchParams.get('digits'), 10) || 6,
      };
    } catch { return null; }
  }
  return { secret: raw, period: 30, digits: 6 };
}

function stopTotp() {
  if (totpTimer) { clearInterval(totpTimer); totpTimer = null; }
}

async function startTotp(totp) {
  const codeEl = $('totp-code');
  const cdEl = $('totp-countdown');
  if (!codeEl) return;

  const tick = async () => {
    try {
      const { code, remaining } = await generateTOTP(totp.secret, { period: totp.period, digits: totp.digits });
      codeEl.dataset.raw = code;
      codeEl.textContent = code.length === 6 ? code.slice(0, 3) + ' ' + code.slice(3) : code;
      if (cdEl) {
        cdEl.textContent = remaining + 's';
        cdEl.classList.toggle('totp-low', remaining <= 5);
      }
    } catch {
      codeEl.textContent = t('totp.invalid');
      if (cdEl) cdEl.textContent = '';
    }
  };

  await tick();
  totpTimer = setInterval(tick, 1000);
}

// ============================================================
// Password generator screen
// ============================================================
function genOptions() {
  return {
    length: parseInt($('gen-length').value, 10),
    upper: $('gen-upper').checked,
    lower: $('gen-lower').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
  };
}

function regenerate() {
  $('gen-output').textContent = generatePassword(genOptions());
}

$('btn-generate').addEventListener('click', () => {
  showScreen('screen-generator');
  regenerate();
});
$('btn-gen-back').addEventListener('click', () => showScreen('screen-main'));
$('btn-gen-generate').addEventListener('click', regenerate);
$('btn-gen-refresh').addEventListener('click', regenerate);
$('btn-gen-copy').addEventListener('click', () => copyText($('gen-output').textContent, $('btn-gen-copy')));

$('gen-length').addEventListener('input', () => {
  $('gen-len-value').textContent = $('gen-length').value;
  regenerate();
});

['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols'].forEach(id => {
  $(id).addEventListener('change', () => {
    // Never allow every class to be off — fall back to lowercase.
    if (!$('gen-upper').checked && !$('gen-lower').checked && !$('gen-digits').checked && !$('gen-symbols').checked) {
      $('gen-lower').checked = true;
    }
    regenerate();
  });
});

// --- Refresh ---
$('btn-refresh').addEventListener('click', async () => {
  const btn = $('btn-refresh');
  btn.disabled = true;
  btn.style.opacity = '0.5';
  try {
    await chrome.runtime.sendMessage({ type: 'refreshItems' });
    await loadItems();
  } finally {
    btn.disabled = false;
    btn.style.opacity = '';
  }
});

// --- Helpers ---
async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = t('actions.copied');
      setTimeout(() => { btn.textContent = prev; }, 1200);
    }
  } catch { /* clipboard unavailable */ }
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// --- Start ---
init();
