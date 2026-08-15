// ============================================================
// Vault Internal — Content Script
// Detects login/signup forms, injects autofill UI
// ============================================================

(() => {
  if (window.__vaultInternalInjected) return;
  window.__vaultInternalInjected = true;

  const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" width="18" height="18"><path fill-rule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clip-rule="evenodd"/></svg>`;

  let dropdown = null;
  let saveBanner = null;
  let activeInput = null;
  let matchingItems = [];
  let lastSubmittedCreds = null;

  // --- Utility ---
  function isVisible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && el.offsetParent !== null;
  }

  function isPasswordField(el) {
    return el.type === 'password';
  }

  function isUsernameField(el) {
    if (el.type === 'password' || el.type === 'hidden' || el.type === 'submit') return false;
    const hints = ['user', 'email', 'login', 'account', 'name', 'identifier'];
    const attrs = [el.name, el.id, el.autocomplete, el.placeholder].join(' ').toLowerCase();
    return hints.some(h => attrs.includes(h)) || el.type === 'email';
  }

  function isNewPasswordField(el) {
    if (el.type !== 'password') return false;
    const ac = (el.autocomplete || '').toLowerCase();
    if (ac === 'new-password') return true;
    // Heuristic: if there are 2+ password fields in the same form, it's likely signup
    const form = el.closest('form');
    if (form && form.querySelectorAll('input[type="password"]').length >= 2) return true;
    return false;
  }

  function findUsernameField(passwordField) {
    const form = passwordField.closest('form');
    const scope = form || document;
    const inputs = [...scope.querySelectorAll('input')];
    const pwIdx = inputs.indexOf(passwordField);
    // Look backwards for the nearest username-like field
    for (let i = pwIdx - 1; i >= 0; i--) {
      if (isUsernameField(inputs[i]) && isVisible(inputs[i])) return inputs[i];
    }
    // Look forward
    for (let i = pwIdx + 1; i < inputs.length; i++) {
      if (isUsernameField(inputs[i]) && isVisible(inputs[i])) return inputs[i];
    }
    return null;
  }

  // --- Vault icon injection ---
  function injectIcons() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
      if (field.dataset.vaultIcon) return;
      if (!isVisible(field)) return;

      field.dataset.vaultIcon = 'true';
      const icon = document.createElement('button');
      icon.className = 'vi-field-icon';
      icon.innerHTML = ICON_SVG;
      icon.tabIndex = -1;
      icon.addEventListener('mousedown', e => {
        e.preventDefault();
        e.stopPropagation();
        toggleDropdown(field);
      });

      // Position relative to the field
      const wrapper = document.createElement('div');
      wrapper.className = 'vi-field-wrapper';
      field.parentNode.insertBefore(wrapper, field);
      wrapper.appendChild(field);
      wrapper.appendChild(icon);
    });
  }

  // --- Dropdown ---
  function toggleDropdown(passwordField) {
    if (dropdown) { removeDropdown(); return; }
    activeInput = passwordField;
    fetchAndShowDropdown(passwordField);
  }

  async function fetchAndShowDropdown(passwordField) {
    const resp = await chrome.runtime.sendMessage({ type: 'getMatchingItems', url: location.href });
    matchingItems = resp?.items || [];
    const status = await chrome.runtime.sendMessage({ type: 'getStatus' });

    removeDropdown();
    dropdown = document.createElement('div');
    dropdown.className = 'vi-dropdown';

    if (!status.loggedIn) {
      dropdown.innerHTML = `<div class="vi-dropdown-empty">Open the Vault Internal extension to log in</div>`;
    } else if (matchingItems.length === 0) {
      const isNew = isNewPasswordField(passwordField);
      dropdown.innerHTML = `
        <div class="vi-dropdown-empty">No saved passwords for this site</div>
        ${isNew ? '<button class="vi-dropdown-action" data-action="generate">Generate a strong password</button>' : ''}
        <button class="vi-dropdown-action" data-action="open">Open Vault Internal</button>
      `;
    } else {
      const itemsHtml = matchingItems.map((item, i) => `
        <button class="vi-dropdown-item" data-index="${i}">
          <div class="vi-dropdown-item-title">${esc(item.data.title || 'Untitled')}</div>
          <div class="vi-dropdown-item-user">${esc(item.data.username || '')}</div>
        </button>
      `).join('');
      const isNew = isNewPasswordField(passwordField);
      dropdown.innerHTML = `
        ${itemsHtml}
        <div class="vi-dropdown-sep"></div>
        ${isNew ? '<button class="vi-dropdown-action" data-action="generate">Generate a strong password</button>' : ''}
      `;
    }

    // Position below the input
    const rect = passwordField.getBoundingClientRect();
    dropdown.style.top = (rect.bottom + window.scrollY + 4) + 'px';
    dropdown.style.left = (rect.left + window.scrollX) + 'px';
    dropdown.style.width = Math.max(rect.width, 280) + 'px';
    document.body.appendChild(dropdown);

    // Event delegation
    dropdown.addEventListener('mousedown', e => {
      e.preventDefault();
      const itemBtn = e.target.closest('.vi-dropdown-item');
      if (itemBtn) {
        const idx = parseInt(itemBtn.dataset.index);
        fillFromItem(matchingItems[idx], passwordField);
        removeDropdown();
        return;
      }
      const actionBtn = e.target.closest('.vi-dropdown-action');
      if (actionBtn) {
        const action = actionBtn.dataset.action;
        if (action === 'generate') generateAndFill(passwordField);
        if (action === 'open') chrome.runtime.sendMessage({ type: 'openPopup' });
        removeDropdown();
      }
    });

    // Close on click outside
    setTimeout(() => document.addEventListener('click', onClickOutside), 0);
  }

  function removeDropdown() {
    if (dropdown) { dropdown.remove(); dropdown = null; }
    document.removeEventListener('click', onClickOutside);
  }

  function onClickOutside(e) {
    if (dropdown && !dropdown.contains(e.target)) removeDropdown();
  }

  // --- Fill credentials ---
  function fillFromItem(item, passwordField) {
    const usernameField = findUsernameField(passwordField);
    if (usernameField && item.data.username) {
      setInputValue(usernameField, item.data.username);
    }
    if (item.data.password) {
      setInputValue(passwordField, item.data.password);
    }
  }

  function setInputValue(input, value) {
    // Use native setter to trigger React/Vue/etc change detection
    const nativeSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    nativeSetter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // --- Generate password ---
  async function generateAndFill(passwordField) {
    const resp = await chrome.runtime.sendMessage({ type: 'generatePassword' });
    if (resp?.password) {
      setInputValue(passwordField, resp.password);
      // If there's a confirm password field, fill that too
      const form = passwordField.closest('form');
      if (form) {
        const pwFields = form.querySelectorAll('input[type="password"]');
        pwFields.forEach(f => {
          if (f !== passwordField) setInputValue(f, resp.password);
        });
      }
      showSaveBannerForGenerated(resp.password, passwordField);
    }
  }

  function showSaveBannerForGenerated(password, passwordField) {
    const usernameField = findUsernameField(passwordField);
    // Wait a bit for user to fill in username, then offer to save
    const checkAndSave = () => {
      const username = usernameField?.value || '';
      if (username) {
        showSaveBanner(username, password);
      }
    };
    // Listen for form submit
    const form = passwordField.closest('form');
    if (form) {
      form.addEventListener('submit', () => {
        setTimeout(checkAndSave, 100);
      }, { once: true });
    }
  }

  // --- Detect form submissions ---
  function watchFormSubmissions() {
    document.addEventListener('submit', async e => {
      const form = e.target;
      const pwField = form.querySelector('input[type="password"]');
      if (!pwField || !pwField.value) return;

      const usernameField = findUsernameField(pwField);
      const username = usernameField?.value || '';
      const password = pwField.value;

      if (!username && !password) return;

      // Check if this credential is already saved
      const resp = await chrome.runtime.sendMessage({ type: 'getMatchingItems', url: location.href });
      const existing = (resp?.items || []).find(i =>
        i.data.username === username && i.data.password === password
      );

      if (!existing) {
        lastSubmittedCreds = { username, password, url: location.href };
        // Delay to let the page navigate
        setTimeout(() => showSaveBanner(username, password), 1500);
      }
    }, true);

    // Also watch for XHR/fetch login (SPA apps that don't use form submit)
    const origSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
      const pwField = this.querySelector('input[type="password"]');
      if (pwField?.value) {
        const usernameField = findUsernameField(pwField);
        lastSubmittedCreds = {
          username: usernameField?.value || '',
          password: pwField.value,
          url: location.href,
        };
      }
      return origSubmit.apply(this, arguments);
    };
  }

  // --- Save banner ---
  function showSaveBanner(username, password) {
    removeSaveBanner();

    saveBanner = document.createElement('div');
    saveBanner.className = 'vi-save-banner';
    saveBanner.innerHTML = `
      <div class="vi-save-banner-content">
        <div class="vi-save-banner-icon">${ICON_SVG}</div>
        <div class="vi-save-banner-text">
          <strong>Save to Vault Internal?</strong>
          <span>${esc(username || 'No username')} on ${esc(extractSiteName())}</span>
        </div>
        <div class="vi-save-banner-actions">
          <button class="vi-save-btn vi-save-btn-primary" data-action="save">Save</button>
          <button class="vi-save-btn vi-save-btn-dismiss" data-action="dismiss">Not now</button>
        </div>
      </div>
    `;
    document.body.appendChild(saveBanner);
    // Animate in
    requestAnimationFrame(() => saveBanner.classList.add('vi-save-banner-show'));

    saveBanner.addEventListener('click', async e => {
      const action = e.target.closest('[data-action]')?.dataset.action;
      if (action === 'save') {
        await saveCredential(username, password);
        removeSaveBanner();
      }
      if (action === 'dismiss') {
        removeSaveBanner();
      }
    });

    // Auto-dismiss after 30s
    setTimeout(removeSaveBanner, 30000);
  }

  function removeSaveBanner() {
    if (saveBanner) { saveBanner.remove(); saveBanner = null; }
  }

  async function saveCredential(username, password) {
    const status = await chrome.runtime.sendMessage({ type: 'getStatus' });
    if (!status.loggedIn) return;

    const vaultsResp = await chrome.runtime.sendMessage({ type: 'getVaults' });
    const vaults = vaultsResp?.vaults || [];
    if (!vaults.length) return;

    // Save to first vault (private vault)
    const vault = vaults.find(v => !v.team_id) || vaults[0];
    const title = extractSiteName();
    const url = location.origin;

    try {
      await chrome.runtime.sendMessage({
        type: 'saveItem',
        vaultId: vault.id,
        data: { title, username, password, url, notes: '' },
      });
      showToast('Password saved to Vault Internal');
    } catch (e) {
      showToast('Failed to save: ' + e.message, true);
    }
  }

  function extractSiteName() {
    const hostname = location.hostname.replace(/^www\./, '');
    // Try to get a clean name from the domain
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts[parts.length - 2].charAt(0).toUpperCase() + parts[parts.length - 2].slice(1);
    }
    return hostname;
  }

  // --- Toast ---
  function showToast(msg, isError = false) {
    const toast = document.createElement('div');
    toast.className = 'vi-toast' + (isError ? ' vi-toast-error' : '');
    toast.textContent = msg;
    document.body.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('vi-toast-show'));
    setTimeout(() => { toast.classList.remove('vi-toast-show'); setTimeout(() => toast.remove(), 300); }, 3000);
  }

  // --- Listen for fill messages from background ---
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'fill') {
      const pwFields = document.querySelectorAll('input[type="password"]');
      pwFields.forEach(pw => {
        if (isVisible(pw)) {
          if (msg.username) {
            const userField = findUsernameField(pw);
            if (userField) setInputValue(userField, msg.username);
          }
          if (msg.password) setInputValue(pw, msg.password);
        }
      });
    }
  });

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ============================================================
  // Passkey relay (WebAuthn provider)
  //
  // page.js (MAIN world) intercepts navigator.credentials and posts the
  // RP options here. We add the user-facing UI (confirm create, pick a
  // passkey) and forward to the background, which owns the vault keys and
  // derives the trusted origin from chrome.runtime's sender. We never
  // pass an origin to the background — only the RP-supplied options.
  // ============================================================

  const PK_NS = '__mpPk';

  // Content scripts don't load the web app's i18n module, so keep a tiny
  // local catalog for the passkey dialogs (es default, en fallback), in
  // the same spirit as the existing hardcoded strings above.
  const PK_STRINGS = {
    es: {
      'pk.shared': 'compartida', 'pk.createTitle': 'Crear un passkey',
      'pk.createFor': 'Para {rp}', 'pk.saveTo': 'Guardar en',
      'pk.cancel': 'Cancelar', 'pk.create': 'Crear',
      'pk.useTitle': 'Usar un passkey', 'pk.useFor': 'Para {rp}',
      'pk.lockedTitle': 'MasPassword está bloqueado',
      'pk.lockedBody': 'Desbloquea la extensión para usar tus passkeys, o continúa con el navegador.',
      'pk.useBrowser': 'Usar el navegador',
    },
    en: {
      'pk.shared': 'shared', 'pk.createTitle': 'Create a passkey',
      'pk.createFor': 'For {rp}', 'pk.saveTo': 'Save to',
      'pk.cancel': 'Cancel', 'pk.create': 'Create',
      'pk.useTitle': 'Use a passkey', 'pk.useFor': 'For {rp}',
      'pk.lockedTitle': 'MasPassword is locked',
      'pk.lockedBody': 'Unlock the extension to use your passkeys, or continue with the browser.',
      'pk.useBrowser': 'Use the browser',
    },
  };
  const PK_LOCALE = (navigator.language || 'es').toLowerCase().startsWith('en') ? 'en' : 'es';
  function t(key, vars) {
    let s = (PK_STRINGS[PK_LOCALE] && PK_STRINGS[PK_LOCALE][key]) || PK_STRINGS.en[key] || key;
    if (vars) for (const k in vars) s = s.replace('{' + k + '}', vars[k]);
    return s;
  }

  function bg(msg) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage(msg, resolve);
    });
  }

  function respondToPage(id, result) {
    if (!id) return;
    window.postMessage({ [PK_NS]: true, dir: 'res', id, result }, location.origin);
  }

  window.addEventListener('message', ev => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d[PK_NS] !== true || d.dir !== 'req') return;
    handlePasskeyReq(d).catch(() => respondToPage(d.id, { cancelled: true }));
  });

  async function handlePasskeyReq(d) {
    if (d.kind === 'create') return handleCreate(d);
    if (d.kind === 'get') return handleGet(d);
    if (d.kind === 'getConditional') return handleConditional(d);
    if (d.kind === 'abortConditional') return abortConditional(d.payload);
  }

  async function handleCreate(d) {
    const p = d.payload;
    const status = await bg({ type: 'getStatus' });
    if (!status.loggedIn) {
      return pkLockedDialog(
        () => respondToPage(d.id, { fallbackNative: true }),
        () => respondToPage(d.id, { cancelled: true }));
    }
    const vaults = (await bg({ type: 'getVaults' })).vaults || [];
    pkCreateDialog(p, vaults,
      async (vaultId) => {
        const res = await bg({ type: 'passkeyRegister', ...p, vaultId });
        respondToPage(d.id, res && res.locked ? { cancelled: true } : res);
      },
      () => respondToPage(d.id, { cancelled: true }),
      () => respondToPage(d.id, { fallbackNative: true }));
  }

  async function handleGet(d) {
    const p = d.payload;
    const cand = await bg({ type: 'passkeyCandidates', rpId: p.rpId, allowCredentialIds: p.allowCredentialIds });
    if (cand.locked) {
      return pkLockedDialog(
        () => respondToPage(d.id, { fallbackNative: true }),
        () => respondToPage(d.id, { cancelled: true }));
    }
    if (cand.securityError) return respondToPage(d.id, { securityError: true });
    if (!cand.items || !cand.items.length) return respondToPage(d.id, { fallbackNative: true });
    pkPickerDialog(cand.rpId, cand.items,
      async (itemId) => {
        const res = await bg({ type: 'passkeyAssert', rpId: p.rpId, challenge: p.challenge, itemId });
        respondToPage(d.id, res);
      },
      () => respondToPage(d.id, { cancelled: true }));
  }

  // Conditional UI: no modal. Arm an inline dropdown that appears when the
  // user focuses an autocomplete="webauthn" field, and resolve only then.
  let conditional = null;
  async function handleConditional(d) {
    const p = d.payload;
    const cand = await bg({ type: 'passkeyCandidates', rpId: p.rpId, allowCredentialIds: p.allowCredentialIds });
    disarmConditional();
    if (cand.locked || cand.securityError || !cand.items || !cand.items.length) {
      // Per spec, conditional get stays pending when there is nothing to
      // offer. Keep the id so an RP abort can be matched and dropped.
      conditional = { id: d.id, challenge: p.challenge, items: [] };
      return;
    }
    conditional = { id: d.id, challenge: p.challenge, rpId: p.rpId, items: cand.items };
    document.addEventListener('focusin', onConditionalFocus, true);
    // If a webauthn field is already focused, offer immediately.
    if (isWebauthnField(document.activeElement)) showConditionalDropdown(document.activeElement);
  }

  function isWebauthnField(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    return (el.autocomplete || el.getAttribute('autocomplete') || '').toLowerCase().includes('webauthn');
  }

  function onConditionalFocus(e) {
    if (conditional && conditional.items.length && isWebauthnField(e.target)) {
      showConditionalDropdown(e.target);
    }
  }

  function disarmConditional() {
    document.removeEventListener('focusin', onConditionalFocus, true);
    removePkDropdown();
  }

  function abortConditional(payload) {
    if (conditional && payload && conditional.challenge === payload.challenge) {
      disarmConditional();
      conditional = null; // page.js already rejected with AbortError
    }
  }

  // --- Passkey UI ---
  let pkOverlay = null;
  let pkDropdown = null;

  function removePkOverlay() {
    if (pkOverlay) { pkOverlay.remove(); pkOverlay = null; }
  }
  function removePkDropdown() {
    if (pkDropdown) { pkDropdown.remove(); pkDropdown = null; }
  }

  function pkModal(innerHtml) {
    removePkOverlay();
    pkOverlay = document.createElement('div');
    pkOverlay.className = 'vi-pk-overlay';
    pkOverlay.innerHTML = `<div class="vi-pk-card" role="dialog" aria-modal="true">
      <div class="vi-pk-brand">${ICON_SVG}<span>MasPassword</span></div>
      ${innerHtml}
    </div>`;
    document.body.appendChild(pkOverlay);
    return pkOverlay;
  }

  function pkCreateDialog(payload, vaults, onConfirm, onCancel, onFallback) {
    const rpId = payload.rpId || location.hostname;
    const account = payload.userName || payload.userDisplayName || '';
    const writable = vaults.filter(v => !v.role || v.role !== 'viewer');
    const options = (writable.length ? writable : vaults)
      .map(v => `<option value="${escAttr(v.id)}">${esc(v.name)}${v.team_id ? ' · ' + esc(t('pk.shared')) : ''}</option>`)
      .join('');
    const modal = pkModal(`
      <div class="vi-pk-title">${esc(t('pk.createTitle'))}</div>
      <div class="vi-pk-sub">${esc(t('pk.createFor', { rp: rpId }))}${account ? ' · ' + esc(account) : ''}</div>
      <label class="vi-pk-label">${esc(t('pk.saveTo'))}</label>
      <select class="vi-pk-select" id="vi-pk-vault">${options}</select>
      <div class="vi-pk-actions">
        <button class="vi-pk-btn vi-pk-btn-ghost" data-act="cancel">${esc(t('pk.cancel'))}</button>
        <button class="vi-pk-btn vi-pk-btn-primary" data-act="confirm">${esc(t('pk.create'))}</button>
      </div>`);
    modal.addEventListener('click', e => {
      const act = e.target.closest('[data-act]')?.dataset.act;
      if (e.target === pkOverlay || act === 'cancel') { removePkOverlay(); onCancel(); }
      else if (act === 'confirm') {
        const vaultId = modal.querySelector('#vi-pk-vault')?.value;
        removePkOverlay();
        onConfirm(vaultId);
      }
    });
  }

  function pkPickerDialog(rpId, items, onPick, onCancel) {
    const rows = items.map(it => `
      <button class="vi-pk-item" data-id="${escAttr(it.itemId)}">
        <div class="vi-pk-item-title">${esc(it.title || rpId)}</div>
        <div class="vi-pk-item-user">${esc(it.userName || '')}</div>
      </button>`).join('');
    const modal = pkModal(`
      <div class="vi-pk-title">${esc(t('pk.useTitle'))}</div>
      <div class="vi-pk-sub">${esc(t('pk.useFor', { rp: rpId }))}</div>
      <div class="vi-pk-list">${rows}</div>
      <div class="vi-pk-actions">
        <button class="vi-pk-btn vi-pk-btn-ghost" data-act="cancel">${esc(t('pk.cancel'))}</button>
      </div>`);
    modal.addEventListener('click', e => {
      if (e.target === pkOverlay || e.target.closest('[data-act="cancel"]')) { removePkOverlay(); onCancel(); return; }
      const btn = e.target.closest('.vi-pk-item');
      if (btn) { removePkOverlay(); onPick(btn.dataset.id); }
    });
  }

  function pkLockedDialog(onFallback, onCancel) {
    const modal = pkModal(`
      <div class="vi-pk-title">${esc(t('pk.lockedTitle'))}</div>
      <div class="vi-pk-sub">${esc(t('pk.lockedBody'))}</div>
      <div class="vi-pk-actions">
        <button class="vi-pk-btn vi-pk-btn-ghost" data-act="cancel">${esc(t('pk.cancel'))}</button>
        <button class="vi-pk-btn vi-pk-btn-primary" data-act="fallback">${esc(t('pk.useBrowser'))}</button>
      </div>`);
    modal.addEventListener('click', e => {
      const act = e.target.closest('[data-act]')?.dataset.act;
      if (e.target === pkOverlay || act === 'cancel') { removePkOverlay(); onCancel(); }
      else if (act === 'fallback') { removePkOverlay(); onFallback(); }
    });
  }

  function showConditionalDropdown(field) {
    if (!conditional || !conditional.items.length) return;
    removePkDropdown();
    pkDropdown = document.createElement('div');
    pkDropdown.className = 'vi-pk-dropdown';
    pkDropdown.innerHTML = `<div class="vi-pk-dropdown-head">${ICON_SVG}<span>${esc(t('pk.useTitle'))}</span></div>` +
      conditional.items.map(it => `
        <button class="vi-pk-item" data-id="${escAttr(it.itemId)}">
          <div class="vi-pk-item-title">${esc(it.title || conditional.rpId)}</div>
          <div class="vi-pk-item-user">${esc(it.userName || '')}</div>
        </button>`).join('');
    const rect = field.getBoundingClientRect();
    pkDropdown.style.top = (rect.bottom + window.scrollY + 4) + 'px';
    pkDropdown.style.left = (rect.left + window.scrollX) + 'px';
    pkDropdown.style.minWidth = Math.max(rect.width, 260) + 'px';
    document.body.appendChild(pkDropdown);
    pkDropdown.addEventListener('mousedown', async e => {
      e.preventDefault();
      const btn = e.target.closest('.vi-pk-item');
      if (!btn) return;
      const cur = conditional;
      disarmConditional();
      conditional = null;
      const res = await bg({ type: 'passkeyAssert', rpId: cur.rpId, challenge: cur.challenge, itemId: btn.dataset.id });
      respondToPage(cur.id, res);
    });
  }

  function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

  // Tell page.js the relay is live so it flushes any buffered requests.
  window.postMessage({ [PK_NS]: true, dir: 'ready' }, location.origin);

  // --- Init ---
  function init() {
    injectIcons();
    watchFormSubmissions();

    // Re-scan when DOM changes (SPA navigation, dynamic forms)
    const observer = new MutationObserver(() => {
      setTimeout(injectIcons, 200);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
