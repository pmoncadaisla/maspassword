// ============================================================
// Sésamo — Content Script
// Detects login/signup forms, injects autofill UI, captures
// submitted credentials, and relays passkey (WebAuthn) requests.
// ============================================================

(() => {
  if (window.__vaultInternalInjected) return;
  window.__vaultInternalInjected = true;

  const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" fill="currentColor" width="18" height="18" aria-hidden="true"><polygon points="8,2 42,14 42,82 8,94"/><polygon points="88,2 54,14 54,82 88,94"/></svg>`;

  let dropdown = null;
  let saveBanner = null;
  let activeInput = null;
  let matchingItems = [];
  // Fallback for multi-step logins: by the time the password is submitted the
  // username field is often gone from the DOM (email on step 1, password on
  // step 2), so remember the last username-ish value the user typed.
  let lastTypedUsername = '';
  // True when this page IS the configured Sésamo server: the extension
  // steps aside completely (native WebAuthn dialogs, no autofill/capture).
  let passthroughNative = false;

  // --- i18n (content scripts don't load the web app's i18n module) ---
  const STRINGS = {
    es: {
      'dd.locked': 'Abre Sésamo para iniciar sesión',
      'dd.empty': 'No hay contraseñas guardadas para este sitio',
      'dd.generate': 'Generar contraseña segura',
      'dd.open': 'Abrir Sésamo',
      'gen.filled': 'Contraseña generada',
      'save.title.new': '¿Guardar contraseña en Sésamo?',
      'save.title.update': '¿Actualizar contraseña en Sésamo?',
      'save.body': '{user} en {site}',
      'save.noUser': 'Sin usuario',
      'save.save': 'Guardar',
      'save.update': 'Actualizar',
      'save.dismiss': 'Ahora no',
      'save.saved': 'Contraseña guardada en Sésamo',
      'save.updated': 'Contraseña actualizada',
      'save.failed': 'No se pudo guardar: {err}',
      'pk.shared': 'compartida', 'pk.createTitle': 'Crear un passkey',
      'pk.createFor': 'Para {rp}', 'pk.saveTo': 'Guardar en',
      'pk.cancel': 'Cancelar', 'pk.create': 'Crear',
      'pk.useTitle': 'Usar un passkey', 'pk.useFor': 'Para {rp}',
      'pk.lockedTitle': 'Sésamo está bloqueado',
      'pk.lockedBody': 'Desbloquea la extensión para usar tus passkeys, o continúa con el navegador.',
      'pk.useBrowser': 'Usar el navegador',
    },
    en: {
      'dd.locked': 'Open Sésamo to log in',
      'dd.empty': 'No saved passwords for this site',
      'dd.generate': 'Generate a strong password',
      'dd.open': 'Open Sésamo',
      'gen.filled': 'Password generated',
      'save.title.new': 'Save password to Sésamo?',
      'save.title.update': 'Update password in Sésamo?',
      'save.body': '{user} on {site}',
      'save.noUser': 'No username',
      'save.save': 'Save',
      'save.update': 'Update',
      'save.dismiss': 'Not now',
      'save.saved': 'Password saved to Sésamo',
      'save.updated': 'Password updated',
      'save.failed': 'Could not save: {err}',
      'pk.shared': 'shared', 'pk.createTitle': 'Create a passkey',
      'pk.createFor': 'For {rp}', 'pk.saveTo': 'Save to',
      'pk.cancel': 'Cancel', 'pk.create': 'Create',
      'pk.useTitle': 'Use a passkey', 'pk.useFor': 'For {rp}',
      'pk.lockedTitle': 'Sésamo is locked',
      'pk.lockedBody': 'Unlock the extension to use your passkeys, or continue with the browser.',
      'pk.useBrowser': 'Use the browser',
    },
  };
  const LOCALE = (navigator.language || 'es').toLowerCase().startsWith('en') ? 'en' : 'es';
  function t(key, vars) {
    let s = (STRINGS[LOCALE] && STRINGS[LOCALE][key]) || STRINGS.en[key] || key;
    if (vars) for (const k in vars) s = s.replace('{' + k + '}', vars[k]);
    return s;
  }

  // Promise wrapper over sendMessage that never throws: the extension can be
  // reloaded/updated under a live page, which invalidates this context.
  function bg(msg) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(msg, resp => {
          void chrome.runtime.lastError;
          resolve(resp);
        });
      } catch { resolve(undefined); }
    });
  }

  // Server-driven skin: everything we inject picks up the ODS look — the
  // Sésamo brand — unless the deployment opts out with theme "light"
  // (same resolution as the web app).
  let uiTheme = 'orange';
  function themed(el) {
    if (uiTheme !== 'light') el.classList.add('vi-orange');
    return el;
  }

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
      themed(icon);
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
    const resp = await bg({ type: 'getMatchingItems', url: location.href });
    matchingItems = resp?.items || [];
    const status = await bg({ type: 'getStatus' });

    removeDropdown();
    dropdown = document.createElement('div');
    dropdown.className = 'vi-dropdown';
    themed(dropdown);

    if (!status?.loggedIn) {
      dropdown.innerHTML = `
        <div class="vi-dropdown-empty">${esc(t('dd.locked'))}</div>
        <button class="vi-dropdown-action" data-action="open">${esc(t('dd.open'))}</button>
      `;
    } else if (matchingItems.length === 0) {
      dropdown.innerHTML = `
        <div class="vi-dropdown-empty">${esc(t('dd.empty'))}</div>
        <button class="vi-dropdown-action" data-action="generate">${esc(t('dd.generate'))}</button>
        <button class="vi-dropdown-action" data-action="open">${esc(t('dd.open'))}</button>
      `;
    } else {
      const itemsHtml = matchingItems.map((item, i) => `
        <button class="vi-dropdown-item" data-index="${i}">
          <div class="vi-dropdown-item-title">${esc(item.data.title || 'Untitled')}</div>
          <div class="vi-dropdown-item-user">${esc(item.data.username || '')}</div>
        </button>
      `).join('');
      dropdown.innerHTML = `
        ${itemsHtml}
        <div class="vi-dropdown-sep"></div>
        <button class="vi-dropdown-action" data-action="generate">${esc(t('dd.generate'))}</button>
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
        if (action === 'open') bg({ type: 'openPopup' });
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
    const resp = await bg({ type: 'generatePassword' });
    if (!resp?.password) return;
    setInputValue(passwordField, resp.password);
    // If there's a confirm password field, fill that too
    const form = passwordField.closest('form');
    if (form) {
      form.querySelectorAll('input[type="password"]').forEach(f => {
        if (f !== passwordField) setInputValue(f, resp.password);
      });
    }
    // Stage right away so the generated secret survives even if we never see
    // a recognizable submit; submit-time capture re-stages with fresh values,
    // so an edited or regenerated password is never saved stale (that was the
    // old bug: the banner closed over the value at generation time).
    const userField = findUsernameField(passwordField);
    stageCredentials((userField && userField.value) || lastTypedUsername, resp.password);
    showToast(t('gen.filled'));
  }

  // --- Credential capture -> pending save ---
  // Submitted credentials are staged in the BACKGROUND immediately (per tab,
  // short TTL). The offer-to-save banner appears once the page has settled:
  // either here after a short delay (SPA, no navigation), or from the content
  // script of the NEXT document — classic logins navigate away, which is
  // exactly where the old setTimeout-in-this-page approach lost them.

  function stageCredentials(username, password) {
    if (!password) return;
    bg({
      type: 'stagePendingSave',
      username: username || '',
      password,
      url: location.href,
      site: extractSiteName(),
    });
  }

  // The password that was submitted: prefer autocomplete="new-password"
  // fields (signup / change-password forms — grabbing the first field picks
  // the *current* password on change forms), else the last filled one.
  function bestPasswordField(scope) {
    let fields = [...scope.querySelectorAll('input[type="password"]')].filter(f => f.value);
    if (!fields.length) return null;
    // Prefer visible fields (hidden ones are usually honeypots), but don't
    // require it — some pages hide the form the instant it is submitted.
    const visible = fields.filter(isVisible);
    if (visible.length) fields = visible;
    const news = fields.filter(f => (f.autocomplete || '').toLowerCase().includes('new-password'));
    const pool = news.length ? news : fields;
    return pool[pool.length - 1];
  }

  function captureAndStage(scope) {
    const pwField = bestPasswordField(scope || document) || bestPasswordField(document);
    if (!pwField) return;
    const userField = findUsernameField(pwField);
    const username = (userField && userField.value) || lastTypedUsername || '';
    stageCredentials(username, pwField.value);
  }

  let bannerTimer = null;
  function scheduleSameDocumentBanner() {
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(offerPendingSave, 1400);
  }

  async function offerPendingSave() {
    if (saveBanner) return;
    const resp = await bg({ type: 'checkPendingSave' });
    if (resp?.pending) showSaveBanner(resp.pending);
  }

  function looksLikeSubmit(btn, form) {
    const type = (btn.type || '').toLowerCase();
    if (type === 'submit') return true;
    // <button> inside a form defaults to type=submit
    if (btn.tagName === 'BUTTON' && form && type !== 'button' && type !== 'reset') return true;
    return /\b(log ?in|sign ?in|sign ?up|submit|continue|next|entrar|iniciar|acceder|registr|continuar|siguiente|enviar|guardar)\b/i
      .test(btn.textContent || btn.value || '');
  }

  function watchCredentialCapture() {
    document.addEventListener('input', e => {
      const el = e.target;
      if (el?.tagName === 'INPUT' && el.value && isUsernameField(el)) lastTypedUsername = el.value;
    }, true);

    document.addEventListener('submit', e => {
      if (e.target instanceof HTMLFormElement) {
        captureAndStage(e.target);
        scheduleSameDocumentBanner();
      }
    }, true);

    document.addEventListener('keydown', e => {
      const el = e.target;
      if (e.key === 'Enter' && el?.tagName === 'INPUT' && el.type === 'password' && el.value) {
        captureAndStage(el.closest('form') || document);
        scheduleSameDocumentBanner();
      }
    }, true);

    // SPAs that "submit" via a button click + fetch and never fire a submit
    // event. (The old HTMLFormElement.prototype.submit override ran in the
    // isolated world, so it never saw the page's own calls — dead code.)
    document.addEventListener('click', e => {
      const btn = e.target?.closest?.('button, input[type="submit"], [role="button"]');
      if (!btn) return;
      const form = btn.closest('form');
      const scope = form || document;
      if (!bestPasswordField(scope)) return;
      captureAndStage(scope);
      if (looksLikeSubmit(btn, form)) scheduleSameDocumentBanner();
    }, true);
  }

  // --- Save banner ---
  async function showSaveBanner(pending) {
    removeSaveBanner();
    const isUpdate = pending.kind === 'update';
    let vaultSelect = '';
    if (!isUpdate) {
      const vaults = (await bg({ type: 'getVaults' }))?.vaults || [];
      if (vaults.length > 1) {
        vaultSelect = `<select class="vi-save-vault" id="vi-save-vault">` +
          vaults.map(v => `<option value="${escAttr(v.id)}">${esc(v.name)}</option>`).join('') +
          `</select>`;
      }
    }
    const user = pending.username || t('save.noUser');
    const site = (isUpdate && pending.title) || pending.site || '';

    saveBanner = document.createElement('div');
    saveBanner.className = 'vi-save-banner';
    themed(saveBanner);
    saveBanner.innerHTML = `
      <div class="vi-save-banner-content">
        <div class="vi-save-banner-icon">${ICON_SVG}</div>
        <div class="vi-save-banner-text">
          <strong>${esc(isUpdate ? t('save.title.update') : t('save.title.new'))}</strong>
          <span>${esc(t('save.body', { user, site }))}</span>
        </div>
        ${vaultSelect}
        <div class="vi-save-banner-actions">
          <button class="vi-save-btn vi-save-btn-primary" data-action="save">${esc(isUpdate ? t('save.update') : t('save.save'))}</button>
          <button class="vi-save-btn vi-save-btn-dismiss" data-action="dismiss">${esc(t('save.dismiss'))}</button>
        </div>
      </div>
    `;
    document.body.appendChild(saveBanner);
    // Animate in
    requestAnimationFrame(() => saveBanner.classList.add('vi-save-banner-show'));

    saveBanner.addEventListener('click', async e => {
      const action = e.target.closest('[data-action]')?.dataset.action;
      if (action === 'save') {
        const vaultId = saveBanner.querySelector('#vi-save-vault')?.value;
        removeSaveBanner();
        const res = await bg({ type: 'commitPendingSave', vaultId });
        if (res?.ok) showToast(res.updated ? t('save.updated') : t('save.saved'));
        else showToast(t('save.failed', { err: res?.error || '' }), true);
      } else if (action === 'dismiss') {
        removeSaveBanner();
        bg({ type: 'dismissPendingSave' });
      }
    });

    // Auto-hide (visual only — the staged entry expires on its own TTL).
    setTimeout(removeSaveBanner, 30000);
  }

  function removeSaveBanner() {
    if (saveBanner) { saveBanner.remove(); saveBanner = null; }
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
    themed(toast);
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
    // On Sésamo itself every WebAuthn request goes to the NATIVE
    // browser dialog: an app-login passkey must live outside the vault it
    // opens (iCloud Keychain, security key…), never inside it.
    if (passthroughNative) {
      if (d.kind === 'abortConditional') return;
      return respondToPage(d.id, { fallbackNative: true });
    }
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
    const vaults = (await bg({ type: 'getVaults' }))?.vaults || [];
    if (!vaults.length) {
      // Expired session or no vaults: never show an empty picker — let the
      // browser create the passkey natively instead.
      return respondToPage(d.id, { fallbackNative: true });
    }
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
    themed(pkOverlay);
    pkOverlay.innerHTML = `<div class="vi-pk-card" role="dialog" aria-modal="true">
      <div class="vi-pk-brand">${ICON_SVG}<span>Sésamo</span></div>
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
    themed(pkDropdown);
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

  // --- Init ---
  async function init() {
    // Detect the extension's own server BEFORE releasing buffered passkey
    // requests, so they resolve natively there.
    const status = await bg({ type: 'getStatus' });
    try {
      passthroughNative = !!status?.serverUrl && new URL(status.serverUrl).origin === location.origin;
    } catch {}

    // Tell page.js the relay is live so it flushes any buffered requests.
    window.postMessage({ [PK_NS]: true, dir: 'ready' }, location.origin);

    // On Sésamo itself: no autofill icons, no credential capture (we
    // are not going to offer saving the master password into the vault it
    // opens), no passkey UI — the browser's native dialogs take over.
    if (passthroughNative) return;

    // Resolve the deployment's theme once; anything injected afterwards is
    // themed. (Injection happens on user interaction, well after this.)
    bg({ type: 'getMode' }).then(mode => { uiTheme = mode?.theme || 'orange'; });
    injectIcons();
    watchCredentialCapture();
    // A login on the previous page may have staged credentials — offer now.
    offerPendingSave();

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
