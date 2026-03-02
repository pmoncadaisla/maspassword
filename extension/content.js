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
