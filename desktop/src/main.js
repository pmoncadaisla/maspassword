// Launcher logic. Runs inside the bundled (frontendDist) window, so it has
// access to the Tauri API via the injected `window.__TAURI__` global
// (withGlobalTauri = true). It only collects a server URL and hands it to the
// Rust `open_vault` command, which opens the real vault window at that origin.

const invoke = window.__TAURI__.core.invoke;

const form = document.getElementById("connect-form");
const input = document.getElementById("server-url");
const errorEl = document.getElementById("error");
const connectBtn = document.getElementById("connect-btn");
const savedBlock = document.getElementById("saved-block");
const openSavedBtn = document.getElementById("open-saved");
const forgetBtn = document.getElementById("forget");

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.hidden = false;
}

function clearError() {
  errorEl.hidden = true;
}

// Accept "vault.example.com", "http://localhost:8080", etc. Default to https,
// and strip any trailing slashes so the origin is clean.
function normalizeUrl(raw) {
  let u = (raw || "").trim();
  if (!u) return "";
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u.replace(/\/+$/, "");
}

async function connect(url) {
  clearError();
  connectBtn.disabled = true;
  openSavedBtn.disabled = true;
  try {
    await invoke("open_vault", { url });
    // On success the Rust side closes this window; nothing else to do.
  } catch (e) {
    showError(String(e));
    connectBtn.disabled = false;
    openSavedBtn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const url = normalizeUrl(input.value);
  if (!url) {
    showError("Enter your server URL to continue.");
    return;
  }
  connect(url);
});

forgetBtn.addEventListener("click", async () => {
  try {
    await invoke("forget_server");
  } catch {
    /* best effort */
  }
  savedBlock.hidden = true;
  form.hidden = false;
  input.value = "";
  input.focus();
});

async function init() {
  try {
    const saved = await invoke("get_server");
    if (saved) {
      // Offer the remembered server without auto-connecting, so an unreachable
      // server doesn't leave the user with a blank window and no launcher.
      form.hidden = true;
      savedBlock.hidden = false;
      openSavedBtn.textContent = "Open " + saved;
      openSavedBtn.addEventListener("click", () => connect(saved));
      openSavedBtn.focus();
      return;
    }
  } catch {
    /* fall through to the manual form */
  }
  input.focus();
}

init();
