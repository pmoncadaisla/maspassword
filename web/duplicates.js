// duplicates.js — pure helpers for duplicate/reuse detection.
// No crypto, no DOM, no network: callers pass already-decrypted item data.

// Separator for composite grouping keys; cannot appear in normal field values.
const KEY_SEP = '\u0000';

/**
 * Normalize a title for comparison: lowercase, trim, collapse runs of
 * whitespace into single spaces.
 */
export function normalizeTitle(s) {
  return String(s ?? '').toLowerCase().trim().replace(/\s+/g, ' ');
}

/**
 * Hostname of a URL without a leading 'www.', lowercased.
 * Bare hosts ('github.com') are accepted ('https://' is assumed).
 * Returns '' when nothing parseable is provided.
 */
export function registrableHost(url) {
  if (!url || typeof url !== 'string') return '';
  let raw = url.trim();
  if (!raw) return '';
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) raw = 'https://' + raw;
  let hostname = '';
  try { hostname = new URL(raw).hostname; } catch { return ''; }
  return hostname.toLowerCase().replace(/^www\./, '');
}

/**
 * Group duplicate login items.
 * items: [{ id, vaultId, vaultName, data: { title, username, url, type } }]
 * Two items are duplicates when ALL of these match:
 *   - normalizeTitle(data.title)
 *   - (data.username || '')
 *   - registrableHost(data.url || '')
 * Only items whose data.type is 'login' or undefined are considered.
 * Returns an array of groups (arrays of the original items, length >= 2).
 */
export function findDuplicateGroups(items) {
  const byKey = new Map();
  for (const item of items || []) {
    const data = (item && item.data) || {};
    if (data.type !== undefined && data.type !== 'login') continue;
    const key = [
      normalizeTitle(data.title || ''),
      data.username || '',
      registrableHost(data.url || ''),
    ].join(KEY_SEP);
    let group = byKey.get(key);
    if (!group) byKey.set(key, (group = []));
    group.push(item);
  }
  return [...byKey.values()].filter((group) => group.length >= 2);
}

/**
 * Find reused passwords across items.
 * Returns a Map password -> items[] containing only passwords used by
 * 2+ items. Empty/missing passwords are ignored.
 */
export function findReusedPasswords(items) {
  const byPassword = new Map();
  for (const item of items || []) {
    const password = item && item.data && item.data.password;
    if (!password) continue;
    let group = byPassword.get(password);
    if (!group) byPassword.set(password, (group = []));
    group.push(item);
  }
  for (const [password, group] of byPassword) {
    if (group.length < 2) byPassword.delete(password);
  }
  return byPassword;
}
