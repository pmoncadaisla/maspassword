import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LOCALES, MESSAGES, initI18n, getLocale, setLocale, t, applyI18n } from '../i18n.js';

// --- Test helpers: mock browser globals (Node 22 has neither localStorage
// by default nor a settable navigator, but both are configurable). ---

function mockLocalStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: (k) => { store.delete(k); },
  };
  return store;
}

function clearLocalStorage() {
  delete globalThis.localStorage;
}

function mockNavigator(language) {
  Object.defineProperty(globalThis, 'navigator', {
    value: { language },
    configurable: true,
    writable: true,
  });
}

// --- Catalog integrity ---

test('LOCALES is es/en/fr with es first (default)', () => {
  assert.deepEqual(LOCALES, ['es', 'en', 'fr']);
  assert.deepEqual(Object.keys(MESSAGES).sort(), [...LOCALES].sort());
});

test('all locales have IDENTICAL key sets', () => {
  const esKeys = Object.keys(MESSAGES.es).sort();
  const enKeys = Object.keys(MESSAGES.en).sort();
  const frKeys = Object.keys(MESSAGES.fr).sort();
  assert.deepEqual(enKeys, esKeys, 'en key set differs from es');
  assert.deepEqual(frKeys, esKeys, 'fr key set differs from es');
  assert.ok(esKeys.length >= 120, `expected a substantial catalog, got ${esKeys.length} keys`);
});

test('every value is a non-empty string in every locale', () => {
  for (const locale of LOCALES) {
    for (const [key, value] of Object.entries(MESSAGES[locale])) {
      assert.equal(typeof value, 'string', `${locale}:${key} is not a string`);
      assert.ok(value.trim().length > 0, `${locale}:${key} is empty`);
    }
  }
});

test('keys use dot.notation (no spaces, no uppercase segments-only weirdness)', () => {
  for (const key of Object.keys(MESSAGES.es)) {
    assert.match(key, /^[a-z][a-zA-Z0-9]*(\.[a-zA-Z0-9]+)+$/, `bad key format: ${key}`);
  }
});

test('required keys for the upcoming UI are present', () => {
  const required = [
    'version.running',
    'items.lastEdited',
    'items.attachments',
    'items.attachments.add',
    'items.attachments.tooBig',
    'items.customFields',
    'items.customFields.add',
    'items.customFields.label',
    'items.customFields.value',
    'items.icon.change',
    'share.title',
    'share.create',
    'share.expires',
    'share.copy',
    'share.oneUse',
    'share.revoked',
    'share.open.title',
    'share.open.gone',
    'vault.sharedWith',
    'teams.promote',
    'teams.demote',
    'teams.role.admin',
    'teams.role.member',
    'search.global.placeholder',
    'watchtower.duplicates',
    'settings.language',
  ];
  for (const key of required) {
    for (const locale of LOCALES) {
      assert.ok(key in MESSAGES[locale], `missing ${key} in ${locale}`);
    }
  }
});

test('spec-pinned ES values are exact', () => {
  assert.equal(MESSAGES.es['version.running'], 'Version {v}');
  assert.equal(MESSAGES.es['items.lastEdited'], 'Editado por {name} {when}');
});

// A key defined twice in the same catalog is invisible at runtime — the last
// literal silently wins — so check the source text, not the parsed object.
test('no locale defines the same key twice', () => {
  const src = readFileSync(new URL('../i18n.js', import.meta.url), 'utf8');
  const starts = [...src.matchAll(/^const (\w+) = \{/gm)];
  const named = starts.filter(([, name]) => LOCALES.includes(name));
  assert.equal(named.length, LOCALES.length, 'every locale has a catalog literal');

  for (const [i, match] of starts.entries()) {
    const name = match[1];
    if (!LOCALES.includes(name)) continue;
    const end = i + 1 < starts.length ? starts[i + 1].index : src.length;
    const seen = new Set();
    const dupes = [];
    for (const [, key] of src.slice(match.index, end).matchAll(/^ {2}'([^']+)':/gm)) {
      if (seen.has(key)) dupes.push(key);
      seen.add(key);
    }
    assert.deepEqual(dupes, [], `${name} defines duplicate keys: ${dupes.join(', ')}`);
  }
});

test('core app strings are covered in the catalog', () => {
  const core = [
    'auth.login', 'auth.signup.title', 'auth.masterPassword', 'lock.title', 'auth.unlock',
    'sidebar.vaults', 'sidebar.teams', 'sidebar.tools', 'sidebar.watchtower',
    'sidebar.generator', 'sidebar.darkMode', 'sidebar.lightMode', 'sidebar.lockVault', 'sidebar.logout',
    'type.login', 'type.card', 'type.note', 'type.identity',
    'items.favorites', 'fields.tags', 'actions.copy', 'actions.edit', 'actions.delete',
    'history.title', 'fields.totp', 'breach.check',
    'strength.veryWeak', 'strength.weak', 'strength.fair', 'strength.strong', 'strength.veryStrong',
    'generator.title', 'watchtower.weak', 'watchtower.reused', 'watchtower.aging', 'watchtower.breaches',
    'cmd.placeholder', 'import.title', 'export.title',
    'teams.members', 'teams.addMember', 'teams.role.owner',
    'toast.copied', 'toast.unlocked',
  ];
  for (const key of core) {
    assert.ok(key in MESSAGES.es, `missing core key ${key}`);
  }
});

// --- initI18n / getLocale / setLocale ---

test('initI18n reads a valid stored locale from localStorage', () => {
  mockLocalStorage({ 'mp-locale': 'fr' });
  assert.equal(initI18n(), 'fr');
  assert.equal(getLocale(), 'fr');
});

test('initI18n ignores an invalid stored locale and prefix-matches navigator.language', () => {
  mockLocalStorage({ 'mp-locale': 'de' });
  mockNavigator('en-US');
  assert.equal(initI18n(), 'en');
});

test('initI18n falls back to navigator.language prefix when nothing is stored', () => {
  mockLocalStorage({});
  mockNavigator('fr-CA');
  assert.equal(initI18n(), 'fr');
});

test("initI18n defaults to 'es' when navigator language is unsupported", () => {
  mockLocalStorage({});
  mockNavigator('de-DE');
  assert.equal(initI18n(), 'es');
});

test("initI18n defaults to 'es' when localStorage is unavailable and navigator has no match", () => {
  clearLocalStorage();
  mockNavigator('pt-BR');
  assert.equal(initI18n(), 'es');
});

test('setLocale switches the active locale and persists to localStorage', () => {
  const store = mockLocalStorage({});
  setLocale('en');
  assert.equal(getLocale(), 'en');
  assert.equal(store.get('mp-locale'), 'en');
});

test('setLocale ignores unsupported locales', () => {
  mockLocalStorage({});
  setLocale('es');
  setLocale('xx');
  assert.equal(getLocale(), 'es');
});

// --- t() ---

test('t translates in the active locale', () => {
  mockLocalStorage({});
  setLocale('es');
  assert.equal(t('toast.copied'), 'Copiado');
  setLocale('en');
  assert.equal(t('toast.copied'), 'Copied');
  setLocale('fr');
  assert.equal(t('toast.copied'), 'Copié');
});

test('t interpolates {name} placeholders from vars', () => {
  mockLocalStorage({});
  setLocale('es');
  assert.equal(t('items.lastEdited', { name: 'Ana', when: 'ayer' }), 'Editado por Ana ayer');
  assert.equal(t('version.running', { v: '1.2.3' }), 'Version 1.2.3');
  setLocale('en');
  assert.equal(
    t('watchtower.summary', { logins: 7, vaults: 2 }),
    'Scanned 7 logins across 2 vaults.',
  );
});

test('t leaves unknown placeholders intact and tolerates missing vars', () => {
  mockLocalStorage({});
  setLocale('en');
  assert.equal(t('items.lastEdited', { name: 'Bob' }), 'Edited by Bob {when}');
  assert.equal(t('items.lastEdited'), 'Edited by {name} {when}');
});

test("t falls back to the 'es' string when a key is missing in the active locale", () => {
  mockLocalStorage({});
  setLocale('en');
  const saved = MESSAGES.en['app.tagline'];
  delete MESSAGES.en['app.tagline'];
  try {
    assert.equal(t('app.tagline'), MESSAGES.es['app.tagline']);
  } finally {
    MESSAGES.en['app.tagline'] = saved;
    setLocale('es');
  }
});

test('t falls back to the key itself for unknown keys (with interpolation)', () => {
  mockLocalStorage({});
  setLocale('es');
  assert.equal(t('nope.not.a.key'), 'nope.not.a.key');
  assert.equal(t('literal {x}', { x: 1 }), 'literal 1');
});

// --- applyI18n ---

function fakeEl(attrs) {
  return {
    attrs: { ...attrs },
    textContent: '',
    getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; },
    setAttribute(name, value) { this.attrs[name] = value; },
  };
}

test('applyI18n sets textContent, placeholder and title from data-i18n* attributes', () => {
  mockLocalStorage({});
  setLocale('en');
  const textNode = fakeEl({ 'data-i18n': 'sidebar.vaults' });
  const inputNode = fakeEl({ 'data-i18n-placeholder': 'items.search.placeholder' });
  const btnNode = fakeEl({ 'data-i18n-title': 'actions.copy' });
  const htmlNode = fakeEl({ 'data-i18n-html': 'landing.how.s3.text' });
  const root = {
    querySelectorAll(selector) {
      if (selector === '[data-i18n]') return [textNode];
      if (selector === '[data-i18n-placeholder]') return [inputNode];
      if (selector === '[data-i18n-title]') return [btnNode];
      if (selector === '[data-i18n-html]') return [htmlNode];
      return [];
    },
  };
  applyI18n(root);
  assert.equal(textNode.textContent, 'Vaults');
  assert.equal(inputNode.attrs.placeholder, 'Search items...');
  assert.equal(btnNode.attrs.title, 'Copy');
  assert.ok(htmlNode.innerHTML.includes('<code>pg_dump</code>'), 'data-i18n-html keeps inline markup');

  setLocale('fr');
  applyI18n(root);
  assert.equal(textNode.textContent, 'Coffres');
  assert.equal(btnNode.attrs.title, 'Copier');
  setLocale('es');
});

test('applyI18n is a no-op for null/invalid roots (never throws)', () => {
  applyI18n(null);
  applyI18n({});
  applyI18n(undefined); // no document in Node -> default resolves to null
});

// Every data-i18n* key referenced by the landing page must exist in the es
// catalog (the fallback locale). A typo here would silently render the raw
// key string on the public landing.
test('landing.html references only existing catalog keys', () => {
  const html = readFileSync(new URL('../landing.html', import.meta.url), 'utf8');
  const keys = [...html.matchAll(/data-i18n(?:-html)?="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(keys.length > 40, `expected a fully tagged landing, found ${keys.length} keys`);
  setLocale('es');
  const missing = keys.filter((k) => t(k) === k);
  assert.deepEqual(missing, [], `landing keys missing from catalogs: ${missing.join(', ')}`);
  // The keys the landing script sets outside data-i18n attributes:
  for (const k of ['landing.title', 'landing.metaDescription']) {
    assert.notEqual(t(k), k, `${k} missing from catalogs`);
  }
});
