const CACHE_NAME = 'vault-v15';
// '/app' is the app shell (also the manifest start_url). '/' (landing) and
// '/index.html' (301 → /app) are intentionally NOT cached: redirects poison
// the cache for navigations, and the landing should always come from the
// network so anonymous visitors get fresh content.
const ASSETS = [
  '/app',
  '/styles.css',
  '/app.js',
  '/crypto.js',
  '/srp.js',
  '/blake2b.js',
  '/generator.js',
  '/strength.js',
  '/breach.js',
  '/import.js',
  '/i18n.js',
  '/icons.js',
  '/attachments.js',
  '/sharelink.js',
  '/duplicates.js',
  '/onboarding.js',
  '/qr.js',
  '/manifest.json',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API calls: network only
  if (url.pathname.startsWith('/auth/') || url.pathname.startsWith('/api/')) {
    return;
  }

  // Static assets: cache first, then network
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request))
  );
});
