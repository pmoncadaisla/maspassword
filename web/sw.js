const CACHE_NAME = 'vault-v5';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/crypto.js',
  '/srp.js',
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
