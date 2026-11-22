const CACHE_NAME = 'recite-pwa-v0.3.23';
const CORE_ASSETS = [
  '/recite/manifest.webmanifest',
  '/recite/apple-touch-icon.png',
  '/recite/cet-catalog.json',
  '/recite/books/CET4_1.json'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS)).catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim()).then(() =>
      self.clients.matchAll({ type: 'window' }).then((clients) => {
        clients.forEach((client) => {
          try { client.navigate(client.url); } catch {}
        });
      })
    )
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith('/recite/')) return;
  if (url.pathname === '/recite/tts' || url.pathname === '/recite/sw.js') return;

  const isHtml = url.pathname === '/recite/' || url.pathname.endsWith('.html');
  if (isHtml) {
    event.respondWith(
      fetch(event.request, { cache: 'no-store' }).then((networkResp) => {
        if (networkResp && networkResp.status === 200) {
          const clone = networkResp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/recite/', clone));
        }
        return networkResp;
      }).catch(() => caches.match('/recite/'))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const fetchPromise = fetch(event.request).then((networkResp) => {
        if (networkResp && networkResp.status === 200) {
          const clone = networkResp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return networkResp;
      }).catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
