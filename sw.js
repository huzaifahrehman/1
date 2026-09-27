const CACHE_NAME = 'salary-ledger-v1.1.0';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-512-maskable.png',
  './vendor/chart.umd.min.js',
  './vendor/html2canvas.min.js',
  './vendor/jspdf.umd.min.js',
  './vendor/firebase-app-compat.js',
  './vendor/firebase-auth-compat.js',
  './vendor/firebase-database-compat.js'
];

const NEVER_CACHE_URL_PATTERNS = [
  /firebasestorage\.googleapis\.com/i,
  /firebaseio\.com/i,
  /firestore\.googleapis\.com/i,
  /identitytoolkit\.googleapis\.com/i,
  /securetoken\.googleapis\.com/i,
  /googleapis\.com/i,
  /gstatic\.com/i,
  /workers\.dev/i,
  /verify-purchase/i,
  /\/__\/auth\//i
];

function shouldNeverCache(request, url) {
  if (request.method !== 'GET') return true;
  if (!url) return false;
  for (let i = 0; i < NEVER_CACHE_URL_PATTERNS.length; i++) {
    if (NEVER_CACHE_URL_PATTERNS[i].test(url.href)) return true;
  }
  try {
    if (request.mode === 'cors' && /google|firebase|cloudflare/i.test(url.hostname)) return true;
  } catch(_) {}
  return false;
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return Promise.allSettled(
        ASSETS.map((asset) => cache.add(asset))
      );
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  let url = null;
  try { url = new URL(request.url); } catch(_) { url = null; }

  if (shouldNeverCache(request, url)) {
    event.respondWith(fetch(request).catch((err) => {
      if (request.method === 'GET') return caches.match(request);
      throw err;
    }));
    return;
  }

  if (request.method !== 'GET') return;

  if (url && /\/index\.html(\?|$|#)/i.test(url.pathname + url.search + url.hash)) {
    event.respondWith(
      fetch(request)
        .then((networkResp) => {
          if (networkResp && networkResp.status === 200 && networkResp.type === 'basic') {
            const copy = networkResp.clone();
            caches.open(CACHE_NAME).then((c) => c.put(request, copy)).catch(() => {});
          }
          return networkResp;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match('./index.html')))
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, copy)).catch(() => {});
        return response;
      }).catch(() => cached);
    })
  );
});
