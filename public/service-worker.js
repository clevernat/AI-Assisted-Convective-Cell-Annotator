// A-CLAT Service Worker - Offline Support
// Developed by clevernat

const CACHE_NAME = 'a-clat-v3.0.0';
const urlsToCache = [
  '/',
  '/static/style.css',
  '/api/health',
  'https://cdn.tailwindcss.com',
  'https://cdn.plot.ly/plotly-2.27.0.min.js',
  'https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css'
];

// Install event - cache resources
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
  self.skipWaiting();
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - serve from cache when offline
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Cache hit - return response
        if (response) {
          return response;
        }

        return fetch(event.request).then(
          (response) => {
            // Check if valid response
            if (!response || response.status !== 200 || response.type === 'opaque') {
              return response;
            }

            // Clone the response
            const responseToCache = response.clone();

            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(event.request, responseToCache);
              });

            return response;
          }
        );
      })
      .catch(() => {
        // Offline fallback
        if (event.request.destination === 'document') {
          return caches.match('/');
        }
      })
  );
});

// Background sync for offline analysis
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-analysis') {
    event.waitUntil(syncAnalysis());
  }
});

async function syncAnalysis() {
  // Sync any pending analysis when back online
  const cache = await caches.open(CACHE_NAME);
  // Implementation for syncing offline data
}