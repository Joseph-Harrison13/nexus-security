const CACHE_NAME = 'nexus-sec-v33';
const CACHE_VERSION = 33;

// Assets to precache on install (static assets only — NOT HTML pages)
const PRECACHE = [
  '/css/styles.css',
  '/js/script.js',
];

// Routes that should never be cached (always network)
const NEVER_CACHE = [
  '/api/',
  '/uploads/',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;
  // Skip page navigations — always fetch from network so routing works correctly
  if (request.mode === 'navigate') return;
  // Skip API and upload paths — never cache
  if (NEVER_CACHE.some(p => url.pathname.startsWith(p))) return;
  // Skip cross-origin except Google Fonts
  if (url.origin !== self.location.origin && !url.hostname.includes('fonts.g')) return;

  // Cache-first for static assets (CSS, JS, fonts, images)
  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) {
        // Serve from cache and refresh in background (stale-while-revalidate)
        fetch(request).then(res => {
          if (res && res.status === 200 && res.type !== 'opaque') {
            caches.open(CACHE_NAME).then(c => c.put(request, res.clone()));
          }
        }).catch(() => {});
        return cached;
      }
      // Not in cache — fetch and store
      return fetch(request).then(res => {
        if (!res || res.status !== 200 || res.type === 'opaque') return res;
        const clone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(request, clone));
        return res;
      }).catch(() => Response.error());
    })
  );
});

// Handle background sync for offline form submissions
self.addEventListener('sync', event => {
  if (event.tag === 'contact-form') {
    event.waitUntil(replayContactForms());
  }
});

async function replayContactForms() {
  // Retrieve queued submissions from IndexedDB and replay them
  // (requires client-side queuing logic — placeholder for future use)
}

// Push notification handler
self.addEventListener('push', event => {
  if (!event.data) return;
  let payload;
  try { payload = event.data.json(); } catch { payload = { title: 'Nexus Security', body: event.data.text() }; }

  event.waitUntil(
    self.registration.showNotification(payload.title || 'Nexus Security', {
      body:    payload.body || '',
      icon:    '/icons/icon-192.png',
      badge:   '/icons/icon-192.png',
      tag:     payload.tag || 'nexus-notif',
      data:    payload.data || {},
      actions: payload.actions || [],
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/pages/dashboard/overview.html';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes(self.location.origin)) {
          client.focus();
          client.navigate(url);
          return;
        }
      }
      return clients.openWindow(url);
    })
  );
});
