// Offline-Fähigkeit: immer zuerst das Netz (damit Updates sofort da sind), sonst die zuletzt geladene Version.
const CACHE = 'radcoach-v1';
self.addEventListener('install', e => { self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['./', 'index.html', 'app.js', 'manifest.webmanifest', 'icon-180.png']))) });
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;  // GitHub-API nie cachen
  const key = u.pathname.endsWith('data.enc') ? 'data.enc' : e.request;
  e.respondWith(fetch(u.href, {cache: 'no-cache'}).then(r => { if (r.ok) { const c = r.clone(); caches.open(CACHE).then(x => x.put(key, c)) } return r })
    .catch(() => caches.match(key).then(r => r || caches.match('index.html'))));
});
