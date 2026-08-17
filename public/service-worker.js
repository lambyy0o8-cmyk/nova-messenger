// ------------------------------------------------------------------
// Service worker для Nova Messenger.
//
// Кэширует только СТАТИКУ (HTML/CSS/JS/иконки), чтобы интерфейс
// открывался мгновенно и даже при плохом/отсутствующем интернете.
// Сами сообщения по-прежнему требуют живого соединения с сервером —
// это кэш интерфейса, а не офлайн-мессенджер.
//
// Версия кэша: увеличивай CACHE_NAME при каждом деплое новой версии
// статики, иначе пользователи будут видеть старые файлы из кэша.
// ------------------------------------------------------------------

const CACHE_NAME = 'nova-static-v1';

const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/style.css',
  '/calls.css',
  '/app.js',
  '/calls-client.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // Socket.IO (WS/polling) и любые чужие origin'ы (CDN qrcodejs и т.п.)
  // сервис-воркер не трогает — только реальная сеть, никакого кэша.
  if (url.pathname.startsWith('/socket.io/') || url.origin !== self.location.origin) {
    return;
  }

  // Стратегия "сеть, с откатом на кэш": если сервер доступен — берём
  // свежую версию файла (и обновляем кэш), если нет — отдаём то, что
  // закэшировано. Это лучше "кэш всегда первый" для дев-проекта,
  // который часто меняется.
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then((cached) => cached || caches.match('/index.html')))
  );
});
