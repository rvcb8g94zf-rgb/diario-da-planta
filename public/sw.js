// ─────────────────────────────────────────────────────────────
// Service Worker — Diário da Planta
// Arquitetura atual: bucket "media" é PÚBLICO (sem reescrita/token),
// "media-private" usa URLs assinadas (nunca passam pelo SW).
//
// Regras de ouro:
//  • NUNCA intercepta recursos de terceiros (imagens de notícia,
//    fontes, analytics, Supabase). Deixa a rede/navegador cuidar —
//    evita bloqueios de CSP e o erro "Failed to convert to Response".
//  • Cacheia apenas os assets DO PRÓPRIO app (mesma origem), com
//    estratégia network-first, para nunca servir bundle velho.
//  • Versionado: bump em CACHE_VERSION troca o cache e limpa o antigo.
// ─────────────────────────────────────────────────────────────

const CACHE_VERSION = 'dp-v4';
const PRECACHE = ['/', '/index.html'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_VERSION)
      .then((c) => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Permite que a página peça atualização imediata (opcional)
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  const req = e.request;

  // Só lida com GET
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch { return; }

  // ── Regra 1: qualquer coisa de OUTRA ORIGEM passa direto (sem interceptar) ──
  // Imagens de notícia, fontes do Google, analytics, Supabase (API/storage/auth):
  // o SW não entra no meio, então nada de bloqueio de CSP nem erros de Response.
  if (url.origin !== self.location.origin) return;

  // ── Regra 2: navegação (HTML) — network-first com fallback ao cache ──
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE_VERSION).then((c) => c.put('/index.html', clone)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then((r) => r || caches.match('/index.html')))
    );
    return;
  }

  // ── Regra 3: assets do próprio app (JS/CSS/ícones/manifest) — network-first ──
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok && res.type === 'basic') {
          const clone = res.clone();
          caches.open(CACHE_VERSION).then((c) => c.put(req, clone)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});
