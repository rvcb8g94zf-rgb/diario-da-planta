
// ─────────────────────────────────────────────────────────────
// /api/render — meta tags dinâmicas para crawlers (Fase B / SEO)
//
// Só crawlers chegam aqui (o rewrite no vercel.json usa `has` de
// User-Agent). Humanos recebem o index.html estático normalmente.
//
// Busca o post publicado no Supabase (REST + anon key, respeitando a
// RLS de leitura pública) e devolve HTML com Open Graph / Twitter Card.
// ─────────────────────────────────────────────────────────────
 
const SB_URL = "https://dqtjuissaqxkczddnkfk.supabase.co";
const ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxdGp1aXNzYXF4a2N6ZGRua2ZrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQwOTczMDgsImV4cCI6MjA4OTY3MzMwOH0.kHOqp0qMO0nN0jlHMitf_jv5oAnmzLkzBE6gyHDX-J0";
const SITE = "https://diariodaplanta.com.br";
const DEFAULT_IMG = SITE + "/icon-512.png";
 
function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
 
function page({ title, desc, image, url, type }) {
  const t = esc(title), d = esc(desc), i = esc(image), u = esc(url);
  const fullTitle = title === "Diário da Planta" ? "Diário da Planta 🌱" : (t + " — Diário da Planta");
  return "<!DOCTYPE html>\n" +
"<html lang=\"pt-BR\">\n<head>\n" +
"<meta charset=\"utf-8\">\n" +
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
"<title>" + fullTitle + "</title>\n" +
"<meta name=\"description\" content=\"" + d + "\">\n" +
"<link rel=\"canonical\" href=\"" + u + "\">\n" +
"<meta property=\"og:site_name\" content=\"Diário da Planta\">\n" +
"<meta property=\"og:locale\" content=\"pt_BR\">\n" +
"<meta property=\"og:type\" content=\"" + (type || "website") + "\">\n" +
"<meta property=\"og:title\" content=\"" + t + "\">\n" +
"<meta property=\"og:description\" content=\"" + d + "\">\n" +
"<meta property=\"og:url\" content=\"" + u + "\">\n" +
"<meta property=\"og:image\" content=\"" + i + "\">\n" +
"<meta property=\"og:image:width\" content=\"1200\">\n" +
"<meta property=\"og:image:height\" content=\"630\">\n" +
"<meta name=\"twitter:card\" content=\"summary_large_image\">\n" +
"<meta name=\"twitter:title\" content=\"" + t + "\">\n" +
"<meta name=\"twitter:description\" content=\"" + d + "\">\n" +
"<meta name=\"twitter:image\" content=\"" + i + "\">\n" +
"</head>\n<body>\n" +
"<h1>" + t + "</h1>\n<p>" + d + "</p>\n" +
"<p><a href=\"" + u + "\">Ler no Diário da Planta</a></p>\n" +
"</body>\n</html>";
}
 
export default async function handler(req, res) {
  const slug = (req.query && req.query.slug ? String(req.query.slug) : "").replace(/\/+$/, "");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "public, s-maxage=600, stale-while-revalidate=86400");
 
  const fallback = () => res.status(200).send(page({
    title: "Diário da Planta",
    desc: "Portal de notícias sobre cannabis medicinal, ciência, legislação e cultivo — do Brasil e do mundo.",
    image: DEFAULT_IMG,
    url: SITE + "/",
  }));
 
  if (!slug) return fallback();
 
  try {
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(slug);
    const col = isUuid ? "id" : "slug";
    const q = SB_URL + "/rest/v1/portal_posts?" + col + "=eq." + encodeURIComponent(slug) +
              "&status=eq.published&select=title,excerpt,cover_url,slug,category,published_at&limit=1";
    const r = await fetch(q, { headers: { apikey: ANON_KEY, Authorization: "Bearer " + ANON_KEY } });
    if (!r.ok) return fallback();
    const rows = await r.json();
    const post = Array.isArray(rows) && rows[0] ? rows[0] : null;
    if (!post) return fallback();
 
    return res.status(200).send(page({
      title: post.title || "Diário da Planta",
      desc: (post.excerpt || "Leia esta matéria no Diário da Planta.").slice(0, 200),
      image: post.cover_url || DEFAULT_IMG,
      url: SITE + "/post/" + (post.slug || slug),
      type: "article",
    }));
  } catch (e) {
    return fallback();
  }
}
 
