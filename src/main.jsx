import React from "react";
import ReactDOM from "react-dom/client";
import * as Sentry from "@sentry/react";
import App from "./App";

// ─────────────────────────────────────────────────────────────
// Sentry — observabilidade de erros de produção
// Privacidade: captura user.id (UUID anônimo), nunca email/senha.
// Sanitiza payloads para remover campos de texto longo, media base64,
// e qualquer header de Authorization/apikey que vaze em breadcrumbs.
// ─────────────────────────────────────────────────────────────
const SENTRY_DSN = "https://1e51f0b583cd373d357973a58ef640ce@o4511214535966720.ingest.us.sentry.io/4511214716583936";
const MODE = import.meta.env.MODE || "production";

const IGNORE_URL_PATTERNS = [
  /extensions\//i,
  /^chrome-extension:/i,
  /^moz-extension:/i,
  /^safari-extension:/i,
  /^safari-web-extension:/i,
];

const IGNORE_ERROR_MESSAGES = [
  /ResizeObserver loop/i,
  /Non-Error promise rejection captured/i,
  /Network request failed/i,
  /Load failed/i,
  /ChunkLoadError/i,
  /Script error\.?$/i,
  /Failed to fetch/i,
  /The operation was aborted/i,
  /cancelled/i,
];

const SENSITIVE_KEYS = /^(password|pw|pw2|token|access_token|refresh_token|apikey|authorization|email|media|media_url|avatar_url|content|text|body|message|msg|description)$/i;
const MAX_STR_LEN = 200;

function sanitize(obj, depth = 0) {
  if (depth > 4 || obj == null) return obj;
  if (typeof obj === "string") {
    if (obj.startsWith("data:")) return "[base64-data]";
    if (obj.length > MAX_STR_LEN) return obj.slice(0, MAX_STR_LEN) + "...[truncated]";
    return obj;
  }
  if (Array.isArray(obj)) return obj.slice(0, 20).map((v) => sanitize(v, depth + 1));
  if (typeof obj === "object") {
    const out = {};
    for (const k of Object.keys(obj)) {
      if (SENSITIVE_KEYS.test(k)) {
        out[k] = "[redacted]";
      } else {
        try { out[k] = sanitize(obj[k], depth + 1); } catch { out[k] = "[unserializable]"; }
      }
    }
    return out;
  }
  return obj;
}

try {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: MODE,
    release: "diario-da-planta@1.0.0",
    tracesSampleRate: 0.1,
    maxBreadcrumbs: 50,
    attachStacktrace: true,
    autoSessionTracking: true,
    ignoreErrors: IGNORE_ERROR_MESSAGES,
    denyUrls: IGNORE_URL_PATTERNS,
    beforeSend(event) {
      try {
        if (event.contexts) event.contexts = sanitize(event.contexts);
        if (event.extra) event.extra = sanitize(event.extra);
        if (event.tags) event.tags = sanitize(event.tags);
        if (event.request) {
          if (event.request.headers) {
            const h = event.request.headers;
            if (h.Authorization) h.Authorization = "[redacted]";
            if (h.authorization) h.authorization = "[redacted]";
            if (h.apikey) h.apikey = "[redacted]";
          }
          if (event.request.data) event.request.data = sanitize(event.request.data);
          if (event.request.query_string && typeof event.request.query_string === "string" && event.request.query_string.length > 200) {
            event.request.query_string = event.request.query_string.slice(0, 200) + "...";
          }
        }
        if (event.user) {
          if (event.user.email) delete event.user.email;
          if (event.user.ip_address) event.user.ip_address = "{{auto}}";
          if (event.user.username) delete event.user.username;
        }
      } catch (e) {}
      return event;
    },
    beforeBreadcrumb(crumb) {
      try {
        if (crumb.category === "fetch" || crumb.category === "xhr") {
          if (crumb.data) {
            if (crumb.data.url && typeof crumb.data.url === "string") {
              crumb.data.url = crumb.data.url.replace(/([?&])(access_token|refresh_token|apikey|token)=[^&]*/gi, "$1$2=[redacted]");
            }
            if (crumb.data.body) crumb.data.body = "[body-omitted]";
          }
        }
        if (crumb.category === "console" && crumb.message && crumb.message.length > MAX_STR_LEN) {
          crumb.message = crumb.message.slice(0, MAX_STR_LEN) + "...";
        }
        if (crumb.category === "navigation" && crumb.data) {
          if (crumb.data.from) crumb.data.from = String(crumb.data.from).replace(/([?&])(access_token|refresh_token|token)=[^&]*/gi, "$1$2=[redacted]");
          if (crumb.data.to) crumb.data.to = String(crumb.data.to).replace(/([?&])(access_token|refresh_token|token)=[^&]*/gi, "$1$2=[redacted]");
        }
      } catch {}
      return crumb;
    },
  });
} catch (e) {
  console.warn("[sentry] init failed:", e);
}

// Fallback UI quando o React dá crash catastrófico
function CrashFallback({ error, resetError }) {
  return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"100vh",padding:"24px",fontFamily:"-apple-system,BlinkMacSystemFont,Inter,sans-serif",background:"#f8f9fa",color:"#1a1a1a"}}>
      <div style={{maxWidth:"480px",textAlign:"center"}}>
        <div style={{fontSize:"48px",marginBottom:"16px"}}>🌱</div>
        <h1 style={{fontSize:"22px",fontWeight:700,marginBottom:"12px"}}>Algo deu errado</h1>
        <p style={{fontSize:"14px",color:"#666",marginBottom:"8px"}}>
          Encontramos um erro inesperado e ele foi reportado automaticamente para nossa equipe.
        </p>
        <p style={{fontSize:"12px",color:"#999",marginBottom:"24px"}}>
          Você pode tentar recarregar a página. Se o problema persistir, nos avise pelo email de suporte.
        </p>
        <div style={{display:"flex",gap:"12px",justifyContent:"center"}}>
          <button onClick={resetError} style={{padding:"10px 20px",borderRadius:"10px",border:"1px solid #ddd",background:"#fff",color:"#1a1a1a",cursor:"pointer",fontSize:"14px",fontWeight:600}}>Tentar novamente</button>
          <button onClick={()=>window.location.reload()} style={{padding:"10px 20px",borderRadius:"10px",border:"none",background:"#1B9E42",color:"#fff",cursor:"pointer",fontSize:"14px",fontWeight:600}}>Recarregar</button>
        </div>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Sentry.ErrorBoundary fallback={CrashFallback} showDialog={false}>
      <App />
    </Sentry.ErrorBoundary>
  </React.StrictMode>
);
