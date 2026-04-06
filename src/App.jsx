import React, { useState, useEffect, useRef, useCallback } from "react";

// ─── Supabase Config ───
const SB_URL = "https://dqtjuissaqxkczddnkfk.supabase.co";
const SB_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxdGp1aXNzYXF4a2N6ZGRua2ZrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQwOTczMDgsImV4cCI6MjA4OTY3MzMwOH0.kHOqp0qMO0nN0jlHMitf_jv5oAnmzLkzBE6gyHDX-J0";

// ─── Error Monitoring (Sentry) ───
// Configure: replace DSN with your Sentry project DSN from https://sentry.io
const SENTRY_DSN = "https://3cdfd5652417b5cabaddf0677781d77c@o4511092002324480.ingest.us.sentry.io/4511092012548096";
const sentryReport = (error, context = {}) => {
  if (!SENTRY_DSN) return;
  try {
    const payload = {
      event_id: crypto.randomUUID?.() || Date.now().toString(36),
      timestamp: new Date().toISOString(),
      platform: "javascript",
      level: "error",
      logger: "diario-da-planta",
      message: { formatted: error?.message || String(error) },
      exception: { values: [{ type: error?.name || "Error", value: error?.message || String(error), stacktrace: error?.stack ? { frames: error.stack.split("\n").slice(0, 10).map(l => ({ filename: l.trim() })) } : undefined }] },
      tags: { app: "diario-da-planta", ...context.tags },
      extra: context.extra || {},
      request: { url: window.location?.href },
      user: context.user ? { id: context.user.id, email: context.user.email, username: context.user.username } : undefined,
    };
    const [, key, url] = SENTRY_DSN.match(/^https:\/\/(.+?)@(.+)$/) || [];
    if (key && url) fetch(`https://${url}/api/store/`, { method: "POST", headers: { "Content-Type": "application/json", "X-Sentry-Auth": `Sentry sentry_key=${key},sentry_version=7` }, body: JSON.stringify(payload) }).catch(() => {});
  } catch {}
};
// Global error handlers
if (typeof window !== "undefined") {
  window.addEventListener("error", (e) => sentryReport(e.error || new Error(e.message), { tags: { type: "uncaught" } }));
  window.addEventListener("unhandledrejection", (e) => sentryReport(e.reason || new Error("Unhandled rejection"), { tags: { type: "unhandled-promise" } }));
}

// ─── Analytics (Umami — privacy-friendly) ───
const UMAMI_ID = "33ca67a1-981d-4e65-9c73-6d0c33dee189";
const trackEvent = (eventName, data = {}) => {
  if (!UMAMI_ID) return;
  try { window.umami?.track(eventName, data); } catch {}
};
// Inject Umami script tag (auto page views)
if (typeof document !== "undefined" && UMAMI_ID) {
  const s = document.createElement("script");
  s.defer = true; s.dataset.websiteId = UMAMI_ID;
  s.src = "https://cloud.umami.is/script.js";
  document.head.appendChild(s);
}

// Token management
let _accessToken = null;
let _refreshToken = null;
const setTokens = (access, refresh) => { _accessToken = access; _refreshToken = refresh; try { if(access) localStorage.setItem("sb-token", JSON.stringify({access,refresh})); else localStorage.removeItem("sb-token"); } catch{} };
const loadTokens = () => { try { const raw = localStorage.getItem("sb-token"); if(raw){ const t=JSON.parse(raw); _accessToken=t.access; _refreshToken=t.refresh; } } catch{} };

// Auth helpers
const sbAuth = {
  signUp: async (email, password, metadata={}) => {
    const res = await fetch(`${SB_URL}/auth/v1/signup`, { method:"POST", headers:{"apikey":SB_KEY,"Content-Type":"application/json"}, body:JSON.stringify({email,password,data:metadata}) });
    const data = await res.json();
    if(!res.ok||data.error||data.error_code) throw new Error(data.error?.message||data.msg||data.error_description||data.error_code||"Erro no cadastro");
    if(data.access_token) setTokens(data.access_token, data.refresh_token);
    return data;
  },
  signIn: async (email, password) => {
    const res = await fetch(`${SB_URL}/auth/v1/token?grant_type=password`, { method:"POST", headers:{"apikey":SB_KEY,"Content-Type":"application/json"}, body:JSON.stringify({email,password}) });
    const data = await res.json();
    if(!res.ok||data.error||data.error_code){
      const msg=data.error_description||data.msg||data.error||data.error_code||"Email ou senha incorretos";
      if(msg.includes("not confirmed")||data.error_code==="email_not_confirmed") throw new Error("Email não confirmado. Verifique sua caixa de entrada.");
      throw new Error(msg);
    }
    setTokens(data.access_token, data.refresh_token);
    return data;
  },
  signOut: async () => { try { await fetch(`${SB_URL}/auth/v1/logout`, { method:"POST", headers:{"apikey":SB_KEY,"Authorization":`Bearer ${_accessToken}`} }); } catch{} setTokens(null,null); },
  getUser: async () => {
    if(!_accessToken) return null;
    const res = await fetch(`${SB_URL}/auth/v1/user`, { headers:{"apikey":SB_KEY,"Authorization":`Bearer ${_accessToken}`} });
    if(!res.ok){ if(res.status===401&&_refreshToken) return sbAuth.refresh(); return null; }
    return res.json();
  },
  refresh: async () => {
    if(!_refreshToken) return null;
    const res = await fetch(`${SB_URL}/auth/v1/token?grant_type=refresh_token`, { method:"POST", headers:{"apikey":SB_KEY,"Content-Type":"application/json"}, body:JSON.stringify({refresh_token:_refreshToken}) });
    if(!res.ok){ setTokens(null,null); return null; }
    const data = await res.json(); setTokens(data.access_token, data.refresh_token);
    return sbAuth.getUser();
  },
  resetPassword: async (email) => {
    const res = await fetch(`${SB_URL}/auth/v1/recover`, { method:"POST", headers:{"apikey":SB_KEY,"Content-Type":"application/json"}, body:JSON.stringify({email}) });
    return res.ok;
  },
};

// Database helpers
const sbHeaders = (extra={}) => ({ "apikey":SB_KEY, "Authorization":`Bearer ${_accessToken||SB_KEY}`, "Content-Type":"application/json", "Prefer":"return=representation", ...extra });

const sb = {
  from: (table) => ({
    select: async (cols="*", filters="") => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}?select=${encodeURIComponent(cols)}${filters}`, { headers:sbHeaders() });
      return res.ok ? res.json() : [];
    },
    selectOne: async (cols="*", filters="") => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}?select=${encodeURIComponent(cols)}${filters}`, { headers:{...sbHeaders(),"Accept":"application/vnd.pgrst.object+json"} });
      return res.ok ? res.json() : null;
    },
    insert: async (data) => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}`, { method:"POST", headers:sbHeaders(), body:JSON.stringify(Array.isArray(data)?data:[data]) });
      if(!res.ok){ const e=await res.json().catch(()=>({})); throw new Error(e.message||"Insert failed"); }
      const result = await res.json(); return Array.isArray(data)?result:result[0];
    },
    update: async (data, filters) => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}?${filters}`, { method:"PATCH", headers:sbHeaders(), body:JSON.stringify(data) });
      return res.ok ? res.json() : [];
    },
    delete: async (filters) => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}?${filters}`, { method:"DELETE", headers:sbHeaders() });
      return res.ok;
    },
    upsert: async (data) => {
      const res = await fetch(`${SB_URL}/rest/v1/${table}`, { method:"POST", headers:{...sbHeaders(),"Prefer":"return=representation,resolution=merge-duplicates"}, body:JSON.stringify(Array.isArray(data)?data:[data]) });
      return res.ok ? res.json() : [];
    },
  }),
  rpc: async (fn, params={}) => {
    const res = await fetch(`${SB_URL}/rest/v1/rpc/${fn}`, { method:"POST", headers:sbHeaders(), body:JSON.stringify(params) });
    return res.ok ? res.json() : null;
  },
};

// Storage helpers
const sbStorage = {
  upload: async (path, file) => {
    const compressed=await compressImage(file);
    const res = await fetch(`${SB_URL}/storage/v1/object/media/${path}`, {
      method:"POST", headers:{"apikey":SB_KEY,"Authorization":`Bearer ${_accessToken}`,"Content-Type":compressed.type||file.type},
      body:compressed
    });
    return res.ok;
  },
  uploadBase64: async (path, base64, contentType="image/jpeg") => {
    const bin = atob(base64.split(",")[1]||base64);
    const arr = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
    const blob = new Blob([arr],{type:contentType});
    return sbStorage.upload(path, blob);
  },
  getUrl: (path) => `${SB_URL}/storage/v1/object/public/media/${path}`,
  delete: async (paths) => {
    await fetch(`${SB_URL}/storage/v1/object/media`, {
      method:"DELETE", headers:{...sbHeaders()}, body:JSON.stringify({prefixes:paths})
    });
  },
};

// ─── Security: Text Sanitization ───
// ─── Image Compression (before upload) ───
const compressImage=async(file,maxW=1200,quality=0.8)=>{
  if(!file.type.startsWith("image/")||file.type==="image/gif")return file;
  return new Promise(resolve=>{
    const img=new Image();
    img.onload=()=>{
      let w=img.width,h=img.height;
      if(w<=maxW){resolve(file);return;}
      const ratio=maxW/w;w=maxW;h=Math.round(h*ratio);
      const canvas=document.createElement("canvas");canvas.width=w;canvas.height=h;
      canvas.getContext("2d").drawImage(img,0,0,w,h);
      canvas.toBlob(blob=>{resolve(blob?new File([blob],file.name,{type:"image/jpeg"}):file);},"image/jpeg",quality);
    };
    img.onerror=()=>resolve(file);
    img.src=URL.createObjectURL(file);
  });
};

const sanitize=(text,maxLen=2000)=>{
  if(!text||typeof text!=="string")return"";
  // Strip HTML tags, script injections, event handlers
  let clean=text
    .replace(/<script[\s\S]*?<\/script>/gi,"")
    .replace(/<style[\s\S]*?<\/style>/gi,"")
    .replace(/on\w+\s*=\s*["'][^"']*["']/gi,"")
    .replace(/on\w+\s*=\s*[^\s>]*/gi,"")
    .replace(/<[^>]*>/g,"")
    .replace(/javascript\s*:/gi,"")
    .replace(/data\s*:\s*text\/html/gi,"")
    .replace(/&#/g,"&amp;#")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g,"");
  return clean.substring(0,maxLen).trim();
};

// ─── Security: Rate Limiter ───
const _rateLimits={};
const rateLimit=(key,maxAttempts=5,windowMs=300000)=>{
  const now=Date.now();
  if(!_rateLimits[key])_rateLimits[key]={attempts:[],blocked:0};
  const rl=_rateLimits[key];
  if(rl.blocked>now)return{allowed:false,remaining:Math.ceil((rl.blocked-now)/1000)};
  rl.attempts=rl.attempts.filter(t=>now-t<windowMs);
  if(rl.attempts.length>=maxAttempts){rl.blocked=now+windowMs;return{allowed:false,remaining:Math.ceil(windowMs/1000)};}
  rl.attempts.push(now);
  return{allowed:true,remaining:0};
};

// ─── Security: Password Policy ───
const validatePassword=(pw)=>{
  const errors=[];
  if(pw.length<8)errors.push("Mínimo 8 caracteres");
  if(!/[A-Z]/.test(pw))errors.push("Uma letra maiúscula");
  if(!/[a-z]/.test(pw))errors.push("Uma letra minúscula");
  if(!/[0-9]/.test(pw))errors.push("Um número");
  return{valid:errors.length===0,errors};
};
const PHASES = ["Germinação", "Vegetação", "Floração", "Colheita"];
const PHASE_ICONS = ["🌱", "🌿", "🌸", "✂️"];
const PHASE_COLORS = ["#059669", "#16a34a", "#9333ea", "#d97706"];
const ENVIRONMENTS = [
  { id: "Indoor", icon: "🏠", label: "Indoor" },
  { id: "Outdoor", icon: "☀️", label: "Outdoor" },
  { id: "Estufa", icon: "🏡", label: "Estufa" },
];
const SUBSTRATES = [
  { id: "Solo", icon: "🪨", label: "Solo" },
  { id: "Coco", icon: "🥥", label: "Coco" },
  { id: "Hidroponia", icon: "💧", label: "Hidroponia" },
  { id: "Aeroponia", icon: "💨", label: "Aeroponia" },
  { id: "Perlita", icon: "⚪", label: "Perlita" },
];
const LIGHTS = [
  { id: "LED", icon: "💡", label: "LED" },
  { id: "HPS", icon: "🔆", label: "HPS" },
  { id: "CFL", icon: "💫", label: "CFL" },
  { id: "Sol Natural", icon: "☀️", label: "Sol Natural" },
  { id: "CMH", icon: "✨", label: "CMH" },
];
const TECHNIQUES = [
  { id: "LST", icon: "↪️", label: "LST" },
  { id: "HST", icon: "💪", label: "HST" },
  { id: "Topping", icon: "✂️", label: "Topping" },
  { id: "FIMing", icon: "🔪", label: "FIMing" },
  { id: "ScrOG", icon: "🕸️", label: "ScrOG" },
  { id: "SoG", icon: "🌿", label: "SoG" },
  { id: "Desfolha", icon: "🍃", label: "Desfolha" },
  { id: "Main-Lining", icon: "🔀", label: "Main-Lining" },
  { id: "Nenhuma", icon: "➖", label: "Nenhuma" },
];
const WATERING = [
  { id: "Manual", icon: "🫗", label: "Manual" },
  { id: "Gotejamento", icon: "💧", label: "Gotejamento" },
  { id: "Automática", icon: "⏱️", label: "Automática" },
  { id: "Hidropônico", icon: "🌊", label: "Hidropônico" },
];

// ─── i18n ───
const LANGS = { pt:"Português", es:"Español", en:"English" };
const T = {
  pt: { home:"Início", explore:"Explorar", myDiaries:"Meus Diários", newDiary:"+ Novo Diário", viewProfile:"Ver Meu Perfil", startDiary:"Iniciar Meu Diário", language:"Idioma", settings:"Configurações", logout:"Sair da Conta", back:"Voltar", save:"Salvar", cancel:"Cancelar", week:"Semana", phase:"Fase", height:"Altura", temp:"Temp", humidity:"Umidade", light:"Luz", watering:"Rega", notes:"Observações", photosVideos:"Fotos e Vídeos", addWeek:"+ Adicionar Semana", saveWeek:"Salvar Semana", createDiary:"Criar Diário", diaryName:"Nome do Diário", strain:"Genética / Variedade", environment:"Ambiente", lighting:"Iluminação", substrate:"Substrato", irrigation:"Irrigação", germination:"Germinação", techniques:"Técnicas de Cultivo", numPlants:"Número de Plantas", diaryInfo:"Informações do Diário", setup:"Configuração", selectOptions:"Selecione as opções do seu grow", selectMore:"Selecione uma ou mais", recentDiaries:"Diários Recentes", exploreDiaries:"Explorar Diários", manageGrows:"Gerencie seus cultivos", followGrowers:"Acompanhe outros cultivadores", registerSteps:"Registre cada etapa", ofYourGrow:"do seu cultivo", communityDesc:"A comunidade brasileira de cultivadores. Crie diários semanais, acompanhe parâmetros e aprenda com outros growers.", diaries:"Diários", growers:"Cultivadores", varieties:"Variedades", noDiaries:"Você ainda não criou nenhum diário.", noResults:"Nenhum diário encontrado.", createFirst:"Criar Meu Primeiro Diário", hello:"Olá", noWeeks:"Nenhuma semana registrada.", editDiary:"Editar Diário", hideDiary:"Esconder Diário", removeDiary:"Remover Diário", confirmRemove:"Tem certeza que deseja remover este diário?", confirmHide:"Tem certeza que deseja esconder este diário?", diaryRemoved:"Diário removido.", diaryHidden:"Diário escondido.", addMedia:"Adicionar Fotos e Vídeos", remaining:"restantes", clickSelect:"Clique para selecionar", weekComment:"Comentário da Semana", growConditions:"Condições de Cultivo", plantPhase:"Fase da Planta", howIsPlant:"Como está sua planta?", media:"mídias", attached:"anexadas", all:"Todos", allPhases:"Todas", configureGrow:"Configure as informações do seu cultivo", exploreBtn:"Explorar Diários", footer:"Feito com 💚 para cultivadores brasileiros", feed:"Feed", strains:"Genéticas", shorts:"Shorts", questions:"Perguntas", contests:"Concursos", seeds:"Sementes", breeders:"Breeders", nutrients:"Nutrientes", equipment:"Equipamentos", blog:"Blog", favorites:"Favoritos", liked:"Gostei", community:"Comunidade", pests:"Pragas e Fungos", ranking:"Ranking", follow:"Seguir", following:"Seguindo", unfollow:"Deixar de seguir", exportPdf:"Exportar PDF", timeline:"Timeline do Cultivo", evolution:"Evolução", tags:"Tags", totalPlants:"Total de plantas", reply:"Responder", replyTo:"Respondendo a", newPost:"Novo Post", writeComment:"Escreva um comentário...", noComments:"Nenhum comentário ainda. Seja o primeiro!", searchGrower:"Buscar cultivador...", mostDiaries:"Mais Diários", mostLikes:"Mais Curtidas", recent:"Recentes", newTopic:"Novo Tópico", postReply:"Postar Resposta", subject:"Assunto", message:"Mensagem", forumDesc:"Fóruns de discussão da comunidade", pestsDesc:"Guia completo para identificar e combater pragas no seu cultivo", contestsDesc:"Participe dos concursos da comunidade e ganhe destaque!", growersDesc:"Conheça a comunidade e o ranking", feedDesc:"Seus diários curtidos, favoritados e de quem você segue", comingSoon:"Em breve" },
  es: { home:"Inicio", explore:"Explorar", myDiaries:"Mis Diarios", newDiary:"+ Nuevo Diario", viewProfile:"Ver Mi Perfil", startDiary:"Iniciar Mi Diario", language:"Idioma", settings:"Configuración", logout:"Cerrar Sesión", back:"Volver", save:"Guardar", cancel:"Cancelar", week:"Semana", phase:"Fase", height:"Altura", temp:"Temp", humidity:"Humedad", light:"Luz", watering:"Riego", notes:"Observaciones", photosVideos:"Fotos y Videos", addWeek:"+ Añadir Semana", saveWeek:"Guardar Semana", createDiary:"Crear Diario", diaryName:"Nombre del Diario", strain:"Genética / Variedad", environment:"Ambiente", lighting:"Iluminación", substrate:"Sustrato", irrigation:"Riego", germination:"Germinación", techniques:"Técnicas de Cultivo", numPlants:"Número de Plantas", diaryInfo:"Información del Diario", setup:"Configuración", selectOptions:"Seleccione las opciones de su cultivo", selectMore:"Seleccione una o más", recentDiaries:"Diarios Recientes", exploreDiaries:"Explorar Diarios", manageGrows:"Gestione sus cultivos", followGrowers:"Siga a otros cultivadores", registerSteps:"Registre cada etapa", ofYourGrow:"de su cultivo", communityDesc:"La comunidad de cultivadores. Cree diarios semanales, controle parámetros y aprenda de otros growers.", diaries:"Diarios", growers:"Cultivadores", varieties:"Variedades", noDiaries:"Aún no has creado ningún diario.", noResults:"No se encontraron diarios.", createFirst:"Crear Mi Primer Diario", hello:"Hola", noWeeks:"Ninguna semana registrada.", editDiary:"Editar Diario", hideDiary:"Ocultar Diario", removeDiary:"Eliminar Diario", confirmRemove:"¿Estás seguro de que deseas eliminar este diario?", confirmHide:"¿Estás seguro de que deseas ocultar este diario?", diaryRemoved:"Diario eliminado.", diaryHidden:"Diario ocultado.", addMedia:"Añadir Fotos y Videos", remaining:"restantes", clickSelect:"Clic para seleccionar", weekComment:"Comentario de la Semana", growConditions:"Condiciones de Cultivo", plantPhase:"Fase de la Planta", howIsPlant:"¿Cómo está tu planta?", media:"medios", attached:"adjuntos", all:"Todos", allPhases:"Todas", configureGrow:"Configure la información de su cultivo", exploreBtn:"Explorar Diarios", footer:"Hecho con 💚 para cultivadores", feed:"Feed", strains:"Genéticas", shorts:"Shorts", questions:"Preguntas", contests:"Concursos", seeds:"Semillas", breeders:"Breeders", nutrients:"Nutrientes", equipment:"Equipos", blog:"Blog", favorites:"Favoritos", liked:"Me gusta", community:"Comunidad", pests:"Plagas y Hongos", ranking:"Ranking", follow:"Seguir", following:"Siguiendo", unfollow:"Dejar de seguir", exportPdf:"Exportar PDF", timeline:"Timeline del Cultivo", evolution:"Evolución", tags:"Tags", totalPlants:"Total de plantas", reply:"Responder", replyTo:"Respondiendo a", newPost:"Nuevo Post", writeComment:"Escribe un comentario...", noComments:"Ningún comentario aún. ¡Sé el primero!", searchGrower:"Buscar cultivador...", mostDiaries:"Más Diarios", mostLikes:"Más Likes", recent:"Recientes", newTopic:"Nuevo Tema", postReply:"Publicar Respuesta", subject:"Asunto", message:"Mensaje", forumDesc:"Foros de discusión de la comunidad", pestsDesc:"Guía completa para identificar y combatir plagas", contestsDesc:"¡Participa en los concursos de la comunidad y gana destaque!", growersDesc:"Conoce la comunidad y el ranking", feedDesc:"Tus diarios gustados, favoritos y de quienes sigues", comingSoon:"Próximamente" },
  en: { home:"Home", explore:"Explore", myDiaries:"My Diaries", newDiary:"+ New Diary", viewProfile:"View My Profile", startDiary:"Start My Diary", language:"Language", settings:"Settings", logout:"Log Out", back:"Back", save:"Save", cancel:"Cancel", week:"Week", phase:"Phase", height:"Height", temp:"Temp", humidity:"Humidity", light:"Light", watering:"Watering", notes:"Notes", photosVideos:"Photos & Videos", addWeek:"+ Add Week", saveWeek:"Save Week", createDiary:"Create Diary", diaryName:"Diary Name", strain:"Strain / Genetics", environment:"Environment", lighting:"Lighting", substrate:"Substrate", irrigation:"Watering", germination:"Germination", techniques:"Grow Techniques", numPlants:"Number of Plants", diaryInfo:"Diary Information", setup:"Setup", selectOptions:"Select your grow options", selectMore:"Select one or more", recentDiaries:"Recent Diaries", exploreDiaries:"Explore Diaries", manageGrows:"Manage your grows", followGrowers:"Follow other growers", registerSteps:"Track every step", ofYourGrow:"of your grow", communityDesc:"The grower community. Create weekly journals, track parameters and learn from other growers.", diaries:"Diaries", growers:"Growers", varieties:"Strains", noDiaries:"You haven't created any diary yet.", noResults:"No diaries found.", createFirst:"Create My First Diary", hello:"Hello", noWeeks:"No weeks recorded yet.", editDiary:"Edit Diary", hideDiary:"Hide Diary", removeDiary:"Remove Diary", confirmRemove:"Are you sure you want to remove this diary?", confirmHide:"Are you sure you want to hide this diary?", diaryRemoved:"Diary removed.", diaryHidden:"Diary hidden.", addMedia:"Add Photos & Videos", remaining:"remaining", clickSelect:"Click to select files", weekComment:"Week Comment", growConditions:"Grow Conditions", plantPhase:"Plant Phase", howIsPlant:"How is your plant?", media:"media", attached:"attached", all:"All", allPhases:"All", configureGrow:"Configure your grow information", exploreBtn:"Explore Diaries", footer:"Made with 💚 for growers", feed:"Feed", strains:"Strains", shorts:"Shorts", questions:"Questions", contests:"Contests", seeds:"Seeds", breeders:"Breeders", nutrients:"Nutrients", equipment:"Equipment", blog:"Blog", favorites:"Favorites", liked:"Liked", community:"Community", pests:"Pests & Fungi", ranking:"Ranking", follow:"Follow", following:"Following", unfollow:"Unfollow", exportPdf:"Export PDF", timeline:"Grow Timeline", evolution:"Evolution", tags:"Tags", totalPlants:"Total plants", reply:"Reply", replyTo:"Replying to", newPost:"New Post", writeComment:"Write a comment...", noComments:"No comments yet. Be the first!", searchGrower:"Search grower...", mostDiaries:"Most Diaries", mostLikes:"Most Likes", recent:"Recent", newTopic:"New Topic", postReply:"Post Reply", subject:"Subject", message:"Message", forumDesc:"Community discussion forums", pestsDesc:"Complete guide to identify and fight pests in your grow", contestsDesc:"Join community contests and get featured!", growersDesc:"Meet the community and rankings", feedDesc:"Your liked, favorited and followed diaries", comingSoon:"Coming soon" },
};
const GERMINATION = [
  { id: "Papel Toalha", icon: "🧻", label: "Papel Toalha" },
  { id: "Copo d'Água", icon: "🥤", label: "Copo d'Água" },
  { id: "Direto no Substrato", icon: "🪴", label: "Direto no Substrato" },
  { id: "Jiffy/Pellet", icon: "⚫", label: "Jiffy/Pellet" },
];
const AVATARS = ["🌱","🌿","🌻","🌴","🍀","🌺","🧑‍🌾","👨‍🌾","👩‍🌾","🌵","🍃","🪴","🎋","🌾","🍄","🦎"];
const LEVELS = [
  { min: 0, name: "Semente", icon: "🌰" },
  { min: 1, name: "Broto", icon: "🌱" },
  { min: 3, name: "Muda", icon: "🌿" },
  { min: 6, name: "Cultivador", icon: "🪴" },
  { min: 10, name: "Grower", icon: "🌳" },
  { min: 20, name: "Mestre", icon: "👑" },
];

const SAMPLE_DIARIES = [];

const COVER_GRADIENTS = [
  "linear-gradient(135deg, #d4edda 0%, #b7e4c7 50%, #a3d9b1 100%)",
  "linear-gradient(135deg, #e8d5c4 0%, #d4c0ae 50%, #c4b09e 100%)",
  "linear-gradient(135deg, #c8e6d8 0%, #a8d8c0 50%, #90ccb0 100%)",
  "linear-gradient(135deg, #e8e0d0 0%, #d8cfbe 50%, #ccc3b0 100%)",
  "linear-gradient(135deg, #d0e8c8 0%, #b8d8a8 50%, #a0cc90 100%)",
  "linear-gradient(135deg, #c8d8e8 0%, #a8c4d8 50%, #90b4cc 100%)",
];

function getUserLevel(n) { let l = LEVELS[0]; for (const x of LEVELS) if (n >= x.min) l = x; return l; }

function generatePlantArt(seed, size = 120) {
  const rng = (s) => { let x = Math.sin(s) * 10000; return x - Math.floor(x); };
  const r = (i) => rng(seed * 100 + i);
  const leafCount = Math.floor(r(1) * 5) + 4;
  const hue = 130 + r(2) * 30;
  let svg = `<svg viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<line x1="${size/2}" y1="${size*0.85}" x2="${size/2}" y2="${size*0.3}" stroke="hsl(${hue},40%,35%)" stroke-width="3" stroke-linecap="round"/>`;
  for (let i = 0; i < leafCount; i++) {
    const angle = (i / leafCount) * 360 + r(i + 10) * 30;
    const len = 15 + r(i + 20) * 20;
    const cy = size * 0.3 + (i / leafCount) * size * 0.4;
    const rad = (angle * Math.PI) / 180;
    const lx = size / 2 + Math.cos(rad) * len;
    const ly = cy + Math.sin(rad) * len * 0.3;
    const sat = 40 + r(i + 30) * 25;
    const light = 35 + r(i + 40) * 20;
    svg += `<ellipse cx="${lx}" cy="${ly}" rx="${len*0.6}" ry="${len*0.2}" fill="hsl(${hue},${sat}%,${light}%)" transform="rotate(${angle}, ${lx}, ${ly})" opacity="0.7"/>`;
  }
  svg += `</svg>`;
  return svg;
}

// ─── Safe storage ───
const LOGO_SRC="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAkACQAAD/4QECRXhpZgAATU0AKgAAAAgABwEOAAIAAAALAAAAYgESAAMAAAABAAEAAAEaAAUAAAABAAAAbgEbAAUAAAABAAAAdgEoAAMAAAABAAIAAAEyAAIAAAAUAAAAfodpAAQAAAABAAAAkgAAAABTY3JlZW5zaG90AAAAAACQAAAAAQAAAJAAAAABMjAyNjowMzoxOSAwODo1NzowMwAABZADAAIAAAAUAAAA1JKGAAcAAAASAAAA6KABAAMAAAAB//8AAKACAAQAAAABAAAEgaADAAQAAAABAAABUgAAAAAyMDI2OjAzOjE5IDA4OjU3OjAzAEFTQ0lJAAAAU2NyZWVuc2hvdP/tAG5QaG90b3Nob3AgMy4wADhCSU0EBAAAAAAANhwBWgADGyVHHAIAAAIAAhwCeAAKU2NyZWVuc2hvdBwCPAAGMDg1NzAzHAI3AAgyMDI2MDMxOThCSU0EJQAAAAAAEDrs3ppqslQCSPxv286vjBz/4gIoSUNDX1BST0ZJTEUAAQEAAAIYYXBwbAQAAABtbnRyUkdCIFhZWiAH5gABAAEAAAAAAABhY3NwQVBQTAAAAABBUFBMAAAAAAAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLWFwcGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApkZXNjAAAA/AAAADBjcHJ0AAABLAAAAFB3dHB0AAABfAAAABRyWFlaAAABkAAAABRnWFlaAAABpAAAABRiWFlaAAABuAAAABRyVFJDAAABzAAAACBjaGFkAAAB7AAAACxiVFJDAAABzAAAACBnVFJDAAABzAAAACBtbHVjAAAAAAAAAAEAAAAMZW5VUwAAABQAAAAcAEQAaQBzAHAAbABhAHkAIABQADNtbHVjAAAAAAAAAAEAAAAMZW5VUwAAADQAAAAcAEMAbwBwAHkAcgBpAGcAaAB0ACAAQQBwAHAAbABlACAASQBuAGMALgAsACAAMgAwADIAMlhZWiAAAAAAAAD21QABAAAAANMsWFlaIAAAAAAAAIPfAAA9v////7tYWVogAAAAAAAASr8AALE3AAAKuVhZWiAAAAAAAAAoOAAAEQsAAMi5cGFyYQAAAAAAAwAAAAJmZgAA8qcAAA1ZAAAT0AAACltzZjMyAAAAAAABDEIAAAXe///zJgAAB5MAAP2Q///7ov///aMAAAPcAADAbv/AABEIAVIEgQMBIgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2wBDAAICAgICAgMCAgMFAwMDBQYFBQUFBggGBgYGBggKCAgICAgICgoKCgoKCgoMDAwMDAwODg4ODg8PDw8PDw8PDw//2wBDAQIDAwQEBAcEBAcQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/3QAEAEn/2gAMAwEAAhEDEQA/AP38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Q/fyiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9H9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/0v38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//T/fyiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9T9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/1f38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoooo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tjvCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD8fP+Ctf/IF+Gf8A18ar/wCgW1filX7W/wDBWv8A5Avwz/6+NV/9Atq/FKuWp8R4GL/is/r4+GX/ACTfwp/2CbD/ANJ0ruK4f4Zf8k38Kf8AYJsP/SdK7iuo95bBRRRQMKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9T9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA/Gf/grj/wA0p/7jv/thX2b/AME+v+TRPAX/AHFP/TndV8sf8FZtBmuPBvw98TqpMWn6hfWbN2DXkUcij8Rbn8q91/4JreJLfW/2XtN0uNgZPD+pahZOM8gyS/ax+YnFZL42efH/AHiXp/kfftFFFanoBRRRQAUUUUAfKP7cX/JqfxC/684P/SqGvjP/AIJLf8ix8R/+vzTv/Rc1fZn7cX/JqfxC/wCvOD/0qhr4z/4JLf8AIsfEf/r807/0XNWf20cU/wCOvQ/XqiiitDtCiiigAooooAK/mb/4J9f8nd+Av+4p/wCmy6r+jP4g+I4PB3gTxH4tuXCRaLpt3esxOMC3haT/ANlr+fL/AIJuaDNq/wC1No2oRKWXRNP1G8c+ivAbXP8A31OB+NYy+JHn4j+JBeZ/R9RRRWx6AUUUUAFFFFABRRRQAUUUUAFFFee/ED4kaB8N7TTr7xCk7x6ndpZReQgciWQEjdllwvynnn6UNpK7JbUVdnoVFFFBQUUV5ppfxT8K6v8AETVPhjZtP/bOkwiebdHiEr8hIV85JHmLnIA54JpNpbibStd7npdFFFMYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFZGuava+H9Ev8AXb4MbbTbeW5lCDLeXChdtoJGTgcc1keCfGOk+PvC9j4u0NZVsdQDmMTKEk/dyNGcgFgOVPfpSur2J5lfl6nXUV5p4i+KfhXwt410TwDqrTjVNfAN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AooooAKKKKACiiigAooooAKKKKACiiigAooooA//1/38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Q/fyiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9H9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/0v38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//T/fyiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9T9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/2Q==";
// safeGet removed — all data now on Supabase

// ─── Design Tokens (GrowDiaries light theme) ───
const F = {
  sans: "'Inter', 'Helvetica Neue', 'Segoe UI', sans-serif",
  body: "'Inter', 'Helvetica Neue', sans-serif",
  serif: "'Palatino Linotype', 'Book Antiqua', Palatino, 'Georgia', serif",
};
const C = {
  bg: "var(--dp-bg)",
  surface: "var(--dp-surface)",
  surface2: "var(--dp-surface2)",
  surfaceLight: "var(--dp-surfaceLight)",
  border: "var(--dp-border)",
  borderLight: "var(--dp-borderLight)",
  text: "var(--dp-text)",
  muted: "var(--dp-muted)",
  dim: "var(--dp-dim)",
  accent: "#1B9E42",
  accentLight: "#22b84d",
  accentDark: "#168836",
  accentBg: "var(--dp-accentBg)",
  accentBorder: "rgba(27,158,66,0.4)",
  error: "#e53e3e",
  errorBg: "var(--dp-errorBg)",
  success: "#1B9E42",
  successBg: "var(--dp-successBg)",
  onAccent: "#fff",
  msgBubble: "var(--dp-msgBubble)",
  cardBg: "var(--dp-cardBg)",
  inputBg: "var(--dp-inputBg)",
  accent44: "var(--dp-accent44)",
  accent33: "var(--dp-accent33)",
  error44: "var(--dp-error44)",
  error33: "var(--dp-error33)",
  border22: "var(--dp-border22)",
  warnBg: "var(--dp-warnBg)",
  warnBorder: "var(--dp-warnBorder)",
  warnText: "var(--dp-warnText)",
};

const baseInput = { width:"100%", padding:"14px 16px", borderRadius:"10px", border:`1px solid ${C.borderLight}`, background:C.cardBg, color:C.text, fontSize:"15px", fontFamily:F.body, outline:"none", boxSizing:"border-box", transition:"border-color 0.2s" };
const btnPrimary = { padding:"12px 24px", borderRadius:"28px", border:"none", background:C.accent, color:C.onAccent, cursor:"pointer", fontSize:"15px", fontWeight:"600", fontFamily:F.sans, transition:"all 0.2s", width:"100%" };
const btnSecondary = { padding:"12px 24px", borderRadius:"28px", border:`1px solid ${C.borderLight}`, background:C.cardBg, color:C.text, cursor:"pointer", fontSize:"14px", fontWeight:"500", fontFamily:F.sans, transition:"all 0.2s", width:"100%" };
const linkBtn = { background:"none", border:"none", color:C.accent, cursor:"pointer", fontSize:"13px", fontFamily:F.sans, padding:"4px 0", textDecoration:"underline", textDecorationColor:"rgba(27,158,66,0.3)", textUnderlineOffset:"3px" };
const cardBase = { background:C.cardBg, borderRadius:"16px", border:`1px solid ${C.border}`, padding:"36px", width:"100%", maxWidth:"420px", boxSizing:"border-box", boxShadow:"0 2px 12px rgba(0,0,0,0.06)" };
const labelSt = { display:"block", fontSize:"12px", color:C.muted, fontFamily:F.sans, textTransform:"uppercase", letterSpacing:"1px", marginBottom:"8px", fontWeight:"600" };
const errorSt = { padding:"10px 14px", borderRadius:"10px", background:C.errorBg, border:"1px solid rgba(229,62,62,0.15)", color:C.error, fontSize:"13px", fontFamily:F.sans, marginBottom:"16px", display:"flex", alignItems:"center", gap:"8px" };
const successSt = { ...errorSt, background:C.successBg, border:"1px solid rgba(27,158,66,0.15)", color:C.success };
const bgOverlay = { position:"fixed", top:0, left:0, right:0, bottom:0, background:"transparent", pointerEvents:"none" };

// ─── Error Boundary ───
class ErrorBoundary extends React.Component {
  constructor(props){super(props);this.state={hasError:false,error:null};}
  static getDerivedStateFromError(error){return{hasError:true,error};}
  componentDidCatch(error,info){sentryReport(error,{tags:{type:"react-boundary"},extra:{componentStack:info?.componentStack}});}
  render(){
    if(this.state.hasError) return(
      <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column",padding:"40px",textAlign:"center",fontFamily:"Inter,sans-serif"}}>
        <div style={{fontSize:"60px",marginBottom:"16px"}}>🌿</div>
        <h1 style={{fontSize:"24px",fontWeight:"800",margin:"0 0 8px"}}>Ops! Algo deu errado</h1>
        <p style={{color:"#666",fontSize:"15px",marginBottom:"24px",maxWidth:"400px"}}>Ocorreu um erro inesperado. Tente recarregar a página.</p>
        <button onClick={()=>window.location.reload()} style={{padding:"12px 28px",borderRadius:"28px",border:"none",background:"#1B9E42",color:"#fff",cursor:"pointer",fontSize:"15px",fontWeight:"600"}}>Recarregar</button>
      </div>
    );
    return this.props.children;
  }
}

function ThemeCSS({dark}){return <style>{`
:root{--dp-bg:#ffffff;--dp-surface:#ffffff;--dp-surface2:#f5f5f5;--dp-surfaceLight:#fafafa;--dp-border:#e5e5e5;--dp-borderLight:#ddd;--dp-text:#1a1a1a;--dp-muted:#666;--dp-dim:#999;--dp-accentBg:rgba(27,158,66,0.06);--dp-errorBg:rgba(229,62,62,0.06);--dp-successBg:rgba(27,158,66,0.06);--dp-cardBg:#ffffff;--dp-inputBg:#ffffff;--dp-msgBubble:#f0f0f0;--dp-accent44:rgba(27,158,66,0.27);--dp-accent33:rgba(27,158,66,0.2);--dp-error44:rgba(229,62,62,0.27);--dp-error33:rgba(229,62,62,0.2);--dp-border22:rgba(229,229,229,0.13);--dp-warnBg:#fffbeb;--dp-warnBorder:#fcd34d;--dp-warnText:#d97706;--dp-overlay85:rgba(255,255,255,0.85);--dp-overlay70:rgba(255,255,255,0.7)}
${dark?`
:root{--dp-bg:#0f1117;--dp-surface:#181a22;--dp-surface2:#1e2028;--dp-surfaceLight:#14161e;--dp-border:#2a2d38;--dp-borderLight:#333640;--dp-text:#e0e0e0;--dp-muted:#9a9daa;--dp-dim:#6b6e7a;--dp-accentBg:rgba(27,158,66,0.12);--dp-errorBg:rgba(229,62,62,0.1);--dp-successBg:rgba(27,158,66,0.1);--dp-cardBg:#181a22;--dp-inputBg:#1e2028;--dp-msgBubble:#252830;--dp-accent44:rgba(27,158,66,0.35);--dp-accent33:rgba(27,158,66,0.25);--dp-error44:rgba(229,62,62,0.35);--dp-error33:rgba(229,62,62,0.25);--dp-border22:rgba(42,45,56,0.2);--dp-warnBg:rgba(217,119,6,0.1);--dp-warnBorder:rgba(217,119,6,0.4);--dp-warnText:#f59e0b;--dp-overlay85:rgba(24,26,34,0.9);--dp-overlay70:rgba(24,26,34,0.75)}
`:""}
@keyframes uploadSpin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
@keyframes uploadPulse{0%,100%{opacity:1}50%{opacity:0.6}}
@keyframes uploadBar{0%{width:5%}50%{width:75%}100%{width:95%}}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
`}</style>;}

// Upload progress bar component (reusable)
function UploadProgressBar({active,text}){
  if(!active)return null;
  return(
    <div style={{padding:"10px 14px",background:"rgba(27,158,66,0.08)",borderRadius:"10px",border:"1px solid rgba(27,158,66,0.2)",marginBottom:"10px",display:"flex",alignItems:"center",gap:"10px"}}>
      <div style={{width:"20px",height:"20px",borderRadius:"50%",border:"2.5px solid #1B9E42",borderTop:"2.5px solid transparent",animation:"uploadSpin 0.7s linear infinite",flexShrink:0}}/>
      <div style={{flex:1}}>
        <div style={{fontFamily:"Inter,sans-serif",fontSize:"12px",fontWeight:"600",color:"#1B9E42",marginBottom:"4px"}}>{text||"Enviando..."}</div>
        <div style={{height:"4px",borderRadius:"2px",background:"rgba(27,158,66,0.15)",overflow:"hidden"}}>
          <div style={{height:"100%",borderRadius:"2px",background:"#1B9E42",animation:"uploadBar 2s ease-in-out infinite"}}/>
        </div>
      </div>
    </div>
  );
}
// ─── Skeleton Shimmer (loading placeholder) ───
function Skeleton({w,h,r,mb}){
  return <div style={{width:w||"100%",height:h||"16px",borderRadius:r||"8px",background:`linear-gradient(90deg, ${C.surface2} 25%, ${C.border}22 50%, ${C.surface2} 75%)`,backgroundSize:"200% 100%",animation:"shimmer 1.5s ease-in-out infinite",marginBottom:mb||"8px"}}/>;
}
function SkeletonCard(){
  return(<div style={{background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"16px",marginBottom:"12px"}}>
    <Skeleton w="60%" h="14px" mb="12px"/>
    <Skeleton w="40%" h="12px" mb="8px"/>
    <Skeleton w="100%" h="120px" r="12px" mb="12px"/>
    <div style={{display:"flex",gap:"8px"}}><Skeleton w="80px" h="12px"/><Skeleton w="60px" h="12px"/></div>
  </div>);
}
// ─── Reusable Components (outside to prevent re-mount) ───
function PwInput({ value, onChange, placeholder, onEnter, showPw, onTogglePw }) {
  return (
    <div style={{ position:"relative" }}>
      <input style={{ ...baseInput, paddingRight:"56px" }} type={showPw?"text":"password"} value={value} onChange={onChange} placeholder={placeholder} onKeyDown={e=>e.key==="Enter"&&onEnter?.()} />
      <button onClick={onTogglePw} style={{ position:"absolute",right:"12px",top:"50%",transform:"translateY(-50%)", background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,padding:"4px 6px",borderRadius:"6px" }}>{showPw?"Ocultar":"Mostrar"}</button>
    </div>
  );
}

function IconCard({ icon, label, selected, onClick, small }) {
  return (
    <div onClick={onClick} style={{
      display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
      gap: small ? "4px" : "6px",
      padding: small ? "10px 8px" : "14px 10px",
      borderRadius:"12px", cursor:"pointer", transition:"all 0.2s",
      border: selected ? `2px solid ${C.accent}` : `1px solid ${C.borderLight}`,
      background: selected ? C.accentBg : C.cardBg,
      minWidth: small ? "70px" : "80px",
    }}>
      <span style={{ fontSize: small ? "20px" : "26px", lineHeight:"1" }}>{icon}</span>
      <span style={{
        fontSize: small ? "10px" : "11px", fontFamily:F.sans, fontWeight:"600",
        color: selected ? C.accent : C.muted, textAlign:"center",
        letterSpacing:"0.3px", lineHeight:"1.2",
      }}>{label}</span>
    </div>
  );
}

function SectionHeader({ title, subtitle }) {
  return (
    <div style={{ marginBottom:"14px", paddingBottom:"10px", borderBottom:`1px solid ${C.border}` }}>
      <div style={{ fontFamily:F.sans, fontSize:"16px", fontWeight:"700", color:C.text }}>{title}</div>
      {subtitle && <div style={{ fontFamily:F.sans, fontSize:"12px", color:C.dim, marginTop:"2px" }}>{subtitle}</div>}
    </div>
  );
}

// ─── Auth Screen ───
function AuthScreen({ onLogin }) {
  const [mode,setMode]=useState("login");
  const [email,setEmail]=useState(""); const [password,setPassword]=useState("");
  const [confirmPw,setConfirmPw]=useState(""); const [username,setUsername]=useState("");
  const [selectedAvatar,setSelectedAvatar]=useState("🌱");
  const [signupPhoto,setSignupPhoto]=useState(null);
  const signupPhotoRef=useRef(null);
  const [bio,setBio]=useState(""); const [city,setCity]=useState("");
  const [error,setError]=useState(""); const [success,setSuccess]=useState("");
  const [loading,setLoading]=useState(false); const [showPw,setShowPw]=useState(false);
  const [step,setStep]=useState(1);
  const [acceptedTerms,setAcceptedTerms]=useState(false);

  const clear=()=>{setError("");setSuccess("");setLoading(false);};
  const switchMode=(m)=>{setMode(m);setError("");setSuccess("");setStep(1);setShowPw(false);};

  const pwStr=(pw)=>{let s=0;if(pw.length>=8)s++;if(pw.length>=12)s++;if(/[A-Z]/.test(pw))s++;if(/[0-9]/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;return s;};
  const strength=pwStr(password);
  const strLabel=["","Fraca","Fraca","Média","Forte","Muito forte"][strength]||"";
  const strColor=["#ddd",C.error,"#d97706","#d97706",C.success,C.success][strength]||C.dim;

  const doLogin=async()=>{
    clear(); if(!email.trim()||!password){setError("Preencha todos os campos.");return;}
    const rl=rateLimit("login-"+email.trim().toLowerCase(),5,300000);
    if(!rl.allowed){setError(`Muitas tentativas. Aguarde ${rl.remaining}s.`);return;}
    setLoading(true);
    try{
      const data=await sbAuth.signIn(email.trim().toLowerCase(),password);
      // Load profile
      const profile=await sb.from("profiles").selectOne("*",`&id=eq.${data.user.id}`);
      if(profile?.banned){setError("Sua conta foi suspensa.");await sbAuth.signOut();setLoading(false);return;}
      onLogin({...profile,avatarImg:profile.avatar_url,createdAt:profile.created_at,authId:data.user.id});
    }catch(e){setError(e.message||"Erro ao conectar.");}setLoading(false);
  };
  const doSignup1=()=>{
    clear();if(!email.trim()){setError("Informe seu e-mail.");return;}
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())){setError("E-mail inválido.");return;}
    if(!password){setError("Crie uma senha.");return;}
    const pwCheck=validatePassword(password);
    if(!pwCheck.valid){setError("Senha fraca: "+pwCheck.errors.join(", ")+".");return;}
    if(password!==confirmPw){setError("As senhas não coincidem.");return;}setStep(2);
  };
  const doSignup2=async()=>{
    clear();if(!username.trim()){setError("Escolha um nome de usuário.");return;}
    if(username.trim().length<3){setError("Nome: mínimo 3 caracteres.");return;}
    const rl=rateLimit("signup-"+email.trim().toLowerCase(),3,600000);
    if(!rl.allowed){setError(`Muitas tentativas de cadastro. Aguarde ${rl.remaining}s.`);return;}
    setLoading(true);
    try{
      const cleanUser=sanitize(username.trim(),30);
      const existing=await sb.from("profiles").select("id",`&username=ilike.${encodeURIComponent(cleanUser)}`);
      if(existing.length>0){setError("Nome de usuário já em uso.");setLoading(false);return;}
      const data=await sbAuth.signUp(email.trim().toLowerCase(),password,{username:cleanUser,avatar:selectedAvatar});
      if(!data.access_token&&data.user){
        setSuccess("Conta criada! Verifique seu e-mail para confirmar.");setMode("reset_sent");setLoading(false);return;
      }
      if(data.user?.id){
        let avatarUrl=null;
        // Upload signup photo if present
        if(signupPhoto&&signupPhoto.startsWith("data:")){
          const path=`${data.user.id}/avatar-${Date.now()}.jpg`;
          const ok=await sbStorage.uploadBase64(path,signupPhoto,"image/jpeg");
          if(ok) avatarUrl=sbStorage.getUrl(path);
        }
        await sb.from("profiles").update({username:cleanUser,avatar:selectedAvatar,avatar_url:avatarUrl,bio:sanitize(bio.trim(),200),city:sanitize(city.trim(),50)},`id=eq.${data.user.id}`);
        const allProfiles=await sb.from("profiles").select("id");
        if(allProfiles.length<=1) await sb.from("profiles").update({role:"admin"},`id=eq.${data.user.id}`);
        const profile=await sb.from("profiles").selectOne("*",`&id=eq.${data.user.id}`);
        onLogin({...profile,avatarImg:profile.avatar_url,createdAt:profile.created_at,authId:data.user.id});
      }
    }catch(e){setError(e.message||"Erro ao criar conta.");}setLoading(false);
  };
  const doForgot=async()=>{
    clear();if(!email.trim()){setError("Informe seu e-mail.");return;}
    const rl=rateLimit("forgot-"+email.trim().toLowerCase(),3,600000);
    if(!rl.allowed){setError(`Muitas tentativas. Aguarde ${rl.remaining}s.`);return;}
    setLoading(true);
    try{
      const ok=await sbAuth.resetPassword(email.trim().toLowerCase());
      if(ok) setSuccess("Link de recuperação enviado para seu e-mail!");
      else setError("Erro ao enviar. Verifique o e-mail.");
      setMode("reset_sent");
    }catch{setError("Erro ao verificar.");}setLoading(false);
  };

  const wrap={minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:"24px",position:"relative",overflow:"hidden"};

  const Logo=()=>(
    <div style={{textAlign:"center",marginBottom:mode==="login"?"40px":"32px",display:"flex",flexDirection:"column",alignItems:"center"}}>
      <img src={LOGO_SRC} alt="Diário da Planta" style={{height:"64px",objectFit:"contain"}}/>
      {mode==="login"&&<div style={{fontFamily:F.sans,fontSize:"14px",color:C.dim,marginTop:"8px"}}>Sua comunidade de cultivo</div>}
    </div>
  );

  if(mode==="login") return (
    <div style={wrap}><div style={bgOverlay}/>
      <div style={{position:"relative",zIndex:1,width:"100%",maxWidth:"420px"}}>
        <Logo/>
        <div style={cardBase}>
          <h2 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 6px",color:C.text}}>Bem-vindo de volta</h2>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.dim,margin:"0 0 24px"}}>Entre na sua conta para continuar cultivando</p>
          {error&&<div style={errorSt}>⚠️ {error}</div>}
          <div style={{marginBottom:"16px"}}><label style={labelSt}>E-mail</label><input style={baseInput} type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="seu@email.com" onKeyDown={e=>e.key==="Enter"&&doLogin()}/></div>
          <div style={{marginBottom:"8px"}}><label style={labelSt}>Senha</label><PwInput value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••" onEnter={doLogin} showPw={showPw} onTogglePw={()=>setShowPw(!showPw)}/></div>
          <div style={{textAlign:"right",marginBottom:"24px"}}><button style={linkBtn} onClick={()=>switchMode("forgot")}>Esqueceu a senha?</button></div>
          <button style={{...btnPrimary,opacity:loading?0.6:1}} onClick={doLogin} disabled={loading}>{loading?"Entrando...":"Entrar"}</button>
          <div style={{textAlign:"center",marginTop:"24px",fontFamily:F.sans,fontSize:"14px",color:C.muted}}>Não tem conta?{" "}<button style={{...linkBtn,fontSize:"14px",fontWeight:"600"}} onClick={()=>switchMode("signup")}>Criar conta grátis</button></div>
        </div>
        <div style={{textAlign:"center",marginTop:"32px",fontFamily:F.sans,fontSize:"12px",color:C.dim}}>Ao entrar, você concorda com nossos Termos de Uso</div>
      </div>
    </div>
  );

  if(mode==="signup") return (
    <div style={wrap}><div style={bgOverlay}/>
      <div style={{position:"relative",zIndex:1,width:"100%",maxWidth:"420px"}}>
        <Logo/>
        <div style={cardBase}>
          <div style={{display:"flex",gap:"8px",marginBottom:"24px"}}>
            <div style={{flex:1,height:"3px",borderRadius:"2px",background:C.accent}}/>
            <div style={{flex:1,height:"3px",borderRadius:"2px",background:step>=2?C.accent:"#e5e5e5"}}/>
          </div>
          {step===1?(<>
            <h2 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 6px"}}>Crie sua conta</h2>
            <p style={{fontFamily:F.sans,fontSize:"13px",color:C.dim,margin:"0 0 24px"}}>Passo 1 de 2 — Credenciais</p>
            {error&&<div style={errorSt}>⚠️ {error}</div>}
            <div style={{marginBottom:"16px"}}><label style={labelSt}>E-mail</label><input style={baseInput} type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="seu@email.com"/></div>
            <div style={{marginBottom:"16px"}}><label style={labelSt}>Senha</label><PwInput value={password} onChange={e=>setPassword(e.target.value)} placeholder="Mínimo 6 caracteres" showPw={showPw} onTogglePw={()=>setShowPw(!showPw)}/>
              {password&&<div style={{marginTop:"8px",display:"flex",alignItems:"center",gap:"8px"}}><div style={{display:"flex",gap:"3px",flex:1}}>{[1,2,3,4,5].map(i=><div key={i} style={{flex:1,height:"3px",borderRadius:"2px",background:i<=strength?strColor:"#e5e5e5"}}/>)}</div><span style={{fontFamily:F.sans,fontSize:"11px",color:strColor,minWidth:"70px"}}>{strLabel}</span></div>}
            </div>
            <div style={{marginBottom:"24px"}}><label style={labelSt}>Confirmar Senha</label><input style={{...baseInput,borderColor:confirmPw&&confirmPw!==password?"rgba(248,81,73,0.5)":C.borderLight}} type={showPw?"text":"password"} value={confirmPw} onChange={e=>setConfirmPw(e.target.value)} placeholder="Repita a senha"/>
              {confirmPw&&confirmPw!==password&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.error,marginTop:"4px"}}>As senhas não coincidem</div>}
            </div>
            <button style={btnPrimary} onClick={doSignup1}>Continuar →</button>
          </>):(<>
            <h2 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 6px"}}>Seu perfil de grower</h2>
            <p style={{fontFamily:F.sans,fontSize:"13px",color:C.dim,margin:"0 0 24px"}}>Passo 2 de 2 — Perfil</p>
            {error&&<div style={errorSt}>⚠️ {error}</div>}
            <div style={{marginBottom:"20px",textAlign:"center"}}>
              <label style={labelSt}>Foto de Perfil</label>
              <div onClick={()=>signupPhotoRef.current?.click()} style={{width:"80px",height:"80px",borderRadius:"50%",border:`3px dashed ${signupPhoto?C.accent:C.borderLight}`,background:signupPhoto?"transparent":C.surface2,display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",margin:"8px auto",overflow:"hidden",transition:"all 0.2s"}}>
                {signupPhoto?<img src={signupPhoto} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:<span style={{fontSize:"28px",opacity:0.5}}>📷</span>}
              </div>
              <button type="button" onClick={()=>signupPhotoRef.current?.click()} style={{...linkBtn,fontSize:"12px"}}>{signupPhoto?"Trocar foto":"Adicionar foto"}</button>
              {signupPhoto&&<button type="button" onClick={()=>{setSignupPhoto(null);setSelectedAvatar("🌱");}} style={{...linkBtn,fontSize:"12px",color:C.error,marginLeft:"12px"}}>Remover</button>}
              <input ref={signupPhotoRef} type="file" accept="image/*" style={{display:"none"}} onChange={e=>{const f=e.target.files?.[0];if(!f)return;const r=new FileReader();r.onload=()=>{setSignupPhoto(r.result);setSelectedAvatar("📷");};r.readAsDataURL(f);e.target.value="";}}/>
              <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"6px"}}>Opcional — você pode adicionar depois</div>
            </div>
            <div style={{marginBottom:"16px"}}><label style={labelSt}>Nome de Usuário *</label><input style={baseInput} value={username} onChange={e=>setUsername(e.target.value.replace(/\s/g,""))} placeholder="ex: GrowerBR420" maxLength={20}/><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>{username.length}/20</div></div>
            <div style={{marginBottom:"16px"}}><label style={labelSt}>Cidade / Estado</label><input style={baseInput} value={city} onChange={e=>setCity(e.target.value)} placeholder="São Paulo, SP"/></div>
            <div style={{marginBottom:"24px"}}><label style={labelSt}>Bio</label><textarea style={{...baseInput,minHeight:"70px",resize:"vertical"}} value={bio} onChange={e=>setBio(e.target.value)} placeholder="Sobre você e seu cultivo..." maxLength={200}/><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>{bio.length}/200</div></div>
            <label style={{display:"flex",alignItems:"flex-start",gap:"10px",marginBottom:"20px",cursor:"pointer",fontFamily:F.sans,fontSize:"13px",color:C.muted,lineHeight:"1.5"}}>
              <input type="checkbox" checked={acceptedTerms} onChange={e=>setAcceptedTerms(e.target.checked)} style={{marginTop:"3px",accentColor:C.accent,width:"18px",height:"18px",flexShrink:0}}/>
              <span>Li e aceito os <button type="button" onClick={e=>{e.preventDefault();window.open?.("#termos","_blank");}} style={{...linkBtn,fontSize:"13px"}}>Termos de Uso</button> e a <button type="button" onClick={e=>{e.preventDefault();window.open?.("#privacidade","_blank");}} style={{...linkBtn,fontSize:"13px"}}>Política de Privacidade</button></span>
            </label>
            <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"12px 20px"}} onClick={()=>{setStep(1);setError("");}}>← Voltar</button><button style={{...btnPrimary,opacity:(loading||!acceptedTerms)?0.6:1}} onClick={doSignup2} disabled={loading||!acceptedTerms}>{loading?"Criando...":"🌱 Criar Conta"}</button></div>
          </>)}
          <div style={{textAlign:"center",marginTop:"24px",fontFamily:F.sans,fontSize:"14px",color:C.muted}}>Já tem conta?{" "}<button style={{...linkBtn,fontSize:"14px",fontWeight:"600"}} onClick={()=>switchMode("login")}>Fazer login</button></div>
        </div>
      </div>
    </div>
  );

  return (
    <div style={wrap}><div style={bgOverlay}/>
      <div style={{position:"relative",zIndex:1,width:"100%",maxWidth:"420px"}}>
        <div style={{textAlign:"center",marginBottom:"32px"}}><div style={{fontSize:"48px",marginBottom:"12px"}}>🔑</div><div style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",color:C.text}}>Recuperar Senha</div></div>
        <div style={cardBase}>
          {mode==="reset_sent"?(<>{success&&<div style={successSt}>✅ {success}</div>}<p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,lineHeight:"1.6",marginBottom:"24px"}}>Verifique as instruções acima.</p><button style={btnPrimary} onClick={()=>switchMode("login")}>Voltar ao Login</button></>
          ):(<><p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,lineHeight:"1.6",marginBottom:"20px"}}>Informe o e-mail da sua conta.</p>
            {error&&<div style={errorSt}>⚠️ {error}</div>}
            <div style={{marginBottom:"24px"}}><label style={labelSt}>E-mail</label><input style={baseInput} type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="seu@email.com" onKeyDown={e=>e.key==="Enter"&&doForgot()}/></div>
            <button style={{...btnPrimary,opacity:loading?0.6:1,marginBottom:"12px"}} onClick={doForgot} disabled={loading}>{loading?"Verificando...":"Enviar Recuperação"}</button>
            <button style={btnSecondary} onClick={()=>switchMode("login")}>← Voltar ao Login</button>
          </>)}
        </div>
      </div>
    </div>
  );
}

// ─── Profile Page ───
function ProfilePage({ user, diaries, onUpdateUser, onLogout, onBack, blockedUsers, onUnblockUser, onDeleteAccount, onNavigate }) {
  const [editing,setEditing]=useState(false); const [avatar,setAvatar]=useState(user.avatar);
  const [avatarImg,setAvatarImg]=useState(user.avatarImg||null);
  const [bio,setBio]=useState(user.bio||""); const [city,setCity]=useState(user.city||"");
  const [saving,setSaving]=useState(false); const [showAvatars,setShowAvatars]=useState(false);
  const [showLogout,setShowLogout]=useState(false);
  const [showDeleteAccount,setShowDeleteAccount]=useState(false);
  const [deleteConfirmText,setDeleteConfirmText]=useState("");
  const avatarFileRef=useRef(null);
  const level=getUserLevel(diaries.length);
  const totalWeeks=diaries.reduce((s,d)=>s+(d.weeks?.length||0),0);
  const uniqueStrains=new Set(diaries.map(d=>d.strain)).size;
  const harvested=diaries.filter(d=>d.phase===3).length;
  const handleSave=async()=>{
    setSaving(true);
    let finalAvatarUrl=avatarImg;
    // Upload avatar to Supabase Storage if it's a base64 data URL
    if(avatarImg&&avatarImg.startsWith("data:")){
      const path=`${user.id}/avatar-${Date.now()}.jpg`;
      const ok=await sbStorage.uploadBase64(path,avatarImg,"image/jpeg");
      if(ok)finalAvatarUrl=sbStorage.getUrl(path);
    }
    const u={...user,avatar,avatarImg:finalAvatarUrl,bio:bio.trim(),city:city.trim()};
    await onUpdateUser(u);setEditing(false);setSaving(false);
  };
  const handleAvatarUpload=e=>{const f=e.target.files?.[0];if(!f)return;const r=new FileReader();r.onload=()=>{setAvatarImg(r.result);setAvatar("📷");};r.readAsDataURL(f);e.target.value="";};
  const removeAvatarImg=()=>{setAvatarImg(null);setAvatar(user.avatar==="📷"?"🌿":user.avatar);};

  const AvatarDisplay=({size,fontSize,editable})=>(
    <div style={{width:size+"px",height:size+"px",borderRadius:"50%",background:avatarImg?"transparent":C.accentBg,border:`3px solid ${C.accent}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:fontSize+"px",margin:"0 auto 4px",overflow:"hidden",position:"relative"}}>
      {avatarImg?<img src={avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:
        (editable?<button onClick={()=>setShowAvatars(!showAvatars)} style={{background:"none",border:"none",fontSize:fontSize+"px",cursor:"pointer",padding:0}}>{avatar}</button>:
        <span>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:user.avatar}</span>)}
    </div>
  );

  return (
    <div style={{maxWidth:"600px",margin:"0 auto",padding:"32px 24px"}}>
      <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px",display:"inline-flex",alignItems:"center",gap:"6px"}}>← Voltar</button>
      <div style={{background:C.surfaceLight,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"32px",textAlign:"center",marginBottom:"20px",position:"relative",overflow:"hidden"}}>
        <div style={{position:"absolute",top:0,left:0,right:0,height:"80px",background:`linear-gradient(135deg, rgba(27,158,66,0.08), rgba(27,158,66,0.02))`}}/>
        <div style={{position:"relative",zIndex:1}}>
          <div style={{position:"relative",display:"inline-block"}}>
            <AvatarDisplay size={80} fontSize={40} editable={editing}/>
            {editing&&<div style={{display:"flex",gap:"4px",justifyContent:"center",marginTop:"4px"}}>
              <button onClick={()=>avatarFileRef.current?.click()} style={{padding:"4px 10px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.accent,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>📷 Foto</button>
              <button onClick={()=>setShowAvatars(!showAvatars)} style={{padding:"4px 10px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>😀 Emoji</button>
              {avatarImg&&<button onClick={removeAvatarImg} style={{padding:"4px 10px",borderRadius:"8px",border:`1px solid rgba(229,62,62,0.3)`,background:C.cardBg,color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>✕</button>}
            </div>}
            <input ref={avatarFileRef} type="file" accept="image/*" style={{display:"none"}} onChange={handleAvatarUpload}/>
            <div style={{position:"absolute",bottom:editing?"30px":"2px",right:"-4px",background:C.surface,borderRadius:"8px",padding:"2px 6px",fontSize:"14px",border:`1px solid ${C.border}`}}>{level.icon}</div>
          </div>
          {editing&&showAvatars&&<div style={{display:"flex",flexWrap:"wrap",gap:"6px",justifyContent:"center",margin:"12px 0",padding:"12px",borderRadius:"12px",background:C.msgBubble,border:`1px solid ${C.border}`}}>{AVATARS.map(a=><button key={a} onClick={()=>{setAvatar(a);setAvatarImg(null);setShowAvatars(false);}} style={{width:"40px",height:"40px",borderRadius:"10px",border:avatar===a&&!avatarImg?`2px solid ${C.accent}`:"1px solid transparent",background:avatar===a&&!avatarImg?C.accentBg:C.cardBg,fontSize:"20px",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center"}}>{a}</button>)}</div>}
          <h2 style={{fontFamily:F.sans,fontSize:"24px",fontWeight:"700",margin:"12px 0 4px"}}>{user.username}</h2>
          <div style={{fontFamily:F.sans,fontSize:"12px",color:C.accent,fontWeight:"700",textTransform:"uppercase",letterSpacing:"1px",marginBottom:"4px"}}>{level.icon} {level.name}</div>
          {user.city&&!editing&&<div style={{fontFamily:F.sans,fontSize:"13px",color:C.dim}}>📍 {user.city}</div>}
          {editing?(<div style={{textAlign:"left",marginTop:"16px"}}>
            <div style={{marginBottom:"14px"}}><label style={labelSt}>Cidade / Estado</label><input style={baseInput} value={city} onChange={e=>setCity(e.target.value)} placeholder="São Paulo, SP"/></div>
            <div style={{marginBottom:"14px"}}><label style={labelSt}>Bio</label><textarea style={{...baseInput,minHeight:"60px",resize:"vertical"}} value={bio} onChange={e=>setBio(e.target.value)} placeholder="Sobre você..." maxLength={200}/><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>{bio.length}/200</div></div>
            <div style={{display:"flex",gap:"10px"}}><button style={{...btnSecondary,padding:"10px 16px"}} onClick={()=>{setEditing(false);setAvatar(user.avatar);setAvatarImg(user.avatarImg||null);setBio(user.bio||"");setCity(user.city||"");}}>Cancelar</button><button style={{...btnPrimary,opacity:saving?0.6:1}} onClick={handleSave} disabled={saving}>{saving?"Salvando...":"Salvar"}</button></div>
          </div>):user.bio&&<p style={{fontFamily:F.body,fontSize:"14px",color:C.muted,fontStyle:"italic",margin:"12px 0 0",lineHeight:"1.5"}}>"{user.bio}"</p>}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:"12px",marginBottom:"20px"}}>
        {[["📓",diaries.length,"Diários"],["📅",totalWeeks,"Semanas"],["🌿",uniqueStrains,"Variedades"],["✂️",harvested,"Colheitas"]].map(([icon,val,label])=>(
          <div key={label} style={{background:C.surfaceLight,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px",textAlign:"center"}}>
            <div style={{fontSize:"22px",marginBottom:"4px"}}>{icon}</div>
            <div style={{fontFamily:F.sans,fontSize:"24px",fontWeight:"700",color:C.accent}}>{val}</div>
            <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,textTransform:"uppercase",letterSpacing:"1px"}}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{background:C.surfaceLight,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px 20px",marginBottom:"20px"}}>
        <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim,marginBottom:"8px",textTransform:"uppercase",letterSpacing:"1px"}}>Informações</div>
        <div style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,lineHeight:"2"}}><div>📧 {user.email}</div><div>📆 Membro desde {new Date(user.createdAt).toLocaleDateString("pt-BR",{month:"long",year:"numeric"})}</div></div>
      </div>
      {(blockedUsers||[]).length>0&&<div style={{background:C.surfaceLight,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px 20px",marginBottom:"20px"}}>
        <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim,marginBottom:"10px",textTransform:"uppercase",letterSpacing:"1px"}}>🚫 Usuários Bloqueados ({blockedUsers.length})</div>
        {blockedUsers.map(uid=>(
          <div key={uid} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.border22}`}}>
            <span style={{fontFamily:F.sans,fontSize:"13px",color:C.muted}}>🚫 {uid.substring(0,8)}...</span>
            <button onClick={()=>onUnblockUser?.(uid)} style={{padding:"4px 12px",borderRadius:"8px",border:`1px solid ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>Desbloquear</button>
          </div>
        ))}
      </div>}
      {!editing&&<div style={{display:"flex",gap:"12px"}}>
        <button style={{...btnSecondary,flex:1}} onClick={()=>setEditing(true)}>✏️ Editar Perfil</button>
        <button style={{...btnSecondary,flex:1,borderColor:"rgba(248,81,73,0.3)",color:C.error}} onClick={()=>setShowLogout(true)}>Sair da Conta</button>
      </div>}
      {!editing&&<div style={{marginTop:"12px"}}>
        <button onClick={()=>setShowDeleteAccount(true)} style={{...btnSecondary,width:"100%",borderColor:"rgba(248,81,73,0.2)",color:C.error,fontSize:"13px",opacity:0.8}}>🗑️ Excluir minha conta</button>
      </div>}
      {!editing&&<div style={{display:"flex",gap:"16px",justifyContent:"center",marginTop:"20px",paddingTop:"16px",borderTop:`1px solid ${C.border}`}}>
        <button onClick={()=>onNavigate?.("privacidade")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>Política de Privacidade</button>
        <button onClick={()=>onNavigate?.("termos")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>Termos de Uso</button>
      </div>}
      {showLogout&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(6px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"24px"}} onClick={()=>setShowLogout(false)}>
        <div style={{...cardBase,maxWidth:"360px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>👋</div>
          <h3 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 8px"}}>Sair da conta?</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Seus diários ficam salvos.</p>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>setShowLogout(false)}>Cancelar</button><button style={{...btnPrimary,background:C.error}} onClick={onLogout}>Sair</button></div>
        </div>
      </div>}
      {showDeleteAccount&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(6px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"24px"}} onClick={()=>{setShowDeleteAccount(false);setDeleteConfirmText("");}}>
        <div style={{...cardBase,maxWidth:"420px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>⚠️</div>
          <h3 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 8px",color:C.error}}>Excluir minha conta</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 8px"}}>Esta ação é permanente e irreversível. Todos os seus dados serão excluídos:</p>
          <div style={{fontFamily:F.sans,fontSize:"13px",color:C.text,textAlign:"left",background:C.errorBg,borderRadius:"10px",padding:"14px 16px",marginBottom:"16px",lineHeight:"1.8"}}>
            • Seu perfil e informações pessoais<br/>
            • Todos os seus diários e semanas<br/>
            • Fotos e vídeos enviados<br/>
            • Comentários e mensagens<br/>
            • Curtidas e favoritos
          </div>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,margin:"0 0 14px"}}>Para confirmar, digite <strong>EXCLUIR</strong> abaixo:</p>
          <input style={{...baseInput,textAlign:"center",marginBottom:"16px",fontWeight:"700",letterSpacing:"2px"}} value={deleteConfirmText} onChange={e=>setDeleteConfirmText(e.target.value.toUpperCase())} placeholder="EXCLUIR"/>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>{setShowDeleteAccount(false);setDeleteConfirmText("");}}>Cancelar</button><button style={{...btnPrimary,background:C.error,opacity:deleteConfirmText!=="EXCLUIR"?0.4:1}} disabled={deleteConfirmText!=="EXCLUIR"} onClick={()=>{onDeleteAccount?.();setShowDeleteAccount(false);}}>Excluir Permanentemente</button></div>
        </div>
      </div>}
    </div>
  );
}

// ─── Diary Card ───
function DiaryCard({ diary, onClick, onLike, onFav, isLiked, isFaved, onViewImage, commentCount, onAuthorClick }) {
  const [h,setH]=useState(false);
  return (
    <div style={{borderRadius:"14px",overflow:"hidden",border:`1px solid ${C.border}`,background:C.cardBg,transition:"all 0.3s",cursor:"pointer",transform:h?"translateY(-4px)":"none",boxShadow:h?"0 6px 24px rgba(0,0,0,0.1)":"0 1px 4px rgba(0,0,0,0.05)"}} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} onClick={onClick}>
      <div style={{height:"140px",background:COVER_GRADIENTS[(diary.cover||0)%6],display:"flex",alignItems:"center",justifyContent:"center",position:"relative",overflow:"hidden"}}>
        {diary.coverImage?<img src={diary.coverImage} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:<div dangerouslySetInnerHTML={{__html:generatePlantArt(diary.id.charCodeAt(1)*7+(diary.id.charCodeAt(0)||1),100)}} style={{opacity:0.8}}/>}
        <div style={{position:"absolute",top:"10px",right:"10px",padding:"4px 10px",borderRadius:"8px",background:PHASE_COLORS[diary.phase]+"22",color:PHASE_COLORS[diary.phase],fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{PHASE_ICONS[diary.phase]} {PHASES[diary.phase]}</div>
        <div style={{position:"absolute",top:"10px",left:"10px",padding:"4px 8px",borderRadius:"8px",background:"var(--dp-overlay85)",color:"#555",fontSize:"11px",fontFamily:F.sans,fontWeight:"500"}}>{diary.env}</div>
      </div>
      <div style={{padding:"14px 16px"}}>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"600",marginBottom:"3px",color:C.text}}>{diary.name}</div>
        <div style={{fontFamily:F.sans,fontSize:"13px",color:C.accent,marginBottom:"10px",display:"flex",alignItems:"center",gap:"6px"}}>
          <span style={{overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{diary.strains?diary.strains[0]:diary.strain}</span>
          {diary.strains&&diary.strains.length>1&&<span style={{fontSize:"11px",padding:"1px 6px",borderRadius:"6px",background:C.accentBg,color:C.accent,fontWeight:"600",flexShrink:0,border:`1px solid ${C.accentBorder}`}}>+{diary.strains.length-1}</span>}
        </div>
        {diary.techniques?.length>0&&<div style={{display:"flex",gap:"4px",flexWrap:"wrap",marginBottom:"6px"}}>{diary.techniques.slice(0,4).map(t=><span key={t} style={{padding:"2px 8px",borderRadius:"6px",fontSize:"10px",background:C.accentBg,color:C.accent,fontFamily:F.sans,fontWeight:"500"}}>{t}</span>)}</div>}
        {diary.tags?.length>0&&<div style={{display:"flex",gap:"4px",flexWrap:"wrap",marginBottom:"10px"}}>{diary.tags.slice(0,5).map(t=><span key={t} style={{padding:"2px 8px",borderRadius:"6px",fontSize:"10px",background:C.surface2,color:C.dim,fontFamily:F.sans,fontWeight:"500"}}>#{t}</span>)}</div>}
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",fontSize:"12px",color:C.dim,fontFamily:F.sans}}>
          <span onClick={e=>{e.stopPropagation();onAuthorClick?.(diary.authorId||diary.ownerEmail);}} style={{cursor:"pointer",display:"flex",alignItems:"center",gap:"4px"}} onMouseOver={e=>e.currentTarget.style.color=C.accent} onMouseOut={e=>e.currentTarget.style.color=C.dim}>{diary.avatar||"🌱"} {diary.author}</span>
          <div style={{display:"flex",gap:"6px",alignItems:"center"}}>
            <button onClick={e=>{e.stopPropagation();onLike?.(diary.id);}} style={{background:"none",border:"none",cursor:"pointer",fontSize:"13px",padding:"2px",display:"flex",alignItems:"center",gap:"2px",color:isLiked?C.error:C.dim}}>
              {isLiked?"❤️":"🤍"}<span style={{fontSize:"11px"}}>{diary.likes||0}</span>
            </button>
            {(commentCount>0||diary.comments>0)&&<span style={{fontSize:"11px",display:"flex",alignItems:"center",gap:"2px"}}>💬 {commentCount||diary.comments||0}</span>}
            <button onClick={e=>{e.stopPropagation();onFav?.(diary.id);}} style={{background:"none",border:"none",cursor:"pointer",fontSize:"13px",padding:"2px",color:isFaved?"#f59e0b":C.dim}}>
              {isFaved?"⭐":"☆"}
            </button>
            <button onClick={e=>{e.stopPropagation();if(navigator.clipboard)navigator.clipboard.writeText(window.location.href+"#diary-"+diary.id);}} title="Compartilhar" style={{background:"none",border:"none",cursor:"pointer",fontSize:"12px",padding:"2px",color:C.dim}}>🔗</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Create Diary Modal (GrowDiaries style) ───
function CreateDiaryModal({ user, onClose, onSave }) {
  const [name,setName]=useState(""); const [strains,setStrains]=useState([""]);
  const [strainQtys,setStrainQtys]=useState([1]);
  const [env,setEnv]=useState("Indoor"); const [light,setLight]=useState("LED");
  const [substrate,setSubstrate]=useState("Solo"); const [techs,setTechs]=useState([]);
  const [watering,setWatering]=useState("Manual"); const [germination,setGermination]=useState("Papel Toalha");
  const [numPlants,setNumPlants]=useState("1");
  const [watts,setWatts]=useState("");
  const [tags,setTags]=useState("");
  const toggle=t=>setTechs(p=>p.includes(t)?p.filter(x=>x!==t):[...p,t]);
  const addStrain=()=>{if(strains.length<8){setStrains(p=>[...p,""]);setStrainQtys(p=>[...p,1]);}};
  const updateStrain=(i,v)=>setStrains(p=>p.map((s,j)=>j===i?v:s));
  const updateStrainQty=(i,v)=>setStrainQtys(p=>p.map((q,j)=>j===i?parseInt(v)||1:q));
  const removeStrain=i=>{setStrains(p=>p.filter((_,j)=>j!==i));setStrainQtys(p=>p.filter((_,j)=>j!==i));};

  const handleSave=()=>{
    const validStrains=strains.map(s=>s.trim()).filter(Boolean);
    if(!name.trim()||validStrains.length===0)return;
    const totalPlants=strainQtys.reduce((s,q)=>s+(parseInt(q)||1),0);
    onSave({id:"u"+Date.now(),name:name.trim(),strain:validStrains.join(", "),strains:validStrains,author:user.username,authorId:user.email,phase:0,week:0,env,light,substrate,likes:0,comments:0,avatar:user.avatar,cover:Math.floor(Math.random()*6),techniques:techs,weeks:[],isOwn:true,watering,germination,numPlants:totalPlants,watts:watts?parseInt(watts):null,tags:tags.split(",").map(t=>t.trim().replace(/^#/,"")).filter(Boolean)});
  };

  return (
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(12px)",display:"flex",alignItems:"flex-start",justifyContent:"center",zIndex:200,overflowY:"auto",padding:"20px 12px"}} onClick={onClose}>
      <div style={{background:C.surface,borderRadius:"16px",border:`1px solid ${C.border}`,width:"100%",maxWidth:"680px",overflow:"hidden"}} onClick={e=>e.stopPropagation()}>

        {/* Header */}
        <div style={{padding:"20px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",justifyContent:"space-between",gap:"12px"}}>
          <div>
            <div style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"800",color:C.text,display:"flex",alignItems:"center",gap:"10px"}}>
              <span style={{fontSize:"24px"}}>🌱</span> Iniciar Novo Diário
            </div>
            <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim,marginTop:"4px"}}>Configure as informações do seu cultivo</div>
          </div>
          <button onClick={onClose} style={{width:"36px",height:"36px",borderRadius:"10px",border:`1px solid ${C.borderLight}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"18px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
        </div>

        <div style={{padding:"20px"}}>

          {/* Diary Info */}
          <SectionHeader title="Informações do Diário" />
          <div style={{marginBottom:"28px"}}>
            <div style={{marginBottom:"16px"}}><label style={labelSt}>Nome do Diário</label><input style={baseInput} value={name} onChange={e=>setName(e.target.value)} placeholder='Ex: "Minha primeira indoor"'/></div>
            <label style={labelSt}>Genética / Variedade <span style={{fontWeight:"400",textTransform:"none",letterSpacing:"0",fontSize:"11px",color:C.dim}}>({strains.length}/8) — informe a quantidade de cada</span></label>
            <div style={{display:"flex",flexDirection:"column",gap:"8px"}}>
              {strains.map((s,i)=>(
                <div key={i} style={{display:"flex",gap:"8px",alignItems:"center"}}>
                  <input style={{...baseInput,flex:1}} value={s} onChange={e=>updateStrain(i,e.target.value)} placeholder={i===0?"Ex: Northern Lights Auto":`Genética ${i+1}`}/>
                  <div style={{display:"flex",alignItems:"center",gap:"4px",flexShrink:0}}>
                    <input type="number" min="1" max="99" value={strainQtys[i]||1} onChange={e=>updateStrainQty(i,e.target.value)} style={{...baseInput,width:"52px",textAlign:"center",padding:"8px 4px"}}/>
                    <span style={{fontFamily:F.sans,fontSize:"10px",color:C.dim}}>un.</span>
                  </div>
                  {strains.length>1&&<button onClick={()=>removeStrain(i)} style={{width:"36px",height:"36px",borderRadius:"10px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.error,cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>✕</button>}
                </div>
              ))}
              {strains.length<8&&<button onClick={addStrain} style={{padding:"10px 16px",borderRadius:"10px",border:`1px dashed ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",gap:"8px",alignSelf:"flex-start"}}>
                🌿 + Adicionar Genética
              </button>}
            </div>
          </div>

          {/* Setup */}
          <SectionHeader title="Configuração" subtitle="Selecione as opções do seu grow" />

          {/* Environment */}
          <div style={{marginBottom:"20px"}}>
            <label style={{...labelSt,fontSize:"11px",color:C.dim}}>Ambiente</label>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:"10px"}}>
              {ENVIRONMENTS.map(e=><IconCard key={e.id} icon={e.icon} label={e.label} selected={env===e.id} onClick={()=>setEnv(e.id)}/>)}
            </div>
          </div>

          {/* Lights */}
          <div style={{marginBottom:"20px"}}>
            <label style={{...labelSt,fontSize:"11px",color:C.dim}}>Iluminação</label>
            <div style={{display:"flex",flexWrap:"wrap",gap:"10px"}}>
              {LIGHTS.map(l=><IconCard key={l.id} icon={l.icon} label={l.label} selected={light===l.id} onClick={()=>setLight(l.id)} small/>)}
            </div>
          </div>

          {/* Watts */}
          <div style={{marginBottom:"20px",maxWidth:"220px"}}>
            <label style={{...labelSt,fontSize:"11px",color:C.dim}}>⚡ Potência (Watts)</label>
            <input style={baseInput} type="number" min="0" max="5000" value={watts} onChange={e=>setWatts(e.target.value)} placeholder="Ex: 240"/>
          </div>

          {/* Substrate */}
          <div style={{marginBottom:"20px"}}>
            <label style={{...labelSt,fontSize:"11px",color:C.dim}}>Substrato</label>
            <div style={{display:"flex",flexWrap:"wrap",gap:"10px"}}>
              {SUBSTRATES.map(s=><IconCard key={s.id} icon={s.icon} label={s.label} selected={substrate===s.id} onClick={()=>setSubstrate(s.id)} small/>)}
            </div>
          </div>

          {/* Watering & Germination */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(200px, 1fr))",gap:"20px",marginBottom:"20px"}}>
            <div>
              <label style={{...labelSt,fontSize:"11px",color:C.dim}}>Irrigação</label>
              <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:"8px"}}>
                {WATERING.map(w=><IconCard key={w.id} icon={w.icon} label={w.label} selected={watering===w.id} onClick={()=>setWatering(w.id)} small/>)}
              </div>
            </div>
            <div>
              <label style={{...labelSt,fontSize:"11px",color:C.dim}}>Germinação</label>
              <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:"8px"}}>
                {GERMINATION.map(g=><IconCard key={g.id} icon={g.icon} label={g.label} selected={germination===g.id} onClick={()=>setGermination(g.id)} small/>)}
              </div>
            </div>
          </div>

          {/* Techniques */}
          <SectionHeader title="Técnicas de Cultivo" subtitle="Selecione uma ou mais" />
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(90px,1fr))",gap:"8px",marginBottom:"24px"}}>
            {TECHNIQUES.map(t=><IconCard key={t.id} icon={t.icon} label={t.label} selected={techs.includes(t.id)} onClick={()=>toggle(t.id)} small/>)}
          </div>

          {/* Number of plants (auto-calculated) */}
          <div style={{marginBottom:"20px",padding:"12px 16px",background:C.surface2,borderRadius:"10px",display:"flex",alignItems:"center",gap:"10px"}}>
            <span style={{fontSize:"18px"}}>🌿</span>
            <span style={{fontFamily:F.sans,fontSize:"13px",color:C.muted}}>Total de plantas:</span>
            <span style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"800",color:C.accent}}>{strainQtys.reduce((s,q)=>s+(parseInt(q)||1),0)}</span>
          </div>

          {/* Tags */}
          <div style={{marginBottom:"28px"}}>
            <label style={labelSt}>#️⃣ Tags / Hashtags</label>
            <input style={baseInput} value={tags} onChange={e=>setTags(e.target.value)} placeholder="LST, SOG, orgânico, hidroponia (separar por vírgula)"/>
            <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>Facilita a descoberta do seu diário por outros cultivadores</div>
          </div>

          {/* Actions */}
          <div style={{display:"flex",gap:"12px",justifyContent:"flex-end"}}>
            <button style={{...btnSecondary,width:"auto",padding:"12px 28px"}} onClick={onClose}>Cancelar</button>
            <button style={{...btnPrimary,width:"auto",padding:"12px 36px",opacity:(!name||!strains.some(s=>s.trim()))?0.4:1,fontSize:"16px"}} onClick={handleSave}>
              🌱 Criar Diário
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Add Week Modal ───
function AddWeekModal({ diary, onClose, onSave, lang }) {
  // Germination doesn't count as a week - week numbering starts at 1 for non-germination phases
  const nonGermWeeks=(diary.weeks||[]).filter(w=>w.phase!==0&&w.phase!==3).length;
  const t=T[lang||"pt"];
  const [phase,setPhase]=useState(diary.phase||0); const [height,setHeight]=useState("");
  const [temp,setTemp]=useState(""); const [humidity,setHumidity]=useState("");
  const [ph,setPh]=useState(""); const [waterMl,setWaterMl]=useState("");
  const [lightHours,setLightHours]=useState(""); const [note,setNote]=useState("");
  const [media,setMedia]=useState([]);
  const [uploadProgress,setUploadProgress]=useState(null); // {current, total}
  const fileRef=useRef(null);
  const MAX_MEDIA=15;

  const handleFiles=async(e)=>{
    const files=Array.from(e.target.files||[]);
    const remaining=MAX_MEDIA-media.length;
    if(remaining<=0)return;
    const toAdd=files.slice(0,remaining);
    setUploadProgress({current:0,total:toAdd.length});
    for(let i=0;i<toAdd.length;i++){
      const f=toAdd[i];
      setUploadProgress({current:i+1,total:toAdd.length});
      const ext=f.name.split(".").pop()||"jpg";
      const path=`${diary.authorId||"anon"}/weeks/${diary.id}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      if(ok){
        setMedia(prev=>{
          if(prev.length>=MAX_MEDIA)return prev;
          return[...prev,{id:Date.now()+Math.random(),name:f.name,type:f.type.startsWith("video")?"video":"photo",data:sbStorage.getUrl(path)}];
        });
      }
    }
    setUploadProgress(null);
    e.target.value="";
  };
  const removeMedia=(id)=>setMedia(prev=>prev.filter(m=>m.id!==id));

  return (
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(12px)",display:"flex",alignItems:"flex-start",justifyContent:"center",zIndex:200,overflowY:"auto",padding:"40px 20px"}} onClick={onClose}>
      <div style={{background:C.surface,borderRadius:"16px",border:`1px solid ${C.border}`,width:"100%",maxWidth:"600px",overflow:"hidden"}} onClick={e=>e.stopPropagation()}>

        {/* Header with back + close */}
        <div style={{padding:"20px 24px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <button onClick={onClose} style={{padding:"6px 14px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"6px"}}>← {t.back}</button>
          <div style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"800",color:C.text,display:"flex",alignItems:"center",gap:"8px"}}>
            <span style={{fontSize:"22px"}}>📝</span> {phase===0?t.germination:phase===3?PHASES[3]:`${t.week} ${nonGermWeeks+1}`}
          </div>
          <button onClick={onClose} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.borderLight}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
        </div>

        <div style={{padding:"24px"}}>
          {/* Phase */}
          <SectionHeader title={t.plantPhase}/>
          <div style={{display:"flex",gap:"8px",flexWrap:"wrap",marginBottom:"24px"}}>
            {PHASES.map((p,i)=>(
              <div key={p} onClick={()=>setPhase(i)} style={{
                padding:"10px 18px",borderRadius:"10px",cursor:"pointer",fontSize:"13px",
                fontFamily:F.sans,transition:"all 0.2s",fontWeight:"600",
                border:phase===i?`2px solid ${PHASE_COLORS[i]}`:`1px solid ${C.borderLight}`,
                background:phase===i?PHASE_COLORS[i]+"18":C.surface2,
                color:phase===i?PHASE_COLORS[i]:C.muted,
              }}>{PHASE_ICONS[i]} {p}</div>
            ))}
          </div>

          {/* Conditions */}
          <SectionHeader title={t.growConditions}/>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(140px, 1fr))",gap:"14px",marginBottom:"24px"}}>
            {[[t.height+" (cm)",height,setHeight,"0","📏"],[t.temp+" (°C)",temp,setTemp,"25","🌡️"],[t.humidity+" (%)",humidity,setHumidity,"60","💧"],["pH",ph,setPh,"6.5","⚗️"],[t.watering+" (ml)",waterMl,setWaterMl,"500","🚿"],[t.light+" (h)",lightHours,setLightHours,"18","💡"]].map(([l,v,s,p,icon])=>(
              <div key={l}>
                <label style={{...labelSt,display:"flex",alignItems:"center",gap:"6px"}}><span>{icon}</span>{l}</label>
                <input style={baseInput} type="number" step={l==="pH"?"0.1":"1"} value={v} onChange={e=>s(e.target.value)} placeholder={p}/>
              </div>
            ))}
          </div>

          {/* Photos & Videos */}
          <SectionHeader title={t.photosVideos} subtitle={`${media.length}/${MAX_MEDIA} ${t.media}`}/>
          {uploadProgress&&<div style={{marginBottom:"12px",background:C.surface2,borderRadius:"10px",padding:"12px 16px",border:`1px solid ${C.accent}33`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"6px"}}>
              <span style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"600",color:C.accent}}>⏳ Enviando {uploadProgress.current} de {uploadProgress.total}...</span>
              <span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{Math.round((uploadProgress.current/uploadProgress.total)*100)}%</span>
            </div>
            <div style={{height:"6px",background:C.border,borderRadius:"3px",overflow:"hidden"}}>
              <div style={{height:"100%",background:`linear-gradient(90deg, ${C.accent}, #2dd4bf)`,borderRadius:"3px",transition:"width 0.3s ease",width:`${(uploadProgress.current/uploadProgress.total)*100}%`}}/>
            </div>
          </div>}
          <div style={{marginBottom:"24px"}}>
            {media.length>0&&(
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(80px,1fr))",gap:"8px",marginBottom:"12px"}}>
                {media.map(m=>(
                  <div key={m.id} style={{position:"relative",borderRadius:"10px",overflow:"hidden",aspectRatio:"1",background:C.surface2,border:`1px solid ${C.border}`}}>
                    {m.type==="photo"?(
                      <img src={m.data} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>
                    ):(
                      <div style={{width:"100%",height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:"4px"}}>
                        <span style={{fontSize:"24px"}}>🎬</span>
                        <span style={{fontSize:"9px",color:C.dim,fontFamily:F.sans,padding:"0 4px",textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"100%"}}>{m.name}</span>
                      </div>
                    )}
                    <button onClick={()=>removeMedia(m.id)} style={{position:"absolute",top:"4px",right:"4px",width:"20px",height:"20px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.4)",color:C.onAccent,cursor:"pointer",fontSize:"11px",display:"flex",alignItems:"center",justifyContent:"center",lineHeight:"1"}}>✕</button>
                  </div>
                ))}
              </div>
            )}
            {media.length<MAX_MEDIA&&(
              <div onClick={()=>fileRef.current?.click()} style={{border:`2px dashed ${C.accent33}`,borderRadius:"12px",padding:"24px",textAlign:"center",cursor:"pointer",transition:"all 0.2s",background:C.surface2}}>
                <div style={{fontSize:"32px",marginBottom:"8px",opacity:0.6}}>☁️</div>
                <div style={{fontFamily:F.sans,fontSize:"14px",color:C.accent,fontWeight:"600",marginBottom:"4px"}}>+ {t.addMedia} ({MAX_MEDIA-media.length} {t.remaining})</div>
                <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim}}>{t.clickSelect}</div>
              </div>
            )}
            <input ref={fileRef} type="file" accept="image/*,video/*" multiple style={{display:"none"}} onChange={handleFiles}/>
          </div>

          {/* Notes */}
          <SectionHeader title={t.weekComment}/>
          <textarea style={{...baseInput,minHeight:"80px",resize:"vertical",marginBottom:"24px"}} value={note} onChange={e=>setNote(e.target.value)} placeholder={t.howIsPlant}/>

          {/* Actions */}
          <div style={{display:"flex",gap:"12px"}}>
            <button style={{...btnSecondary,width:"auto",padding:"12px 24px"}} onClick={onClose}>{t.cancel}</button>
            <button style={btnPrimary} onClick={()=>onSave({
              week:(phase===0||phase===3)?0:nonGermWeeks+1,phase,height:height||null,temp:temp||null,humidity:humidity||null,
              ph:ph||null,waterMl:waterMl||null,lightHours:lightHours||null,note:note||"",
              media:media.map(m=>({id:m.id,name:m.name,type:m.type,data:m.data})),
              mediaCount:media.length,
            })}>{t.saveWeek}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Diary Detail ───
function DiaryDetail({ diary, onBack, onUpdate, onRemove, onHide, lang, onLike, onFav, isLiked, isFaved, onViewImage, onReport, comments, onAddComment, onDeleteComment, onEditComment, blockedByOwner, onBlockUser, onUnblockUser, onReportUser, currentUserEmail, onAuthorClick }) {
  const [showAdd,setShowAdd]=useState(false);
  const [showSettings,setShowSettings]=useState(false);
  const [showEdit,setShowEdit]=useState(false);
  const [confirm,setConfirm]=useState(null);
  const [expandedWeek,setExpandedWeek]=useState(null);
  const [confirmDeleteWeek,setConfirmDeleteWeek]=useState(null);
  const [editingWeekIdx,setEditingWeekIdx]=useState(null);
  const [showReport,setShowReport]=useState(false);
  const [reportReason,setReportReason]=useState("");
  const [commentText,setCommentText]=useState("");
  const [replyTo,setReplyTo]=useState(null); // {id, username}
  const [reportUserTarget,setReportUserTarget]=useState(null);
  const [reportUserReason,setReportUserReason]=useState("");
  const [confirmBlock,setConfirmBlock]=useState(null);
  const [editingComment,setEditingComment]=useState(null); // {id, text}
  const t=T[lang];
  const settRef=useRef(null);
  useEffect(()=>{const h=e=>{if(settRef.current&&!settRef.current.contains(e.target))setShowSettings(false);};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);

  // Edit diary state
  const [editName,setEditName]=useState(diary.name);
  const [editStrains,setEditStrains]=useState(diary.strains||[diary.strain]);
  const [editEnv,setEditEnv]=useState(diary.env);
  const [editLight,setEditLight]=useState(diary.light);
  const [editSubstrate,setEditSubstrate]=useState(diary.substrate);
  const [editWatts,setEditWatts]=useState(diary.watts||"");

  const addWeek=wd=>{onUpdate({...diary,weeks:[...(diary.weeks||[]),wd],week:wd.week,phase:wd.phase});setShowAdd(false);};
  const deleteWeek=idx=>{const nw=[...(diary.weeks||[])];const removed=nw.splice(idx,1)[0];const last=nw[nw.length-1];onUpdate({...diary,weeks:nw,week:last?last.week:0,phase:last?last.phase:0,_deletedWeekIds:removed?.id?[removed.id]:[]});setConfirmDeleteWeek(null);setExpandedWeek(null);};
  const saveEdit=()=>{const vs=editStrains.map(s=>s.trim()).filter(Boolean);onUpdate({...diary,name:editName.trim()||diary.name,strain:vs.join(", ")||diary.strain,strains:vs.length?vs:diary.strains,env:editEnv,light:editLight,substrate:editSubstrate,watts:editWatts?parseInt(editWatts):null});setShowEdit(false);};
  const saveWeekEdit=(idx,wd)=>{const weeks=[...(diary.weeks||[])];weeks[idx]={...weeks[idx],...wd};const last=weeks[weeks.length-1];onUpdate({...diary,weeks,week:last.week,phase:last.phase});setEditingWeekIdx(null);};
  const deleteCover=()=>onUpdate({...diary,coverImage:null});
  const coverRef=useRef(null);
  const [weekMediaTarget,setWeekMediaTarget]=useState(null);
  const weekMediaInputRef=useRef(null);

  const handleCoverUpload=async(e)=>{
    const f=e.target.files?.[0];if(!f)return;
    const path=`${diary.authorId||"anon"}/covers/${diary.id}-${Date.now()}.${f.name.split(".").pop()||"jpg"}`;
    const ok=await sbStorage.upload(path,f);
    if(ok){const url=sbStorage.getUrl(path);onUpdate({...diary,coverImage:url});}
    e.target.value="";
  };

  const addWeekMedia=async(weekIdx,files)=>{
    const w=(diary.weeks||[])[weekIdx];
    if(!w)return;
    const existing=w.media||[];
    const remaining=15-existing.length;if(remaining<=0)return;
    const toAdd=Array.from(files).slice(0,remaining);
    const uploaded=[];
    for(const f of toAdd){
      const ext=f.name.split(".").pop()||"jpg";
      const path=`${diary.authorId||"anon"}/weeks/${diary.id}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      if(ok){
        uploaded.push({id:Date.now()+Math.random(),name:f.name,type:f.type.startsWith("video")?"video":"photo",data:sbStorage.getUrl(path)});
      }
    }
    if(uploaded.length>0){
      const weeks=[...(diary.weeks||[])];
      const newMedia=[...existing,...uploaded];
      weeks[weekIdx]={...weeks[weekIdx],media:newMedia,mediaCount:newMedia.length};
      onUpdate({...diary,weeks});
    }
  };

  const removeWeekMedia=(weekIdx,mediaId)=>{
    const weeks=[...(diary.weeks||[])];
    const w={...weeks[weekIdx]};
    w.media=(w.media||[]).filter(m=>m.id!==mediaId);
    w.mediaCount=w.media.length;
    weeks[weekIdx]=w;
    onUpdate({...diary,weeks});
  };

  return (
    <div>
      <div style={{padding:"60px 24px 40px",textAlign:"center",position:"relative"}}>
        <div style={{position:"absolute",top:0,left:0,right:0,bottom:0,background:COVER_GRADIENTS[(diary.cover||0)%6],opacity:0.6}}/>
        {diary.coverImage&&<div style={{position:"absolute",top:0,left:0,right:0,bottom:0,backgroundImage:`url(${diary.coverImage})`,backgroundSize:"cover",backgroundPosition:"center",opacity:0.3}}/>}
        <div style={{position:"relative",zIndex:1}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
            <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,display:"inline-flex",alignItems:"center",gap:"6px"}}>← {t.back}</button>
            {diary.isOwn&&<div ref={settRef} style={{position:"relative"}}>
              <button onClick={()=>setShowSettings(!showSettings)} style={{padding:"8px 18px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"6px"}}>{t.settings} ⚙️</button>
              {showSettings&&<div style={{position:"absolute",top:"42px",right:0,background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"6px",minWidth:"180px",boxShadow:"0 8px 24px rgba(0,0,0,0.1)",zIndex:20}}>
                {[
                  {icon:"✏️",label:t.editDiary,action:()=>{setShowSettings(false);setShowEdit(true);setEditName(diary.name);setEditStrains(diary.strains||[diary.strain]);setEditEnv(diary.env);setEditLight(diary.light);setEditSubstrate(diary.substrate);setEditWatts(diary.watts||"");}},
                  {icon:"📄",label:"Exportar PDF",action:()=>{setShowSettings(false);
                    // Generate PDF using printable view
                    const win=window.open("","_blank");
                    if(!win)return;
                    const weeks=(diary.weeks||[]);
                    const weeksHtml=weeks.map(w=>`<div style="border:1px solid #e5e5e5;border-radius:12px;padding:16px;margin-bottom:12px"><h3 style="color:#1B9E42;margin:0 0 8px">${w.phase===0?"Germinação":w.phase===3?"Colheita":"Semana "+w.week} — ${PHASES[w.phase]}</h3><div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;font-size:13px;margin-bottom:8px">${w.height?`<span>📏 Altura: ${w.height}cm</span>`:""}${w.temp?`<span>🌡️ Temp: ${w.temp}°C</span>`:""}${w.humidity?`<span>💧 Umidade: ${w.humidity}%</span>`:""}${w.ph?`<span>⚗️ pH: ${w.ph}</span>`:""}${w.waterMl?`<span>🚿 Rega: ${w.waterMl}ml</span>`:""}${w.lightHours?`<span>💡 Luz: ${w.lightHours}h</span>`:""}</div>${w.note?`<p style="color:#666;margin:8px 0 0;font-size:13px">${w.note}</p>`:""}</div>`).join("");
                    win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${diary.name} - Diário da Planta</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet"><style>body{font-family:Inter,sans-serif;max-width:700px;margin:0 auto;padding:32px;color:#333}h1{color:#1B9E42}@media print{body{padding:16px}}</style></head><body><h1>🌱 ${diary.name}</h1><p><strong>Genética:</strong> ${diary.strain}</p><p><strong>Ambiente:</strong> ${diary.env} · <strong>Luz:</strong> ${diary.light} · <strong>Substrato:</strong> ${diary.substrate}</p>${diary.tags?.length?`<p><strong>Tags:</strong> ${diary.tags.map(t=>"#"+t).join(" ")}</p>`:""}<p><strong>Fase atual:</strong> ${PHASES[diary.phase]} · <strong>Semanas:</strong> ${weeks.length}</p><hr style="margin:20px 0"><h2>Semanas</h2>${weeksHtml||"<p>Nenhuma semana registrada.</p>"}<hr style="margin:20px 0"><p style="font-size:11px;color:#999">Exportado de diariodaplanta.com.br · ${new Date().toLocaleDateString("pt-BR")}</p><script>setTimeout(()=>window.print(),500)</script></body></html>`);
                    win.document.close();
                  }},
                  {icon:"👁️",label:t.hideDiary,action:()=>{setShowSettings(false);setConfirm("hide");}},
                  {icon:"🗑️",label:t.removeDiary,action:()=>{setShowSettings(false);setConfirm("remove");},color:C.error},
                ].map(item=>(
                  <button key={item.label} onClick={item.action} style={{width:"100%",padding:"10px 14px",borderRadius:"8px",border:"none",background:"transparent",color:item.color||C.text,cursor:"pointer",fontSize:"14px",fontFamily:F.sans,textAlign:"left",display:"flex",alignItems:"center",gap:"10px"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                    <span>{item.icon}</span>{item.label}
                  </button>
                ))}
              </div>}
            </div>}
          </div>

          {/* Author avatar + cover upload */}
          <div style={{position:"relative",display:"inline-block",margin:"0 auto 16px"}}>
            {diary.coverImage?(
              <div onClick={()=>onViewImage?.(diary.coverImage)} style={{width:"120px",height:"120px",borderRadius:"16px",overflow:"hidden",border:"3px solid rgba(255,255,255,0.8)",boxShadow:"0 2px 12px rgba(0,0,0,0.1)",margin:"0 auto",cursor:"pointer"}}>
                <img src={diary.coverImage} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>
              </div>
            ):(
              <div dangerouslySetInnerHTML={{__html:generatePlantArt(diary.id.charCodeAt(1)*7,80)}} style={{width:"80px",opacity:0.8,margin:"0 auto"}}/>
            )}
            {/* Author avatar badge */}
            <div style={{position:"absolute",bottom:diary.coverImage?"-6px":"-8px",right:diary.coverImage?"-6px":"-20px",width:"36px",height:"36px",borderRadius:"50%",background:C.cardBg,border:"2px solid #fff",boxShadow:"0 2px 6px rgba(0,0,0,0.15)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"18px",overflow:"hidden"}}>
              {diary.avatarImg?<img src={diary.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:diary.avatar||"🌱"}
            </div>
            {diary.isOwn&&<div style={{position:"absolute",top:diary.coverImage?"-8px":"-4px",right:diary.coverImage?"-12px":"-28px",display:"flex",gap:"4px"}}>
              <button onClick={()=>coverRef.current?.click()} style={{width:"28px",height:"28px",borderRadius:"50%",background:C.accent,color:C.onAccent,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"13px",border:"2px solid #fff",boxShadow:"0 2px 6px rgba(0,0,0,0.15)",cursor:"pointer"}}>📷</button>
              {diary.coverImage&&<button onClick={deleteCover} style={{width:"28px",height:"28px",borderRadius:"50%",background:C.cardBg,color:C.error,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"12px",border:`2px solid ${C.border}`,boxShadow:"0 2px 6px rgba(0,0,0,0.1)",cursor:"pointer"}}>✕</button>}
            </div>}
            <input ref={coverRef} type="file" accept="image/*" style={{display:"none"}} onChange={handleCoverUpload}/>
          </div>

          <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",marginBottom:"8px",textShadow:"0 0 3px rgba(255,255,255,0.8), 0 1px 2px rgba(0,0,0,0.1)",WebkitTextStroke:"0.5px rgba(0,0,0,0.1)"}}>{diary.name}</h1>
          <div style={{display:"flex",justifyContent:"center",gap:"6px",flexWrap:"wrap",marginBottom:"12px"}}>
            {(diary.strains||[diary.strain]).map((s,i)=><span key={i} style={{color:C.accent,fontSize:"14px",fontFamily:F.sans,fontWeight:"600",textShadow:"0 0 3px rgba(255,255,255,0.8)",padding:"2px 10px",background:"rgba(255,255,255,0.6)",borderRadius:"8px",border:`1px solid ${C.accentBorder}`}}>{s}</span>)}
          </div>
          <div style={{display:"flex",justifyContent:"center",gap:"20px",fontSize:"13px",color:"#444",fontFamily:F.sans,flexWrap:"wrap",textShadow:"0 0 4px rgba(255,255,255,0.9)"}}><span>{diary.avatar} {diary.author}</span><span>{diary.env}</span><span>{diary.light}{diary.watts?" · "+diary.watts+"W":""}</span><span>{diary.substrate}</span></div>
          {diary.techniques?.length>0&&<div style={{display:"flex",justifyContent:"center",gap:"6px",marginTop:"12px",flexWrap:"wrap"}}>{diary.techniques.map(t2=><span key={t2} style={{padding:"2px 8px",borderRadius:"6px",fontSize:"10px",background:"var(--dp-overlay70)",color:C.accent,fontFamily:F.sans,fontWeight:"600",border:`1px solid ${C.accentBorder}`}}>{t2}</span>)}</div>}

          {/* Like + Fav bar */}
          <div style={{display:"flex",justifyContent:"center",gap:"12px",marginTop:"16px",fontSize:"14px",fontFamily:F.sans,flexWrap:"wrap"}}>
            <button onClick={()=>onLike?.(diary.id)} style={{background:isLiked?C.errorBg:C.cardBg,border:`1px solid ${isLiked?"#fca5a5":C.border}`,borderRadius:"20px",padding:"6px 16px",cursor:"pointer",display:"flex",alignItems:"center",gap:"6px",fontSize:"14px",fontFamily:F.sans,color:isLiked?C.error:C.muted,fontWeight:"500",transition:"all 0.2s"}}>
              {isLiked?"❤️":"🤍"} {diary.likes||0}
            </button>
            <button onClick={()=>onFav?.(diary.id)} style={{background:isFaved?C.warnBg:C.cardBg,border:`1px solid ${isFaved?"#fcd34d":C.border}`,borderRadius:"20px",padding:"6px 16px",cursor:"pointer",display:"flex",alignItems:"center",gap:"6px",fontSize:"14px",fontFamily:F.sans,color:isFaved?"#d97706":C.muted,fontWeight:"500",transition:"all 0.2s"}}>
              {isFaved?"⭐":"☆"} {isFaved?"Favoritado":"Favoritar"}
            </button>
            {!diary.isOwn&&<button onClick={()=>setShowReport(true)} style={{background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"20px",padding:"6px 12px",cursor:"pointer",display:"flex",alignItems:"center",gap:"4px",fontSize:"13px",fontFamily:F.sans,color:C.dim,fontWeight:"500",transition:"all 0.2s"}}>🚩</button>}
            <span style={{display:"flex",alignItems:"center",gap:"4px",color:PHASE_COLORS[diary.phase],fontSize:"14px",fontWeight:"700"}}>{PHASE_ICONS[diary.phase]} {PHASES[diary.phase]}</span>
            <span style={{display:"flex",alignItems:"center",color:C.dim,fontSize:"14px",fontWeight:"700"}}>{diary.phase===0?t.germination:diary.phase===3?PHASES[3]:`${t.week} ${diary.week}`}</span>
          </div>
        </div>
      </div>

      {/* Week cards */}
      <div style={{maxWidth:"700px",margin:"0 auto",padding:"0 24px"}}>
        {diary.weeks?.length>0?diary.weeks.map((w,i)=>{
          const isOpen=expandedWeek===i;
          const weekMedia=w.media||[];
          return (
            <div key={i} style={{background:C.cardBg,borderRadius:"14px",border:`1px solid ${C.border}`,marginBottom:"16px",overflow:"hidden",boxShadow:"0 1px 3px rgba(0,0,0,0.04)"}}>
              {/* Clickable header */}
              <div onClick={()=>setExpandedWeek(isOpen?null:i)} style={{padding:"16px 20px",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",background:isOpen?C.surface2:C.cardBg,transition:"background 0.2s"}}>
                <div style={{display:"flex",alignItems:"center",gap:"12px"}}>
                  <div style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",color:C.accent}}>{w.phase===0?t.germination:w.phase===3?PHASES[3]:`${t.week} ${w.week}`}</div>
                  {(w.mediaCount>0||weekMedia.length>0)&&<span style={{fontSize:"12px",color:C.dim}}>📷 {weekMedia.length||w.mediaCount}</span>}
                </div>
                <div style={{display:"flex",alignItems:"center",gap:"10px"}}>
                  <div style={{padding:"3px 10px",borderRadius:"8px",background:PHASE_COLORS[w.phase]+"18",color:PHASE_COLORS[w.phase],fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{PHASE_ICONS[w.phase]} {PHASES[w.phase]}</div>
                  <span style={{fontSize:"16px",color:C.dim,transition:"transform 0.2s",transform:isOpen?"rotate(180deg)":"rotate(0deg)"}}>▾</span>
                </div>
              </div>

              {/* Expanded content */}
              {isOpen&&<div style={{padding:"0 20px 20px",borderTop:`1px solid ${C.border}`}}>
                <div style={{paddingTop:"16px"}}>
                  {/* Parameters */}
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(90px,1fr))",gap:"8px",marginBottom:"16px"}}>
                    {[["📏",w.height,"cm",t.height],["🌡️",w.temp,"°C",t.temp],["💧",w.humidity,"%",t.humidity],["⚗️",w.ph,"","pH"],["🚿",w.waterMl,"ml",t.watering],["💡",w.lightHours,"h",t.light]].map(([ic,val,u,lab])=>val?<div key={lab} style={{background:C.surface2,borderRadius:"10px",padding:"10px",textAlign:"center"}}><div style={{fontSize:"16px",marginBottom:"2px"}}>{ic}</div><div style={{fontSize:"14px",fontWeight:"600",color:C.text,fontFamily:F.sans}}>{val}{u}</div><div style={{fontSize:"9px",color:C.dim,textTransform:"uppercase",letterSpacing:"0.8px",fontFamily:F.sans}}>{lab}</div></div>:null)}
                  </div>

                  {/* Note */}
                  {w.note&&<div style={{fontSize:"14px",color:C.muted,lineHeight:"1.6",fontFamily:F.body,fontStyle:"italic",padding:"12px",background:C.surface2,borderRadius:"10px",borderLeft:`3px solid ${C.accent33}`,marginBottom:"16px"}}>{w.note}</div>}

                  {/* Media gallery */}
                  {(weekMedia.length>0||diary.isOwn)&&<div style={{marginBottom:"16px"}}>
                    <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.muted,marginBottom:"10px",textTransform:"uppercase",letterSpacing:"0.8px"}}>{t.photosVideos} ({weekMedia.length}/15)</div>
                    {weekMedia.length>0&&(
                      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(90px,1fr))",gap:"8px",marginBottom:"10px"}}>
                        {weekMedia.map(m=>(
                          <div key={m.id} style={{position:"relative",borderRadius:"10px",overflow:"hidden",aspectRatio:"1",background:C.surface2,border:`1px solid ${C.border}`,cursor:m.type==="photo"&&m.data?"pointer":"default"}} onClick={()=>m.type==="photo"&&m.data&&onViewImage?.(m.data)}>
                            {m.type==="photo"&&m.data?(
                              <img src={m.data} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>
                            ):(
                              <div style={{width:"100%",height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:"4px"}}>
                                <span style={{fontSize:"24px"}}>{m.type==="video"?"🎬":"🖼️"}</span>
                                <span style={{fontSize:"9px",color:C.dim,fontFamily:F.sans,padding:"0 4px",textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"100%"}}>{m.name}</span>
                              </div>
                            )}
                            {diary.isOwn&&<button onClick={e=>{e.stopPropagation();removeWeekMedia(i,m.id);}} style={{position:"absolute",top:"4px",right:"4px",width:"22px",height:"22px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.5)",color:C.onAccent,cursor:"pointer",fontSize:"11px",display:"flex",alignItems:"center",justifyContent:"center",lineHeight:"1"}}>✕</button>}
                          </div>
                        ))}
                      </div>
                    )}
                    {diary.isOwn&&weekMedia.length<15&&(
                      <button onClick={()=>{setWeekMediaTarget(i);setTimeout(()=>weekMediaInputRef.current?.click(),50);}} style={{width:"100%",padding:"14px",borderRadius:"10px",border:`2px dashed ${C.accent33}`,background:C.surface2,color:C.accent,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",justifyContent:"center",gap:"8px"}}>
                        📷 + {t.addMedia} ({15-weekMedia.length} {t.remaining})
                      </button>
                    )}
                  </div>}

                  {/* Week actions */}
                  {diary.isOwn&&<div style={{display:"flex",justifyContent:"flex-end",gap:"8px"}}>
                    <button onClick={()=>setEditingWeekIdx(i)} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"6px",fontWeight:"500"}}>✏️ Editar</button>
                    <button onClick={()=>setConfirmDeleteWeek(i)} style={{padding:"6px 14px",borderRadius:"8px",border:"1px solid rgba(229,62,62,0.2)",background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"6px"}}>🗑️ Excluir</button>
                  </div>}
                </div>
              </div>}
            </div>
          );
        }):<div style={{textAlign:"center",padding:"60px 24px",color:C.dim}}><div style={{fontSize:"48px",marginBottom:"16px"}}>🌱</div><p style={{fontFamily:F.body,fontSize:"16px"}}>{t.noWeeks}</p></div>}
        {diary.isOwn&&<button onClick={()=>setShowAdd(true)} style={{width:"100%",padding:"16px",borderRadius:"12px",border:`2px dashed ${C.accent33}`,background:"transparent",color:C.accent,cursor:"pointer",fontSize:"15px",fontFamily:F.sans,fontWeight:"600",transition:"all 0.2s",marginBottom:"24px"}}>{t.addWeek}</button>}
        <input ref={weekMediaInputRef} type="file" accept="image/*,video/*" multiple style={{display:"none"}} onChange={e=>{if(weekMediaTarget!==null)addWeekMedia(weekMediaTarget,e.target.files);e.target.value="";setWeekMediaTarget(null);}}/>

        {/* Phase Timeline */}
        {(diary.weeks||[]).length>0&&<div style={{marginBottom:"24px",background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"18px 20px"}}>
          <h3 style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"12px"}}>📊 Timeline do Cultivo</h3>
          <div style={{display:"flex",gap:"2px",borderRadius:"8px",overflow:"hidden",height:"28px"}}>
            {(diary.weeks||[]).map((w,i)=>{
              const color=PHASE_COLORS[w.phase]||C.accent;
              return <div key={i} title={`${w.phase===0?PHASES[0]:w.phase===3?PHASES[3]:t.week+" "+w.week} — ${PHASES[w.phase]}`} style={{flex:1,background:color,display:"flex",alignItems:"center",justifyContent:"center",cursor:"pointer",transition:"all 0.2s",minWidth:"24px"}} onClick={()=>setExpandedWeek(i)}><span style={{fontSize:"9px",color:"#fff",fontWeight:"700",textShadow:"0 1px 2px rgba(0,0,0,0.3)"}}>{w.phase===0?"G":w.phase===3?"C":w.week}</span></div>;
            })}
          </div>
          <div style={{display:"flex",justifyContent:"space-between",marginTop:"6px",fontFamily:F.sans,fontSize:"10px",color:C.dim}}>
            {[...new Set((diary.weeks||[]).map(w=>w.phase))].map(p=><span key={p} style={{display:"flex",alignItems:"center",gap:"4px"}}><span style={{width:"8px",height:"8px",borderRadius:"2px",background:PHASE_COLORS[p]}}></span>{PHASES[p]}</span>)}
          </div>
        </div>}

        {/* Simple Stats */}
        {(diary.weeks||[]).filter(w=>w.height||w.temp||w.ph).length>1&&<div style={{marginBottom:"24px",background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"18px 20px"}}>
          <h3 style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"12px"}}>📈 Evolução</h3>
          {(()=>{
            const ws=(diary.weeks||[]).filter(w=>w.phase!==0&&w.phase!==3);
            const heights=ws.map(w=>parseFloat(w.height)||0).filter(h=>h>0);
            const temps=ws.map(w=>parseFloat(w.temp)||0).filter(t=>t>0);
            const phs=ws.map(w=>parseFloat(w.ph)||0).filter(p=>p>0);
            const miniChart=(data,color,label,unit)=>{
              if(data.length<2)return null;
              const max=Math.max(...data),min=Math.min(...data);
              const range=max-min||1;
              const w=200,h=50;
              const pts=data.map((v,i)=>`${(i/(data.length-1))*w},${h-((v-min)/range)*h}`).join(" ");
              return <div style={{marginBottom:"12px"}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"4px"}}><span style={{fontFamily:F.sans,fontSize:"11px",fontWeight:"600",color}}>{label}</span><span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{data[data.length-1]}{unit}</span></div><svg viewBox={`-5 -5 ${w+10} ${h+10}`} style={{width:"100%",height:"50px"}}><polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>{data.map((v,i)=><circle key={i} cx={(i/(data.length-1))*w} cy={h-((v-min)/range)*h} r="3" fill={color}/>)}</svg></div>;
            };
            return <div>{miniChart(heights,"#38a169","🌿 Altura","cm")}{miniChart(temps,"#e53e3e","🌡️ Temperatura","°C")}{miniChart(phs,"#3182ce","💧 pH","")}</div>;
          })()}
        </div>}

        {/* Comments Section */}
        <div style={{marginBottom:"40px"}}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",marginBottom:"16px",display:"flex",alignItems:"center",gap:"8px"}}>💬 Comentários {(comments||[]).length>0&&<span style={{fontSize:"13px",color:C.dim,fontWeight:"400"}}>({(comments||[]).length})</span>}</h3>

          {/* Comment input */}
          {!blockedByOwner?<div style={{marginBottom:"20px"}}>
            {replyTo&&<div style={{display:"flex",alignItems:"center",gap:"8px",padding:"8px 14px",background:C.accentBg,borderRadius:"10px 10px 0 0",fontSize:"12px",fontFamily:F.sans,color:C.accent}}>↩️ Respondendo a <strong>{replyTo.username}</strong><button onClick={()=>setReplyTo(null)} style={{marginLeft:"auto",background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"14px"}}>✕</button></div>}
            <div style={{display:"flex",gap:"10px",borderRadius:replyTo?"0 0 10px 10px":"10px"}}>
            <input style={{...baseInput,borderRadius:replyTo?"0 0 24px 24px":"24px",padding:"12px 18px",flex:1}} value={commentText} onChange={e=>setCommentText(e.target.value)} placeholder={replyTo?`Responder ${replyTo.username}...`:"Escreva um comentário..."} onKeyDown={e=>{if(e.key==="Enter"&&commentText.trim()){onAddComment?.(diary.id,commentText.trim(),replyTo?.id);setCommentText("");setReplyTo(null);}}}/>
            <button onClick={()=>{if(commentText.trim()){onAddComment?.(diary.id,commentText.trim(),replyTo?.id);setCommentText("");setReplyTo(null);}}} style={{width:"44px",height:"44px",borderRadius:"50%",border:"none",background:commentText.trim()?C.accent:C.surface2,color:commentText.trim()?C.onAccent:C.dim,cursor:"pointer",fontSize:"18px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all 0.2s"}}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
          </div></div>:<div style={{padding:"14px",borderRadius:"12px",background:C.errorBg,border:`1px solid ${C.error33}`,fontFamily:F.sans,fontSize:"13px",color:C.error,textAlign:"center",marginBottom:"20px"}}>🚫 Você foi bloqueado de comentar neste diário.</div>}

          {/* Comments list */}
          {(()=>{
            const allC=comments||[];
            const rootComments=allC.filter(c=>!c.parentId);
            const replies=allC.filter(c=>c.parentId);
            const getReplies=(parentId)=>replies.filter(r=>r.parentId===parentId);
            const renderComment=(c,isReply)=>(
            <div key={c.id} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"14px 16px",marginBottom:isReply?"6px":"10px",marginLeft:isReply?"32px":0}}>
              {c.parentId&&(()=>{const parent=allC.find(p=>p.id===c.parentId);return parent?<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginBottom:"6px"}}>↩️ respondendo a <strong>{parent.username}</strong></div>:null;})()}
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:"10px"}}>
                <div style={{display:"flex",gap:"10px",alignItems:"flex-start",flex:1,minWidth:0}}>
                  <div onClick={()=>onAuthorClick?.(c.authorEmail)} style={{width:"32px",height:"32px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"16px",border:`1px solid ${C.border}`,flexShrink:0,overflow:"hidden",cursor:"pointer"}}>{c.avatarImg?<img src={c.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:c.avatar||"🌿"}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",alignItems:"center",gap:"6px",flexWrap:"wrap"}}>
                      <span onClick={()=>onAuthorClick?.(c.authorEmail)} style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",cursor:"pointer"}} onMouseOver={e=>e.currentTarget.style.color=C.accent} onMouseOut={e=>e.currentTarget.style.color=C.text}>{c.username}</span>
                      {c.authorEmail===diary.authorId&&<span style={{fontSize:"9px",padding:"1px 6px",borderRadius:"5px",background:C.accentBg,color:C.accent,fontWeight:"600",fontFamily:F.sans}}>AUTOR</span>}
                      <span style={{fontFamily:F.sans,fontSize:"10px",color:C.dim}}>{(() => { const d=Date.now()-c.time; const m=Math.floor(d/60000); if(m<60)return m+"min"; const h=Math.floor(m/60); if(h<24)return h+"h"; return Math.floor(h/24)+"d"; })()}{c.editedAt?" · editado":""}</span>
                    </div>
                    {editingComment?.id===c.id?(
                      <div style={{marginTop:"6px",display:"flex",gap:"6px"}}>
                        <input style={{...baseInput,borderRadius:"8px",padding:"8px 12px",fontSize:"13px",flex:1}} value={editingComment.text} onChange={e=>setEditingComment(p=>({...p,text:e.target.value}))} onKeyDown={e=>{if(e.key==="Enter"&&editingComment.text.trim()){onEditComment?.(diary.id,c.id,editingComment.text.trim());setEditingComment(null);}if(e.key==="Escape")setEditingComment(null);}} autoFocus/>
                        <button onClick={()=>{if(editingComment.text.trim()){onEditComment?.(diary.id,c.id,editingComment.text.trim());setEditingComment(null);}}} style={{padding:"6px 12px",borderRadius:"8px",border:"none",background:C.accent,color:C.onAccent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600",flexShrink:0}}>✓</button>
                        <button onClick={()=>setEditingComment(null)} style={{padding:"6px 10px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.dim,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,flexShrink:0}}>✕</button>
                      </div>
                    ):<div style={{fontFamily:F.body,fontSize:"14px",color:C.text,lineHeight:"1.5",marginTop:"4px"}}>{c.text}</div>}
                  </div>
                </div>
                {/* Comment actions */}
                {editingComment?.id!==c.id&&<div style={{display:"flex",gap:"3px",flexShrink:0}}>
                  <button onClick={()=>setReplyTo({id:c.id,username:c.username})} title="Responder" style={{width:"26px",height:"26px",borderRadius:"6px",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.color=C.accent} onMouseOut={e=>e.currentTarget.style.color=C.dim}>↩️</button>
                  {c.authorEmail===currentUserEmail&&<button onClick={()=>setEditingComment({id:c.id,text:c.text})} title="Editar" style={{width:"26px",height:"26px",borderRadius:"6px",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.color=C.accent} onMouseOut={e=>e.currentTarget.style.color=C.dim}>✏️</button>}
                  {(c.authorEmail===currentUserEmail||diary.isOwn)&&<button onClick={()=>onDeleteComment?.(diary.id,c.id)} title="Excluir" style={{width:"26px",height:"26px",borderRadius:"6px",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.color=C.error} onMouseOut={e=>e.currentTarget.style.color=C.dim}>🗑️</button>}
                  {diary.isOwn&&c.authorEmail!==currentUserEmail&&<>
                    <button onClick={()=>setReportUserTarget(c)} title="Denunciar" style={{width:"26px",height:"26px",borderRadius:"6px",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.color=C.warnText} onMouseOut={e=>e.currentTarget.style.color=C.dim}>🚩</button>
                    <button onClick={()=>setConfirmBlock(c)} title="Bloquear" style={{width:"26px",height:"26px",borderRadius:"6px",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.color=C.error} onMouseOut={e=>e.currentTarget.style.color=C.dim}>🚫</button>
                  </>}
                </div>}
              </div>
            </div>
            );
            return rootComments.length>0?<>{rootComments.map(c=><React.Fragment key={c.id}>{renderComment(c,false)}{getReplies(c.id).map(r=>renderComment(r,true))}</React.Fragment>)}</>:<div style={{textAlign:"center",padding:"30px",color:C.dim,fontFamily:F.sans,fontSize:"14px"}}>Nenhum comentário ainda. Seja o primeiro!</div>;
          })()}
        </div>
      </div>

      {/* Report User Modal (from comment) */}
      {reportUserTarget&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>{setReportUserTarget(null);setReportUserReason("");}}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px",display:"flex",alignItems:"center",gap:"8px"}}>🚩 Denunciar {reportUserTarget.username}</h3>
          <div style={{display:"flex",gap:"6px",flexWrap:"wrap",marginBottom:"12px"}}>
            {["Comentário ofensivo","Spam","Assédio","Conteúdo impróprio"].map(r=>(
              <button key={r} onClick={()=>setReportUserReason(r)} style={{padding:"5px 10px",borderRadius:"8px",border:reportUserReason===r?`2px solid ${C.accent}`:`1px solid ${C.border}`,background:reportUserReason===r?C.accentBg:C.surface2,color:reportUserReason===r?C.accent:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"500"}}>{r}</button>
            ))}
          </div>
          <textarea style={{...baseInput,minHeight:"60px",resize:"vertical",marginBottom:"16px"}} value={reportUserReason} onChange={e=>setReportUserReason(e.target.value)} placeholder="Detalhes..."/>
          <div style={{display:"flex",gap:"12px"}}>
            <button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>{setReportUserTarget(null);setReportUserReason("");}}>Cancelar</button>
            <button style={{...btnPrimary,background:"#d97706",opacity:!reportUserReason.trim()?0.4:1}} disabled={!reportUserReason.trim()} onClick={()=>{onReportUser?.(reportUserTarget.authorEmail,reportUserReason.trim(),reportUserTarget.username);setReportUserTarget(null);setReportUserReason("");}}>Enviar Denúncia</button>
          </div>
        </div>
      </div>}

      {/* Block User Confirm Modal */}
      {confirmBlock&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setConfirmBlock(null)}>
        <div style={{...cardBase,maxWidth:"380px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>🚫</div>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 8px"}}>Bloquear {confirmBlock.username}?</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Este usuário não poderá mais comentar nos seus diários.</p>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>setConfirmBlock(null)}>Cancelar</button><button style={{...btnPrimary,background:C.error}} onClick={()=>{onBlockUser?.(confirmBlock.authorEmail);setConfirmBlock(null);}}>Bloquear</button></div>
        </div>
      </div>}

      {/* Confirm remove/hide modal */}
      {confirm&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"24px"}} onClick={()=>setConfirm(null)}>
        <div style={{...cardBase,maxWidth:"380px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>{confirm==="remove"?"🗑️":"👁️"}</div>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 8px"}}>{confirm==="remove"?t.removeDiary:t.hideDiary}</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>{confirm==="remove"?t.confirmRemove:t.confirmHide}</p>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>setConfirm(null)}>{t.cancel}</button><button style={{...btnPrimary,background:confirm==="remove"?C.error:C.accent}} onClick={()=>{if(confirm==="remove")onRemove(diary.id);else onHide(diary.id);setConfirm(null);}}>{confirm==="remove"?t.removeDiary:t.hideDiary}</button></div>
        </div>
      </div>}

      {/* Confirm delete week modal */}
      {confirmDeleteWeek!==null&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"24px"}} onClick={()=>setConfirmDeleteWeek(null)}>
        <div style={{...cardBase,maxWidth:"380px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>🗑️</div>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 8px"}}>Excluir {t.week} {diary.weeks[confirmDeleteWeek]?.week}?</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Esta ação não pode ser desfeita.</p>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>setConfirmDeleteWeek(null)}>{t.cancel}</button><button style={{...btnPrimary,background:C.error}} onClick={()=>deleteWeek(confirmDeleteWeek)}>Excluir</button></div>
        </div>
      </div>}

      {/* Edit Diary Modal */}
      {showEdit&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"flex-start",justifyContent:"center",zIndex:300,padding:"40px 24px",overflowY:"auto"}} onClick={()=>setShowEdit(false)}>
        <div style={{...cardBase,maxWidth:"480px",textAlign:"left"}} onClick={e=>e.stopPropagation()}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"24px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"800",margin:0,display:"flex",alignItems:"center",gap:"8px"}}>✏️ {t.editDiary}</h3>
            <button onClick={()=>setShowEdit(false)} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>{t.diaryName}</label><input style={baseInput} value={editName} onChange={e=>setEditName(e.target.value)}/></div>
          <div style={{marginBottom:"16px"}}>
            <label style={labelSt}>{t.strain} <span style={{fontWeight:"400",textTransform:"none",letterSpacing:"0",fontSize:"11px",color:C.dim}}>({editStrains.length}/8)</span></label>
            <div style={{display:"flex",flexDirection:"column",gap:"8px"}}>
              {editStrains.map((s,i)=>(
                <div key={i} style={{display:"flex",gap:"8px",alignItems:"center"}}>
                  <input style={{...baseInput,flex:1}} value={s} onChange={e=>{const n=[...editStrains];n[i]=e.target.value;setEditStrains(n);}} placeholder={i===0?"Ex: Northern Lights Auto":`Genética ${i+1}`}/>
                  {editStrains.length>1&&<button onClick={()=>setEditStrains(p=>p.filter((_,j)=>j!==i))} style={{width:"36px",height:"36px",borderRadius:"10px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.error,cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>✕</button>}
                </div>
              ))}
              {editStrains.length<8&&<button onClick={()=>setEditStrains(p=>[...p,""])} style={{padding:"8px 14px",borderRadius:"10px",border:`1px dashed ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",gap:"6px",alignSelf:"flex-start"}}>🌿 + Adicionar</button>}
            </div>
          </div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>{t.environment}</label>
            <div style={{display:"flex",gap:"8px"}}>{ENVIRONMENTS.map(e=><IconCard key={e.id} icon={e.icon} label={e.label} selected={editEnv===e.id} onClick={()=>setEditEnv(e.id)} small/>)}</div>
          </div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>{t.lighting}</label>
            <div style={{display:"flex",gap:"8px",flexWrap:"wrap"}}>{LIGHTS.map(l=><IconCard key={l.id} icon={l.icon} label={l.label} selected={editLight===l.id} onClick={()=>setEditLight(l.id)} small/>)}</div>
          </div>
          <div style={{marginBottom:"16px",maxWidth:"220px"}}><label style={labelSt}>⚡ Potência (Watts)</label>
            <input style={baseInput} type="number" min="0" max="5000" value={editWatts} onChange={e=>setEditWatts(e.target.value)} placeholder="Ex: 240"/>
          </div>
          <div style={{marginBottom:"24px"}}><label style={labelSt}>{t.substrate}</label>
            <div style={{display:"flex",gap:"8px",flexWrap:"wrap"}}>{SUBSTRATES.map(s=><IconCard key={s.id} icon={s.icon} label={s.label} selected={editSubstrate===s.id} onClick={()=>setEditSubstrate(s.id)} small/>)}</div>
          </div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"12px 24px"}} onClick={()=>setShowEdit(false)}>{t.cancel}</button><button style={btnPrimary} onClick={saveEdit}>{t.save}</button></div>
        </div>
      </div>}

      {showAdd&&<AddWeekModal diary={diary} onClose={()=>setShowAdd(false)} onSave={addWeek} lang={lang}/>}

      {/* Edit Week Modal */}
      {editingWeekIdx!==null&&(()=>{
        const ew=diary.weeks[editingWeekIdx];if(!ew)return null;
        return <EditWeekModal week={ew} weekIdx={editingWeekIdx} onClose={()=>setEditingWeekIdx(null)} onSave={saveWeekEdit} lang={lang} diaryId={diary.id} userId={diary.authorId}/>;
      })()}

      {/* Report Modal */}
      {showReport&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>{setShowReport(false);setReportReason("");}}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px",display:"flex",alignItems:"center",gap:"8px"}}>🚩 Denunciar Diário</h3>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,margin:"0 0 14px"}}>Descreva o motivo da denúncia. Nossa equipe irá analisar.</p>
          <div style={{display:"flex",gap:"6px",flexWrap:"wrap",marginBottom:"12px"}}>
            {["Conteúdo impróprio","Spam","Informações falsas","Assédio/ofensa"].map(r=>(
              <button key={r} onClick={()=>setReportReason(r)} style={{padding:"5px 10px",borderRadius:"8px",border:reportReason===r?`2px solid ${C.accent}`:`1px solid ${C.border}`,background:reportReason===r?C.accentBg:C.surface2,color:reportReason===r?C.accent:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"500"}}>{r}</button>
            ))}
          </div>
          <textarea style={{...baseInput,minHeight:"70px",resize:"vertical",marginBottom:"16px"}} value={reportReason} onChange={e=>setReportReason(e.target.value)} placeholder="Detalhes adicionais..."/>
          <div style={{display:"flex",gap:"12px"}}>
            <button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>{setShowReport(false);setReportReason("");}}>Cancelar</button>
            <button style={{...btnPrimary,background:"#d97706",opacity:!reportReason.trim()?0.4:1}} disabled={!reportReason.trim()} onClick={()=>{onReport?.(diary,reportReason.trim());setShowReport(false);setReportReason("");}}>Enviar Denúncia</button>
          </div>
        </div>
      </div>}
    </div>
  );
}

// ─── Edit Week Modal ───
function EditWeekModal({ week, weekIdx, onClose, onSave, lang, diaryId, userId }) {
  const t=T[lang||"pt"];
  const [phase,setPhase]=useState(week.phase||0);
  const [height,setHeight]=useState(week.height||"");
  const [temp,setTemp]=useState(week.temp||"");
  const [humidity,setHumidity]=useState(week.humidity||"");
  const [ph,setPh]=useState(week.ph||"");
  const [waterMl,setWaterMl]=useState(week.waterMl||"");
  const [lightHours,setLightHours]=useState(week.lightHours||"");
  const [note,setNote]=useState(week.note||"");
  const [existingMedia,setExistingMedia]=useState([]);
  const [newMedia,setNewMedia]=useState([]);
  const [removedMediaIds,setRemovedMediaIds]=useState([]);
  const [uploading,setUploading]=useState(false);
  const fileRef=useRef(null);

  // Load existing media
  useEffect(()=>{
    if(!week.id)return;
    (async()=>{try{
      const rows=await sb.from("week_media").select("*",`&week_id=eq.${week.id}`);
      setExistingMedia(rows.map(m=>({id:m.id,url:m.media_url,type:m.media_type})));
    }catch{}})();
  },[week.id]);

  const handleNewFiles=async(e)=>{
    const files=Array.from(e.target.files||[]);
    setUploading(true);
    for(const f of files){
      const ext=f.name.split(".").pop()||"jpg";
      const path=`${userId||"anon"}/weeks/${diaryId}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      if(ok) setNewMedia(prev=>[...prev,{id:"new"+Date.now()+Math.random(),url:sbStorage.getUrl(path),type:f.type.startsWith("video")?"video":"image",name:f.name}]);
    }
    setUploading(false);e.target.value="";
  };

  const removeExisting=(id)=>{setRemovedMediaIds(p=>[...p,id]);setExistingMedia(p=>p.filter(m=>m.id!==id));};
  const removeNew=(id)=>setNewMedia(p=>p.filter(m=>m.id!==id));

  const doSave=async()=>{
    // Remove deleted media from DB
    for(const mid of removedMediaIds){try{await sb.from("week_media").delete(`id=eq.${mid}`);}catch{}}
    // Insert new media
    if(week.id){for(const m of newMedia){try{await sb.from("week_media").insert({week_id:week.id,media_url:m.url,media_type:m.type});}catch{}}}
    onSave(weekIdx,{phase,height:height||null,temp:temp||null,humidity:humidity||null,ph:ph||null,waterMl:waterMl||null,lightHours:lightHours||null,note:note||""});
  };

  const allMedia=[...existingMedia,...newMedia];

  return (
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"flex-start",justifyContent:"center",zIndex:300,padding:"20px",overflowY:"auto"}} onClick={onClose}>
      <div style={{...cardBase,maxWidth:"560px"}} onClick={e=>e.stopPropagation()}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
          <h3 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"800",margin:0,display:"flex",alignItems:"center",gap:"8px"}}>✏️ Editar {week.phase===0?t.germination:week.phase===3?PHASES[3]:`${t.week} ${week.week}`}</h3>
          <button onClick={onClose} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
        </div>

        <div style={{marginBottom:"16px"}}><label style={labelSt}>{t.plantPhase}</label>
          <div style={{display:"flex",gap:"8px",flexWrap:"wrap"}}>{PHASES.map((p,i)=>(
            <div key={p} onClick={()=>setPhase(i)} style={{padding:"8px 16px",borderRadius:"10px",cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"600",border:phase===i?`2px solid ${PHASE_COLORS[i]}`:`1px solid ${C.borderLight}`,background:phase===i?PHASE_COLORS[i]+"18":C.surface2,color:phase===i?PHASE_COLORS[i]:C.muted}}>{PHASE_ICONS[i]} {p}</div>
          ))}</div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(140px, 1fr))",gap:"12px",marginBottom:"16px"}}>
          {[[t.height+" (cm)",height,setHeight,"📏"],[t.temp+" (°C)",temp,setTemp,"🌡️"],[t.humidity+" (%)",humidity,setHumidity,"💧"],["pH",ph,setPh,"⚗️"],[t.watering+" (ml)",waterMl,setWaterMl,"🚿"],[t.light+" (h)",lightHours,setLightHours,"💡"]].map(([l,v,s,icon])=>(
            <div key={l}><label style={{...labelSt,display:"flex",alignItems:"center",gap:"6px"}}><span>{icon}</span>{l}</label><input style={baseInput} type="number" step={l==="pH"?"0.1":"1"} value={v} onChange={e=>s(e.target.value)}/></div>
          ))}
        </div>

        {/* Existing + New Media */}
        <div style={{marginBottom:"16px"}}>
          <label style={labelSt}>📷 Fotos e Vídeos ({allMedia.length})</label>
          <UploadProgressBar active={uploading} text="Enviando mídia..."/>
          {allMedia.length>0&&<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(70px,1fr))",gap:"6px",marginBottom:"10px"}}>
            {allMedia.map(m=>(
              <div key={m.id} style={{position:"relative",borderRadius:"8px",overflow:"hidden",aspectRatio:"1",background:C.surface2,border:`1px solid ${C.border}`}}>
                {m.type==="video"?<div style={{width:"100%",height:"100%",display:"flex",alignItems:"center",justifyContent:"center"}}><span style={{fontSize:"20px"}}>🎬</span></div>:<img src={m.url} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>}
                <button onClick={()=>m.id.toString().startsWith("new")?removeNew(m.id):removeExisting(m.id)} style={{position:"absolute",top:"2px",right:"2px",width:"18px",height:"18px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.5)",color:"#fff",cursor:"pointer",fontSize:"10px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
              </div>
            ))}
          </div>}
          <button onClick={()=>fileRef.current?.click()} style={{padding:"8px 14px",borderRadius:"8px",border:`1px dashed ${C.accent}44`,background:C.surface2,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>+ Adicionar mídia</button>
          <input ref={fileRef} type="file" accept="image/*,video/*" multiple style={{display:"none"}} onChange={handleNewFiles}/>
        </div>

        <div style={{marginBottom:"20px"}}><label style={labelSt}>{t.weekComment}</label>
          <textarea style={{...baseInput,minHeight:"70px",resize:"vertical"}} value={note} onChange={e=>setNote(e.target.value)} placeholder={t.howIsPlant}/>
        </div>

        <div style={{display:"flex",gap:"12px"}}>
          <button style={{...btnSecondary,width:"auto",padding:"12px 24px"}} onClick={onClose}>{t.cancel}</button>
          <button style={btnPrimary} onClick={doSave}>{t.save}</button>
        </div>
      </div>
    </div>
  );
}

// ─── Messages Page ───
function MessagesPage({ msgs, user, onSend, onSendMedia, onMarkRead, onMarkUnread, onDeleteConv, onForwardMsg, onCreateGroup, onNewDM, onBack, lang }) {
  const t=T[lang||"pt"];
  const [activeConv,setActiveConv]=useState(null);
  const [newMsg,setNewMsg]=useState("");
  const [convMenu,setConvMenu]=useState(null);
  const [showNewGroup,setShowNewGroup]=useState(false);
  const [showNewDM,setShowNewDM]=useState(false);
  const [dmUsername,setDmUsername]=useState("");
  const [dmFirstMsg,setDmFirstMsg]=useState("");
  const [groupName,setGroupName]=useState("");
  const [groupMembers,setGroupMembers]=useState("");
  const [forwardingMsg,setForwardingMsg]=useState(null);
  const [forwardTarget,setForwardTarget]=useState(null);
  const endRef=useRef(null);
  const menuRef=useRef(null);
  const mediaInputRef=useRef(null);
  useEffect(()=>{endRef.current?.scrollIntoView({behavior:"smooth"});},[activeConv,msgs]);
  useEffect(()=>{const h=e=>{if(menuRef.current&&!menuRef.current.contains(e.target))setConvMenu(null);};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);

  const openConv=(id)=>{setActiveConv(id);onMarkRead?.(id);};
  const conv=activeConv?msgs.find(c=>c.id===activeConv):null;

  const timeStr=(ts)=>{const d=new Date(ts);return d.getHours().toString().padStart(2,"0")+":"+d.getMinutes().toString().padStart(2,"0");};
  const dateStr=(ts)=>{const d=new Date(ts);return d.toLocaleDateString(lang==="en"?"en":"pt-BR",{day:"numeric",month:"short"});};

  const handleSend=()=>{if(!newMsg.trim()||!activeConv)return;onSend(activeConv,newMsg.trim());setNewMsg("");};

  const handleMediaUpload=async(e)=>{
    const files=e.target.files;if(!files||!activeConv)return;
    for(const f of Array.from(files)){
      const isVideo=f.type.startsWith("video");
      const ext=f.name.split(".").pop()||"jpg";
      const path=`messages/${activeConv}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      if(ok){
        const url=sbStorage.getUrl(path);
        onSendMedia?.(activeConv,{type:isVideo?"video":"image",data:url,name:f.name});
      }
    }
    e.target.value="";
  };

  const doForward=(targetId)=>{
    if(forwardingMsg&&targetId){onForwardMsg?.(targetId,forwardingMsg.text);setForwardingMsg(null);setForwardTarget(null);}
  };

  const handleCreateGroup=()=>{
    if(!groupName.trim())return;
    const members=groupMembers.split(",").map(m=>m.trim()).filter(Boolean);
    if(members.length===0)return;
    onCreateGroup?.(groupName.trim(),members);
    setGroupName("");setGroupMembers("");setShowNewGroup(false);
  };

  const handleNewDM=()=>{
    if(!dmUsername.trim()||!dmFirstMsg.trim())return;
    onNewDM?.(dmUsername.trim(),dmFirstMsg.trim());
    setDmUsername("");setDmFirstMsg("");setShowNewDM(false);
  };

  // Forward target picker
  if(forwardingMsg) return (
    <div style={{maxWidth:"700px",margin:"0 auto",padding:"24px"}}>
      <div style={{display:"flex",alignItems:"center",gap:"12px",marginBottom:"16px"}}>
        <button onClick={()=>setForwardingMsg(null)} style={{padding:"6px 12px",borderRadius:"16px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>← Voltar</button>
        <h2 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:0}}>Encaminhar para...</h2>
      </div>
      <div style={{padding:"12px 16px",background:C.surface2,borderRadius:"10px",marginBottom:"20px",fontFamily:F.sans,fontSize:"13px",color:C.muted,borderLeft:`3px solid ${C.accent}`}}>"{forwardingMsg.text}"</div>
      {msgs.filter(c=>c.id!==forwardingMsg.fromConv).map(c=>(
        <button key={c.id} onClick={()=>doForward(c.id)} style={{width:"100%",padding:"14px 16px",borderRadius:"12px",border:`1px solid ${C.border}`,background:C.cardBg,marginBottom:"8px",cursor:"pointer",display:"flex",alignItems:"center",gap:"12px",textAlign:"left"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background=C.cardBg}>
          <div style={{width:"40px",height:"40px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",border:`1px solid ${C.border}`,flexShrink:0}}>{c.avatar}</div>
          <span style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"600",color:C.text}}>{c.isGroup?"👥 ":""}{c.with}</span>
        </button>
      ))}
    </div>
  );

  // Chat view
  if(conv) return (
    <div style={{maxWidth:"700px",margin:"0 auto",display:"flex",flexDirection:"column",height:"calc(100vh - 140px)"}}>
      <div style={{padding:"14px 20px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:"12px"}}>
        <button onClick={()=>setActiveConv(null)} style={{padding:"6px 12px",borderRadius:"16px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>←</button>
        <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:conv.isGroup?"16px":"20px",border:`1px solid ${C.border}`}}>{conv.isGroup?"👥":conv.avatar}</div>
        <div style={{flex:1}}>
          <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>{conv.with}</div>
          {conv.isGroup&&conv.members&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{conv.members.join(", ")}</div>}
        </div>
      </div>

      <div style={{flex:1,overflowY:"auto",padding:"16px 20px",display:"flex",flexDirection:"column",gap:"8px"}}>
        {conv.messages.map((m,i)=>{
          const isMe=m.from===user.email;
          const showDate=i===0||dateStr(m.time)!==dateStr(conv.messages[i-1].time);
          return (<div key={m.id}>
            {showDate&&<div style={{textAlign:"center",margin:"12px 0 8px",fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{dateStr(m.time)}</div>}
            {conv.isGroup&&!isMe&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.accent,marginBottom:"2px",marginLeft:"4px"}}>{m.from}</div>}
            <div style={{display:"flex",justifyContent:isMe?"flex-end":"flex-start",alignItems:"flex-end",gap:"6px"}}>
              <div style={{maxWidth:"75%",padding:m.media?"6px":"10px 14px",borderRadius:isMe?"16px 16px 4px 16px":"16px 16px 16px 4px",background:isMe?C.accent:C.msgBubble,color:isMe?C.onAccent:C.text,fontFamily:F.sans,fontSize:"14px",lineHeight:"1.5",position:"relative",overflow:"hidden"}}>
                {m.forwarded&&<div style={{fontSize:"11px",color:isMe?"rgba(255,255,255,0.5)":C.dim,marginBottom:"4px",fontStyle:"italic",padding:m.media?"4px 8px 0":"0"}}>↪ Encaminhada</div>}
                {m.media&&m.media.type==="image"&&<img src={m.media.data} alt="" style={{maxWidth:"100%",borderRadius:m.text?"10px 10px 0 0":"10px",display:"block",maxHeight:"240px",objectFit:"cover",loading:"lazy"}}/>}
                {m.media&&m.media.type==="video"&&<video src={m.media.data} controls style={{maxWidth:"100%",borderRadius:m.text?"10px 10px 0 0":"10px",display:"block",maxHeight:"240px"}}/>}
                {m.text&&<div style={{padding:m.media?"8px 8px 0":"0"}}>{m.text}</div>}
                <div style={{fontSize:"10px",color:isMe?"rgba(255,255,255,0.55)":C.dim,marginTop:"4px",textAlign:"right",padding:m.media?"0 8px 6px":"0"}}>{timeStr(m.time)}</div>
              </div>
              <button onClick={()=>setForwardingMsg({text:m.text||"[mídia]",fromConv:conv.id})} title="Encaminhar" style={{width:"24px",height:"24px",borderRadius:"50%",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",flexShrink:0,opacity:0.5,display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.opacity="1"} onMouseOut={e=>e.currentTarget.style.opacity="0.5"}>↪</button>
            </div>
          </div>);
        })}
        <div ref={endRef}/>
      </div>

      <div style={{padding:"12px 20px",borderTop:`1px solid ${C.border}`,display:"flex",gap:"8px",background:C.cardBg,alignItems:"center"}}>
        <button onClick={()=>mediaInputRef.current?.click()} title="Enviar foto/vídeo" style={{width:"40px",height:"40px",borderRadius:"50%",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>📷</button>
        <input ref={mediaInputRef} type="file" accept="image/*,video/*" multiple style={{display:"none"}} onChange={handleMediaUpload}/>
        <input style={{...baseInput,borderRadius:"24px",padding:"12px 18px",flex:1}} value={newMsg} onChange={e=>setNewMsg(e.target.value)} placeholder="Escreva uma mensagem..." onKeyDown={e=>e.key==="Enter"&&handleSend()}/>
        <button onClick={handleSend} style={{width:"44px",height:"44px",borderRadius:"50%",border:"none",background:newMsg.trim()?C.accent:C.surface2,color:newMsg.trim()?C.onAccent:C.dim,cursor:"pointer",fontSize:"18px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all 0.2s"}}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
        </button>
      </div>
    </div>
  );

  // Conversation list
  const convMenuItem=(icon,label,onClick,color)=>(
    <button onClick={e=>{e.stopPropagation();onClick();setConvMenu(null);}} style={{width:"100%",padding:"10px 14px",borderRadius:"8px",border:"none",background:"transparent",color:color||C.text,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,textAlign:"left",display:"flex",alignItems:"center",gap:"10px"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
      <span>{icon}</span>{label}
    </button>
  );

  return (
    <div style={{maxWidth:"700px",margin:"0 auto",padding:"24px"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:"24px",flexWrap:"wrap",gap:"8px"}}>
        <div style={{display:"flex",alignItems:"center",gap:"12px"}}>
          <button onClick={onBack} style={{padding:"6px 14px",borderRadius:"16px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>← {t.back}</button>
          <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800",margin:0}}>✉️ Mensagens</h2>
        </div>
        <div style={{display:"flex",gap:"6px"}}>
          <button onClick={()=>setShowNewDM(true)} style={{padding:"8px 14px",borderRadius:"20px",border:`1px solid ${C.accent}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",gap:"4px"}}>✉️ Nova Mensagem</button>
          <button onClick={()=>setShowNewGroup(true)} style={{padding:"8px 14px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",gap:"4px"}}>👥 Grupo</button>
        </div>
      </div>

      {msgs.length>0?msgs.map(c=>{
        const lastMsg=c.messages[c.messages.length-1];
        const isUnread=lastMsg&&lastMsg.from!==user.email&&(!c.readAt||lastMsg.time>c.readAt);
        return (
          <div key={c.id} style={{position:"relative",marginBottom:"10px"}}>
            <div onClick={()=>openConv(c.id)} style={{padding:"14px 16px",borderRadius:"12px",border:`1px solid ${C.border}`,background:C.cardBg,cursor:"pointer",display:"flex",alignItems:"center",gap:"14px",transition:"all 0.15s",boxShadow:"0 1px 3px rgba(0,0,0,0.04)"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background=C.cardBg}>
              <div style={{width:"44px",height:"44px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:c.isGroup?"18px":"22px",border:`1px solid ${C.border}`,flexShrink:0}}>{c.isGroup?"👥":c.avatar}</div>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",color:C.text}}>{c.with}</span>
                  {lastMsg&&<span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{dateStr(lastMsg.time)}</span>}
                </div>
                {lastMsg&&<div style={{fontFamily:F.sans,fontSize:"13px",color:isUnread?C.text:C.muted,fontWeight:isUnread?"600":"400",marginTop:"2px",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{lastMsg.from===user.email?"Você: ":""}{lastMsg.text}</div>}
              </div>
              <div style={{display:"flex",alignItems:"center",gap:"6px",flexShrink:0}}>
                {isUnread&&<div style={{width:"10px",height:"10px",borderRadius:"50%",background:C.accent}}/>}
                <button onClick={e=>{e.stopPropagation();setConvMenu(convMenu===c.id?null:c.id);}} style={{width:"28px",height:"28px",borderRadius:"50%",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>⋯</button>
              </div>
            </div>
            {/* Context menu */}
            {convMenu===c.id&&<div ref={menuRef} style={{position:"absolute",top:"50px",right:"8px",background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"4px",minWidth:"200px",boxShadow:"0 8px 24px rgba(0,0,0,0.12)",zIndex:20}}>
              {isUnread?convMenuItem("✅","Marcar como lida",()=>onMarkRead?.(c.id)):convMenuItem("🔵","Marcar como não lida",()=>onMarkUnread?.(c.id))}
              {convMenuItem("🗑️","Excluir conversa",()=>onDeleteConv?.(c.id),C.error)}
            </div>}
          </div>
        );
      }):<div style={{textAlign:"center",padding:"60px 24px",color:C.dim}}>
        <div style={{fontSize:"48px",marginBottom:"16px"}}>✉️</div>
        <p style={{fontFamily:F.sans,fontSize:"16px"}}>Nenhuma conversa ainda</p>
      </div>}

      {/* New Group Modal */}
      {showNewGroup&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setShowNewGroup(false)}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"800",margin:0}}>👥 Novo Grupo</h3>
            <button onClick={()=>setShowNewGroup(false)} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Nome do Grupo</label><input style={baseInput} value={groupName} onChange={e=>setGroupName(e.target.value)} placeholder="Ex: Growers do SP"/></div>
          <div style={{marginBottom:"20px"}}><label style={labelSt}>Membros (separados por vírgula)</label><input style={baseInput} value={groupMembers} onChange={e=>setGroupMembers(e.target.value)} placeholder="Ex: VerdeBR, GrowSP, AquaGrow"/></div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>setShowNewGroup(false)}>Cancelar</button><button style={{...btnPrimary,opacity:(!groupName.trim()||!groupMembers.trim())?0.4:1}} onClick={handleCreateGroup}>Criar Grupo</button></div>
        </div>
      </div>}

      {/* New DM Modal */}
      {showNewDM&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setShowNewDM(false)}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"800",margin:0}}>✉️ Nova Mensagem</h3>
            <button onClick={()=>setShowNewDM(false)} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Nome do Destinatário</label><input style={baseInput} value={dmUsername} onChange={e=>setDmUsername(e.target.value)} placeholder="Ex: VerdeBR"/></div>
          <div style={{marginBottom:"20px"}}><label style={labelSt}>Mensagem</label><textarea style={{...baseInput,minHeight:"70px",resize:"vertical"}} value={dmFirstMsg} onChange={e=>setDmFirstMsg(e.target.value)} placeholder="Escreva sua primeira mensagem..."/></div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>setShowNewDM(false)}>Cancelar</button><button style={{...btnPrimary,opacity:(!dmUsername.trim()||!dmFirstMsg.trim())?0.4:1}} onClick={handleNewDM}>Enviar</button></div>
        </div>
      </div>}
    </div>
  );
}

// ─── Admin Panel ───
function AdminPanel({ user, onBack, onNewPost }) {
  const [tab,setTab]=useState("dashboard");
  const [allUsers,setAllUsers]=useState({});
  const [allDiariesMap,setAllDiariesMap]=useState({});
  const [loading,setLoading]=useState(true);
  const [editUser,setEditUser]=useState(null);
  const [editForm,setEditForm]=useState({});
  const [confirm,setConfirm]=useState(null);
  const [warnTarget,setWarnTarget]=useState(null);
  const [warnMsg,setWarnMsg]=useState("");
  const [warnSearch,setWarnSearch]=useState("");
  const [newUserForm,setNewUserForm]=useState(null);
  const [toast,setToast]=useState("");
  const [searchUsers,setSearchUsers]=useState("");
  const [searchDiaries,setSearchDiaries]=useState("");
  const [reports,setReports]=useState([]);
  const [auditLog,setAuditLog]=useState([]);
  const [announceMsg,setAnnounceMsg]=useState("");
  const [allComments,setAllComments]=useState([]);
  const [searchComments,setSearchComments]=useState("");
  const [blogPosts,setBlogPosts]=useState([]);

  const showToast=(msg)=>{setToast(msg);setTimeout(()=>setToast(""),2500);};

  const addAudit=async(action,target,detail)=>{
    const entry={id:crypto.randomUUID?.()?.slice(0,8)||("a"+Date.now()),time:Date.now(),admin:user.username,adminEmail:user.email,action,target,detail};
    const next=[entry,...auditLog].slice(0,200);
    setAuditLog(next);
    try{await sb.from("audit_log").insert({admin_id:user.id,action,target,detail});}catch{}
  };

  useEffect(()=>{(async()=>{
    try{
      // Load all data in parallel (was sequential - 6x faster now)
      const [profiles,diaries,reps,al,ac,bp]=await Promise.all([
        sb.from("profiles").select("*","&order=created_at.desc"),
        sb.from("diaries").select("*,profiles(username,avatar)","&order=created_at.desc"),
        sb.from("reports").select("*,reporter:reporter_id(username),target_user:target_user_id(username,email),target_diary:target_diary_id(name)","&order=created_at.desc"),
        sb.from("audit_log").select("*,admin:admin_id(username,email)","&order=created_at.desc&limit=200"),
        sb.from("comments").select("id,text,created_at,user_id,diary_id,profiles(username,avatar,avatar_url),diaries(name)","&order=created_at.desc&limit=500"),
        sb.from("blog_posts").select("*,profiles(username)","&order=created_at.desc"),
      ]);

      const uMap={};(profiles||[]).forEach(p=>{uMap[p.id]={...p,email:p.email,username:p.username,avatar:p.avatar,avatarImg:p.avatar_url,bio:p.bio,city:p.city,role:p.role,banned:p.banned,createdAt:new Date(p.created_at).getTime()};});
      setAllUsers(uMap);

      const dm={};
      (diaries||[]).forEach(d=>{
        const uid=d.user_id;
        if(!dm[uid])dm[uid]=[];
        dm[uid].push({id:d.id,name:d.name,strain:d.strain,author:d.profiles?.username||"",avatar:d.profiles?.avatar||"🌱",phase:d.phase,week:d.current_week,env:d.environment,light:d.lighting,hidden:d.hidden,likes:d.likes_count,comments:d.comments_count,techniques:d.techniques||[],tags:d.tags||[],weeks:[]});
      });
      setAllDiariesMap(dm);

      setReports((reps||[]).map(r=>({id:r.id,status:r.status,reporterName:r.reporter?.username,reporterEmail:r.reporter_id,targetName:r.target_user?.username||"",targetEmail:r.target_user?.email||"",targetType:r.target_type,targetDiaryName:r.target_diary?.name||"",targetDiaryId:r.target_diary_id,reason:r.reason,resolvedBy:r.resolved_by,resolvedAt:r.resolved_at?new Date(r.resolved_at).getTime():null,time:new Date(r.created_at).getTime()})));
      setAuditLog((al||[]).map(a=>({id:a.id,time:new Date(a.created_at).getTime(),admin:a.admin?.username,adminEmail:a.admin?.email,action:a.action,target:a.target,detail:a.detail})));
      setAllComments((ac||[]).map(c=>({id:c.id,text:c.text,username:c.profiles?.username,avatar:c.profiles?.avatar,avatarImg:c.profiles?.avatar_url,authorEmail:c.user_id,diaryId:c.diary_id,diaryName:c.diaries?.name,time:new Date(c.created_at).getTime()})));
      setBlogPosts((bp||[]).map(p=>({...p,authorName:p.profiles?.username})));
    }catch(e){console.error("Admin load error:",e);}setLoading(false);
  })();},[]);

  const doDeleteUser=async(userId)=>{
    const u=allUsers[userId];if(!u)return;
    try{
      // Delete via Supabase auth admin or just ban — for now we delete profile (cascade handles rest)
      await sb.from("profiles").delete(`id=eq.${userId}`);
      const next={...allUsers};delete next[userId];setAllUsers(next);
      setAllDiariesMap(p=>{const n={...p};delete n[userId];return n;});
      await addAudit("Excluiu usuário",u.email,u.username);
    }catch{}
    showToast("Usuário excluído.");setConfirm(null);
  };
  const doBanUser=async(userId)=>{
    const u=allUsers[userId];if(!u)return;
    const newBanned=!u.banned;
    try{await sb.from("profiles").update({banned:newBanned},`id=eq.${userId}`);}catch{}
    setAllUsers(p=>({...p,[userId]:{...p[userId],banned:newBanned}}));
    await addAudit(newBanned?"Baniu":"Desbaniu",u.email,u.username);
    showToast(newBanned?"Usuário banido.":"Ban removido.");setConfirm(null);
  };
  const doSaveEdit=async()=>{
    if(!editUser)return;
    try{await sb.from("profiles").update({username:editForm.username,bio:editForm.bio||"",city:editForm.city||""},`id=eq.${editUser}`);}catch{}
    setAllUsers(p=>({...p,[editUser]:{...p[editUser],...editForm}}));
    await addAudit("Editou usuário",allUsers[editUser]?.email,editForm.username);
    setEditUser(null);showToast("Usuário atualizado.");
  };
  const doSetRole=async(userId,role)=>{
    try{await sb.from("profiles").update({role},`id=eq.${userId}`);}catch{}
    setAllUsers(p=>({...p,[userId]:{...p[userId],role}}));
    await addAudit("Alterou papel → "+role,allUsers[userId]?.email,allUsers[userId]?.username);
    showToast(`Papel alterado para ${role}.`);
  };
  const doCreateUser=async()=>{
    if(!newUserForm?.email||!newUserForm?.username||!newUserForm?.password)return;
    try{
      // Sign up via Supabase Auth (admin creating user)
      const data=await sbAuth.signUp(newUserForm.email.trim().toLowerCase(),newUserForm.password,{username:newUserForm.username.trim()});
      if(data.user?.id){
        await sb.from("profiles").update({role:newUserForm.role||"user",username:newUserForm.username.trim()},`id=eq.${data.user.id}`);
        setAllUsers(p=>({...p,[data.user.id]:{id:data.user.id,email:newUserForm.email.trim().toLowerCase(),username:newUserForm.username.trim(),avatar:"🌱",bio:"",city:"",role:newUserForm.role||"user",banned:false,createdAt:Date.now()}}));
        await addAudit("Criou usuário",newUserForm.email,newUserForm.username);
      }
    }catch(e){showToast(e.message||"Erro ao criar.");return;}
    setNewUserForm(null);showToast("Usuário criado.");
  };
  const doDeleteDiary=async(userId,diaryId)=>{
    const diary=(allDiariesMap[userId]||[]).find(x=>x.id===diaryId);
    try{await sb.from("diaries").delete(`id=eq.${diaryId}`);}catch{}
    setAllDiariesMap(p=>({...p,[userId]:(p[userId]||[]).filter(x=>x.id!==diaryId)}));
    await addAudit("Excluiu diário",allUsers[userId]?.email,diary?.name||diaryId);
    showToast("Diário excluído.");setConfirm(null);
  };
  const doHideDiary=async(userId,diaryId)=>{
    const d=(allDiariesMap[userId]||[]).find(x=>x.id===diaryId);
    const newHidden=!d?.hidden;
    try{await sb.from("diaries").update({hidden:newHidden},`id=eq.${diaryId}`);}catch{}
    setAllDiariesMap(p=>({...p,[userId]:(p[userId]||[]).map(x=>x.id===diaryId?{...x,hidden:newHidden}:x)}));
    await addAudit(newHidden?"Ocultou diário":"Mostrou diário",allUsers[userId]?.email,d?.name||diaryId);
    showToast("Visibilidade alterada.");
  };
  const doSendWarning=async()=>{
    if(!warnTarget||!warnMsg.trim())return;const cleanWarn=sanitize(warnMsg.trim(),500);
    try{await sb.from("notifications").insert({user_id:warnTarget,type:"warning",from_username:"Administração",from_avatar:"🛡️",text:cleanWarn});}catch{}
    await addAudit("Enviou aviso",allUsers[warnTarget]?.email||warnTarget,cleanWarn.substring(0,60));
    setWarnTarget(null);setWarnMsg("");showToast("Aviso enviado ao usuário.");
  };
  const doSendAnnouncement=async()=>{
    if(!announceMsg.trim())return;const cleanAnn=sanitize(announceMsg.trim(),500);
    const userIds=Object.keys(allUsers);let count=0;
    const inserts=userIds.map(uid=>({user_id:uid,type:"announcement",from_username:"Administração",from_avatar:"📢",text:cleanAnn}));
    try{await sb.from("notifications").insert(inserts);count=inserts.length;}catch{}
    await addAudit("Enviou anúncio global","todos ("+count+")",cleanAnn.substring(0,60));
    setAnnounceMsg("");showToast(`Anúncio enviado para ${count} usuários.`);
  };
  const doResolveReport=async(id,status)=>{
    try{await sb.from("reports").update({status,resolved_by:user.id,resolved_at:new Date().toISOString()},`id=eq.${id}`);}catch{}
    setReports(p=>p.map(r=>r.id===id?{...r,status,resolvedBy:user.username,resolvedAt:Date.now()}:r));
    const rep=reports.find(r=>r.id===id);
    await addAudit("Resolveu denúncia → "+status,rep?.targetEmail||"",rep?.reason?.substring(0,40)||"");
    showToast("Denúncia atualizada.");
  };
  const doDeleteReport=async(id)=>{
    try{await sb.from("reports").delete(`id=eq.${id}`);}catch{}
    setReports(p=>p.filter(r=>r.id!==id));showToast("Denúncia removida.");
  };

  const allDiariesFlat=Object.entries(allDiariesMap).flatMap(([userId,diaries])=>(diaries||[]).map(d=>({...d,ownerUserId:userId,ownerEmail:allUsers[userId]?.email||""})));
  const userList=Object.values(allUsers).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  const filteredUsers=searchUsers?userList.filter(u=>(u.username+" "+u.email).toLowerCase().includes(searchUsers.toLowerCase())):userList;
  const filteredDiaries=searchDiaries?allDiariesFlat.filter(d=>(d.name+" "+d.strain+" "+d.author+" "+d.ownerEmail).toLowerCase().includes(searchDiaries.toLowerCase())):allDiariesFlat;
  const pendingReports=reports.filter(r=>r.status==="pending").length;

  const timeAgo=(ts)=>{if(!ts)return"";const d=Date.now()-ts;const m=Math.floor(d/60000);if(m<60)return m+"min";const h=Math.floor(m/60);if(h<24)return h+"h";return Math.floor(h/24)+"d";};

  const tabBtn=(id,icon,label,badge)=>(
    <button onClick={()=>setTab(id)} style={{width:"100%",padding:"10px 14px",borderRadius:"10px",border:"none",background:tab===id?C.accentBg:"transparent",color:tab===id?C.accent:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:tab===id?"700":"500",display:"flex",alignItems:"center",gap:"10px",textAlign:"left",position:"relative",transition:"all 0.15s"}} onMouseOver={e=>{if(tab!==id)e.currentTarget.style.background=C.surface2}} onMouseOut={e=>{if(tab!==id)e.currentTarget.style.background="transparent"}}>{icon} {label}{badge>0&&<span style={{marginLeft:"auto",minWidth:"20px",height:"20px",borderRadius:"10px",background:C.error,color:C.onAccent,fontSize:"10px",fontWeight:"700",display:"flex",alignItems:"center",justifyContent:"center",padding:"0 5px"}}>{badge}</span>}</button>
  );

  const searchInput=(val,set,placeholder)=>(
    <div style={{position:"relative",marginBottom:"16px"}}><input style={{...baseInput,paddingLeft:"36px"}} value={val} onChange={e=>set(e.target.value)} placeholder={placeholder}/><span style={{position:"absolute",left:"12px",top:"50%",transform:"translateY(-50%)",fontSize:"14px",color:C.dim}}>🔍</span></div>
  );

  if(loading) return <div style={{textAlign:"center",padding:"80px",color:C.dim,fontFamily:F.sans}}>Carregando...</div>;

  return (
    <div style={{maxWidth:"1100px",margin:"0 auto",padding:"24px"}}>
      <div style={{display:"flex",alignItems:"center",gap:"12px",marginBottom:"20px"}}>
        <button onClick={onBack} style={{padding:"6px 14px",borderRadius:"16px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>← Voltar</button>
        <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800",margin:0,display:"flex",alignItems:"center",gap:"8px"}}>🛡️ Painel Admin</h2>
      </div>

      <div style={{display:"flex",gap:"20px"}}>
        {/* Sidebar */}
        <div style={{width:"200px",flexShrink:0}}>
          <div style={{background:C.cardBg,borderRadius:"14px",border:`1px solid ${C.border}`,padding:"8px",position:"sticky",top:"80px"}}>
            {tabBtn("dashboard","📊","Dashboard")}
            {tabBtn("users","👥","Usuários")}
            {tabBtn("diaries","📓","Diários")}
            {tabBtn("comments","💬","Comentários")}
            {tabBtn("blog","📰","Blog",blogPosts.filter(p=>p.status==="draft").length)}
            {tabBtn("reports","🚨","Denúncias",pendingReports)}
            {tabBtn("announce","📢","Anúncios")}
            {tabBtn("warnings","⚠️","Avisos")}
            {tabBtn("log","📋","Auditoria")}
          </div>
        </div>

        {/* Main content */}
        <div style={{flex:1,minWidth:0}}>

      {/* DASHBOARD TAB */}
      {tab==="dashboard"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"16px"}}>📊 Visão Geral</div>
        {(()=>{
          const totalUsers=userList.length;
          const totalDiaries=Object.values(allDiariesMap).flat().length;
          const totalComments=allComments.length;
          const totalBlogPosts=blogPosts.filter(p=>p.status==="published").length;
          const blogDrafts=blogPosts.filter(p=>p.status==="draft").length;
          const pendingReps=reports.filter(r=>r.status==="pending").length;
          const today=Date.now()-86400000;
          const newUsersToday=userList.filter(u=>u.createdAt>today).length;
          const commentsWeek=allComments.filter(c=>c.time>Date.now()-604800000).length;
          const stat=(icon,label,value,color)=><div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px 20px",textAlign:"center"}}><div style={{fontSize:"28px",marginBottom:"4px"}}>{icon}</div><div style={{fontFamily:F.sans,fontSize:"24px",fontWeight:"800",color:color||C.text}}>{value}</div><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"2px"}}>{label}</div></div>;
          return(<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(140px,1fr))",gap:"12px"}}>
            {stat("👥","Total Usuários",totalUsers,"#3182ce")}
            {stat("🆕","Novos Hoje",newUsersToday,"#38a169")}
            {stat("📓","Diários Ativos",totalDiaries,"#805ad5")}
            {stat("💬","Comentários",totalComments,"#d69e2e")}
            {stat("📝","Comentários (7d)",commentsWeek,"#dd6b20")}
            {stat("📰","Posts Blog",totalBlogPosts,"#e53e3e")}
            {stat("📋","Rascunhos",blogDrafts,"#718096")}
            {stat("🚨","Denúncias",pendingReps,"#e53e3e")}
          </div>);
        })()}
      </div>}

      {/* USERS TAB */}
      {tab==="users"&&<div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"12px",gap:"10px",flexWrap:"wrap"}}>
          <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>{filteredUsers.length} usuários</div>
          <button onClick={()=>setNewUserForm({email:"",username:"",password:"",role:"user"})} style={{padding:"8px 14px",borderRadius:"10px",border:`1px solid ${C.accent}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>+ Criar</button>
        </div>
        {searchInput(searchUsers,setSearchUsers,"Buscar por nome ou email...")}
        {filteredUsers.map(u=>(
          <div key={u.email} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${u.banned?C.error+"44":C.border}`,padding:"12px 14px",marginBottom:"8px",display:"flex",alignItems:"center",gap:"10px",flexWrap:"wrap",opacity:u.banned?0.6:1}}>
            <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"18px",border:`1px solid ${C.border}`,overflow:"hidden",flexShrink:0}}>{u.avatarImg?<img src={u.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:u.avatar}</div>
            <div style={{flex:1,minWidth:"100px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",display:"flex",alignItems:"center",gap:"4px",flexWrap:"wrap"}}>{u.username} {u.role==="admin"&&<span style={{fontSize:"9px",padding:"1px 5px",borderRadius:"5px",background:C.warnBg,color:C.warnText,fontWeight:"600"}}>ADMIN</span>} {u.banned&&<span style={{fontSize:"9px",padding:"1px 5px",borderRadius:"5px",background:C.errorBg,color:C.error,fontWeight:"600"}}>BANIDO</span>}</div>
              <div style={{fontFamily:F.sans,fontSize:"10px",color:C.dim}}>{u.email}</div>
            </div>
            <div style={{display:"flex",gap:"3px",flexWrap:"wrap"}}>
              <button onClick={()=>{setEditUser(u.id);setEditForm({username:u.username,bio:u.bio||"",city:u.city||""});}} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>✏️</button>
              <button onClick={()=>setConfirm({action:"ban",target:u.id,label:u.banned?"Desbanir":"Banir",name:u.username})} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${u.banned?"#fcd34d":C.error+"44"}`,background:u.banned?"#fffbeb":C.errorBg,color:u.banned?"#d97706":C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>{u.banned?"🔓":"🚫"}</button>
              <button onClick={()=>setWarnTarget(u.id)} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.warnBorder}`,background:C.warnBg,color:C.warnText,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>⚠️</button>
              {u.role!=="admin"?<button onClick={()=>doSetRole(u.id,"admin")} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>👑</button>:<button onClick={()=>doSetRole(u.id,"user")} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>👤</button>}
              {u.id!==user.id&&<button onClick={()=>setConfirm({action:"deleteUser",target:u.id,label:"Excluir",name:u.username})} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.error44}`,background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>🗑️</button>}
            </div>
          </div>
        ))}
        {filteredUsers.length===0&&<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum usuário encontrado.</div>}
      </div>}

      {/* DIARIES TAB */}
      {tab==="diaries"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"12px"}}>{filteredDiaries.length} diários</div>
        {searchInput(searchDiaries,setSearchDiaries,"Buscar por nome, genética ou autor...")}
        {filteredDiaries.map(d=>(
          <div key={d.id+(d.ownerUserId||"")} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${d.hidden?C.error+"33":C.border}`,padding:"12px 14px",marginBottom:"8px",display:"flex",alignItems:"center",gap:"10px",flexWrap:"wrap",opacity:d.hidden?0.5:1}}>
            <div style={{flex:1,minWidth:"120px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",display:"flex",alignItems:"center",gap:"4px"}}>{d.name} {d.hidden&&<span style={{fontSize:"9px",padding:"1px 5px",borderRadius:"5px",background:C.surface2,color:C.dim}}>OCULTO</span>}</div>
              <div style={{fontFamily:F.sans,fontSize:"10px",color:C.dim}}>{d.strain} · {d.author} ({d.ownerEmail}) · {d.weeks?.length||0} sem.</div>
            </div>
            <div style={{display:"flex",gap:"3px"}}>
              <button onClick={()=>doHideDiary(d.ownerUserId,d.id)} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>{d.hidden?"👁️":"🙈"}</button>
              <button onClick={()=>setConfirm({action:"deleteDiary",target:{userId:d.ownerUserId,id:d.id},label:"Excluir diário",name:d.name})} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.error44}`,background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>🗑️</button>
            </div>
          </div>
        ))}
        {filteredDiaries.length===0&&<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum diário encontrado.</div>}
      </div>}

      {/* COMMENTS MODERATION TAB */}
      {tab==="comments"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"12px"}}>{allComments.length} comentários</div>
        {searchInput(searchComments,setSearchComments,"Buscar por texto, usuário ou diário...")}
        {(searchComments?allComments.filter(c=>(c.text+" "+c.username+" "+c.diaryName).toLowerCase().includes(searchComments.toLowerCase())):allComments).map(c=>(
          <div key={c.id} style={{background:C.cardBg,borderRadius:"10px",border:`1px solid ${C.border}`,padding:"12px 14px",marginBottom:"6px",display:"flex",gap:"10px",alignItems:"flex-start"}}>
            <div style={{width:"30px",height:"30px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",border:`1px solid ${C.border}`,flexShrink:0,overflow:"hidden"}}>{c.avatarImg?<img src={c.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:c.avatar||"🌿"}</div>
            <div style={{flex:1,minWidth:0}}>
              <div style={{fontFamily:F.sans,fontSize:"12px",display:"flex",gap:"6px",alignItems:"center",flexWrap:"wrap"}}><span style={{fontWeight:"700"}}>{c.username}</span><span style={{color:C.dim}}>em</span><span style={{color:C.accent,fontWeight:"600"}}>{c.diaryName}</span><span style={{color:C.dim,fontSize:"10px"}}>{timeAgo(c.time)}</span></div>
              <div style={{fontFamily:F.body,fontSize:"13px",color:C.text,marginTop:"4px"}}>{c.text}</div>
            </div>
            <button onClick={async()=>{try{await sb.from("comments").delete(`id=eq.${c.id}`);setAllComments(p=>p.filter(x=>x.id!==c.id));await addAudit("Excluiu comentário",c.authorEmail,c.text.substring(0,40));showToast("Comentário excluído.");}catch{}}} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.error44}`,background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,flexShrink:0}}>🗑️</button>
          </div>
        ))}
        {allComments.length===0&&<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum comentário encontrado.</div>}
      </div>}

      {/* BLOG MANAGEMENT TAB */}
      {tab==="blog"&&<div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}}>
          <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>📰 Gestão do Blog ({blogPosts.length} posts)</div>
          <button onClick={()=>onNewPost?.()} style={{...btnPrimary,width:"auto",padding:"8px 16px",fontSize:"12px"}}>✏️ Novo Post</button>
        </div>
        {blogPosts.length===0?<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum post criado.</div>:
        <div style={{display:"flex",flexDirection:"column",gap:"8px"}}>
          {blogPosts.map(p=>(
            <div key={p.id} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"14px 16px",display:"flex",alignItems:"center",gap:"12px"}}>
              {p.cover_url&&<img src={p.cover_url} alt="" style={{width:"48px",height:"48px",borderRadius:"8px",objectFit:"cover",flexShrink:0}}/>}
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.title}</div>
                <div style={{display:"flex",gap:"8px",alignItems:"center",marginTop:"2px"}}>
                  <span style={{padding:"1px 8px",borderRadius:"10px",background:p.status==="published"?C.accentBg:"#fef3c7",color:p.status==="published"?C.accent:"#92400e",fontSize:"10px",fontFamily:F.sans,fontWeight:"600"}}>{p.status==="published"?"Publicado":"Rascunho"}</span>
                  <span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{p.category} · {p.authorName}</span>
                  <span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{new Date(p.created_at).toLocaleDateString("pt-BR")}</span>
                </div>
              </div>
              <button onClick={async()=>{if(!window.confirm("Deletar post '"+p.title+"'?"))return;try{const r=await fetch(`${SB_URL}/rest/v1/blog_posts?id=eq.${p.id}`,{method:"DELETE",headers:sbHeaders()});if(r.ok){setBlogPosts(prev=>prev.filter(x=>x.id!==p.id));addAudit("Deletou post",p.title,"");}else{console.error("Delete failed:",await r.text());}}catch(e){console.error("Delete error:",e);}}} style={{padding:"6px 10px",borderRadius:"8px",border:`1px solid ${C.error}33`,background:C.error+"08",color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,flexShrink:0}}>🗑️</button>
            </div>
          ))}
        </div>}
      </div>}

      {/* REPORTS TAB */}
      {tab==="reports"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"16px"}}>🚨 Fila de Moderação ({pendingReports} pendentes)</div>
        {reports.length>0?reports.map(r=>(
          <div key={r.id} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${r.status==="pending"?"#fcd34d":r.status==="resolved"?C.accent+"44":C.border}`,padding:"14px 16px",marginBottom:"10px"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:"10px",marginBottom:"8px"}}>
              <div>
                <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",display:"flex",alignItems:"center",gap:"6px"}}>
                  {r.status==="pending"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.warnBg,color:C.warnText,fontSize:"9px",fontWeight:"700"}}>PENDENTE</span>}
                  {r.status==="resolved"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.accentBg,color:C.accent,fontSize:"9px",fontWeight:"700"}}>RESOLVIDA</span>}
                  {r.status==="dismissed"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.surface2,color:C.dim,fontSize:"9px",fontWeight:"700"}}>DISPENSADA</span>}
                  Denúncia de {r.reporterName}
                </div>
                <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"2px"}}>Alvo: {r.targetName} ({r.targetEmail}) · {r.targetType==="diary"?"Diário: "+r.targetDiaryName:"Perfil"} · {timeAgo(r.time)}</div>
              </div>
            </div>
            <div style={{fontFamily:F.sans,fontSize:"13px",color:C.text,padding:"10px",background:C.surface2,borderRadius:"8px",borderLeft:`3px solid #d97706`,marginBottom:"10px"}}>{r.reason}</div>
            {r.resolvedBy&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginBottom:"8px"}}>Resolvida por {r.resolvedBy} · {timeAgo(r.resolvedAt)}</div>}
            {r.status==="pending"&&<div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
              <button onClick={()=>doResolveReport(r.id,"resolved")} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>✅ Resolvida</button>
              <button onClick={()=>doResolveReport(r.id,"dismissed")} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>❌ Dispensar</button>
              <button onClick={()=>{setWarnTarget(r.targetEmail);setWarnMsg("Recebemos uma denúncia sobre seu conteúdo. Por favor, revise e adeque às diretrizes da comunidade.");}} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.warnBorder}`,background:C.warnBg,color:C.warnText,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>⚠️ Avisar</button>
              <button onClick={()=>doDeleteReport(r.id)} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.error44}`,background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>🗑️</button>
            </div>}
          </div>
        )):<div style={{textAlign:"center",padding:"60px 24px",color:C.dim}}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>✅</div>
          <p style={{fontFamily:F.sans,fontSize:"14px"}}>Nenhuma denúncia no momento</p>
        </div>}
      </div>}

      {/* ANNOUNCE TAB */}
      {tab==="announce"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"16px"}}>📢 Anúncio Global</div>
        <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"20px"}}>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,marginBottom:"14px"}}>Este anúncio será enviado como notificação para todos os {userList.length} usuários.</p>
          <textarea style={{...baseInput,minHeight:"100px",resize:"vertical",marginBottom:"14px"}} value={announceMsg} onChange={e=>setAnnounceMsg(e.target.value)} placeholder="Ex: Bem-vindos à nova versão do Diário da Planta! Confira as novidades..."/>
          <div style={{display:"flex",gap:"8px",flexWrap:"wrap",marginBottom:"16px"}}>
            {["🎉 Nova atualização disponível!","📋 Novas regras da comunidade","🔧 Manutenção programada","🌱 Novo concurso aberto!"].map(t=>(
              <button key={t} onClick={()=>setAnnounceMsg(t)} style={{padding:"5px 10px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>{t}</button>
            ))}
          </div>
          <button onClick={doSendAnnouncement} disabled={!announceMsg.trim()} style={{...btnPrimary,opacity:!announceMsg.trim()?0.4:1}}>📢 Enviar para todos ({userList.length})</button>
        </div>
      </div>}

      {/* WARNINGS TAB */}
      {tab==="warnings"&&<div>
        <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"16px"}}>⚠️ Enviar aviso individual</div>
        <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"20px"}}>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Buscar Usuário</label>
            <input style={{...baseInput,marginBottom:"8px"}} value={warnSearch} onChange={e=>setWarnSearch(e.target.value)} placeholder="🔍 Buscar por nome ou email..."/>
            {warnTarget&&<div style={{display:"flex",alignItems:"center",gap:"8px",padding:"8px 12px",background:C.accentBg,borderRadius:"8px",marginBottom:"8px"}}>
              <span style={{fontFamily:F.sans,fontSize:"13px",color:C.accent,fontWeight:"600"}}>✓ {allUsers[warnTarget]?.username||"Usuário"}</span>
              <button onClick={()=>setWarnTarget(null)} style={{background:"none",border:"none",color:C.error,cursor:"pointer",fontSize:"12px",marginLeft:"auto"}}>✕</button>
            </div>}
            {warnSearch&&!warnTarget&&<div style={{maxHeight:"150px",overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:"8px",background:C.cardBg}}>
              {userList.filter(u=>(u.username+" "+u.email).toLowerCase().includes(warnSearch.toLowerCase())).slice(0,10).map(u=>(
                <div key={u.id} onClick={()=>{setWarnTarget(u.id);setWarnSearch("");}} style={{padding:"10px 14px",cursor:"pointer",display:"flex",alignItems:"center",gap:"10px",borderBottom:`1px solid ${C.border22}`,fontFamily:F.sans,fontSize:"13px"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                  <div style={{width:"28px",height:"28px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`}}>{u.avatarImg?<img src={u.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:u.avatar}</div>
                  <div><div style={{fontWeight:"600"}}>{u.username}</div><div style={{fontSize:"11px",color:C.dim}}>{u.email}</div></div>
                </div>
              ))}
              {userList.filter(u=>(u.username+" "+u.email).toLowerCase().includes(warnSearch.toLowerCase())).length===0&&<div style={{padding:"12px",textAlign:"center",color:C.dim,fontSize:"12px"}}>Nenhum usuário encontrado</div>}
            </div>}
          </div>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Mensagem</label>
            <textarea style={{...baseInput,minHeight:"80px",resize:"vertical"}} value={warnMsg} onChange={e=>setWarnMsg(e.target.value)} placeholder="Descreva o motivo do aviso..."/>
          </div>
          <div style={{display:"flex",gap:"6px",flexWrap:"wrap",marginBottom:"16px"}}>
            {["Conteúdo impróprio detectado","Violação de diretrizes da comunidade","Spam ou conteúdo duplicado","Uso indevido do sistema de mensagens"].map(t=>(
              <button key={t} onClick={()=>setWarnMsg(t)} style={{padding:"5px 10px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>{t}</button>
            ))}
          </div>
          <button onClick={doSendWarning} disabled={!warnTarget||!warnMsg.trim()} style={{...btnPrimary,opacity:(!warnTarget||!warnMsg.trim())?0.4:1}}>⚠️ Enviar Aviso</button>
        </div>
      </div>}

      {/* AUDIT LOG TAB */}
      {tab==="log"&&<div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}}>
          <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>📋 Log de Auditoria ({auditLog.length})</div>
          {auditLog.length>0&&<button onClick={async()=>{setAuditLog([]);try{await sb.from("audit_log").delete(`admin_id=eq.${user.id}`);}catch{}showToast("Log limpo.");}} style={{padding:"6px 12px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Limpar</button>}
        </div>
        {auditLog.length>0?auditLog.map(a=>(
          <div key={a.id} style={{background:C.cardBg,borderRadius:"10px",border:`1px solid ${C.border}`,padding:"12px 14px",marginBottom:"6px",display:"flex",gap:"10px",alignItems:"flex-start"}}>
            <div style={{width:"32px",height:"32px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",flexShrink:0,border:`1px solid ${C.border}`}}>🛡️</div>
            <div style={{flex:1,minWidth:0}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",color:C.text}}><span style={{fontWeight:"700"}}>{a.admin}</span> <span style={{color:C.muted}}>{a.action}</span>{a.detail&&<span style={{color:C.accent,fontWeight:"600"}}> — {a.detail}</span>}</div>
              <div style={{fontFamily:F.sans,fontSize:"10px",color:C.dim,marginTop:"2px"}}>{a.target} · {new Date(a.time).toLocaleString("pt-BR")}</div>
            </div>
          </div>
        )):<div style={{textAlign:"center",padding:"60px 24px",color:C.dim}}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>📋</div>
          <p style={{fontFamily:F.sans,fontSize:"14px"}}>Nenhuma ação registrada ainda</p>
        </div>}
      </div>}

      {/* Edit User Modal */}
      {editUser&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setEditUser(null)}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px",display:"flex",alignItems:"center",gap:"8px"}}>✏️ Editar {editForm.username}</h3>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Username</label><input style={baseInput} value={editForm.username||""} onChange={e=>setEditForm(p=>({...p,username:e.target.value}))}/></div>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Cidade</label><input style={baseInput} value={editForm.city||""} onChange={e=>setEditForm(p=>({...p,city:e.target.value}))}/></div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>Bio</label><textarea style={{...baseInput,minHeight:"60px",resize:"vertical"}} value={editForm.bio||""} onChange={e=>setEditForm(p=>({...p,bio:e.target.value}))}/></div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>setEditUser(null)}>Cancelar</button><button style={btnPrimary} onClick={doSaveEdit}>Salvar</button></div>
        </div>
      </div>}

      {/* Create User Modal */}
      {newUserForm&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setNewUserForm(null)}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px"}}>+ Criar Usuário</h3>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Email *</label><input style={baseInput} value={newUserForm.email} onChange={e=>setNewUserForm(p=>({...p,email:e.target.value}))}/></div>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Username *</label><input style={baseInput} value={newUserForm.username} onChange={e=>setNewUserForm(p=>({...p,username:e.target.value}))}/></div>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Senha *</label><input style={baseInput} type="password" value={newUserForm.password} onChange={e=>setNewUserForm(p=>({...p,password:e.target.value}))}/></div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>Papel</label>
            <div style={{display:"flex",gap:"8px"}}>{["user","admin"].map(r=><button key={r} onClick={()=>setNewUserForm(p=>({...p,role:r}))} style={{padding:"8px 14px",borderRadius:"8px",border:newUserForm.role===r?`2px solid ${C.accent}`:`1px solid ${C.border}`,background:newUserForm.role===r?C.accentBg:C.cardBg,color:newUserForm.role===r?C.accent:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"600"}}>{r==="admin"?"👑 Admin":"👤 Usuário"}</button>)}</div>
          </div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>setNewUserForm(null)}>Cancelar</button><button style={btnPrimary} onClick={doCreateUser}>Criar</button></div>
        </div>
      </div>}

      {/* Confirm Modal */}
      {confirm&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setConfirm(null)}>
        <div style={{...cardBase,maxWidth:"380px",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
          <div style={{fontSize:"40px",marginBottom:"12px"}}>{confirm.action==="ban"?"🚫":"🗑️"}</div>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 8px"}}>{confirm.label} "{confirm.name}"?</h3>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Esta ação pode ser irreversível.</p>
          <div style={{display:"flex",gap:"12px"}}><button style={btnSecondary} onClick={()=>setConfirm(null)}>Cancelar</button><button style={{...btnPrimary,background:C.error}} onClick={()=>{
            if(confirm.action==="deleteUser")doDeleteUser(confirm.target);
            else if(confirm.action==="ban")doBanUser(confirm.target);
            else if(confirm.action==="deleteDiary")doDeleteDiary(confirm.target.userId,confirm.target.id);
          }}>Confirmar</button></div>
        </div>
      </div>}

      {/* Warning Modal (from other tabs) */}
      {warnTarget&&tab!=="warnings"&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>{setWarnTarget(null);setWarnMsg("");}}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px"}}>⚠️ Aviso para {allUsers[warnTarget]?.username}</h3>
          <textarea style={{...baseInput,minHeight:"80px",resize:"vertical",marginBottom:"16px"}} value={warnMsg} onChange={e=>setWarnMsg(e.target.value)} placeholder="Descreva o motivo do aviso..."/>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>{setWarnTarget(null);setWarnMsg("");}}>Cancelar</button><button style={{...btnPrimary,background:"#d97706"}} onClick={doSendWarning} disabled={!warnMsg.trim()}>Enviar</button></div>
        </div>
      </div>}

      {/* Toast */}
      {toast&&<div style={{position:"fixed",bottom:"24px",left:"50%",transform:"translateX(-50%)",background:C.accent,color:C.onAccent,padding:"12px 24px",borderRadius:"12px",fontFamily:F.sans,fontSize:"14px",fontWeight:"600",boxShadow:"0 4px 20px rgba(0,0,0,0.15)",zIndex:400,animation:"fadeIn 0.3s"}}>{toast}</div>}
      <style>{`@keyframes fadeIn{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}@media(max-width:768px){.dp-admin-sidebar{display:none!important}.dp-admin-main{min-width:100%!important}}`}</style>
        </div>{/* end main content */}
      </div>{/* end flex row */}
    </div>
  );
}

// ─── Public Profile ───
function PublicProfile({ targetUser, diaries, onBack, onViewDiary, lang }) {
  const t=T[lang||"pt"];
  const level=getUserLevel(diaries.length);
  const totalWeeks=diaries.reduce((s,d)=>s+(d.weeks?.length||0),0);
  return (
    <div style={{maxWidth:"700px",margin:"0 auto",padding:"32px 24px"}}>
      <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px"}}>← {t.back}</button>
      <div style={{background:C.surfaceLight,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"32px",textAlign:"center",marginBottom:"20px"}}>
        <div style={{width:"80px",height:"80px",borderRadius:"50%",background:C.accentBg,border:`3px solid ${C.accent}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"40px",margin:"0 auto 12px",overflow:"hidden"}}>{targetUser.avatarImg?<img src={targetUser.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:targetUser.avatar||"🌱"}</div>
        <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",margin:"0 0 4px"}}>{targetUser.username}</h2>
        <div style={{fontFamily:F.sans,fontSize:"12px",color:C.accent,fontWeight:"700",textTransform:"uppercase",letterSpacing:"1px",marginBottom:"4px"}}>{level.icon} {level.name}</div>
        {targetUser.city&&<div style={{fontFamily:F.sans,fontSize:"13px",color:C.dim}}>📍 {targetUser.city}</div>}
        {targetUser.bio&&<p style={{fontFamily:F.body,fontSize:"14px",color:C.muted,fontStyle:"italic",margin:"12px 0 0",lineHeight:"1.5"}}>"{targetUser.bio}"</p>}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:"10px",marginBottom:"24px"}}>
        {[["📓",diaries.length,"Diários"],["📅",totalWeeks,"Semanas"],["🌿",new Set(diaries.map(d=>d.strain)).size,"Variedades"]].map(([icon,val,label])=>(
          <div key={label} style={{background:C.surfaceLight,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"14px",textAlign:"center"}}>
            <div style={{fontSize:"18px"}}>{icon}</div><div style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",color:C.accent}}>{val}</div><div style={{fontFamily:F.sans,fontSize:"10px",color:C.dim,textTransform:"uppercase",letterSpacing:"0.8px"}}>{label}</div>
          </div>
        ))}
      </div>
      <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",marginBottom:"16px"}}>📓 Diários de {targetUser.username}</h3>
      {diaries.length>0?<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(260px,1fr))",gap:"14px"}}>
        {diaries.filter(d=>!d.hidden).map(d=><div key={d.id} onClick={()=>onViewDiary(d)} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px",cursor:"pointer",transition:"all 0.15s"}} onMouseOver={e=>e.currentTarget.style.boxShadow="0 4px 16px rgba(0,0,0,0.08)"} onMouseOut={e=>e.currentTarget.style.boxShadow="none"}>
          <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"4px"}}>{d.name}</div>
          <div style={{fontFamily:F.sans,fontSize:"12px",color:C.accent,marginBottom:"6px"}}>{d.strain}</div>
          <div style={{display:"flex",gap:"8px",fontSize:"11px",color:C.dim,fontFamily:F.sans}}>
            <span>{PHASE_ICONS[d.phase]} {PHASES[d.phase]}</span><span>· {d.weeks?.length||0} sem.</span><span>· ❤️ {d.likes||0}</span>
          </div>
        </div>)}
      </div>:<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum diário público.</div>}
    </div>
  );
}

// ─── Blog Editor (Admin only — WordPress-like) ───
const BLOG_CATEGORIES=["Dicas de Cultivo","Genéticas","Nutrição","Equipamentos","Pragas e Doenças","Legislação","Comunidade","Sem categoria"];

function BlogEditor({post,onSave,onClose,user}){
  const [title,setTitle]=useState(post?.title||"");
  const [content,setContent]=useState(post?.content||"");
  const [excerpt,setExcerpt]=useState(post?.excerpt||"");
  const [category,setCategory]=useState(post?.category||"Sem categoria");
  const [coverUrl,setCoverUrl]=useState(post?.cover_url||null);
  const [saving,setSaving]=useState(false);
  const [showPreview,setShowPreview]=useState(false);
  const [showYTModal,setShowYTModal]=useState(false);
  const [ytUrl,setYtUrl]=useState("");
  const [uploading,setUploading]=useState(false);
  const coverRef=useRef(null);
  const inlinePhotoRef=useRef(null);
  const contentRef=useRef(null);

  // Insert text at cursor position
  const insertAtCursor=(text)=>{
    const ta=contentRef.current;if(!ta)return;
    const start=ta.selectionStart,end=ta.selectionEnd;
    const newContent=content.substring(0,start)+text+content.substring(end);
    setContent(newContent);
    // Restore focus after state update
    setTimeout(()=>{ta.focus();ta.selectionStart=ta.selectionEnd=start+text.length;},50);
  };

  const insertFormat=(tag)=>{
    const ta=contentRef.current;if(!ta)return;
    const start=ta.selectionStart,end=ta.selectionEnd;
    const sel=content.substring(start,end);
    let insert="";
    if(tag==="b")insert=`**${sel||"texto em negrito"}**`;
    else if(tag==="i")insert=`*${sel||"texto em itálico"}*`;
    else if(tag==="h2")insert=`\n## ${sel||"Subtítulo"}\n`;
    else if(tag==="h3")insert=`\n### ${sel||"Subtítulo menor"}\n`;
    else if(tag==="ul")insert=`\n- ${sel||"Item da lista"}\n`;
    else if(tag==="ol")insert=`\n1. ${sel||"Item numerado"}\n`;
    else if(tag==="quote")insert=`\n> ${sel||"Citação"}\n`;
    else if(tag==="hr")insert=`\n---\n`;
    else if(tag==="link")insert=`[${sel||"texto do link"}](https://)`;
    setContent(content.substring(0,start)+insert+content.substring(end));
  };

  // Upload inline photo
  const handleInlinePhoto=async(e)=>{
    const f=e.target.files?.[0];if(!f)return;
    setUploading(true);
    try{
      const path=`blog/inline/${Date.now()}-${Math.random().toString(36).slice(2,5)}.${f.name.split(".").pop()||"jpg"}`;
      const ok=await sbStorage.upload(path,f);
      if(ok){
        const url=sbStorage.getUrl(path);
        insertAtCursor(`\n![${f.name}](${url})\n`);
      }
    }catch(err){console.error("Upload inline photo:",err);}
    setUploading(false);e.target.value="";
  };

  // Extract YouTube video ID from various URL formats
  const extractYTId=(url)=>{
    const m=url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    return m?m[1]:null;
  };

  const insertYT=()=>{
    const vid=extractYTId(ytUrl);
    if(!vid){alert("URL do YouTube inválida. Cole um link como:\nhttps://youtube.com/watch?v=...\nhttps://youtu.be/...");return;}
    insertAtCursor(`\n[youtube:${vid}]\n`);
    setYtUrl("");setShowYTModal(false);
  };

  const handleCover=async(e)=>{
    const f=e.target.files?.[0];if(!f)return;
    setUploading(true);
    const path=`blog/covers/${Date.now()}-${Math.random().toString(36).slice(2,5)}.${f.name.split(".").pop()||"jpg"}`;
    const ok=await sbStorage.upload(path,f);
    if(ok)setCoverUrl(sbStorage.getUrl(path));
    setUploading(false);e.target.value="";
  };

  const doSave=async(status)=>{
    if(!title.trim()){alert("Título é obrigatório");return;}
    setSaving(true);
    try{
      const data={title:sanitize(title,200),content,excerpt:sanitize(excerpt,500),category,cover_url:coverUrl,status,updated_at:new Date().toISOString()};
      if(status==="published"&&!post?.published_at)data.published_at=new Date().toISOString();
      if(post?.id){
        await sb.from("blog_posts").update(data,`id=eq.${post.id}`);
      }else{
        data.author_id=user.id;
        await sb.from("blog_posts").insert(data);
      }
      onSave?.();
    }catch(e){console.error("Save post error:",e);}
    setSaving(false);
  };

  // Render markdown + custom tags to HTML for preview
  const renderPreview=(text)=>{
    if(!text)return"";
    return text
      // YouTube embeds
      .replace(/\[youtube:([a-zA-Z0-9_-]{11})\]/g,'<div style="position:relative;padding-bottom:56.25%;height:0;margin:16px 0;border-radius:12px;overflow:hidden"><iframe src="https://www.youtube.com/embed/$1?cc_load_policy=1&cc_lang_pref=pt&hl=pt&rel=0" style="position:absolute;top:0;left:0;width:100%;height:100%;border:none" allowfullscreen></iframe></div>')
      // Images
      .replace(/!\[([^\]]*)\]\(([^)]+)\)/g,'<div style="margin:16px 0"><img src="$2" alt="$1" style="max-width:100%;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.1)"/></div>')
      // Headers
      .replace(/^### (.+)$/gm,'<h4 style="margin:20px 0 8px;font-size:16px;font-weight:700;font-family:Inter,sans-serif">$1</h4>')
      .replace(/^## (.+)$/gm,'<h3 style="margin:24px 0 10px;font-size:20px;font-weight:700;font-family:Inter,sans-serif">$1</h3>')
      // Bold, italic
      .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
      .replace(/\*(.+?)\*/g,"<em>$1</em>")
      // Blockquote
      .replace(/^> (.+)$/gm,'<blockquote style="border-left:3px solid #1B9E42;padding:8px 16px;color:#888;margin:12px 0;font-style:italic;background:rgba(27,158,66,0.04);border-radius:0 8px 8px 0">$1</blockquote>')
      // Lists
      .replace(/^- (.+)$/gm,'<div style="padding-left:20px;margin:4px 0">• $1</div>')
      .replace(/^\d+\. (.+)$/gm,'<div style="padding-left:20px;margin:4px 0">$1</div>')
      // Horizontal rule
      .replace(/^---$/gm,'<hr style="border:none;border-top:1px solid var(--dp-border);margin:20px 0"/>')
      // Links
      .replace(/\[(.+?)\]\((.+?)\)/g,'<a href="$2" target="_blank" rel="noopener" style="color:#1B9E42;text-decoration:underline">$1</a>')
      // Paragraphs
      .replace(/\n\n/g,"</p><p style='margin:0 0 14px;line-height:1.8'>")
      .replace(/\n/g,"<br/>");
  };

  const wordCount=content.trim()?content.trim().split(/\s+/).length:0;
  const tbtn=(icon,tag,tip)=><button key={tag} title={tip} onClick={()=>insertFormat(tag)} style={{width:"34px",height:"34px",borderRadius:"6px",border:`1px solid ${C.border}`,background:C.surface2,color:C.text,cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center",fontWeight:tag==="b"?"800":"400"}}>{icon}</button>;

  // Preview mode
  if(showPreview) return(
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:C.bg,zIndex:400,overflowY:"auto"}}>
      <div style={{maxWidth:"740px",margin:"0 auto",padding:"32px 24px"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"24px"}}>
          <button onClick={()=>setShowPreview(false)} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>← Voltar ao Editor</button>
          <span style={{padding:"4px 12px",borderRadius:"20px",background:"rgba(234,179,8,0.1)",color:"#d97706",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>👁️ Modo Preview</span>
        </div>
        {coverUrl&&<img src={coverUrl} alt="" style={{width:"100%",maxHeight:"360px",objectFit:"cover",borderRadius:"16px",marginBottom:"24px"}}/>}
        <div style={{display:"flex",gap:"8px",alignItems:"center",marginBottom:"12px"}}>
          <span style={{padding:"3px 12px",borderRadius:"20px",background:C.accentBg,color:C.accent,fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>{category}</span>
          <span style={{fontSize:"13px",color:C.dim,fontFamily:F.sans}}>{new Date().toLocaleDateString("pt-BR",{day:"numeric",month:"long",year:"numeric"})}</span>
        </div>
        <h1 style={{fontFamily:F.sans,fontSize:"32px",fontWeight:"800",margin:"0 0 16px",lineHeight:"1.3"}}>{title||"Título do post"}</h1>
        <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"32px",paddingBottom:"20px",borderBottom:`1px solid ${C.border}`}}>
          <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",overflow:"hidden",border:`1px solid ${C.border}`}}>{user?.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:user?.avatar||"🌱"}</div>
          <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"600"}}>{user?.username}</div>
        </div>
        <div style={{fontFamily:F.body,fontSize:"16px",color:C.text,lineHeight:"1.8"}} dangerouslySetInnerHTML={{__html:`<p style='margin:0 0 14px;line-height:1.8'>${renderPreview(content)}</p>`}}/>
      </div>
    </div>
  );

  return(
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:C.bg,zIndex:400,overflowY:"auto"}}>
      <div style={{maxWidth:"960px",margin:"0 auto",padding:"20px 24px"}}>
        {/* Header */}
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"24px",paddingBottom:"16px",borderBottom:`1px solid ${C.border}`}}>
          <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800",margin:0}}>✏️ {post?.id?"Editar Post":"Novo Post"}</h2>
          <div style={{display:"flex",gap:"8px",alignItems:"center"}}>
            {uploading&&<span style={{fontSize:"12px",color:C.accent,fontFamily:F.sans}}>⏳ Enviando...</span>}
            <button onClick={onClose} style={{width:"36px",height:"36px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"18px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
        </div>

        <div style={{display:"flex",gap:"24px",flexWrap:"wrap"}}>
          {/* Main editor */}
          <div style={{flex:1,minWidth:"300px"}}>
            <input style={{...baseInput,fontSize:"22px",fontWeight:"700",marginBottom:"16px",padding:"16px"}} value={title} onChange={e=>setTitle(e.target.value)} placeholder="Digite o título aqui"/>

            {/* Toolbar */}
            <div style={{display:"flex",gap:"4px",flexWrap:"wrap",marginBottom:"8px",padding:"10px",background:C.surface2,borderRadius:"10px",border:`1px solid ${C.border}`,alignItems:"center"}}>
              {tbtn("B","b","Negrito")}{tbtn("𝐼","i","Itálico")}
              <div style={{width:"1px",height:"24px",background:C.border,margin:"0 4px"}}/>
              {tbtn("H2","h2","Subtítulo")}{tbtn("H3","h3","Subtítulo menor")}
              <div style={{width:"1px",height:"24px",background:C.border,margin:"0 4px"}}/>
              {tbtn("•","ul","Lista")}{tbtn("1.","ol","Lista numerada")}{tbtn("❝","quote","Citação")}{tbtn("—","hr","Separador")}
              <div style={{width:"1px",height:"24px",background:C.border,margin:"0 4px"}}/>
              {tbtn("🔗","link","Inserir link")}
              <button title="Inserir foto no post" onClick={()=>inlinePhotoRef.current?.click()} style={{width:"34px",height:"34px",borderRadius:"6px",border:`1px solid ${C.accent}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center"}}>📷</button>
              <button title="Inserir vídeo do YouTube" onClick={()=>setShowYTModal(true)} style={{width:"34px",height:"34px",borderRadius:"6px",border:`1px solid #e53e3e`,background:"rgba(229,62,62,0.06)",color:"#e53e3e",cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center"}}>▶️</button>
              <input ref={inlinePhotoRef} type="file" accept="image/*" style={{display:"none"}} onChange={handleInlinePhoto}/>
            </div>

            {/* Visual / Texto tabs */}
            <div style={{display:"flex",gap:"0",marginBottom:"-1px",position:"relative",zIndex:1}}>
              <button onClick={()=>{}} style={{padding:"8px 16px",borderRadius:"8px 8px 0 0",border:`1px solid ${C.border}`,borderBottom:"none",background:C.cardBg,color:C.text,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>Texto</button>
            </div>

            <textarea ref={contentRef} style={{...baseInput,minHeight:"420px",resize:"vertical",fontFamily:"'SF Mono','Fira Code',monospace",fontSize:"14px",lineHeight:"1.8",borderRadius:"0 10px 10px 10px",borderTopLeftRadius:0}} value={content} onChange={e=>setContent(e.target.value)} placeholder={"Escreva o conteúdo do post aqui...\n\nFormatação disponível:\n**negrito**  *itálico*  ## Subtítulo\n- lista com traço\n> citação\n[texto](https://link.com)\n\nMídia:\n📷 Use o botão da barra para inserir fotos\n▶️ Use o botão vermelho para embed YouTube"}/>

            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:"6px"}}>
              <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>Palavras: {wordCount}</div>
              <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>Caminho: p</div>
            </div>
          </div>

          {/* Sidebar */}
          <div style={{width:"260px",flexShrink:0}}>
            {/* Publish box */}
            <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px",marginBottom:"16px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",marginBottom:"12px"}}>📤 Publicar</div>
              <div style={{fontFamily:F.sans,fontSize:"12px",color:C.muted,marginBottom:"4px"}}>Status: <strong>{post?.status==="published"?"Publicado":"Rascunho"}</strong></div>
              <div style={{fontFamily:F.sans,fontSize:"12px",color:C.muted,marginBottom:"4px"}}>Visibilidade: <strong>Público</strong></div>
              <div style={{fontFamily:F.sans,fontSize:"12px",color:C.muted,marginBottom:"12px"}}>Publicar: <strong>Imediatamente</strong></div>
              <div style={{display:"flex",gap:"8px",marginBottom:"8px"}}>
                <button onClick={()=>doSave("draft")} disabled={saving} style={{...btnSecondary,fontSize:"12px",padding:"8px 12px",width:"auto"}}>💾 Rascunho</button>
                <button onClick={()=>setShowPreview(true)} style={{...btnSecondary,fontSize:"12px",padding:"8px 12px",width:"auto"}}>👁️ Visualizar</button>
              </div>
              <button onClick={()=>doSave("published")} disabled={saving||!title.trim()} style={{...btnPrimary,fontSize:"13px",padding:"10px 16px",opacity:(saving||!title.trim())?0.5:1}}>{saving?"Salvando...":"🚀 Publicar"}</button>
              {post?.id&&post?.status==="published"&&<button onClick={()=>doSave("draft")} style={{...linkBtn,fontSize:"11px",color:C.error,marginTop:"8px"}}>Mover para rascunho</button>}
            </div>

            {/* Category */}
            <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px",marginBottom:"16px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",marginBottom:"10px"}}>📁 Categorias</div>
              {BLOG_CATEGORIES.map(c=>(
                <label key={c} style={{display:"flex",alignItems:"center",gap:"8px",cursor:"pointer",padding:"4px 0",fontFamily:F.sans,fontSize:"13px",color:category===c?C.accent:C.muted}}>
                  <input type="checkbox" checked={category===c} onChange={()=>setCategory(c)} style={{accentColor:C.accent}}/>{c}
                </label>
              ))}
            </div>

            {/* Cover image */}
            <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px",marginBottom:"16px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",marginBottom:"10px"}}>🖼️ Imagem Destacada</div>
              {coverUrl?<div style={{position:"relative",marginBottom:"8px"}}><img src={coverUrl} alt="" style={{width:"100%",borderRadius:"8px",maxHeight:"150px",objectFit:"cover",loading:"lazy"}}/><button onClick={()=>setCoverUrl(null)} style={{position:"absolute",top:"4px",right:"4px",width:"24px",height:"24px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.5)",color:"#fff",cursor:"pointer",fontSize:"12px"}}>✕</button></div>:<div onClick={()=>coverRef.current?.click()} style={{border:`2px dashed ${C.borderLight}`,borderRadius:"8px",padding:"20px",textAlign:"center",cursor:"pointer"}}><div style={{fontSize:"24px",marginBottom:"4px"}}>🖼️</div><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>Definir imagem destacada</div></div>}
              {coverUrl&&<button onClick={()=>coverRef.current?.click()} style={{...linkBtn,fontSize:"11px"}}>Trocar imagem</button>}
              <input ref={coverRef} type="file" accept="image/*" style={{display:"none"}} onChange={handleCover}/>
            </div>

            {/* Excerpt */}
            <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",marginBottom:"10px"}}>📝 Resumo</div>
              <textarea style={{...baseInput,minHeight:"60px",resize:"vertical",fontSize:"12px"}} value={excerpt} onChange={e=>setExcerpt(e.target.value)} placeholder="Descrição curta do post para listagem..." maxLength={500}/>
            </div>
          </div>
        </div>
      </div>

      {/* YouTube Modal */}
      {showYTModal&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.5)",backdropFilter:"blur(6px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:500,padding:"24px"}} onClick={()=>setShowYTModal(false)}>
        <div style={{...cardBase,maxWidth:"480px"}} onClick={e=>e.stopPropagation()}>
          <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"0 0 16px",display:"flex",alignItems:"center",gap:"8px"}}>▶️ Inserir Vídeo do YouTube</h3>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,margin:"0 0 16px"}}>Cole o link do vídeo do YouTube:</p>
          <input style={baseInput} value={ytUrl} onChange={e=>setYtUrl(e.target.value)} placeholder="https://youtube.com/watch?v=... ou https://youtu.be/..." onKeyDown={e=>e.key==="Enter"&&insertYT()}/>
          {ytUrl&&extractYTId(ytUrl)&&<div style={{margin:"16px 0",borderRadius:"12px",overflow:"hidden",position:"relative",paddingBottom:"56.25%",background:"#000"}}><iframe src={`https://www.youtube.com/embed/${extractYTId(ytUrl)}?cc_load_policy=1&cc_lang_pref=pt&hl=pt&rel=0`} style={{position:"absolute",top:0,left:0,width:"100%",height:"100%",border:"none"}} allowFullScreen/></div>}
          <div style={{display:"flex",gap:"12px",marginTop:"16px"}}><button onClick={()=>setShowYTModal(false)} style={btnSecondary}>Cancelar</button><button onClick={insertYT} disabled={!ytUrl} style={{...btnPrimary,opacity:ytUrl?1:0.5}}>Inserir Vídeo</button></div>
        </div>
      </div>}
    </div>
  );
}

// ─── Blog Page (public) ───
function BlogPage({onBack,user,onOpenPost,onNewPost}){
  const [posts,setPosts]=useState([]);const [loading,setLoading]=useState(true);
  useEffect(()=>{(async()=>{
    try{
      const rows=await sb.from("blog_posts").select("*,profiles(username,avatar,avatar_url)",`&status=eq.published&order=published_at.desc`);
      setPosts(rows.map(p=>({...p,authorName:p.profiles?.username,authorAvatar:p.profiles?.avatar,authorAvatarImg:p.profiles?.avatar_url})));
    }catch{}setLoading(false);
  })();},[]);

  // Strip all markdown/custom tags for clean text preview
  const cleanText=(text)=>{
    if(!text)return"";
    return text
      .replace(/\[youtube:[^\]]+\]/g,"")
      .replace(/!\[[^\]]*\]\([^)]+\)/g,"")
      .replace(/\[([^\]]+)\]\([^)]+\)/g,"$1")
      .replace(/\*\*(.+?)\*\*/g,"$1")
      .replace(/\*(.+?)\*/g,"$1")
      .replace(/^#{1,4}\s*/gm,"")
      .replace(/^>\s*/gm,"")
      .replace(/^-\s*/gm,"")
      .replace(/^\d+\.\s*/gm,"")
      .replace(/---/g,"")
      .replace(/\n+/g," ")
      .trim();
  };

  // Extract first YouTube ID from content
  const getFirstYT=(text)=>{if(!text)return null;const m=text.match(/\[youtube:([a-zA-Z0-9_-]{11})\]/);return m?m[1]:null;};
  // Extract first image URL from content
  const getFirstImg=(text)=>{if(!text)return null;const m=text.match(/!\[[^\]]*\]\(([^)]+)\)/);return m?m[1]:null;};

  return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"32px"}}>
        <div>
          <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>📰 Blog</h1>
          <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:0}}>Artigos e dicas da comunidade</p>
        </div>
        {user?.role==="admin"&&null}
      </div>
      {loading?<div style={{textAlign:"center",padding:"60px",color:C.dim}}>Carregando...</div>:
      posts.length===0?<div style={{textAlign:"center",padding:"60px",color:C.dim,fontFamily:F.sans}}>Nenhum artigo publicado ainda.</div>:
      <div style={{display:"flex",flexDirection:"column",gap:"24px"}}>
        {posts.map(p=>{
          const ytId=getFirstYT(p.content);
          const firstImg=getFirstImg(p.content);
          const previewImg=p.cover_url||firstImg||(ytId?`https://img.youtube.com/vi/${ytId}/hqdefault.jpg`:null);
          return(
          <div key={p.id} onClick={()=>onOpenPost?.(p)} style={{background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,overflow:"hidden",cursor:"pointer",transition:"all 0.2s",boxShadow:"0 2px 8px rgba(0,0,0,0.04)"}}>
            {previewImg&&<div style={{position:"relative"}}>
              <img src={previewImg} alt="" style={{width:"100%",height:"200px",objectFit:"cover",loading:"lazy"}}/>
              {ytId&&!p.cover_url&&!firstImg&&<div style={{position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)",width:"56px",height:"56px",borderRadius:"50%",background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{width:0,height:0,borderStyle:"solid",borderWidth:"10px 0 10px 18px",borderColor:"transparent transparent transparent #fff",marginLeft:"4px"}}/></div>}
            </div>}
            <div style={{padding:"20px 24px"}}>
              <div style={{display:"flex",gap:"8px",alignItems:"center",marginBottom:"8px"}}>
                <span style={{padding:"2px 10px",borderRadius:"20px",background:C.accentBg,color:C.accent,fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{p.category}</span>
                <span style={{fontSize:"12px",color:C.dim,fontFamily:F.sans}}>{new Date(p.published_at).toLocaleDateString("pt-BR",{day:"numeric",month:"short",year:"numeric"})}</span>
              </div>
              <h2 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"700",margin:"0 0 8px",color:C.text}}>{p.title}</h2>
              <p style={{fontFamily:F.body,fontSize:"14px",color:C.muted,lineHeight:"1.6",margin:"0 0 12px"}}>{p.excerpt||cleanText(p.content)?.substring(0,200)+"..."}</p>
              <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
                <div style={{width:"24px",height:"24px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`}}>{p.authorAvatarImg?<img src={p.authorAvatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:p.authorAvatar||"🌱"}</div>
                <span style={{fontFamily:F.sans,fontSize:"12px",color:C.muted}}>{p.authorName}</span>
              </div>
            </div>
          </div>
          );
        })}
      </div>}
    </div>
  );
}

// ─── Blog Post View ───
function BlogPostView({post,onBack,user,onEdit,onViewImage}){
  const contentRef=useRef(null);
  const renderMarkdown=(text)=>{
    if(!text)return"";
    return text
      // YouTube embeds
      .replace(/\[youtube:([a-zA-Z0-9_-]{11})\]/g,'<div style="position:relative;padding-bottom:56.25%;height:0;margin:20px 0;border-radius:12px;overflow:hidden"><iframe src="https://www.youtube.com/embed/$1?cc_load_policy=1&cc_lang_pref=pt&hl=pt&rel=0" style="position:absolute;top:0;left:0;width:100%;height:100%;border:none" allowfullscreen></iframe></div>')
      // Images - clickable
      .replace(/!\[([^\]]*)\]\(([^)]+)\)/g,'<div style="margin:20px 0"><img src="$2" alt="$1" data-zoomable="true" style="max-width:100%;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);cursor:pointer"/></div>')
      // Headers
      .replace(/^### (.+)$/gm,'<h4 style="margin:20px 0 8px;font-size:16px;font-weight:700;font-family:Inter,sans-serif">$1</h4>')
      .replace(/^## (.+)$/gm,'<h3 style="margin:24px 0 10px;font-size:20px;font-weight:700;font-family:Inter,sans-serif">$1</h3>')
      // Bold, italic
      .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
      .replace(/\*(.+?)\*/g,"<em>$1</em>")
      // Blockquote
      .replace(/^> (.+)$/gm,'<blockquote style="border-left:3px solid #1B9E42;padding:8px 16px;color:#888;margin:12px 0;font-style:italic;background:rgba(27,158,66,0.04);border-radius:0 8px 8px 0">$1</blockquote>')
      // Lists
      .replace(/^- (.+)$/gm,'<div style="padding-left:20px;margin:4px 0">• $1</div>')
      .replace(/^\d+\. (.+)$/gm,'<div style="padding-left:20px;margin:4px 0">$1</div>')
      // HR
      .replace(/^---$/gm,'<hr style="border:none;border-top:1px solid var(--dp-border);margin:20px 0"/>')
      // Links
      .replace(/\[(.+?)\]\((.+?)\)/g,'<a href="$2" target="_blank" rel="noopener" style="color:#1B9E42;text-decoration:underline">$1</a>')
      // Paragraphs
      .replace(/\n\n/g,"</p><p style='margin:0 0 14px;line-height:1.8'>")
      .replace(/\n/g,"<br/>");
  };

  // Attach click handlers to images after render
  useEffect(()=>{
    if(!contentRef.current)return;
    const imgs=contentRef.current.querySelectorAll("img[data-zoomable]");
    const handler=(e)=>onViewImage?.(e.target.src);
    imgs.forEach(img=>img.addEventListener("click",handler));
    return()=>imgs.forEach(img=>img.removeEventListener("click",handler));
  });

  return(
    <div style={{maxWidth:"740px",margin:"0 auto",padding:"32px 24px"}}>
      <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px"}}>← Voltar ao Blog</button>
      {post.cover_url&&<img src={post.cover_url} alt="" onClick={()=>onViewImage?.(post.cover_url)} style={{width:"100%",maxHeight:"360px",objectFit:"cover",borderRadius:"16px",marginBottom:"24px",cursor:"pointer"}}/>}
      <div style={{display:"flex",gap:"8px",alignItems:"center",marginBottom:"12px"}}>
        <span style={{padding:"3px 12px",borderRadius:"20px",background:C.accentBg,color:C.accent,fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>{post.category}</span>
        <span style={{fontSize:"13px",color:C.dim,fontFamily:F.sans}}>{post.published_at?new Date(post.published_at).toLocaleDateString("pt-BR",{day:"numeric",month:"long",year:"numeric"}):""}</span>
        {user?.role==="admin"&&<button onClick={()=>onEdit?.(post)} style={{...linkBtn,fontSize:"12px",marginLeft:"auto"}}>✏️ Editar</button>}
      </div>
      <h1 style={{fontFamily:F.sans,fontSize:"32px",fontWeight:"800",margin:"0 0 16px",lineHeight:"1.3"}}>{post.title}</h1>
      <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"32px",paddingBottom:"20px",borderBottom:`1px solid ${C.border}`}}>
        <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",overflow:"hidden",border:`1px solid ${C.border}`}}>{post.authorAvatarImg?<img src={post.authorAvatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:post.authorAvatar||"🌱"}</div>
        <div><div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"600"}}>{post.authorName}</div></div>
      </div>
      <div ref={contentRef} style={{fontFamily:F.body,fontSize:"16px",color:C.text,lineHeight:"1.8"}} dangerouslySetInnerHTML={{__html:`<p style='margin:0 0 14px;line-height:1.8'>${renderMarkdown(post.content)}</p>`}}/>
    </div>
  );
}

// ─── Cultivadores (Growers) Page ───
function GrowersPage({user,onBack,onViewProfile,follows,onFollow,onUnfollow}){
  const [growers,setGrowers]=useState([]);const [loading,setLoading]=useState(true);const [search,setSearch]=useState("");
  const [sortG,setSortG]=useState("diaries"); // diaries | recent | name
  useEffect(()=>{(async()=>{
    try{
      const profiles=await sb.from("profiles").select("*",`&order=created_at.desc`);
      const diaries=await sb.from("diaries").select("user_id,likes_count",`&hidden=eq.false`);
      const countMap={},likesMap={};
      diaries.forEach(d=>{countMap[d.user_id]=(countMap[d.user_id]||0)+1;likesMap[d.user_id]=(likesMap[d.user_id]||0)+(d.likes_count||0);});
      setGrowers(profiles.map(p=>({...p,diaryCount:countMap[p.id]||0,totalLikes:likesMap[p.id]||0,level:getUserLevel(countMap[p.id]||0)})));
    }catch{}setLoading(false);
  })();},[]);
  const sorted=[...growers].sort((a,b)=>sortG==="diaries"?(b.diaryCount-a.diaryCount):sortG==="likes"?(b.totalLikes-a.totalLikes):sortG==="name"?((a.username||"").localeCompare(b.username||"")):new Date(b.created_at)-new Date(a.created_at));
  const filtered=search?sorted.filter(g=>(g.username||"").toLowerCase().includes(search.toLowerCase())):sorted;
  const medals=["🥇","🥈","🥉"];
  return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      <div style={{marginBottom:"24px"}}>
        <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>👥 Cultivadores</h1>
        <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 16px"}}>Conheça a comunidade e o ranking</p>
        <input style={{...baseInput,marginBottom:"12px"}} value={search} onChange={e=>setSearch(e.target.value)} placeholder="🔍 Buscar cultivador..."/>
        <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
          {[["diaries","🏆 Mais Diários"],["likes","❤️ Mais Curtidas"],["recent","🆕 Recentes"],["name","🔤 A-Z"]].map(([v,l])=>(
            <button key={v} onClick={()=>setSortG(v)} style={{padding:"6px 12px",borderRadius:"20px",border:sortG===v?`1px solid ${C.accent}`:`1px solid ${C.border}`,background:sortG===v?C.accentBg:C.surface2,color:sortG===v?C.accent:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"500"}}>{l}</button>
          ))}
        </div>
      </div>
      {loading?<div style={{textAlign:"center",padding:"60px",color:C.dim}}>Carregando...</div>:
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:"16px"}}>
        {filtered.map((g,idx)=>(
          <div key={g.id} onClick={()=>onViewProfile?.(g)} style={{background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"20px 16px",textAlign:"center",cursor:"pointer",transition:"all 0.2s",boxShadow:"0 2px 8px rgba(0,0,0,0.04)",position:"relative"}}>
            {idx<3&&(sortG==="diaries"||sortG==="likes")&&<div style={{position:"absolute",top:"-6px",left:"-6px",fontSize:"20px"}}>{medals[idx]}</div>}
            <div style={{width:"64px",height:"64px",borderRadius:"50%",margin:"0 auto 12px",overflow:"hidden",border:`3px solid ${g.level?.color||C.accent}`,display:"flex",alignItems:"center",justifyContent:"center",background:C.surface2,fontSize:"28px"}}>
              {g.avatar_url?<img src={g.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:g.avatar||"🌱"}
            </div>
            <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"4px"}}>{g.username}</div>
            <div style={{fontFamily:F.sans,fontSize:"11px",color:g.level?.color||C.accent,fontWeight:"600",marginBottom:"6px"}}>{g.level?.emoji} {g.level?.name}</div>
            <div style={{display:"flex",justifyContent:"center",gap:"12px",fontFamily:F.sans,fontSize:"11px",color:C.dim}}>
              <span>📔 {g.diaryCount}</span>
              <span>❤️ {g.totalLikes}</span>
            </div>
            {g.city&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>📍 {g.city}</div>}
            {user&&g.id!==user.id&&<button onClick={e=>{e.stopPropagation();follows?.includes(g.id)?onUnfollow?.(g.id):onFollow?.(g.id);}} style={{marginTop:"8px",padding:"5px 14px",borderRadius:"20px",border:follows?.includes(g.id)?`1px solid ${C.border}`:`1px solid ${C.accent}`,background:follows?.includes(g.id)?C.surface2:C.accent,color:follows?.includes(g.id)?C.muted:C.onAccent,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{follows?.includes(g.id)?"Seguindo":"+ Seguir"}</button>}
          </div>
        ))}
      </div>}
      {!loading&&filtered.length===0&&<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum cultivador encontrado.</div>}
    </div>
  );
}

// ─── Concursos (Contests) Page ───
function ContestsPage({onBack}){
  const contests=[
    {id:1,emoji:"🌸",title:"Bud Mais Bonito",desc:"Mostre o bud mais impressionante do seu cultivo! Os mais curtidos ganham destaque.",status:"Em breve",color:"#e53e3e"},
    {id:2,emoji:"📸",title:"Foto da Semana",desc:"Compartilhe a melhor foto da sua grow room ou jardim. A comunidade vota!",status:"Em breve",color:"#d69e2e"},
    {id:3,emoji:"👨‍🌾",title:"Cultivador do Mês",desc:"O cultivador mais ativo e com melhores diários é escolhido pela comunidade.",status:"Em breve",color:"#38a169"},
    {id:4,emoji:"🧬",title:"Melhor Genética",desc:"Qual strain produziu o melhor resultado? Poste seu diário e concorra!",status:"Em breve",color:"#3182ce"},
  ];
  return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>🏆 Concursos</h1>
      <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 32px"}}>Participe dos concursos da comunidade e ganhe destaque!</p>
      <div style={{display:"flex",flexDirection:"column",gap:"20px"}}>
        {contests.map(c=>(
          <div key={c.id} style={{background:C.cardBg,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"24px",display:"flex",gap:"20px",alignItems:"center",boxShadow:"0 2px 8px rgba(0,0,0,0.04)"}}>
            <div style={{width:"72px",height:"72px",borderRadius:"16px",background:c.color+"14",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"36px",flexShrink:0}}>{c.emoji}</div>
            <div style={{flex:1}}>
              <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"6px"}}>
                <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:0}}>{c.title}</h3>
                <span style={{padding:"2px 10px",borderRadius:"20px",background:c.color+"18",color:c.color,fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{c.status}</span>
              </div>
              <p style={{fontFamily:F.body,fontSize:"14px",color:C.muted,margin:0,lineHeight:"1.5"}}>{c.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <div style={{textAlign:"center",marginTop:"40px",padding:"32px",background:C.surface2,borderRadius:"16px"}}>
        <div style={{fontSize:"40px",marginBottom:"8px"}}>🚧</div>
        <p style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"600",marginBottom:"4px"}}>Em construção!</p>
        <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted}}>Os concursos serão abertos em breve. Fique ligado!</p>
      </div>
    </div>
  );
}

// ─── Comunidades (Forum) Page ───
function ForumPage({user,onBack}){
  const [categories,setCategories]=useState([]);
  const [topics,setTopics]=useState([]);
  const [threads,setThreads]=useState([]);
  const [replies,setReplies]=useState([]);
  const [loading,setLoading]=useState(true);
  const [latestThreads,setLatestThreads]=useState([]);
  const [view,setView]=useState("categories");
  const [selCat,setSelCat]=useState(null);
  const [selTopic,setSelTopic]=useState(null);
  const [selThread,setSelThread]=useState(null);
  const [newTitle,setNewTitle]=useState("");
  const [newContent,setNewContent]=useState("");
  const [replyText,setReplyText]=useState("");
  const [showNewThread,setShowNewThread]=useState(false);
  const [posting,setPosting]=useState(false);

  useEffect(()=>{(async()=>{
    try{
      const cats=await sb.from("forum_categories").select("*",`&order=sort_order.asc`);
      const tops=await sb.from("forum_topics").select("*",`&order=sort_order.asc`);
      let lt=[];try{lt=await sb.from("forum_threads").select("id,title,topic_id,created_at,profiles(username)",`&order=created_at.desc&limit=20`);}catch{}
      setCategories(cats||[]);setTopics(tops||[]);setLatestThreads(lt||[]);
    }catch(e){console.error("Forum load:",e);}
    setLoading(false);
  })();},[]);

  const loadThreads=async(tid)=>{try{const r=await sb.from("forum_threads").select("*,profiles(username,avatar,avatar_url)",`&topic_id=eq.${tid}&order=pinned.desc,updated_at.desc`);setThreads(r||[]);}catch{setThreads([]);}};
  const loadReplies=async(tid)=>{try{const r=await sb.from("forum_replies").select("*,profiles(username,avatar,avatar_url)",`&thread_id=eq.${tid}&order=created_at.asc`);setReplies(r||[]);}catch{setReplies([]);}};

  const catTopics=(catId)=>(topics||[]).filter(t=>t.category_id===catId);
  const fmtDate=(d)=>{try{return new Date(d).toLocaleDateString("pt-BR",{day:"numeric",month:"short"});}catch{return"";}};
  const getLatestForCat=(catId)=>{const tids=catTopics(catId).map(t=>t.id);return(latestThreads||[]).find(t=>tids.includes(t.topic_id));};

  const renderContent=(text)=>{
    if(!text)return{__html:""};
    try{
      const h=text
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
        // YouTube embeds
        .replace(/\[youtube:([a-zA-Z0-9_-]{11})\]/g,'<div style="position:relative;padding-bottom:56.25%;height:0;margin:12px 0;border-radius:10px;overflow:hidden"><iframe src="https://www.youtube.com/embed/$1?cc_load_policy=1&cc_lang_pref=pt&hl=pt&rel=0" style="position:absolute;top:0;left:0;width:100%;height:100%;border:none" allowfullscreen></iframe></div>')
        // Video embeds [video:url] (new format)
        .replace(/\[video:([^\]]+)\]/g,'<div style="margin:12px 0;border-radius:10px;overflow:hidden"><video src="$1" controls playsinline style="width:100%;max-height:400px;border-radius:10px;background:#000"></video></div>')
        // Legacy video links [Vídeo](url)
        .replace(/\[Vídeo\]\(([^)]+)\)/g,'<div style="margin:12px 0;border-radius:10px;overflow:hidden"><video src="$1" controls playsinline style="width:100%;max-height:400px;border-radius:10px;background:#000"></video></div>')
        // Images
        .replace(/!\[([^\]]*)\]\(([^)]+)\)/g,'<img src="$2" alt="$1" style="max-width:100%;border-radius:10px;margin:8px 0"/>')
        // Formatting
        .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
        .replace(/\*(.+?)\*/g,"<em>$1</em>")
        .replace(/^&gt; (.+)$/gm,'<blockquote style="border-left:3px solid #1B9E42;padding:6px 14px;color:#888;margin:8px 0;background:rgba(27,158,66,0.04);border-radius:0 8px 8px 0">$1</blockquote>')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2" target="_blank" style="color:#1B9E42">$1</a>')
        .replace(/\n/g,"<br/>");
      return{__html:h};
    }catch{return{__html:(text||"").replace(/</g,"&lt;").replace(/\n/g,"<br/>")};}
  };

  const insertTag=(setter,tag)=>{
    if(tag==="b")setter(p=>p+"**negrito**");
    else if(tag==="i")setter(p=>p+"*itálico*");
    else if(tag==="q")setter(p=>p+"\n> citação\n");
    else if(tag==="link")setter(p=>p+"[link](https://)");
    else if(tag==="yt"){
      const url=window.prompt("Cole a URL do YouTube:");if(!url)return;
      const m=url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
      if(m)setter(p=>p+"\n[youtube:"+m[1]+"]\n");
    }
  };

  const [uploadingMedia,setUploadingMedia]=useState(false);

  const handleMediaUpload=async(e,setter)=>{
    const f=e.target?.files?.[0];if(!f)return;
    setUploadingMedia(true);
    try{
      const path="forum/"+Date.now()+"-"+Math.random().toString(36).slice(2,5)+"."+(f.name.split(".").pop()||"jpg");
      const ok=await sbStorage.upload(path,f);
      if(ok){const url=sbStorage.getUrl(path);setter(p=>p+(f.type.startsWith("video")?"\n[video:"+url+"]\n":"\n![foto]("+url+")\n"));}
    }catch(er){console.error(er);}
    setUploadingMedia(false);
    if(e.target)e.target.value="";
  };

  const tbBtnSt={width:"32px",height:"32px",borderRadius:"6px",border:"1px solid "+C.border,background:C.cardBg,color:C.text,cursor:"pointer",fontSize:"13px",display:"flex",alignItems:"center",justifyContent:"center"};
  const renderToolbar=(setter)=>(
    <div style={{display:"flex",gap:"4px",flexWrap:"wrap",marginBottom:"8px",padding:"6px 8px",background:C.surface2,borderRadius:"8px",alignItems:"center"}}>
      <button type="button" onClick={()=>insertTag(setter,"b")} style={{...tbBtnSt,fontWeight:"800"}}>B</button>
      <button type="button" onClick={()=>insertTag(setter,"i")} style={tbBtnSt}>I</button>
      <button type="button" onClick={()=>insertTag(setter,"q")} style={tbBtnSt}>❝</button>
      <button type="button" onClick={()=>insertTag(setter,"link")} style={tbBtnSt}>🔗</button>
      <div style={{width:"1px",height:"24px",background:C.border,margin:"4px 2px"}}/>
      <label style={{...tbBtnSt,border:"1px solid "+C.accent,background:C.accentBg,color:C.accent,opacity:uploadingMedia?0.5:1,pointerEvents:uploadingMedia?"none":"auto"}}>📷<input type="file" accept="image/*,video/*" style={{display:"none"}} onChange={e=>handleMediaUpload(e,setter)} disabled={uploadingMedia}/></label>
      <button type="button" onClick={()=>insertTag(setter,"yt")} style={{...tbBtnSt,border:"1px solid #e53e3e",background:"rgba(229,62,62,0.06)",color:"#e53e3e"}}>▶️</button>
      {uploadingMedia&&<div style={{display:"flex",alignItems:"center",gap:"6px",marginLeft:"4px",padding:"4px 10px",background:C.accentBg,borderRadius:"6px",animation:"uploadPulse 1.5s ease-in-out infinite"}}>
        <div style={{width:"14px",height:"14px",border:"2px solid "+C.accent,borderTop:"2px solid transparent",borderRadius:"50%",animation:"uploadSpin 0.8s linear infinite"}}/>
        <span style={{fontFamily:F.sans,fontSize:"11px",color:C.accent,fontWeight:"600"}}>Enviando...</span>
      </div>}
    </div>
  );

  const createThread=async()=>{
    if(!newTitle.trim()||!newContent.trim()||!user||!selTopic)return;
    setPosting(true);
    try{
      await sb.from("forum_threads").insert({topic_id:selTopic.id,author_id:user.id,title:newTitle.trim().substring(0,200),content:newContent.substring(0,5000)});
      await loadThreads(selTopic.id);
      setNewTitle("");setNewContent("");setShowNewThread(false);
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const postReply=async()=>{
    if(!replyText.trim()||!user||!selThread)return;
    setPosting(true);
    try{
      await sb.from("forum_replies").insert({thread_id:selThread.id,author_id:user.id,content:replyText.substring(0,5000)});
      await loadReplies(selThread.id);
      setReplyText("");
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const av=(p)=><div style={{width:"32px",height:"32px",borderRadius:"50%",background:C.surface2,overflow:"hidden",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"16px",border:"1px solid "+C.border,flexShrink:0}}>{p?.avatar_url?<img src={p.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:(p?.avatar||"🌱")}</div>;

  const goBack=()=>{
    if(view==="thread"){setView("threads");setSelThread(null);setReplies([]);}
    else if(view==="threads"){setView("topics");setSelTopic(null);setThreads([]);}
    else if(view==="topics"){setView("categories");setSelCat(null);}
  };
  const backBtn=()=><button type="button" onClick={goBack} style={{padding:"8px 16px",borderRadius:"20px",border:"1px solid "+C.border,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"20px"}}>← Voltar</button>;

  if(loading)return <div style={{textAlign:"center",padding:"60px",color:C.dim}}>Carregando...</div>;

  // ─── THREAD DETAIL ───
  if(view==="thread"&&selThread) return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      {backBtn()}
      <div style={{background:C.cardBg,borderRadius:"16px",border:"1px solid "+C.border,padding:"20px 24px",marginBottom:"16px"}}>
        <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800",margin:"0 0 12px"}}>{selThread.title||""}</h2>
        <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"12px"}}>
          {av(selThread.profiles)}
          <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{selThread.profiles?.username||"Anônimo"}</span>
          <span style={{fontFamily:F.sans,fontSize:"12px",color:C.dim}}>{fmtDate(selThread.created_at)}</span>
        </div>
        <div style={{fontFamily:F.body,fontSize:"15px",color:C.text,lineHeight:"1.7"}} dangerouslySetInnerHTML={renderContent(selThread.content)}/>
      </div>

      <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",marginBottom:"12px"}}>💬 Respostas ({(replies||[]).length})</h3>
      {(replies||[]).map(r=>(
        <div key={r.id} style={{background:C.cardBg,borderRadius:"12px",border:"1px solid "+C.border,padding:"14px 18px",marginBottom:"8px"}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:"8px"}}>
            <div style={{display:"flex",alignItems:"center",gap:"8px"}}>
              {av(r.profiles)}
              <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{r.profiles?.username||"Anônimo"}</span>
              <span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{fmtDate(r.created_at)}</span>
            </div>
            <button type="button" onClick={()=>setReplyText(p=>p+"\n> "+(r.profiles?.username||"")+": "+(r.content||"").substring(0,80)+"...\n\n")} style={{padding:"4px 10px",borderRadius:"6px",border:"1px solid "+C.border,background:C.surface2,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>❝ Citar</button>
          </div>
          <div style={{fontFamily:F.body,fontSize:"14px",color:C.text,lineHeight:"1.6"}} dangerouslySetInnerHTML={renderContent(r.content)}/>
        </div>
      ))}

      <div style={{marginTop:"16px",background:C.cardBg,borderRadius:"12px",border:"1px solid "+C.border,padding:"16px"}}>
        <label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",marginBottom:"8px",display:"block"}}>Sua resposta</label>
        {renderToolbar(setReplyText)}
        <textarea style={{...baseInput,minHeight:"100px",resize:"vertical",marginBottom:"10px"}} value={replyText} onChange={e=>setReplyText(e.target.value)} placeholder="Escreva sua resposta... **negrito** *itálico* > citação"/>
        <button type="button" onClick={postReply} disabled={posting||!replyText.trim()} style={{...btnPrimary,width:"auto",padding:"10px 24px",opacity:(posting||!replyText.trim())?0.5:1}}>{posting?"Enviando...":"Postar Resposta"}</button>
      </div>
    </div>
  );

  // ─── THREAD LIST ───
  if(view==="threads"&&selTopic) return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      {backBtn()}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"24px"}}>
        <h1 style={{fontFamily:F.sans,fontSize:"24px",fontWeight:"800",margin:0}}>{selTopic.emoji} {selTopic.name}</h1>
        <button type="button" onClick={()=>setShowNewThread(true)} style={{...btnPrimary,width:"auto",padding:"10px 20px",fontSize:"13px"}}>+ Novo Tópico</button>
      </div>
      {(threads||[]).length===0&&<div style={{textAlign:"center",padding:"40px",color:C.dim,fontFamily:F.sans}}>Nenhum tópico ainda. Seja o primeiro!</div>}
      {(threads||[]).map(t=>(
        <div key={t.id} onClick={()=>{setSelThread(t);loadReplies(t.id);setView("thread");}} style={{background:C.cardBg,borderRadius:"12px",border:"1px solid "+C.border,padding:"14px 18px",marginBottom:"8px",cursor:"pointer",display:"flex",alignItems:"center",gap:"14px"}}>
          {av(t.profiles)}
          <div style={{flex:1,minWidth:0}}>
            <h3 style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",margin:0,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t.pinned?"📌 ":""}{t.title||""}</h3>
            <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim,marginTop:"2px"}}>{t.profiles?.username||""} · {fmtDate(t.created_at)}</div>
          </div>
        </div>
      ))}
      {showNewThread&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"flex-start",justifyContent:"center",zIndex:300,padding:"40px 20px",overflowY:"auto"}} onClick={()=>setShowNewThread(false)}>
        <div onClick={e=>e.stopPropagation()} style={{background:C.surface,borderRadius:"16px",border:"1px solid "+C.border,padding:"24px",width:"100%",maxWidth:"600px"}}>
          <h3 style={{fontFamily:F.sans,fontSize:"20px",fontWeight:"800",margin:"0 0 16px"}}>📝 Novo Tópico em {selTopic.name}</h3>
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Assunto *</label><input style={baseInput} value={newTitle} onChange={e=>setNewTitle(e.target.value)} placeholder="Título do tópico"/></div>
          <div style={{marginBottom:"16px"}}><label style={labelSt}>Mensagem *</label>
            {renderToolbar(setNewContent)}
            <textarea style={{...baseInput,minHeight:"160px",resize:"vertical"}} value={newContent} onChange={e=>setNewContent(e.target.value)} placeholder="Escreva sua mensagem..."/>
          </div>
          <div style={{display:"flex",gap:"12px"}}><button type="button" onClick={()=>setShowNewThread(false)} style={btnSecondary}>Cancelar</button><button type="button" onClick={createThread} disabled={posting||!newTitle.trim()||!newContent.trim()} style={{...btnPrimary,opacity:(posting||!newTitle.trim()||!newContent.trim())?0.5:1}}>{posting?"Criando...":"Criar Tópico"}</button></div>
        </div>
      </div>}
    </div>
  );

  // ─── TOPICS ───
  if(view==="topics"&&selCat) return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      {backBtn()}
      <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>{selCat.emoji} {selCat.name}</h1>
      <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>{selCat.description||""}</p>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:"12px"}}>
        {catTopics(selCat.id).map(t=>(
          <div key={t.id} onClick={()=>{setSelTopic(t);loadThreads(t.id);setView("threads");}} style={{background:C.cardBg,borderRadius:"14px",border:"1px solid "+C.border,padding:"18px",cursor:"pointer",boxShadow:"0 2px 8px rgba(0,0,0,0.04)"}}>
            <div style={{fontSize:"28px",marginBottom:"8px"}}>{t.emoji}</div>
            <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",margin:0}}>{t.name}</h3>
          </div>
        ))}
      </div>
    </div>
  );

  // ─── CATEGORIES (main) ───
  return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>🏛️ Comunidade</h1>
      <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Fóruns de discussão da comunidade</p>
      <div style={{display:"flex",flexDirection:"column",gap:"16px"}}>
        {(categories||[]).map(cat=>{
          const latest=getLatestForCat(cat.id);
          return(
          <div key={cat.id} onClick={()=>{setSelCat(cat);setView("topics");}} style={{background:C.cardBg,borderRadius:"16px",border:"1px solid "+C.border,padding:"20px",cursor:"pointer",boxShadow:"0 2px 8px rgba(0,0,0,0.04)"}}>
            <div style={{display:"flex",alignItems:"center",gap:"14px"}}>
              <div style={{width:"52px",height:"52px",borderRadius:"14px",background:C.accentBg,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"26px",flexShrink:0}}>{cat.emoji}</div>
              <div style={{flex:1,minWidth:0}}>
                <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:0}}>{cat.name}</h3>
                <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,margin:"2px 0 0"}}>{cat.description||""}</p>
                <div style={{display:"flex",gap:"8px",marginTop:"6px",flexWrap:"wrap"}}>{catTopics(cat.id).slice(0,5).map(t=><span key={t.id} style={{padding:"2px 10px",borderRadius:"8px",background:C.surface2,fontSize:"11px",fontFamily:F.sans,color:C.dim}}>{t.emoji} {t.name}</span>)}</div>
                {latest&&<div style={{marginTop:"8px",padding:"6px 10px",background:C.surface2,borderRadius:"8px",fontSize:"11px",fontFamily:F.sans,color:C.dim}}>💬 <strong>{latest.profiles?.username||""}</strong>: {(latest.title||"").substring(0,50)} · {fmtDate(latest.created_at)}</div>}
              </div>
              <span style={{color:C.dim,fontSize:"18px"}}>›</span>
            </div>
          </div>);
        })}
      </div>
    </div>
  );
}
// ─── Pragas e Fungos Page (content from PDF) ───
function PestsPage({onBack,onViewImage}){
  const pests=[
    {name:"Aranha Vermelha",emoji:"🕷️",color:"#e53e3e",
      chars:"Ácaro com quatro patas, cabeça de ~0.5mm. Verde-claro com manchas negras no verão, laranja no outono/inverno. Instala-se por trás das folhas.",
      damage:"Alimenta-se do sumo celular das folhas. Surgem manchas claras que tornam a folha amarela, seca e morre. Danos irreversíveis.",
      reproduction:"Reproduz-se por ovos (40-55% humidade). Ovos ovais amarelados/avermelhados na parte debaixo da folha. 3 estados: Larva → Protoninfa → Deutoninfa.",
      elimination:"Preventivo: óleo de Neem a cada 15 dias. Crescimento: Dicogreen, Rotenona, Compo aranha vermelha. Pulverizar sempre por baixo da folha. Na floração: só água.",
      enemies:"Phitoseiulus Persimilis, Amblyseius Californicus, Feltiella Acarisuga, Stehorus Punctillum"},
    {name:"Mosca Branca",emoji:"🪰",color:"#d69e2e",
      chars:"Insecto com 2 asas brancas, não supera 2mm. Fixa-se na parte inferior das folhas no inverno. Atraída por cor amarelo e verde-claro.",
      damage:"Subtrai seiva da planta. O excremento forma lâmina pegajosa que facilita fungos e vírus. Transmite doenças vérmicas.",
      reproduction:"180-200 ovos na parte inferior das folhas. Eclosão em 20-24h. 4 estados larvais. 1 mês em estado larvário.",
      elimination:"Óleo de neem, piretrina, Biokill, rotenona, sabão potássico. Tiras adesivas amarelas reduzem a propagação.",
      enemies:"Eretmocerus Eremicus, Macrolophus Caliginosus"},
    {name:"Pulga (Pulgão)",emoji:"🐛",color:"#38a169",
      chars:"Tamanho 1-3mm, cores variadas (negro, amarelo, verde). Patas compridas, duas antenas, forma de pêra. Vive em colónias massivas.",
      damage:"Extrai sumo celular. Deformação de folhas, transmite doenças virais, produz capa pegajosa que facilita fungos. Formigas são aliadas dos pulgões.",
      reproduction:"Por ovos e de forma sexual. Capacidade elevada de reprodução. Após gerações criam asas para migrar.",
      elimination:"Óleo de neem, rotenona, Compo anti-pulga. Detectar cedo é essencial — em floração é mais difícil.",
      enemies:"Joaninha (Adalia Bipunctata), Aphidius Colemani, Chrysopa Carnea"},
    {name:"Trip",emoji:"🦗",color:"#805ad5",
      chars:"Insecto de 0.8-3mm, forma comprida, tons castanhos/cinzentos. 2 asas, 2 antenas. Uma das pragas mais importantes.",
      damage:"Extraem sumo celular das folhas, flores e frutos. Aspecto cinzento prateado. Bons transmissores de vírus.",
      reproduction:"Por ovos, temperatura ideal 20-25°C. 6 estados: Ovo → 2 larvais → Proninfa → Ninfa → Adulto.",
      elimination:"Tiras adesivas azuis. Óleo de neem, Biokill, Dimegreen40, rotenona, sabão potássico.",
      enemies:"Amblyseius Cucumeris, Amblyseius Degenerans, Orius Majusculus"},
    {name:"Mosca Minadora",emoji:"🪲",color:"#dd6b20",
      chars:"Mosca pequena de 0.4-0.5mm, coloração café a verde oliva. Vive no interior das folhas criando galerias.",
      damage:"Larvas escavam galerias nas folhas, destruindo-as. Reduz capacidade fotossintética e vigor da planta.",
      reproduction:"Ovos de ~1mm, transparentes. Incubação 3-10 dias. 3 estados larvais em ~8-10 dias. Ciclo total: 15-20 dias a 25°C.",
      elimination:"Óleo de neem, Biokill, rotenona, Dimegreen40 (só em crescimento). Remédio caseiro: água com cigarro macerado, pulverizar e repetir em 1 semana.",
      enemies:"Dacnusa Sibirica, Diglyphus Isaea"},
    {name:'Mosca da Humidade "Mosquito"',emoji:"🦟",color:"#319795",
      chars:"Adultos cinza/preto, 2-4mm, patas compridas. Adoram ambientes húmidos e escuros. Voam lento sobre substrato húmido.",
      damage:"Larvas alimentam-se dos pelos radiculares, impedindo a planta de se alimentar. Raízes infectam-se de fungos.",
      reproduction:"Fêmeas põem até 200 ovos semanais no substrato húmido. Nascem como larva e após se fortalecerem, voam.",
      elimination:"Óleo de neem por borrifadas no substrato. Cobrir terra com vermiculita. Biokill.",
      enemies:"Atheta Coriaria, Hypoapsis Miles, Steinernema-System"},
    {name:"Cochonilha",emoji:"🐚",color:"#e53e3e",
      chars:"Corpo coberto com excrescências cerosas brancas. Uma das pragas mais difíceis de controlar. Machos têm asas.",
      damage:"Absorvem seiva e produzem melada que facilita fungos. Reduzem vigor da planta. Formigas são aliadas.",
      reproduction:"300-500 ovos em bolsa de fibra cerosa. 3 estados de ninfas. Ciclo: 30 dias (30°C) a 90 dias (18°C).",
      elimination:"Compo Anti Cochonilhas (crescimento). Em floração: remoção manual. Biokill.",
      enemies:"Cryptolaemus Montrouzieri (joaninha), Leptomastix Dactylopii"},
    {name:"Larva / Lagarta",emoji:"🐛",color:"#2d3748",
      chars:"Família dos lepidópteros, +10.000 espécies. Estado jovem de borboleta. Fazem buracos em folhas, flores, frutos e talos.",
      damage:"Decoram folhas impedindo fotossíntese. Nos cabeços fazem buracos e túneis, facilitando Botrytis.",
      reproduction:"Ovos na parte inferior das folhas. Larva 12-28 dias. Pupa no substrato 10-18 dias.",
      elimination:"Bacillus Thuringiensis (BT) — bactéria em pó diluída em água. Funciona em crescimento e floração. Reaplicar após chuva.",
      enemies:"Bacillus Thuringiensis, Vespas predadoras"},
  ];
  const tipExtra={title:"⚠️ Excesso de Rega",text:"Regar demais pode causar fungos nas raízes e arrastar os nutrientes do substrato, deixando a planta sem alimentação. Controle a frequência e quantidade de água."};
  const [expanded,setExpanded]=useState(null);

  return(
    <div style={{maxWidth:"800px",margin:"0 auto",padding:"24px"}}>
      <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",margin:"0 0 4px"}}>🐛 Pragas e Fungos</h1>
      <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,margin:"0 0 24px"}}>Guia completo para identificar e combater pragas no seu cultivo</p>

      {/* Excesso de rega warning */}
      <div style={{background:"#fef3c7",borderRadius:"16px",padding:"20px 24px",marginBottom:"24px",border:"1px solid #f59e0b33"}}>
        <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",margin:"0 0 8px",color:"#92400e"}}>{tipExtra.title}</h3>
        <p style={{fontFamily:F.body,fontSize:"14px",color:"#78350f",margin:0,lineHeight:"1.6"}}>{tipExtra.text}</p>
      </div>

      <div style={{display:"flex",flexDirection:"column",gap:"12px"}}>
        {pests.map((p,i)=>(
          <div key={i} style={{background:C.cardBg,borderRadius:"16px",border:`1px solid ${expanded===i?p.color+"44":C.border}`,overflow:"hidden",transition:"all 0.2s"}}>
            <div onClick={()=>setExpanded(expanded===i?null:i)} style={{padding:"18px 20px",display:"flex",alignItems:"center",gap:"16px",cursor:"pointer"}}>
              <div style={{width:"48px",height:"48px",borderRadius:"12px",background:p.color+"14",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"24px",flexShrink:0}}>{p.emoji}</div>
              <div style={{flex:1}}>
                <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",margin:0}}>{p.name}</h3>
                <p style={{fontFamily:F.sans,fontSize:"12px",color:C.muted,margin:"2px 0 0",lineHeight:"1.4"}}>{p.chars.substring(0,80)}...</p>
              </div>
              <span style={{fontSize:"18px",color:C.dim,transform:expanded===i?"rotate(180deg)":"rotate(0)",transition:"transform 0.2s"}}>▼</span>
            </div>
            {expanded===i&&<div style={{padding:"0 20px 20px",borderTop:`1px solid ${C.border}`}}>
              <div style={{display:"grid",gap:"16px",marginTop:"16px"}}>
                <div><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:p.color,marginBottom:"4px",textTransform:"uppercase"}}>🔬 Características</div><p style={{fontFamily:F.body,fontSize:"13px",color:C.text,margin:0,lineHeight:"1.6"}}>{p.chars}</p></div>
                <div><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:"#e53e3e",marginBottom:"4px",textTransform:"uppercase"}}>💀 Danos</div><p style={{fontFamily:F.body,fontSize:"13px",color:C.text,margin:0,lineHeight:"1.6"}}>{p.damage}</p></div>
                <div><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:"#3182ce",marginBottom:"4px",textTransform:"uppercase"}}>🥚 Reprodução</div><p style={{fontFamily:F.body,fontSize:"13px",color:C.text,margin:0,lineHeight:"1.6"}}>{p.reproduction}</p></div>
                <div style={{background:C.accentBg,borderRadius:"12px",padding:"14px"}}><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:C.accent,marginBottom:"4px",textTransform:"uppercase"}}>🧪 Eliminação</div><p style={{fontFamily:F.body,fontSize:"13px",color:C.text,margin:0,lineHeight:"1.6"}}>{p.elimination}</p></div>
                <div><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:"#805ad5",marginBottom:"4px",textTransform:"uppercase"}}>🦎 Inimigos Naturais</div><p style={{fontFamily:F.body,fontSize:"13px",color:C.text,margin:0,lineHeight:"1.6"}}>{p.enemies}</p></div>
              </div>
            </div>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Privacy Policy (LGPD) ───
function PrivacyPolicyPage({onBack}){
  const s={maxWidth:"740px",margin:"0 auto",padding:"32px 24px"};
  const h2={fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"28px 0 10px",color:C.text};
  const p={fontFamily:F.body,fontSize:"14px",lineHeight:"1.8",color:C.muted,margin:"0 0 14px"};
  return(<div style={s}>
    <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px"}}>← Voltar</button>
    <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",marginBottom:"8px"}}>🔒 Política de Privacidade</h1>
    <p style={{...p,color:C.dim,fontSize:"12px"}}>Última atualização: Março de 2026</p>
    <p style={p}>O Diário da Planta ("nós", "nosso") se compromete a proteger a privacidade dos seus dados pessoais, em conformidade com a Lei Geral de Proteção de Dados (LGPD — Lei nº 13.709/2018).</p>

    <h2 style={h2}>1. Dados que coletamos</h2>
    <p style={p}>Coletamos apenas os dados necessários para o funcionamento da plataforma: email, nome de usuário, cidade (opcional), bio (opcional), foto de perfil (opcional), e o conteúdo que você cria (diários, semanas, comentários, mensagens).</p>

    <h2 style={h2}>2. Finalidade do tratamento</h2>
    <p style={p}>Seus dados são utilizados exclusivamente para: autenticação e acesso à plataforma; exibição do seu perfil público para outros usuários; funcionamento dos diários, comentários e mensagens; envio de notificações da plataforma; e moderação de conteúdo pela administração.</p>

    <h2 style={h2}>3. Base legal</h2>
    <p style={p}>O tratamento dos seus dados é realizado com base no seu consentimento (Art. 7º, I da LGPD), fornecido ao criar sua conta, e na execução do contrato de uso da plataforma (Art. 7º, V).</p>

    <h2 style={h2}>4. Compartilhamento de dados</h2>
    <p style={p}>Não vendemos, alugamos ou compartilhamos seus dados pessoais com terceiros para fins comerciais. Seus dados podem ser compartilhados apenas com: Supabase Inc. (provedor de infraestrutura e banco de dados); Vercel Inc. (provedor de hospedagem); e autoridades competentes quando exigido por lei.</p>

    <h2 style={h2}>5. Armazenamento e segurança</h2>
    <p style={p}>Seus dados são armazenados em servidores seguros da Supabase (AWS), protegidos por criptografia em trânsito (TLS/HTTPS) e em repouso. Senhas são armazenadas com hash bcrypt e nunca são acessíveis em texto puro. Implementamos Row Level Security (RLS) para garantir que cada usuário acesse apenas seus próprios dados.</p>

    <h2 style={h2}>6. Seus direitos (LGPD Art. 18)</h2>
    <p style={p}>Você tem direito a: acessar seus dados pessoais; corrigir dados incompletos ou desatualizados; solicitar a exclusão dos seus dados (opção "Excluir minha conta" no perfil); revogar o consentimento a qualquer momento; e solicitar portabilidade dos seus dados. Para exercer esses direitos, utilize as opções no seu perfil ou entre em contato pelo email: contato@diariodaplanta.com.br.</p>

    <h2 style={h2}>7. Cookies</h2>
    <p style={p}>Utilizamos cookies estritamente necessários para: manter sua sessão de login ativa (token de autenticação); e armazenar suas preferências (tema claro/escuro). Não utilizamos cookies de rastreamento, analytics de terceiros, ou cookies de publicidade.</p>

    <h2 style={h2}>8. Retenção de dados</h2>
    <p style={p}>Seus dados são mantidos enquanto sua conta estiver ativa. Ao solicitar a exclusão da conta, todos os seus dados pessoais, diários, fotos, comentários e mensagens são removidos permanentemente em até 30 dias.</p>

    <h2 style={h2}>9. Alterações nesta política</h2>
    <p style={p}>Podemos atualizar esta política periodicamente. Notificaremos sobre alterações significativas através de notificação na plataforma.</p>

    <h2 style={h2}>10. Contato do Encarregado (DPO)</h2>
    <p style={p}>Para questões sobre proteção de dados: contato@diariodaplanta.com.br</p>
  </div>);
}

// ─── Terms of Use ───
function TermsPage({onBack}){
  const s={maxWidth:"740px",margin:"0 auto",padding:"32px 24px"};
  const h2={fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:"28px 0 10px",color:C.text};
  const p={fontFamily:F.body,fontSize:"14px",lineHeight:"1.8",color:C.muted,margin:"0 0 14px"};
  return(<div style={s}>
    <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px"}}>← Voltar</button>
    <h1 style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",marginBottom:"8px"}}>📋 Termos de Uso</h1>
    <p style={{...p,color:C.dim,fontSize:"12px"}}>Última atualização: Março de 2026</p>
    <p style={p}>Ao criar uma conta e utilizar o Diário da Planta, você concorda com os seguintes termos.</p>

    <h2 style={h2}>1. Aceitação dos termos</h2>
    <p style={p}>Ao acessar ou utilizar a plataforma, você declara ter lido, compreendido e concordado com estes Termos de Uso e com nossa Política de Privacidade. Se não concordar, não utilize a plataforma.</p>

    <h2 style={h2}>2. Descrição do serviço</h2>
    <p style={p}>O Diário da Planta é uma plataforma comunitária para registro e compartilhamento de diários de cultivo de plantas. Oferecemos ferramentas para documentar semanalmente o progresso dos cultivos, incluindo parâmetros, fotos e anotações.</p>

    <h2 style={h2}>3. Cadastro e conta</h2>
    <p style={p}>Você deve fornecer informações verdadeiras ao criar sua conta. Você é responsável por manter a confidencialidade da sua senha e por todas as atividades realizadas em sua conta. Cada pessoa pode ter apenas uma conta.</p>

    <h2 style={h2}>4. Conduta do usuário</h2>
    <p style={p}>Ao utilizar a plataforma, você concorda em não: publicar conteúdo ilegal, ofensivo, difamatório ou que viole direitos de terceiros; utilizar a plataforma para spam, assédio ou qualquer forma de abuso; compartilhar informações pessoais de outros usuários sem consentimento; tentar acessar contas de outros usuários ou sistemas internos da plataforma; e utilizar bots, scripts ou ferramentas automatizadas sem autorização.</p>

    <h2 style={h2}>5. Conteúdo do usuário</h2>
    <p style={p}>Você mantém a propriedade do conteúdo que publica (textos, fotos, vídeos). Ao publicar conteúdo na plataforma, você nos concede uma licença não exclusiva para exibir e distribuir esse conteúdo dentro da plataforma. A administração pode remover conteúdo que viole estes termos.</p>

    <h2 style={h2}>6. Moderação</h2>
    <p style={p}>Nos reservamos o direito de moderar, ocultar ou remover conteúdo, e de suspender ou banir contas que violem estes termos, a critério da administração, com ou sem aviso prévio.</p>

    <h2 style={h2}>7. Isenção de responsabilidade</h2>
    <p style={p}>A plataforma é oferecida "como está". Não garantimos disponibilidade ininterrupta, ausência de erros, ou que o conteúdo publicado por outros usuários seja preciso ou seguro. Não somos responsáveis por danos diretos ou indiretos resultantes do uso da plataforma ou de informações obtidas através dela.</p>

    <h2 style={h2}>8. Exclusão de conta</h2>
    <p style={p}>Você pode excluir sua conta a qualquer momento através da opção "Excluir minha conta" no seu perfil. A exclusão é permanente e remove todos os seus dados conforme descrito na Política de Privacidade.</p>

    <h2 style={h2}>9. Alterações nos termos</h2>
    <p style={p}>Podemos modificar estes termos a qualquer momento. Alterações significativas serão comunicadas por notificação na plataforma. O uso continuado após as alterações constitui aceitação dos novos termos.</p>

    <h2 style={h2}>10. Legislação aplicável</h2>
    <p style={p}>Estes termos são regidos pelas leis da República Federativa do Brasil. Qualquer litígio será resolvido no foro da comarca do domicílio do usuário, conforme previsto no Código de Defesa do Consumidor.</p>
  </div>);
}

// ─── Cookie Banner ───
function CookieBanner({onAccept,onReject}){
  return(
    <div style={{position:"fixed",bottom:0,left:0,right:0,background:C.cardBg,borderTop:`1px solid ${C.border}`,padding:"16px 24px",zIndex:500,boxShadow:"0 -4px 20px rgba(0,0,0,0.1)",display:"flex",alignItems:"center",justifyContent:"center",gap:"16px",flexWrap:"wrap"}}>
      <div style={{flex:1,minWidth:"240px",fontFamily:F.sans,fontSize:"13px",color:C.muted,lineHeight:"1.6"}}>
        🍪 Utilizamos cookies estritamente necessários para manter sua sessão e preferências. Não usamos cookies de rastreamento ou publicidade. <span style={{color:C.dim,fontSize:"12px"}}>Consulte nossa Política de Privacidade.</span>
      </div>
      <div style={{display:"flex",gap:"8px",flexShrink:0}}>
        <button onClick={onReject} style={{padding:"8px 18px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"500"}}>Recusar</button>
        <button onClick={onAccept} style={{padding:"8px 18px",borderRadius:"20px",border:"none",background:C.accent,color:"#fff",cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"600"}}>Aceitar</button>
      </div>
    </div>
  );
}

// ─── Image Viewer (fullscreen) ───
function ImageViewer({ src, onClose }) {
  if(!src) return null;
  return (
    <div onClick={onClose} style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.9)",zIndex:400,display:"flex",alignItems:"center",justifyContent:"center",cursor:"zoom-out",padding:"20px"}}>
      <button onClick={onClose} style={{position:"absolute",top:"20px",right:"20px",width:"40px",height:"40px",borderRadius:"50%",border:"none",background:"rgba(255,255,255,0.15)",color:C.onAccent,cursor:"pointer",fontSize:"20px",display:"flex",alignItems:"center",justifyContent:"center",backdropFilter:"blur(8px)"}}>✕</button>
      <img src={src} alt="" style={{maxWidth:"100%",maxHeight:"90vh",borderRadius:"8px",objectFit:"contain",boxShadow:"0 8px 40px rgba(0,0,0,0.5)"}} onClick={e=>e.stopPropagation()}/>
    </div>
  );
}

// ─── Nav Bar ───
function NavBar({ user, page, setPage, setShowCreate, myDiaries, onLogout, onNavigate, lang, setLang, unreadNotifs, unreadMsgs, notifs, onMarkNotifsRead, dark, onToggleDark }) {
  const [showMenu,setShowMenu]=useState(false);
  const [showLangSub,setShowLangSub]=useState(false);
  const [showSidebar,setShowSidebar]=useState(false);
  const [showNotifs,setShowNotifs]=useState(false);
  const ref=useRef(null);
  const notifRef=useRef(null);
  const t=T[lang];
  useEffect(()=>{const h=e=>{
    if(ref.current&&!ref.current.contains(e.target)){setShowMenu(false);setShowLangSub(false);}
    if(notifRef.current&&!notifRef.current.contains(e.target))setShowNotifs(false);
  };document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);
  const level=getUserLevel(myDiaries.length);
  const nav=(p)=>{onNavigate(p);setShowMenu(false);setShowLangSub(false);setShowSidebar(false);setShowNotifs(false);};

  const timeAgo=(ts)=>{const d=Date.now()-ts;const m=Math.floor(d/60000);if(m<60)return m+"min";const h=Math.floor(m/60);if(h<24)return h+"h";return Math.floor(h/24)+"d";};

  const Badge=({count,color})=>count>0?<div style={{position:"absolute",top:"-4px",right:"-4px",minWidth:"18px",height:"18px",borderRadius:"9px",background:color||"#e53e3e",color:C.onAccent,fontSize:"10px",fontWeight:"700",fontFamily:F.sans,display:"flex",alignItems:"center",justifyContent:"center",padding:"0 4px",border:"2px solid #fff"}}>{count>99?"99+":count}</div>:null;

  const menuItem=(icon,label,onClick,color)=>(
    <button onClick={onClick} style={{width:"100%",padding:"12px 16px",borderRadius:"8px",border:"none",background:"transparent",color:color||C.text,cursor:"pointer",fontSize:"14px",fontFamily:F.sans,textAlign:"left",display:"flex",alignItems:"center",gap:"12px"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
      <span style={{fontSize:"16px",width:"20px",textAlign:"center",opacity:0.7}}>{icon}</span>{label}
    </button>
  );

  // Sidebar menu items matching GrowDiaries
  const sidebarItems=[
    {icon:"➕",label:t.startDiary,action:()=>{setShowSidebar(false);setPage("home");setShowCreate(true);}},
    {icon:"🏠",label:t.home,action:()=>nav("home"),active:page==="home"},
    {icon:"⭐",label:t.feed,action:()=>nav("feed"),active:page==="feed"},
    {icon:"🔍",label:t.diaries,action:()=>nav("explorar"),active:page==="explorar"},
    {icon:"🌿",label:t.strains,action:()=>nav("explorar"),badge:"NEW"},
    {icon:"👥",label:t.growers,action:()=>nav("cultivadores"),active:page==="cultivadores"},
    {icon:"🏆",label:t.contests,action:()=>nav("concursos"),active:page==="concursos"},
    {icon:"🏛️",label:t.community,action:()=>nav("comunidade"),active:page==="comunidade"},
    {icon:"🌱",label:t.seeds,action:()=>nav("explorar")},
    {icon:"💧",label:t.nutrients,action:()=>nav("explorar")},
    {icon:"🐛",label:t.pests,action:()=>nav("pragas"),active:page==="pragas"},
    {icon:"📰",label:t.blog,action:()=>nav("blog"),active:page==="blog"},
  ];

  return (
    <>
      <style>{`
        .dp-nav-links{display:flex;gap:4px;align-items:center}
        .dp-notif-dd{width:320px}
        @media(max-width:768px){
          .dp-nav-links{display:none!important}
          .dp-notif-dd{width:calc(100vw - 32px);right:-60px!important}
          .dp-hero-stats{gap:24px!important}
          .dp-hero-title{font-size:28px!important}
          .dp-section{padding:20px 12px!important}
          .dp-grid{grid-template-columns:1fr!important}
          .dp-filter-bar{gap:4px!important}
          .dp-filter-bar>div{padding:5px 10px!important;font-size:11px!important}
        }
        @media(max-width:480px){
          .dp-hero-title{font-size:24px!important}
        }
      `}</style>
      <nav style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 16px",borderBottom:`1px solid ${C.border}`,backdropFilter:"blur(20px)",background:"var(--dp-overlay85)",position:"sticky",top:0,zIndex:100,gap:"8px"}}>
        {/* Left: hamburger + logo */}
        <div style={{display:"flex",alignItems:"center",gap:"10px",flexShrink:0}}>
          <button onClick={()=>setShowSidebar(true)} style={{background:"none",border:"none",cursor:"pointer",padding:"4px",display:"flex",flexDirection:"column",gap:"4px",justifyContent:"center",flexShrink:0}}>
            <span style={{display:"block",width:"20px",height:"2px",background:C.dim,borderRadius:"2px"}}/>
            <span style={{display:"block",width:"20px",height:"2px",background:C.dim,borderRadius:"2px"}}/>
            <span style={{display:"block",width:"20px",height:"2px",background:C.dim,borderRadius:"2px"}}/>
          </button>
          <div style={{display:"flex",alignItems:"center",cursor:"pointer",flexShrink:0}} onClick={()=>nav("home")}>
            <img src={LOGO_SRC} alt="Diário da Planta" style={{height:"36px",objectFit:"contain"}}/>
          </div>
        </div>

        {/* Center: nav links (hidden on mobile) */}
        <div className="dp-nav-links">
          {[["home",t.home],["explorar",t.explore],["meus",t.myDiaries]].map(([p,label])=>(
            <button key={p} onClick={()=>nav(p)} style={{padding:"8px 14px",borderRadius:"8px",border:"none",background:page===p?C.accentBg:"transparent",color:page===p?C.accent:C.muted,cursor:"pointer",fontSize:"13px",fontWeight:"600",fontFamily:F.sans,whiteSpace:"nowrap"}}>{label}</button>
          ))}
        </div>

        {/* Right: bell + envelope + avatar */}
        <div style={{display:"flex",gap:"2px",alignItems:"center",flexShrink:0}}>

          {/* Notifications bell */}
          <div ref={notifRef} style={{position:"relative"}}>
            <button onClick={()=>{setShowNotifs(!showNotifs);if(!showNotifs)onMarkNotifsRead?.();}} style={{width:"36px",height:"36px",borderRadius:"50%",border:"none",background:showNotifs?C.surface2:"transparent",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",position:"relative",transition:"all 0.2s"}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={C.dim} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
              <Badge count={unreadNotifs}/>
            </button>
            {showNotifs&&<div className="dp-notif-dd" style={{position:"absolute",top:"44px",right:0,background:C.cardBg,borderRadius:"14px",border:`1px solid ${C.border}`,padding:0,maxHeight:"400px",overflowY:"auto",boxShadow:"0 8px 30px rgba(0,0,0,0.12)",zIndex:115}}>
              <div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>Notificações</div>
              {notifs.length>0?notifs.map(n=>(
                <div key={n.id} style={{padding:"12px 16px",display:"flex",gap:"10px",alignItems:"flex-start",borderBottom:`1px solid ${C.border}`,background:n.read?"transparent":"rgba(27,158,66,0.03)"}}>
                  <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"18px",flexShrink:0}}>{n.avatar}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontFamily:F.sans,fontSize:"13px",color:C.text,lineHeight:"1.4"}}>
                      <span style={{fontWeight:"700"}}>{n.from}</span>{" "}<span style={{color:C.muted}}>{n.text}</span>
                      {n.diary&&<span style={{color:C.accent,fontWeight:"600"}}>{" "}{n.diary}</span>}
                    </div>
                    <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"2px"}}>{timeAgo(n.time)}</div>
                  </div>
                  {!n.read&&<div style={{width:"8px",height:"8px",borderRadius:"50%",background:C.accent,flexShrink:0,marginTop:"6px"}}/>}
                </div>
              )):<div style={{padding:"40px 20px",textAlign:"center",color:C.dim,fontFamily:F.sans,fontSize:"14px"}}>Nenhuma notificação</div>}
            </div>}
          </div>

          {/* Messages envelope */}
          <div style={{position:"relative"}}>
            <button onClick={()=>nav("mensagens")} style={{width:"36px",height:"36px",borderRadius:"50%",border:"none",background:page==="mensagens"?C.surface2:"transparent",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",position:"relative",transition:"all 0.2s"}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={page==="mensagens"?C.accent:"#666"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
              <Badge count={unreadMsgs}/>
            </button>
          </div>

          <div ref={ref} style={{position:"relative"}}>
            <button onClick={()=>{setShowMenu(!showMenu);setShowLangSub(false);}} style={{width:"36px",height:"36px",borderRadius:"50%",border:`2px solid ${showMenu?C.accent:C.border}`,background:showMenu?C.accentBg:C.surface2,fontSize:"18px",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",transition:"all 0.2s",overflow:"hidden",padding:0}}>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:user.avatar}</button>

            {showMenu&&<div style={{position:"absolute",top:"46px",right:0,background:C.cardBg,borderRadius:"14px",border:`1px solid ${C.border}`,padding:"8px",minWidth:"240px",boxShadow:"0 8px 30px rgba(0,0,0,0.12)",zIndex:110}}>
              {/* Profile header */}
              <div style={{padding:"12px 16px",display:"flex",alignItems:"center",gap:"12px",borderBottom:`1px solid ${C.border}`,marginBottom:"6px",paddingBottom:"14px"}}>
                <div style={{width:"44px",height:"44px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"24px",border:`2px solid ${C.border}`,overflow:"hidden"}}>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover",loading:"lazy"}}/>:user.avatar}</div>
                <div>
                  <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",color:C.text}}>@{user.username}</div>
                  <button onClick={()=>nav("perfil")} style={{background:"none",border:"none",padding:0,color:C.accent,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"500"}}>{t.viewProfile}</button>
                </div>
              </div>
              {menuItem("➕",t.startDiary,()=>{setShowMenu(false);setShowCreate(true);})}
              {menuItem("⭐",t.favorites,()=>nav("favoritos"))}
              {menuItem("❤️",t.liked,()=>nav("gostei"))}              {/* Language */}
              <div style={{position:"relative"}}>
                <button onClick={()=>setShowLangSub(!showLangSub)} style={{width:"100%",padding:"12px 16px",borderRadius:"8px",border:"none",background:"transparent",color:C.text,cursor:"pointer",fontSize:"14px",fontFamily:F.sans,textAlign:"left",display:"flex",alignItems:"center",gap:"12px",justifyContent:"space-between"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                  <span style={{display:"flex",alignItems:"center",gap:"12px"}}><span style={{fontSize:"16px",width:"20px",textAlign:"center",opacity:0.7}}>🌐</span>{t.language}</span>
                  <span style={{fontSize:"12px",color:C.dim}}>›</span>
                </button>
                {showLangSub&&<div style={{position:"absolute",left:"-170px",top:0,background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"6px",minWidth:"160px",boxShadow:"0 8px 24px rgba(0,0,0,0.1)"}}>
                  {Object.entries(LANGS).map(([code,name])=>(
                    <button key={code} onClick={()=>{setLang(code);setShowLangSub(false);setShowMenu(false);}} style={{width:"100%",padding:"10px 14px",borderRadius:"8px",border:"none",background:lang===code?C.accentBg:"transparent",color:lang===code?C.accent:C.text,cursor:"pointer",fontSize:"14px",fontFamily:F.sans,textAlign:"left",display:"flex",alignItems:"center",gap:"8px",fontWeight:lang===code?"600":"400"}} onMouseOver={e=>e.currentTarget.style.background=lang===code?C.accentBg:C.surface2} onMouseOut={e=>e.currentTarget.style.background=lang===code?C.accentBg:"transparent"}>
                      {lang===code&&<span style={{color:C.accent}}>✓</span>}{name}
                    </button>
                  ))}
                </div>}
              </div>
              {menuItem("⚙️",t.settings,()=>nav("perfil"))}
              {user.role==="admin"&&menuItem("🛡️","Painel Admin",()=>nav("admin"))}
              {menuItem(dark?"☀️":"🌙",dark?"Modo Claro":"Modo Escuro",onToggleDark)}
              <div style={{borderTop:`1px solid ${C.border}`,marginTop:"6px",paddingTop:"6px"}}>
                {menuItem("🚪",t.logout,onLogout,C.error)}
              </div>
            </div>}
          </div>
        </div>
      </nav>

      {/* Sidebar overlay + drawer */}
      {showSidebar&&<>
        <div onClick={()=>setShowSidebar(false)} style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.3)",zIndex:200,transition:"opacity 0.3s"}}/>
        <div style={{position:"fixed",top:0,left:0,bottom:0,width:"250px",maxWidth:"75vw",background:C.cardBg,zIndex:201,boxShadow:"4px 0 24px rgba(0,0,0,0.12)",overflowY:"auto",WebkitOverflowScrolling:"touch",overscrollBehavior:"contain",display:"flex",flexDirection:"column"}}>
          {/* Sidebar header */}
          <div style={{padding:"16px 14px 8px",display:"flex",justifyContent:"space-between",alignItems:"center",borderBottom:`1px solid ${C.border}`,flexShrink:0}}>
            <span style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",color:C.text}}>Menu</span>
            <button onClick={()=>setShowSidebar(false)} style={{width:"28px",height:"28px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"14px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
          {/* Sidebar content */}
          <div style={{flex:1,padding:"6px 8px",overflowY:"auto",WebkitOverflowScrolling:"touch"}}>
            {sidebarItems.map((item,idx)=>(
              <button key={idx} onClick={item.action} style={{
                width:"100%",padding:"12px 14px",borderRadius:"8px",border:"none",
                background:item.active?C.surface2:"transparent",
                color:item.active?C.text:C.muted,cursor:"pointer",fontSize:"14px",
                fontFamily:F.sans,fontWeight:item.active?"700":"500",textAlign:"left",
                display:"flex",alignItems:"center",gap:"12px",transition:"background 0.15s",
              }} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background=item.active?C.surface2:"transparent"}>
                <span style={{fontSize:"17px",width:"24px",textAlign:"center",opacity:0.75}}>{item.icon}</span>
                <span>{item.label}</span>
                {item.badge&&<span style={{marginLeft:"auto",fontSize:"10px",fontWeight:"800",color:C.accent,letterSpacing:"0.5px"}}>{item.badge}</span>}
              </button>
            ))}
          </div>
        </div>
      </>}
    </>
  );
}

// ─── Main App ───
function AppInner() {
  const [user,setUser]=useState(null); const [authLoading,setAuthLoading]=useState(true);
  const [page,setPage]=useState("home"); const [filter,setFilter]=useState("_ALL_");
  const [phaseFilter,setPhaseFilter]=useState("_ALL_"); const [showCreate,setShowCreate]=useState(false);
  const [myDiaries,setMyDiaries]=useState([]); const [selectedDiary,setSelectedDiary]=useState(null);
  const [dataLoaded,setDataLoaded]=useState(false);
  const [lang,setLang]=useState("pt");
  const [viewImage,setViewImage]=useState(null);
  const [dark,setDark]=useState(()=>{try{return localStorage.getItem("dp-dark")==="1";}catch{return false;}});
  const [searchQ,setSearchQ]=useState("");
  const [debouncedSearch,setDebouncedSearch]=useState("");
  useEffect(()=>{const t=setTimeout(()=>setDebouncedSearch(searchQ),300);return()=>clearTimeout(t);},[searchQ]);
  const [sortBy,setSortBy]=useState("recent"); // recent | likes | comments
  const [publicProfile,setPublicProfile]=useState(null); // {user, diaries}
  const [cookieConsent,setCookieConsent]=useState(()=>{try{return localStorage.getItem("dp-cookies");}catch{return null;}});
  const [blogPost,setBlogPost]=useState(null); // viewing a post
  const [blogEditor,setBlogEditor]=useState(null); // editing/creating a post (null or post object)
  const [recoveryMode,setRecoveryMode]=useState(false); // password recovery
  const [follows,setFollows]=useState([]); // IDs of users the current user follows

  const toggleDark=()=>{const next=!dark;setDark(next);try{localStorage.setItem("dp-dark",next?"1":"0");}catch{};};
  const acceptCookies=()=>{setCookieConsent("accepted");try{localStorage.setItem("dp-cookies","accepted");}catch{}};
  const rejectCookies=()=>{setCookieConsent("rejected");try{localStorage.setItem("dp-cookies","rejected");}catch{}};

  // ─── Notification polling (every 30s) + Browser Notifications ───
  const lastNotifRef=useRef(0);
  useEffect(()=>{
    if(!user)return;
    // Request browser notification permission
    if("Notification" in window && Notification.permission==="default"){
      Notification.requestPermission();
    }
    const poll=async()=>{
      try{
        const n=await sb.from("notifications").select("*",`&user_id=eq.${user.id}&order=created_at.desc&limit=50`);
        const mapped=n.map(x=>({id:x.id,type:x.type,from:x.from_username,avatar:x.from_avatar,text:x.text,diary:x.diary_name,time:new Date(x.created_at).getTime(),read:x.read}));
        // Show browser notification for new unread ones
        if(lastNotifRef.current>0&&"Notification" in window&&Notification.permission==="granted"){
          const newOnes=mapped.filter(x=>!x.read&&x.time>lastNotifRef.current);
          for(const nn of newOnes){
            try{new Notification("Diário da Planta 🌱",{body:`${nn.from||""} ${nn.text||""}`,icon:"/icon-192.png",tag:nn.id});}catch{}
          }
        }
        if(mapped.length>0)lastNotifRef.current=Math.max(...mapped.map(x=>x.time));
        setNotifs(mapped);
      }catch{}
    };
    poll(); // initial poll to set lastNotifRef
    const interval=setInterval(poll,30000);
    return()=>clearInterval(interval);
  },[user?.id]);

  // ─── Messages (Supabase) ───
  const [notifs,setNotifs]=useState([]);
  const [msgs,setMsgs]=useState([]);
  useEffect(()=>{if(!user)return;(async()=>{try{
    // ─── Messages (Supabase conversations/messages) ───
    const convRows=await sb.from("conversation_members").select("conversation_id,read_at,conversations(id,is_group,group_name,created_at)",`&user_id=eq.${user.id}`);
    const convIds=convRows.map(r=>r.conversation_id);
    if(convIds.length>0){
      const convList=[];
      for(const cr of convRows){
        const c=cr.conversations;if(!c)continue;
        const members=await sb.from("conversation_members").select("user_id,profiles(username,avatar,avatar_url)",`&conversation_id=eq.${c.id}`);
        const msgRows=await sb.from("messages").select("id,text,media_url,media_type,forwarded,created_at,sender_id,profiles(username)",`&conversation_id=eq.${c.id}&order=created_at.asc`);
        const other=members.find(m=>m.user_id!==user.id);
        convList.push({
          id:c.id,
          with:c.is_group?c.group_name:(other?.profiles?.username||"Usuário"),
          avatar:c.is_group?"👥":(other?.profiles?.avatar||"🌱"),
          isGroup:c.is_group,
          members:c.is_group?members.map(m=>m.profiles?.username).filter(Boolean):[],
          readAt:cr.read_at?new Date(cr.read_at).getTime():null,
          messages:msgRows.map(m=>({id:m.id,from:m.sender_id===user.id?user.email:(m.profiles?.username||m.sender_id),text:m.text||"",media:m.media_url?{type:m.media_type||"image",data:m.media_url}:null,time:new Date(m.created_at).getTime(),forwarded:m.forwarded})),
        });
      }
      setMsgs(convList);
    }
  }catch{}})();},[user]);

  const saveMsgs=async(m)=>{setMsgs(m);};
  const markNotifsRead=async()=>{
    if(!user)return;
    setNotifs(p=>p.map(n=>({...n,read:true})));
    await sb.from("notifications").update({read:true},`user_id=eq.${user.id}&read=eq.false`);
  };
  const sendMsg=async(convId,text)=>{
    if(!user)return;const clean=sanitize(text,2000);if(!clean)return;
    try{await sb.from("messages").insert({conversation_id:convId,sender_id:user.id,text:clean});
    setMsgs(p=>p.map(c=>c.id===convId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:clean,time:Date.now()}],readAt:Date.now()}:c));
    await sb.from("conversation_members").update({read_at:new Date().toISOString()},`conversation_id=eq.${convId}&user_id=eq.${user.id}`);}catch{}
  };
  const markMsgRead=async(convId)=>{
    try{await sb.from("conversation_members").update({read_at:new Date().toISOString()},`conversation_id=eq.${convId}&user_id=eq.${user.id}`);}catch{}
    setMsgs(p=>p.map(c=>c.id===convId?{...c,readAt:Date.now()}:c));
  };
  const markMsgUnread=async(convId)=>{
    try{await sb.from("conversation_members").update({read_at:null},`conversation_id=eq.${convId}&user_id=eq.${user.id}`);}catch{}
    setMsgs(p=>p.map(c=>c.id===convId?{...c,readAt:null}:c));
  };
  const deleteConv=async(convId)=>{
    try{await sb.from("conversation_members").delete(`conversation_id=eq.${convId}&user_id=eq.${user.id}`);}catch{}
    setMsgs(p=>p.filter(c=>c.id!==convId));
  };
  const forwardMsg=async(targetConvId,text)=>{
    if(!user)return;const clean=sanitize(text,2000);
    try{await sb.from("messages").insert({conversation_id:targetConvId,sender_id:user.id,text:clean,forwarded:true});}catch{}
    setMsgs(p=>p.map(c=>c.id===targetConvId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:clean,time:Date.now(),forwarded:true}],readAt:Date.now()}:c));
  };
  const createGroup=async(name,members)=>{
    if(!user)return;const cleanName=sanitize(name,50);if(!cleanName)return;
    try{
      const conv=await sb.from("conversations").insert({is_group:true,group_name:cleanName});
      if(!conv?.id)return;
      // Add self + members by username lookup
      await sb.from("conversation_members").insert({conversation_id:conv.id,user_id:user.id,read_at:new Date().toISOString()});
      for(const mName of members){
        const p=await sb.from("profiles").select("id",`&username=ilike.${encodeURIComponent(mName)}&limit=1`);
        if(p[0])await sb.from("conversation_members").insert({conversation_id:conv.id,user_id:p[0].id});
      }
      await sb.from("messages").insert({conversation_id:conv.id,sender_id:user.id,text:"Grupo criado! 🌱"});
      setMsgs(p=>[{id:conv.id,with:cleanName,avatar:"👥",isGroup:true,members,messages:[{id:"m"+Date.now(),from:user.email,text:"Grupo criado! 🌱",time:Date.now()}],readAt:Date.now()},...p]);
    }catch{}
  };
  const newDM=async(username,firstMsg)=>{
    if(!user)return;const cleanMsg=sanitize(firstMsg,2000);if(!cleanMsg)return;
    const ex=msgs.find(c=>!c.isGroup&&c.with===username);
    if(ex){await sendMsg(ex.id,cleanMsg);return;}
    try{
      const targets=await sb.from("profiles").select("id,username,avatar",`&username=ilike.${encodeURIComponent(sanitize(username,30))}&limit=1`);
      const target=targets[0];if(!target)return;
      const conv=await sb.from("conversations").insert({is_group:false});
      if(!conv?.id)return;
      await sb.from("conversation_members").insert([{conversation_id:conv.id,user_id:user.id,read_at:new Date().toISOString()},{conversation_id:conv.id,user_id:target.id}]);
      await sb.from("messages").insert({conversation_id:conv.id,sender_id:user.id,text:cleanMsg});
      setMsgs(p=>[{id:conv.id,with:target.username,avatar:target.avatar||"🌱",isGroup:false,members:[],messages:[{id:"m"+Date.now(),from:user.email,text:cleanMsg,time:Date.now()}],readAt:Date.now()},...p]);
    }catch{}
  };
  const sendMedia=async(convId,media)=>{
    if(!user)return;
    // Upload to Supabase Storage
    let mediaUrl=media.data;
    if(media.data&&media.data.startsWith("data:")){
      const ext=media.type==="video"?"mp4":"jpg";
      const path=`${user.id}/msg-${Date.now()}.${ext}`;
      const ok=await sbStorage.uploadBase64(path,media.data,media.type==="video"?"video/mp4":"image/jpeg");
      if(ok)mediaUrl=sbStorage.getUrl(path);
    }
    try{await sb.from("messages").insert({conversation_id:convId,sender_id:user.id,text:"",media_url:mediaUrl,media_type:media.type||"image"});}catch{}
    setMsgs(p=>p.map(c=>c.id===convId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:"",media:{type:media.type,data:mediaUrl},time:Date.now()}],readAt:Date.now()}:c));
  };
  const unreadNotifs=notifs.filter(n=>!n.read).length;
  const unreadMsgs=user?msgs.reduce((s,c)=>{const last=c.messages[c.messages.length-1];return s+(last&&last.from!==user.email&&(!c.readAt||last.time>c.readAt)?1:0);},0):0;

  // ─── Session restore (Supabase) ───
  useEffect(()=>{(async()=>{
    // Check for password recovery token in URL hash
    const hash=window.location.hash;
    if(hash.includes("type=recovery")){
      const params=new URLSearchParams(hash.replace("#",""));
      const accessToken=params.get("access_token");
      const refreshToken=params.get("refresh_token");
      if(accessToken){
        _accessToken=accessToken;
        if(refreshToken)_refreshToken=refreshToken;
        saveTokens(accessToken,refreshToken||"");
        setRecoveryMode(true);
        window.history.replaceState(null,"",window.location.pathname);
        setAuthLoading(false);
        return;
      }
    }
    loadTokens();
    try{
      const authUser=await sbAuth.getUser();
      if(authUser?.id){
        const profile=await sb.from("profiles").selectOne("*",`&id=eq.${authUser.id}`);
        if(profile&&!profile.banned) setUser({...profile,avatarImg:profile.avatar_url,createdAt:profile.created_at,authId:authUser.id});
      }
    }catch{}
    setAuthLoading(false);
  })();},[]);

  // ─── Load diaries from Supabase ───
  useEffect(()=>{if(!user)return;(async()=>{try{
    const rows=await sb.from("diaries").select("*",`&user_id=eq.${user.id}&order=created_at.desc`);
    const mapped=rows.map(d=>({
      id:d.id,name:d.name,strain:d.strain,strains:d.strains||[],author:user.username,authorId:user.id,avatar:user.avatar,avatarImg:user.avatarImg,
      phase:d.phase,week:d.current_week,env:d.environment,light:d.lighting,watts:d.watts,substrate:d.substrate,
      watering:d.watering,germination:d.germination,techniques:d.techniques||[],numPlants:d.num_plants,tags:d.tags||[],
      likes:d.likes_count,comments:d.comments_count,cover:0,coverImage:d.cover_url,hidden:d.hidden,isOwn:true,
      weeks:[], // loaded on demand
    }));
    setMyDiaries(mapped);
  }catch{}setDataLoaded(true);})();},[user]);

  const doLogin=u=>{setUser(u);setPage("home");trackEvent("login");};
  const doLogout=async()=>{
    trackEvent("logout");
    await sbAuth.signOut();
    setUser(null);setMyDiaries([]);setNotifs([]);setMsgs([]);setLikes({});setFavs({});setCommentsMap({});setBlockedUsers([]);setFollows([]);setDataLoaded(false);setSelectedDiary(null);setPublicProfile(null);setPage("home");
  };

  // ─── Load follows ───
  useEffect(()=>{if(!user)return;(async()=>{
    try{const rows=await sb.from("follows").select("following_id",`&follower_id=eq.${user.id}`);setFollows(rows.map(r=>r.following_id));}catch{}
  })();},[user?.id]);
  const doFollow=async(targetId)=>{
    if(!user||targetId===user.id)return;
    try{await sb.from("follows").insert({follower_id:user.id,following_id:targetId});setFollows(p=>[...p,targetId]);
      await sb.from("notifications").insert({user_id:targetId,type:"follow",from_username:user.username,from_avatar:user.avatar,text:`${user.username} começou a te seguir`});
    }catch{}
  };
  const doUnfollow=async(targetId)=>{
    try{await sb.from("follows").delete(`follower_id=eq.${user.id}&following_id=eq.${targetId}`);setFollows(p=>p.filter(id=>id!==targetId));}catch{}
  };
  const doDeleteAccount=async()=>{
    if(!user)return;
    try{
      await sb.from("profiles").delete(`id=eq.${user.id}`);
      await sbAuth.signOut();
      trackEvent("delete_account");
    }catch(e){sentryReport(e,{tags:{action:"delete_account"},user});console.error("Delete account error:",e);}
    setUser(null);setMyDiaries([]);setNotifs([]);setMsgs([]);setLikes({});setFavs({});setCommentsMap({});setBlockedUsers([]);setDataLoaded(false);setSelectedDiary(null);setPublicProfile(null);setPage("home");
  };
  const doUpdateUser=async updated=>{
    if(!user)return;
    try{
      let avatarUrl=updated.avatarImg||null;
      if(avatarUrl&&avatarUrl.startsWith("data:")){
        const path=`${user.id}/avatar-${Date.now()}.jpg`;
        const ok=await sbStorage.uploadBase64(path,avatarUrl);
        if(ok)avatarUrl=sbStorage.getUrl(path);else avatarUrl=null;
      }
      await sb.from("profiles").update({username:updated.username,avatar:updated.avatar,avatar_url:avatarUrl,bio:sanitize(updated.bio),city:sanitize(updated.city)},`id=eq.${user.id}`);
      setUser({...user,...updated,avatarImg:avatarUrl});
    }catch(e){sentryReport(e,{tags:{action:"update_user"},user});}
  };
  const doCreateDiary=async(d)=>{
    if(!user)return;
    try{
      const row=await sb.from("diaries").insert({user_id:user.id,name:sanitize(d.name,100),strain:sanitize(d.strain,100),strains:(d.strains||[]).map(s=>sanitize(s,100)),environment:d.env,lighting:d.light,watts:d.watts?parseInt(d.watts):null,substrate:d.substrate,watering:d.watering,germination:d.germination,techniques:d.techniques||[],num_plants:d.numPlants||1,tags:d.tags||[]});
      const mapped={...d,id:row.id,authorId:user.id,author:user.username,avatar:user.avatar,avatarImg:user.avatarImg,likes:0,comments:0,phase:0,week:0,isOwn:true,weeks:[]};
      setMyDiaries(p=>[mapped,...p]);
      trackEvent("create_diary",{strain:d.strain,env:d.env});
    }catch(e){sentryReport(e,{tags:{action:"create_diary"},user});}
    setShowCreate(false);setPage("meus");
  };
  const doUpdateDiary=async(updated)=>{
    if(!user)return;
    try{
      let coverUrl=updated.coverImage;
      if(coverUrl&&coverUrl.startsWith("data:")){
        const path=`${user.id}/cover-${updated.id}-${Date.now()}.jpg`;
        const ok=await sbStorage.uploadBase64(path,coverUrl);
        if(ok)coverUrl=sbStorage.getUrl(path);else coverUrl=null;
        updated={...updated,coverImage:coverUrl};
      }
      await sb.from("diaries").update({name:sanitize(updated.name),strain:sanitize(updated.strain),strains:(updated.strains||[]).map(s=>sanitize(s,100)),environment:updated.env,lighting:updated.light,watts:updated.watts,substrate:updated.substrate,cover_url:coverUrl,hidden:updated.hidden,phase:updated.phase,current_week:updated.week},`id=eq.${updated.id}`);

      // Sync weeks to Supabase
      const weeks=updated.weeks||[];
      const isUUID=(id)=>typeof id==="string"&&id.length>10&&id.includes("-");
      const insertedIds=[];
      for(const w of weeks){
        if(isUUID(w.id)){
          await sb.from("weeks").update({phase:w.phase,height:w.height||null,temperature:w.temp||null,humidity:w.humidity||null,ph:w.ph||null,water_ml:w.waterMl||null,light_hours:w.lightHours||null,note:sanitize(w.note||"",1000)},`id=eq.${w.id}`);
        }else{
          try{
            const row=await sb.from("weeks").insert({diary_id:updated.id,week_number:w.week,phase:w.phase,height:w.height||null,temperature:w.temp||null,humidity:w.humidity||null,ph:w.ph||null,water_ml:w.waterMl||null,light_hours:w.lightHours||null,note:sanitize(w.note||"",1000)});
            if(row?.id){
              w.id=row.id;insertedIds.push(row.id);
              if(w.media?.length>0){
                for(const m of w.media){
                  if(m.data) await sb.from("week_media").insert({week_id:row.id,media_url:m.data,media_type:m.type==="video"?"video":"image"});
                }
              }
            }
          }catch(e){console.error("Insert week error:",e);}
        }
      }
      // Only delete weeks that were explicitly removed by user
      if(updated._deletedWeekIds?.length>0){
        for(const wid of updated._deletedWeekIds){
          await sb.from("weeks").delete(`id=eq.${wid}`);
        }
      }
    }catch(e){console.error("Update diary error:",e);}
    setMyDiaries(p=>p.map(d=>d.id===updated.id?updated:d));setSelectedDiary(updated);
  };
  const doNavigate=p=>{setSelectedDiary(null);setPublicProfile(null);setPage(p);};
  const doRemoveDiary=async(id)=>{
    try{await sb.from("diaries").delete(`id=eq.${id}`);}catch{}
    setMyDiaries(p=>p.filter(d=>d.id!==id));setSelectedDiary(null);setPage("meus");
  };
  const doHideDiary=async(id)=>{
    try{await sb.from("diaries").update({hidden:true},`id=eq.${id}`);}catch{}
    setMyDiaries(p=>p.map(d=>d.id===id?{...d,hidden:true}:d));setSelectedDiary(null);setPage("meus");
  };

  // ─── Likes & Favorites (Supabase) ───
  const [likes,setLikes]=useState({});
  const [favs,setFavs]=useState({});
  useEffect(()=>{if(!user)return;(async()=>{try{
    const [lk,fv]=await Promise.all([
      sb.from("likes").select("diary_id",`&user_id=eq.${user.id}`),
      sb.from("favorites").select("diary_id",`&user_id=eq.${user.id}`)
    ]);
    const lm={};(lk||[]).forEach(l=>lm[l.diary_id]=true);setLikes(lm);
    const fm={};(fv||[]).forEach(f=>fm[f.diary_id]=true);setFavs(fm);
  }catch{}})();},[user]);

  const doLike=async(id)=>{
    if(!user)return;
    const isLiked=!!likes[id];
    const nxt={...likes};
    if(isLiked){delete nxt[id];try{await sb.from("likes").delete(`user_id=eq.${user.id}&diary_id=eq.${id}`);}catch{}}
    else{nxt[id]=true;try{await sb.from("likes").insert({user_id:user.id,diary_id:id});}catch{}}
    setLikes(nxt);
    const delta=isLiked?-1:1;
    setMyDiaries(p=>p.map(d=>d.id===id?{...d,likes:(d.likes||0)+delta}:d));
    if(selectedDiary?.id===id)setSelectedDiary(sd=>({...sd,likes:(sd.likes||0)+delta}));
  };
  const doFav=async(id)=>{
    if(!user)return;
    const nxt={...favs};
    if(nxt[id]){delete nxt[id];try{await sb.from("favorites").delete(`user_id=eq.${user.id}&diary_id=eq.${id}`);}catch{}}
    else{nxt[id]=true;try{await sb.from("favorites").insert({user_id:user.id,diary_id:id});}catch{}}
    setFavs(nxt);
  };

  // ─── Reports (Supabase) ───
  const doReport=async(diary,reason)=>{
    if(!user)return;
    try{await sb.from("reports").insert({reporter_id:user.id,target_diary_id:diary.id,target_type:"diary",reason:sanitize(reason,500)});}catch{}
  };

  // ─── Comments (Supabase) ───
  const [commentsMap,setCommentsMap]=useState({});
  const [blockedUsers,setBlockedUsers]=useState([]);
  useEffect(()=>{if(!user)return;(async()=>{
    try{const bk=await sb.from("blocked_users").select("blocked_id",`&blocker_id=eq.${user.id}`);setBlockedUsers(bk.map(b=>b.blocked_id));}catch{}
  })();},[user]);

  const loadComments=async(diaryId)=>{
    try{
      const rows=await sb.from("comments").select("id,text,edited_at,created_at,user_id,parent_id,profiles(username,avatar,avatar_url)",`&diary_id=eq.${diaryId}&order=created_at.asc`);
      const mapped=rows.map(c=>({id:c.id,text:c.text,username:c.profiles?.username,avatar:c.profiles?.avatar,avatarImg:c.profiles?.avatar_url,authorEmail:c.user_id,time:new Date(c.created_at).getTime(),editedAt:c.edited_at?new Date(c.edited_at).getTime():null,parentId:c.parent_id}));
      setCommentsMap(p=>({...p,[diaryId]:mapped}));
    }catch{}
  };

  const doAddComment=async(diaryId,text,parentId)=>{
    if(!user||!text.trim())return;
    const clean=sanitize(text);
    try{
      const data={diary_id:diaryId,user_id:user.id,text:clean};
      if(parentId)data.parent_id=parentId;
      await sb.from("comments").insert(data);
      await loadComments(diaryId);
      const diary=selectedDiary||myDiaries.find(d=>d.id===diaryId);
      if(diary?.authorId&&diary.authorId!==user.id){
        await sb.from("notifications").insert({user_id:diary.authorId,type:"comment",from_username:user.username,from_avatar:user.avatar,text:parentId?"respondeu um comentário":"comentou no seu diário",diary_name:diary.name});
      }
    }catch{}
  };
  const doEditComment=async(diaryId,commentId,newText)=>{
    const clean=sanitize(newText);if(!clean)return;
    try{await sb.from("comments").update({text:clean,edited_at:new Date().toISOString()},`id=eq.${commentId}`);await loadComments(diaryId);}catch{}
  };
  const doDeleteComment=async(diaryId,commentId)=>{
    try{await sb.from("comments").delete(`id=eq.${commentId}`);await loadComments(diaryId);}catch{}
  };
  const doBlockUser=async(blockedId)=>{
    if(!user||blockedUsers.includes(blockedId))return;
    try{await sb.from("blocked_users").insert({blocker_id:user.id,blocked_id:blockedId});setBlockedUsers(p=>[...p,blockedId]);}catch{}
  };
  const doUnblockUser=async(blockedId)=>{
    if(!user)return;
    try{await sb.from("blocked_users").delete(`blocker_id=eq.${user.id}&blocked_id=eq.${blockedId}`);setBlockedUsers(p=>p.filter(e=>e!==blockedId));}catch{}
  };
  const doReportUser=async(targetUserId,reason,targetName)=>{
    if(!user)return;
    try{await sb.from("reports").insert({reporter_id:user.id,target_user_id:targetUserId,target_type:"user",reason:sanitize(reason,500)});}catch{}
  };
  // Like with notification
  const doLikeWithNotif=async(id)=>{
    const wasLiked=!!likes[id];
    await doLike(id);
    if(!wasLiked){
      const diary=[...myDiaries,...SAMPLE_DIARIES].find(d=>d.id===id);
      if(diary?.authorId&&diary.authorId!==user?.id){
        try{await sb.from("notifications").insert({user_id:diary.authorId,type:"like",from_username:user.username,from_avatar:user.avatar,text:"curtiu seu diário",diary_name:diary.name});}catch{}
      }
    }
  };
  // Public profile loader
  const openPublicProfile=async(targetId)=>{
    if(!targetId||targetId===user?.id){setPage("perfil");return;}
    try{
      const target=await sb.from("profiles").selectOne("*",`&id=eq.${targetId}`);
      if(!target)return;
      const diaries=await sb.from("diaries").select("*",`&user_id=eq.${targetId}&hidden=eq.false&order=created_at.desc`);
      const mapped=diaries.map(d=>({id:d.id,name:d.name,strain:d.strain,strains:d.strains||[],author:target.username,authorId:target.id,avatar:target.avatar,avatarImg:target.avatar_url,phase:d.phase,week:d.current_week,env:d.environment,light:d.lighting,likes:d.likes_count,comments:d.comments_count,cover:0,coverImage:d.cover_url,hidden:false,techniques:d.techniques||[],weeks:[]}));
      setPublicProfile({user:{...target,avatarImg:target.avatar_url},diaries:mapped});
    }catch{}
  };

  // Load comments AND weeks when diary selected
  useEffect(()=>{
    if(!selectedDiary)return;
    loadComments(selectedDiary.id);
    // Load weeks from Supabase
    (async()=>{
      try{
        const weekRows=await sb.from("weeks").select("*",`&diary_id=eq.${selectedDiary.id}&order=week_number.asc`);
        if(weekRows.length>0){
          // Load media for each week
          const weekIds=weekRows.map(w=>w.id);
          let mediaMap={};
          if(weekIds.length>0){
            const mediaRows=await sb.from("week_media").select("*",`&week_id=in.(${weekIds.join(",")})`);
            mediaRows.forEach(m=>{if(!mediaMap[m.week_id])mediaMap[m.week_id]=[];mediaMap[m.week_id].push({id:m.id,name:"",type:m.media_type==="video"?"video":"photo",data:m.media_url});});
          }
          const weeks=weekRows.map(w=>({
            id:w.id,week:w.week_number,phase:w.phase,height:w.height?String(w.height):null,temp:w.temperature?String(w.temperature):null,
            humidity:w.humidity?String(w.humidity):null,ph:w.ph?String(w.ph):null,waterMl:w.water_ml?String(w.water_ml):null,
            lightHours:w.light_hours?String(w.light_hours):null,note:sanitize(w.note||"",1000),media:mediaMap[w.id]||[],mediaCount:(mediaMap[w.id]||[]).length,
          }));
          setSelectedDiary(sd=>sd&&sd.id===selectedDiary.id?{...sd,weeks,week:weeks[weeks.length-1]?.week||0,phase:weeks[weeks.length-1]?.phase||0}:sd);
          setMyDiaries(p=>p.map(d=>d.id===selectedDiary.id?{...d,weeks}:d));
        }
      }catch(e){console.error("Load weeks error:",e);}
    })();
  },[selectedDiary?.id]);

  const t=T[lang];

  if(authLoading) return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column"}}>
      <ThemeCSS dark={dark}/>
      <img src={LOGO_SRC} alt="Diário da Planta" style={{height:"56px",objectFit:"contain",animation:"pulse 2s infinite"}}/>
      <style>{`@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.1)}}`}</style>
    </div>
  );

  if(!user&&recoveryMode){
    const RecoveryForm=()=>{
      const [pw,setPw]=useState("");const [pw2,setPw2]=useState("");const [msg,setMsg]=useState("");const [ld,setLd]=useState(false);const [done,setDone]=useState(false);
      const doReset=async()=>{
        if(pw.length<8){setMsg("Senha deve ter no mínimo 8 caracteres.");return;}
        if(pw!==pw2){setMsg("As senhas não coincidem.");return;}
        setLd(true);setMsg("");
        try{
          const res=await fetch(`${SB_URL}/auth/v1/user`,{method:"PUT",headers:{"apikey":SB_KEY,"Authorization":`Bearer ${_accessToken}`,"Content-Type":"application/json"},body:JSON.stringify({password:pw})});
          if(res.ok){setDone(true);setMsg("Senha alterada com sucesso!");}
          else{const d=await res.json();setMsg(d.msg||d.error_description||"Erro ao alterar senha.");}
        }catch{setMsg("Erro de conexão.");}
        setLd(false);
      };
      if(done) return(<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:C.bg}}><ThemeCSS dark={dark}/><div style={{textAlign:"center",maxWidth:"400px",padding:"40px"}}><div style={{fontSize:"48px",marginBottom:"16px"}}>✅</div><h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",marginBottom:"12px",color:C.text}}>Senha Alterada!</h2><p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,marginBottom:"24px"}}>Sua senha foi redefinida com sucesso.</p><button onClick={()=>{setRecoveryMode(false);window.location.reload();}} style={{...btnPrimary,width:"auto",padding:"12px 32px"}}>Fazer Login</button></div></div>);
      return(<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:C.bg}}><ThemeCSS dark={dark}/><div style={{maxWidth:"400px",width:"100%",padding:"40px"}}><div style={{textAlign:"center",marginBottom:"32px"}}><div style={{fontSize:"48px",marginBottom:"12px"}}>🔑</div><h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",color:C.text}}>Nova Senha</h2><p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,marginTop:"4px"}}>Escolha uma nova senha para sua conta</p></div>{msg&&<div style={{padding:"12px",borderRadius:"10px",background:"#fee2e2",color:"#991b1b",fontFamily:F.sans,fontSize:"13px",marginBottom:"16px",textAlign:"center"}}>{msg}</div>}<div style={{marginBottom:"14px"}}><label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.text,marginBottom:"6px",display:"block"}}>Nova Senha</label><input type="password" style={baseInput} value={pw} onChange={e=>setPw(e.target.value)} placeholder="Mínimo 8 caracteres"/></div><div style={{marginBottom:"24px"}}><label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.text,marginBottom:"6px",display:"block"}}>Confirmar Senha</label><input type="password" style={baseInput} value={pw2} onChange={e=>setPw2(e.target.value)} placeholder="Repita a nova senha" onKeyDown={e=>e.key==="Enter"&&doReset()}/></div><button onClick={doReset} disabled={ld} style={{...btnPrimary,opacity:ld?0.6:1}}>{ld?"Salvando...":"Redefinir Senha"}</button></div></div>);
    };
    return <RecoveryForm/>;
  }

  if(!user) return <><ThemeCSS dark={dark}/><AuthScreen onLogin={doLogin}/></>;

  const shellStyle={minHeight:"100vh",background:C.bg,color:C.text,fontFamily:F.body,position:"relative",overflow:"hidden"};

  const renderPage=()=>{
    if(publicProfile) return <PublicProfile targetUser={publicProfile.user} diaries={publicProfile.diaries} onBack={()=>setPublicProfile(null)} onViewDiary={d=>{setPublicProfile(null);setSelectedDiary(d);}} lang={lang}/>;
    if(page==="privacidade") return <PrivacyPolicyPage onBack={()=>setPage("home")}/>;
    if(page==="termos") return <TermsPage onBack={()=>setPage("home")}/>;
    if(blogPost) return <BlogPostView post={blogPost} onBack={()=>setBlogPost(null)} user={user} onEdit={p=>{setBlogPost(null);setBlogEditor(p);}} onViewImage={setViewImage}/>;
    if(page==="blog") return <BlogPage onBack={()=>setPage("home")} user={user} onOpenPost={p=>setBlogPost(p)} onNewPost={()=>setBlogEditor({})}/>;
    if(page==="cultivadores") return <GrowersPage user={user} onBack={()=>setPage("home")} follows={follows} onFollow={doFollow} onUnfollow={doUnfollow} onViewProfile={async(g)=>{try{const diaries=await sb.from("diaries").select("*",`&user_id=eq.${g.id}&hidden=eq.false&order=created_at.desc`);setPublicProfile({user:{...g,username:g.username,avatar:g.avatar,avatarImg:g.avatar_url,bio:g.bio,city:g.city,createdAt:g.created_at},diaries:diaries.map(d=>({...d,author:g.username,avatar:g.avatar,avatarImg:g.avatar_url}))});}catch{}}}/>;
    if(page==="concursos") return <ContestsPage onBack={()=>setPage("home")}/>;
    if(page==="comunidade") return <ForumPage user={user} onBack={()=>setPage("home")}/>;
    if(page==="pragas") return <PestsPage onBack={()=>setPage("home")} onViewImage={setViewImage}/>;
    if(page==="perfil") return <ProfilePage user={user} diaries={myDiaries} onUpdateUser={doUpdateUser} onLogout={doLogout} onBack={()=>setPage("home")} blockedUsers={blockedUsers} onUnblockUser={doUnblockUser} onDeleteAccount={doDeleteAccount} onNavigate={doNavigate}/>;
    if(page==="mensagens") return <MessagesPage msgs={msgs} user={user} onSend={sendMsg} onSendMedia={sendMedia} onMarkRead={markMsgRead} onMarkUnread={markMsgUnread} onDeleteConv={deleteConv} onForwardMsg={forwardMsg} onCreateGroup={createGroup} onNewDM={newDM} onBack={()=>setPage("home")} lang={lang}/>;
    if(page==="admin"&&user.role==="admin") return <AdminPanel user={user} onBack={()=>setPage("home")} onNewPost={()=>setBlogEditor({})}/>;
    if(selectedDiary){
      const diaryComments=(commentsMap[selectedDiary.id]||[]).sort((a,b)=>b.time-a.time);
      const isOwnerViewing=selectedDiary.isOwn;
      return <DiaryDetail diary={selectedDiary} onBack={()=>setSelectedDiary(null)} onUpdate={doUpdateDiary} onRemove={doRemoveDiary} onHide={doHideDiary} lang={lang} onLike={doLikeWithNotif} onFav={doFav} isLiked={!!likes[selectedDiary.id]} isFaved={!!favs[selectedDiary.id]} onViewImage={setViewImage} onReport={doReport} comments={diaryComments} onAddComment={doAddComment} onDeleteComment={doDeleteComment} onEditComment={doEditComment} blockedByOwner={!isOwnerViewing&&blockedUsers.includes(user.id)} onBlockUser={doBlockUser} onUnblockUser={doUnblockUser} onReportUser={doReportUser} currentUserEmail={user.id} onAuthorClick={openPublicProfile}/>;
    }
    return null;
  };

  const pageContent=renderPage();
  if(pageContent) return (
    <div style={shellStyle}>
      <ThemeCSS dark={dark}/>
      <div style={{position:"relative",zIndex:1}}>
        <NavBar user={user} page={page} setPage={setPage} setShowCreate={setShowCreate} myDiaries={myDiaries} onLogout={doLogout} onNavigate={doNavigate} lang={lang} setLang={setLang} unreadNotifs={unreadNotifs} unreadMsgs={unreadMsgs} notifs={notifs} onMarkNotifsRead={markNotifsRead} dark={dark} onToggleDark={toggleDark}/>
        {pageContent}
        <div style={{textAlign:"center",padding:"40px 24px",borderTop:`1px solid ${C.border}`,fontSize:"13px",color:C.dim,fontFamily:F.sans}}>
          <div>Diário da Planta © 2026 — {t.footer}</div>
          <div style={{display:"flex",gap:"16px",justifyContent:"center",marginTop:"8px"}}><button onClick={()=>doNavigate("privacidade")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Privacidade</button><button onClick={()=>doNavigate("termos")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Termos</button></div>
        </div>
      </div>
      <ImageViewer src={viewImage} onClose={()=>setViewImage(null)}/>
      {blogEditor&&<BlogEditor post={blogEditor.id?blogEditor:null} user={user} onClose={()=>setBlogEditor(null)} onSave={()=>{setBlogEditor(null);if(page==="blog")setPage("_");setTimeout(()=>setPage("blog"),50);}}/>}
      {!cookieConsent&&<CookieBanner onAccept={acceptCookies} onReject={rejectCookies}/>}
    </div>
  );

  const allPool=[...myDiaries.filter(d=>!d.hidden),...SAMPLE_DIARIES];
  const allDiaries=page==="meus"?myDiaries.filter(d=>!d.hidden):page==="favoritos"?allPool.filter(d=>favs[d.id]):page==="gostei"?allPool.filter(d=>likes[d.id]):page==="feed"?allPool.filter(d=>follows.includes(d.authorId)||favs[d.id]||likes[d.id]):allPool;
  const envIds=ENVIRONMENTS.map(e=>e.id);
  // Search filter
  const searchFiltered=debouncedSearch?allDiaries.filter(d=>(d.name+" "+d.strain+" "+d.author+(d.strains?d.strains.join(" "):"")+(d.tags?d.tags.join(" "):"")).toLowerCase().includes(debouncedSearch.toLowerCase())):allDiaries;
  const envFiltered=searchFiltered.filter(d=>{if(filter!=="_ALL_"&&d.env!==filter)return false;if(phaseFilter!=="_ALL_"&&PHASES[d.phase]!==phaseFilter)return false;return true;});
  // Sort
  const filtered=[...envFiltered].sort((a,b)=>{
    if(sortBy==="likes")return(b.likes||0)-(a.likes||0);
    if(sortBy==="comments")return(b.comments||0)-(a.comments||0);
    return 0; // recent = default order
  });

  const pageTitle=page==="meus"?t.myDiaries:page==="explorar"?t.exploreDiaries:page==="favoritos"?"⭐ "+t.favorites:page==="gostei"?"❤️ "+t.liked:page==="feed"?"⭐ Feed":t.recentDiaries;
  const pageSub=page==="meus"?t.manageGrows:page==="feed"?"Seus diários curtidos, favoritados e de quem você segue":page==="favoritos"||page==="gostei"?"":t.followGrowers;

  return (
    <div style={shellStyle}>
      <ThemeCSS dark={dark}/>
      <div style={{position:"relative",zIndex:1}}>
        <NavBar user={user} page={page} setPage={setPage} setShowCreate={setShowCreate} myDiaries={myDiaries} onLogout={doLogout} onNavigate={doNavigate} lang={lang} setLang={setLang} unreadNotifs={unreadNotifs} unreadMsgs={unreadMsgs} notifs={notifs} onMarkNotifsRead={markNotifsRead} dark={dark} onToggleDark={toggleDark}/>
      {page==="home"&&(
        <div style={{textAlign:"center",padding:"60px 20px 50px",background:C.surfaceLight}}>
          <div style={{fontFamily:F.sans,fontSize:"14px",color:C.accent,marginBottom:"12px",fontWeight:"600"}}>{t.hello}, {user.username}! {getUserLevel(myDiaries.length).icon}</div>
          <h1 className="dp-hero-title" style={{fontFamily:F.sans,fontSize:"clamp(28px, 5vw, 56px)",fontWeight:"800",lineHeight:"1.1",marginBottom:"20px",letterSpacing:"-1px"}}>{t.registerSteps}<br/><span style={{color:C.accent}}>{t.ofYourGrow}</span></h1>
          <p style={{fontFamily:F.sans,fontSize:"15px",color:C.muted,maxWidth:"520px",margin:"0 auto 32px",lineHeight:"1.6",fontWeight:"400"}}>{t.communityDesc}</p>
          <div style={{display:"flex",gap:"10px",justifyContent:"center",flexWrap:"wrap"}}>
            <button style={{padding:"12px 28px",borderRadius:"28px",border:"none",background:C.accent,color:C.onAccent,cursor:"pointer",fontSize:"14px",fontWeight:"700",fontFamily:F.sans,boxShadow:"0 2px 8px rgba(27,158,66,0.2)"}} onClick={()=>setShowCreate(true)}>🌱 {t.startDiary}</button>
            <button style={{padding:"12px 28px",borderRadius:"28px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.text,cursor:"pointer",fontSize:"14px",fontFamily:F.sans,fontWeight:"500"}} onClick={()=>setPage("explorar")}>{t.exploreBtn}</button>
          </div>
          <div className="dp-hero-stats" style={{display:"flex",justifyContent:"center",gap:"48px",marginTop:"40px",flexWrap:"wrap"}}>
            {[[SAMPLE_DIARIES.length+myDiaries.length,t.diaries],[new Set([...SAMPLE_DIARIES,...myDiaries].map(d=>d.author)).size,t.growers],[new Set([...SAMPLE_DIARIES,...myDiaries].map(d=>d.strain)).size,t.varieties]].map(([v,l])=>(
              <div key={l} style={{textAlign:"center"}}><div style={{fontFamily:F.sans,fontSize:"28px",fontWeight:"800",color:C.accent}}>{v}</div><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,textTransform:"uppercase",letterSpacing:"1.5px",marginTop:"4px"}}>{l}</div></div>
            ))}
          </div>
        </div>
      )}
      <div className="dp-section" style={{padding:"32px 20px",maxWidth:"1100px",margin:"0 auto"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"8px",gap:"12px",flexWrap:"wrap"}}>
          <div>
            <div style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800"}}>{pageTitle}</div>
            {pageSub&&<div style={{fontFamily:F.sans,fontSize:"13px",color:C.dim,marginTop:"4px"}}>{pageSub}</div>}
          </div>
          {page==="meus"&&<button onClick={()=>setShowCreate(true)} style={{padding:"10px 20px",borderRadius:"24px",border:"none",background:C.accent,color:C.onAccent,cursor:"pointer",fontSize:"13px",fontWeight:"700",fontFamily:F.sans,boxShadow:"0 2px 8px rgba(27,158,66,0.2)",whiteSpace:"nowrap",display:"flex",alignItems:"center",gap:"6px"}}>🌱 {t.newDiary}</button>}
        </div>
        {/* Search bar + sort */}
        <div style={{display:"flex",gap:"10px",marginTop:"16px",marginBottom:"12px",flexWrap:"wrap"}}>
          <div style={{flex:1,minWidth:"200px",position:"relative"}}>
            <input style={{...baseInput,paddingLeft:"36px",borderRadius:"24px",padding:"10px 16px 10px 36px"}} value={searchQ} onChange={e=>setSearchQ(e.target.value)} placeholder="Buscar por nome, genética ou autor..."/>
            <span style={{position:"absolute",left:"12px",top:"50%",transform:"translateY(-50%)",fontSize:"14px",color:C.dim}}>🔍</span>
          </div>
          <div style={{display:"flex",gap:"4px"}}>
            {[["recent","Recentes"],["likes","❤️ Curtidos"],["comments","💬 Comentados"]].map(([v,l])=>(
              <button key={v} onClick={()=>setSortBy(v)} style={{padding:"8px 14px",borderRadius:"20px",border:sortBy===v?`1px solid ${C.accentBorder}`:`1px solid ${C.border}`,background:sortBy===v?C.accentBg:C.surface2,color:sortBy===v?C.accent:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"500",whiteSpace:"nowrap"}}>{l}</button>
            ))}
          </div>
        </div>
        <div className="dp-filter-bar" style={{display:"flex",gap:"6px",marginBottom:"20px",flexWrap:"wrap"}}>
          {[["_ALL_",t.all],...envIds.map(e=>[e,e])].map(([val,label])=><div key={val} onClick={()=>setFilter(val)} style={{padding:"6px 14px",borderRadius:"20px",cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"500",transition:"all 0.2s",border:filter===val?`1px solid ${C.accentBorder}`:`1px solid ${C.border}`,background:filter===val?C.accentBg:C.surface2,color:filter===val?C.accent:C.muted}}>{label}</div>)}
          <div style={{width:"1px",background:C.border,margin:"0 4px"}}/>
          {[["_ALL_",t.allPhases],...PHASES.map(p=>[p,p])].map(([val,label])=><div key={val+label} onClick={()=>setPhaseFilter(val)} style={{padding:"6px 14px",borderRadius:"20px",cursor:"pointer",fontSize:"13px",fontFamily:F.sans,fontWeight:"500",transition:"all 0.2s",border:phaseFilter===val?`1px solid ${C.accentBorder}`:`1px solid ${C.border}`,background:phaseFilter===val?C.accentBg:C.surface2,color:phaseFilter===val?C.accent:C.muted}}>{label}</div>)}
        </div>
        {!dataLoaded?(
          <div className="dp-grid" style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(290px, 1fr))",gap:"16px"}}>
            <SkeletonCard/><SkeletonCard/><SkeletonCard/><SkeletonCard/>
          </div>
        ):filtered.length>0?(
          <div className="dp-grid" style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(290px, 1fr))",gap:"16px"}}>
            {filtered.map(d=><DiaryCard key={d.id} diary={d} onClick={()=>setSelectedDiary(d)} onLike={doLikeWithNotif} onFav={doFav} isLiked={!!likes[d.id]} isFaved={!!favs[d.id]} onViewImage={setViewImage} commentCount={(commentsMap[d.id]||[]).length||d.comments||0} onAuthorClick={openPublicProfile}/>)}
          </div>
        ):(
          <div style={{textAlign:"center",padding:"60px 24px",color:C.dim}}>
            <div style={{fontSize:"48px",marginBottom:"16px"}}>🌱</div>
            <p style={{fontFamily:F.body,fontSize:"16px",marginBottom:"16px"}}>{page==="meus"?t.noDiaries:page==="favoritos"?"Nenhum diário favoritado ainda.":page==="gostei"?"Nenhum diário curtido ainda.":page==="feed"?"Curta, favorite ou siga cultivadores para personalizar seu feed!":t.noResults}</p>
            {page==="meus"&&<button style={{padding:"12px 28px",borderRadius:"28px",border:"none",background:C.accent,color:C.onAccent,cursor:"pointer",fontSize:"15px",fontWeight:"700",fontFamily:F.sans,boxShadow:"0 2px 8px rgba(27,158,66,0.2)"}} onClick={()=>setShowCreate(true)}>{t.createFirst}</button>}
            {(page==="favoritos"||page==="gostei")&&<button style={{padding:"12px 28px",borderRadius:"28px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.text,cursor:"pointer",fontSize:"15px",fontFamily:F.sans,fontWeight:"500"}} onClick={()=>setPage("explorar")}>{t.exploreBtn}</button>}
          </div>
        )}
      </div>
      {showCreate&&<CreateDiaryModal user={user} onClose={()=>setShowCreate(false)} onSave={doCreateDiary}/>}
        <div style={{textAlign:"center",padding:"40px 24px",borderTop:`1px solid ${C.border}`,fontSize:"13px",color:C.dim,fontFamily:F.sans}}>
          <div>Diário da Planta © 2026 — {t.footer}</div>
          <div style={{display:"flex",gap:"16px",justifyContent:"center",marginTop:"8px"}}><button onClick={()=>doNavigate("privacidade")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Privacidade</button><button onClick={()=>doNavigate("termos")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Termos</button></div>
        </div>
      </div>
      <ImageViewer src={viewImage} onClose={()=>setViewImage(null)}/>
      {blogEditor&&<BlogEditor post={blogEditor.id?blogEditor:null} user={user} onClose={()=>setBlogEditor(null)} onSave={()=>{setBlogEditor(null);if(page==="blog")setPage("_");setTimeout(()=>setPage("blog"),50);}}/>}
      {!cookieConsent&&<CookieBanner onAccept={acceptCookies} onReject={rejectCookies}/>}
    </div>
  );
}

export default function App() {
  return <ErrorBoundary><AppInner/></ErrorBoundary>;
}
