import React, { useState, useEffect, useRef, useCallback } from "react";
import * as Sentry from "@sentry/react";
import DOMPurify from "dompurify";

// ─── Analytics (Umami) ───
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

// ─── Supabase SDK Client ───
import { createClient } from "@supabase/supabase-js";

const _sbUrl = import.meta.env.VITE_SUPABASE_URL;
const _sbKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
const SB_URL = (_sbUrl && _sbUrl.includes(".supabase.co") && !_sbUrl.includes("your-project")) ? _sbUrl : "https://dqtjuissaqxkczddnkfk.supabase.co";
const SB_KEY = (_sbKey && _sbKey.length > 50) ? _sbKey : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxdGp1aXNzYXF4a2N6ZGRua2ZrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQwOTczMDgsImV4cCI6MjA4OTY3MzMwOH0.kHOqp0qMO0nN0jlHMitf_jv5oAnmzLkzBE6gyHDX-J0";

const supabase = createClient(SB_URL, SB_KEY, {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    storageKey: "sb-token",
  },
});

// ─── Auth shim (same API as before) ───
const sbAuth = {
  signUp: async (email, password, metadata = {}) => {
    const { data, error } = await supabase.auth.signUp({ email, password, options: { data: metadata } });
    if (error) throw new Error(error.message || "Erro no cadastro");
    return data;
  },
  signIn: async (email, password) => {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      const msg = error.message || "";
      if (msg.includes("not confirmed") || msg.includes("Email not confirmed")) throw new Error("Email não confirmado. Verifique sua caixa de entrada.");
      throw new Error(msg || "Email ou senha incorretos");
    }
    return data;
  },
  signOut: async () => { await supabase.auth.signOut(); },
  getUser: async () => {
    const { data: { user } } = await supabase.auth.getUser();
    return user;
  },
  getSession: async () => {
    const { data: { session } } = await supabase.auth.getSession();
    return session;
  },
  resetPassword: async (email) => {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/?recovery=true`,
    });
    return !error;
  },
  onAuthStateChange: (callback) => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(callback);
    return subscription;
  },
};

// Session-expired event: fired when SDK detects SIGNED_OUT after having a session
supabase.auth.onAuthStateChange((event) => {
  if (event === "SIGNED_OUT") {
    try { window.dispatchEvent(new CustomEvent("sb:session-expired")); } catch {}
  }
});

// ─── Database shim (same API as before) ───
const _buildQuery = (query, filters) => {
  if (!filters) return query;
  // Parse filter string like "&col=eq.val&order=created_at.desc&limit=20"
  const params = new URLSearchParams(filters.replace(/^&/, ""));
  for (const [key, val] of params.entries()) {
    if (key === "order") {
      const [col, dir] = val.split(".");
      query = query.order(col, { ascending: dir === "asc" });
    } else if (key === "limit") {
      query = query.limit(parseInt(val));
    } else if (key === "offset") {
      query = query.range(parseInt(val), parseInt(val) + 999);
    } else {
      // operator: eq, neq, gt, gte, lt, lte, like, ilike, is, in, cs, cd
      const dotIdx = val.indexOf(".");
      if (dotIdx === -1) continue;
      const op = val.substring(0, dotIdx);
      const v = val.substring(dotIdx + 1);
      if (op === "eq") query = v === "null" ? query.is(key, null) : query.eq(key, v);
      else if (op === "neq") query = query.neq(key, v);
      else if (op === "gt") query = query.gt(key, v);
      else if (op === "gte") query = query.gte(key, v);
      else if (op === "lt") query = query.lt(key, v);
      else if (op === "lte") query = query.lte(key, v);
      else if (op === "like") query = query.like(key, v);
      else if (op === "ilike") query = query.ilike(key, v);
      else if (op === "is") query = query.is(key, v === "null" ? null : v === "true" ? true : false);
      else if (op === "in") query = query.in(key, v.replace(/[()]/g, "").split(","));
      else if (op === "cs") query = query.contains(key, v);
      else if (op === "cd") query = query.containedBy(key, v);
    }
  }
  return query;
};

const sb = {
  from: (table) => ({
    select: async (cols = "*", filters = "") => {
      let q = supabase.from(table).select(cols);
      q = _buildQuery(q, filters);
      const { data, error } = await q;
      if (error) { console.error(`[sb.select] ${table}:`, error.message); return []; }
      return data || [];
    },
    selectOne: async (cols = "*", filters = "") => {
      let q = supabase.from(table).select(cols);
      q = _buildQuery(q, filters);
      q = q.single();
      const { data, error } = await q;
      if (error && error.code !== "PGRST116") { console.error(`[sb.selectOne] ${table}:`, error.message); return null; }
      return data || null;
    },
    insert: async (data) => {
      const payload = Array.isArray(data) ? data : [data];
      const { data: result, error } = await supabase.from(table).insert(payload).select();
      if (error) throw new Error(error.message || "Insert failed");
      return Array.isArray(data) ? result : result[0];
    },
    update: async (data, filters) => {
      let q = supabase.from(table).update(data);
      q = _buildQuery(q, filters);
      const { data: result } = await q.select();
      return result || [];
    },
    delete: async (filters) => {
      let q = supabase.from(table).delete();
      q = _buildQuery(q, filters);
      const { error } = await q;
      return !error;
    },
    upsert: async (data) => {
      const payload = Array.isArray(data) ? data : [data];
      const { data: result, error } = await supabase.from(table).upsert(payload).select();
      if (error) { console.error(`[sb.upsert] ${table}:`, error.message); return []; }
      return result || [];
    },
  }),
  rpc: async (fn, params = {}) => {
    const { data, error } = await supabase.rpc(fn, params);
    if (error) { console.error(`[sb.rpc] ${fn}:`, error.message); return null; }
    return data;
  },
};

// ─── Storage shim ───
const sbStorage = {
  upload: async (path, file) => {
    const compressed = await compressImage(file);
    const { error } = await supabase.storage.from("media").upload(path, compressed, {
      contentType: compressed.type || file.type,
      upsert: true,
    });
    return !error;
  },
  uploadBase64: async (path, base64, contentType = "image/jpeg") => {
    const bin = atob(base64.split(",")[1] || base64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    const blob = new Blob([arr], { type: contentType });
    return sbStorage.upload(path, blob);
  },
  getUrl: (path) => supabase.storage.from("media").getPublicUrl(path).data.publicUrl,
  delete: async (paths) => {
    await supabase.storage.from("media").remove(paths);
  },
};

// ─── Anexos privados de mensagens (bucket media-private, URLs assinadas) ───
// Guardamos o CAMINHO no banco (messages.media_url) e geramos URLs assinadas
// de curta duração (1h) na hora de exibir. Só usuários autenticados acessam.
const sbPrivate = {
  uploadBase64: async (path, base64, contentType = "image/jpeg") => {
    const bin = atob(base64.split(",")[1] || base64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    const blob = new Blob([arr], { type: contentType });
    const { error } = await supabase.storage.from("media-private").upload(path, blob, { contentType, upsert: true });
    return !error;
  },
  // Assina vários caminhos de uma vez (uma requisição). URLs antigas/locais passam direto.
  signBatch: async (values) => {
    const map = {};
    const paths = [...new Set((values || []).filter((v) => v && !v.startsWith("http") && !v.startsWith("data:") && !v.startsWith("blob:")))];
    if (!paths.length) return map;
    try {
      const { data } = await supabase.storage.from("media-private").createSignedUrls(paths, 3600);
      (data || []).forEach((it) => { if (it.signedUrl && it.path) map[it.path] = it.signedUrl; });
    } catch (e) { console.warn("[sbPrivate] signBatch falhou:", e); }
    return map;
  },
};



// ─── Notificações: inserção sem .select() ───
// A RLS de SELECT de "notifications" só deixa o DONO ler suas notificações. Logo,
// INSERT ... RETURNING (o .select() do shim sb.insert) FALHA ao notificar OUTRO
// usuário. Este helper insere SEM RETURNING, evitando o erro. Usar para toda
// criação de notificação (anúncios, avisos, fórum, likes, menções).
const insertNotifications = async (rows) => {
  const arr = Array.isArray(rows) ? rows : [rows];
  if (!arr.length) return { ok: true, count: 0 };
  const { error } = await supabase.from("notifications").insert(arr);
  if (error) console.error("[insertNotifications]", error.message);
  return { ok: !error, count: error ? 0 : arr.length, error };
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
const LOGO_SRC="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAu4AAADcCAYAAAAvMCRFAAABWGlDQ1BJQ0MgUHJvZmlsZQAAeJx9kLFLw1AQxr9WpaB1EB0cHDKJQ5SSCro4tBVEcQhVweqUvqapkMZHkiIFN/+Bgv+BCs5uFoc6OjgIopPo5uSk4KLleS+JpCJ6j+N+fO+74zggOW5wbvcDqDu+W1zKK5ulLSX1jAS9IAzm8Zyur0r+rj/j/T703k7LWb///43Biukxqp+UGcZdH0ioxPqezyXvE4+5tBRxS7IV8onkcsjngWe9WCC+JlZYzagQvxCr5R7d6uG63WDRDnL7tOlsrMk5lBNYxA48cNgw0IQCHdk//LOBv4BdcjfhUp+FGnzqyZEiJ5jEy3DAMAOVWEOGUpN3ju53F91PjbWDJ2ChI4S4iLWVDnA2Rydrx9rUPDAyBFy1ueEagdRHmaxWgddTYLgEjN5Qz7ZXzWrh9uk8MPAoxNskkDoEui0hPo6E6B5T8wNw6XwBA6diE8HYWhMAAM7OSURBVHja7H13nF1F+f7zzpxzbt2STa+QEEKooQpSpAhIExBFVJoFv/au2BXr167fH4qIKIqIINKLNEOHEJAe0ntv2/eWc2bm/f0xc+69u9lNoYjKPHyWZDd77z1nzpTnbc9LzAwPDw8PDw8PDw8Pj39vCD8EHh4eHh4eHh4eHp64e3h4eHh4eHh4eHh44u7h4eHh4eHh4eHhibuHh4eHh4eHh4eHhyfuHh4eHh4eHh4eHh6euHt4eHh4eHh4eHh44u7h4eHh4eHh4eHh4Ym7h4eHh4eHh4eHh4cn7h4eHh4eHh4eHh6euHt4eHh4eHh4eHh4eOLu4eHh4eHh4eHh4Ym7h4eHh4eHh4eHh4cn7h4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eOLu4eHh4eHh4eHh4eGJu4eHh4eHh4eHh4eHJ+4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eHji7uHh4eHh4eHh4eHhibuHh4eHh4eHh4eHJ+4eHh4eHh4eHh4eHp64e3h4eHh4eHh4eHji7uHh4eHh4eHh4eHhibuHh4eHh4eHh4eHhyfuHh4eHh4eHh4eHp64e3h4eHh4eHh4eHh44u7h4eHh4eHh4eHh4Ym7h4eHh4eHh4eHhyfuHh4eHh4eHh4eHh6euHt4eHh4eHh4eHh44u7h4eHh4eHh4eHh4Ym7h4eHh4eHh4eHh4cn7h4eHh4eHh4eHh6euHt4eHh4eHh4eHh4eOLu4eHh4eHh4eHh4eGJu4eHh4eHh4eHh4cn7h4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eHji7uHh4eHh4eHh4eGJu4eHh4eHh4eHh4eHJ+4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eHji7uHh4eHh4eHh4eHhibuHh4eHh4eHh4eHJ+4eHh4eHh4eHh4eHp64e3h4eHh4eHh4eHh44u7h4eHh4eHh4eHhibuHh4eHh4eHh4eHhyfuHh4eHh4eHh4eHp64e3h4eHh4eHh4eHh44u7h4eHh4eHh4eHh4Ym7h4eHh4eHh4eHhyfuHh4eHh4eHh4eHh6euHt4eHh4eHh4eHh4eOLu4eHh4eHh4eHh4Ym7h4eHh4eHh4eHh4cn7h4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eOLu4eHh4eHh4eHh4eGJu4eHh4eHh4eHh4cn7h4eHh4eHh4eHh4enrh7eHh4eHh4eHh4eHji7uHh4eHh4eHh4eGJu4eHh4eHh4eHh4eHJ+4eHh4eHh4eHh4eHp64e3h4eHh4eHh4eHji7uHh4eHh4eHh4eHhibuHh4eHh4eHh4eHJ+4eHh4eHh4eHh4eHp64e3h4eHh4eHh4eHh44u7h4eHh4eHh4eHx34zAD8F/D9j9SX4oXtdz4N/t+TOzuyYCM4OZ7UVS/aKJCETkx9bDw8Mfqh4enrj/J8M07Bxk9xFmMJP9kTYgQWCC/UqJETPADWTD/ryNQBUSVHot98AU5C6OGQAjCwBSiAoJAgmCdoSPHPkTQrgbMgPeSQz6GfTfzroaDhXe4v5N/XaZAEeK+59DZsDbEahhkLZ4Xi+RtBtmEAMCBswaIogGf2Pm2nW+FoPJ7o5piPn0uj/DG9aQcd+KQcaDa//nLdYo+bF8ZffQQX9ohtj4yI/4Dm1qpuF33AFLr8y+6OHxckDM7EfhP43Kaw1AgAgwhkGOAbNgSJL/FfeotXY8jiAaNktBQ2R30TYI1n85cR/6Nh2BYtHv0Ol/4LOzovobQa+c6ckQILAxADHWrFvLMWt7LDLAhpEPQowbM47w7+B156Hn1ev6kOa6kWgaaCANGBxPyl9r4t5olHviviPjucWy95PZ498Q3uP+n3FW9ttEiAjGKBjDCMKwH9nq7On469Jly85ct24dNrW3o6/cB2UMDFluxkZDvobkiBt2wcbjJJfPYVjrMAwfPhyTJ0/GhJHj+12kUgmkkM79ji1dd/70AagexRiUeQ55/jg29mrNCwYSoxDKAA/Oeog//plPwQQAEyGiAOXePrztlFPxv9/6PowxNrLy73KK8yBj5w/xwSlgw9yjrW5kHq+IJblViIZB94Pf35Gw7dFI40UDt0TahuPEw8MTd49BNhQDbRRkEIAgUFaVYQsWL2x/9PFH8fjjs7Fs+TKUK2V0dnWhmiSoJDEMDDhNlWADIpu6wFR3tHJ64G7n9zv6mvSzaik+DRufIIKUErlcDrlsDk1NTRg3YjQfNGN/HHnk0dh1yq7LR7QO2xkAlDEQRBCNDIEHkNetulBeB+f7Fuc8bZ08UcPDakh0oFdo0AiAgYFmg2tv/Bs6yt0oDGuGUgkMG7AATjvjNPe7/yYPqsZ3uGFsPNI51Gh0DzR4aHvZkccOE3dy6ZKNq5WGjAqRt5qGIOSeb3v8RztOfKrMf8ZBCQDGaOeNJHRXet532513/P72u+/Ak888jVKlDCElSAiEQQAZhiApIKRo2PpTpm5ewwk3yM+IwIahtILRBolKwLFCYGxe4e67TcfRRx2D0085FbuM35lSAi+F2Eqo+HV5rg9tsAzyO4btPDCox2yMmxsCgBDBoM6+HT34jDGAIDy/4EV+74ffj+64DBEJCCaUuvtw1BsPx+W/uFSGMjBDpkL9C8dSs3HLzua9N+a8i/+AItpXfZ7R4JHAdIEzGGRE/wniWdLLwOA1PWn9CA9+XFgHB/mB39pWSUOONWHL3EIPj38PeI/7v9OmwmxJDhpUNphgtIFmHUZhmJSrpYOuv+2m2Vf99S+Yu2gBNAxyTUUU86010htXE8SlPiitAWMLVY0xYLDNEXc1nv9SR4z7LMGoef8bL4CIEAQBoihCGAQQuQBhKMGG8eLS+Xj6hedw3Q1/xSknnMzvPfs8TBg1npRJIEAgkjWlEgKBNYPEfz/BSu/ZsHbHOdWfMQkwA0YbiHQsBpDwlCSLfpRAbHmy8SCsYEdohzYIRIB7/nEP1m7agKbhrTBaQ0CADOOUE05CJohMopOaoflaQGlGIAlyG8aD919uyYSYtTVzGCAhkA4h9zMUOfUW1eavEOL1awjt8EDXS4HZ7ZnbSnv0c3UbRD09CBlgaOtEckY72B2UgoasJ/Kc3uM1mcfe4/7vRdpTwp7+nQEoo5EJQjzx7FP804t/isefmg0KAkS5HGQg0VsqQVVjZIMQLc0t2G3XaZi8884YPWo0WpqakI0yICabJgNykf9UzmUHc2Qa0wZecp4NpVIxABGUVujr68PGDRuxbMVyLFq0CGvb16M3KUEQIZ8vQAqJuFSBqsSYNG48PnTB/+DsM84mwCAxBhIChg0kSUsEXge7qQFDGQ0hyIWADQQI2miEIgIxwbABwRIpcmJDJIBYJfjJxb/gNevXIIxCsDb23wVDGYO2Yis+fMH/YNyosWTlHOupSXX1Fdquec3M6OjpeOHt55y158pN6yAyEmBGUq5i2qRdcM0frr62JVd8lxDyNSNx1rAlPDv3Bf7Dn64ABdbAVUbbVC4RolIq4eAD34D3nXXu6/OsHqLqOy06NmlKnEtl0w1KMnZ+MiQIxAbpsfOa1TP8h630RtPapjsKLFy2hC+7/DIo1oAkFykSEAyoaox9956B9559HoXSOja8gTTIXE6/4XqBvmE7pwVJwLgIkhAwDBvVHqDi5Wewx78a3uP+72ZJUd0DbZghpQSMEhf/7hL9+yuvQHtXJ4qtRYAE+vpKUEmCnSdNxqEHHITjjn4zZuw9o7ulqbklI6P/yPtXRqGvt/f6RSuXnXHXgzPx0KMPYd6C+TC6jHw+j0wUYd2mDfjmd7+Fx598nC/87IWYMGICxdpAClnL0Kb/YuaeHsJz5r3I3//JD6C1BqQlTSrWCEIJXVHYY+p0fPeib5PWbjwo9XYSjNGT7/7H3ZizcC7CTAbkagcgBOIkxujWEXj3We/GuFFjwcZGMF6KH4+NgZAS9878x57LVq5A1JSDMQaRkFCJwSnHn4i2Yuu74iQJpaTktRpTbQzCIMC69Wvxtxv/BpmNoGFqh7YAoaezG1JKvO+sc70rs5HzOI+lFAF+9btf85333oVioQjFxpF2gUAIdHd147Of/BTefPjRpLVCIKQfv5dkZDKkBNZtWI+/Xn8dOAA0sVVvIomABHo7u9Hb04Pzzz3f1+9vxyRm1iASYCJL2IUzmCTVpBRkQ/IcBrNhPTw8cX/9EXaqFZDa7SGQEp193T/7+ve/9Zkbb7kRxdYm5FsLqCYxqqUqdpsyFee88z047shjMX7MuAYBbusxMFZSMXQfkLh/C1/jG00G2TZrGu1BEKClufXtB+y5Lw7Yc190vf9D73pk9qN/+cs1f8FDsx6BkAHy+Ry0VvjbrTdh3qJF+PFFP+IZe+xFZZUUIin7DDMkif9a8p4S956+Xjz57FPQbOzBTfbnkQhQ6SmBNdfGt39khcCEpNBSRMuINohQQIIQAFAMGAO0DhsOeplpK+l19lXLb7rx9ltgJIGFTf9KYoURw4bj1JNOtRuRDJLXUsY9/VwpJVpaWxHmIiRQYCIYrRGFGQRhiGwx70/sRulHF9xSxtbOLFu5HE888xSKLUXo1FtpCGEQoH3jJmzcvMkaSsz5gLkEJs9+tm+GYqCIeCADNA1rBiKJhJU13hkIKUQYhSi0NLmag9eBNO4OTN3G9W5JO4OFQKVaPaqr1HsfE4FhwGQjG2CG0Yx8Jndta7HlXVt2vPDw8MT99W37M8OwQSADdHV3Xfepr37uHfc+eB9aR7QhMQmq5T40FZvxgbPPx4fO++B1bcVh7wQAFSvJQCikqBARmAkiCAEgqRW3MgDmRIgd23KGEhR7KaqMNMRGalwXJuUMD2gNMNAcFa456Yjjrjnu8Dfjpjtv5V9d/mssWroYhWIeraNGYMGyJfjIpz+BX/zk5/yGffalqlYIhXxdbKtMjDCbBbFCEAobMidAsERG5RBkwiE4JsOAi4oNEpMgoBDaGBjDMCSRJAqJSmxu58sgqam3/Yln/vnAU889i1yxAM0JhJAol0o45i1vxaQJk8jWdby2Eu7pfBGOqCdaQbGGIQ0QIdExtFHQxry+ne1DbARCEAyATD6LKJdFmA8hdF2bKBAhcvkcwjBKiVPJMPs0g+2C6C9L6haKtnphUCqGDhis3ToSQCWpItHKpn2k/de8632Ls8r2MNQIZIQHHnnovi9+7auIchko0tBkU0sjEaCnuxtnnv72s779pYveVSsH9knuHp64v962jsakDnLp3i5PWwRo7+m4/bNf/cJJ9z36IJpammEMo6+zF3vvvge++/Vv48A99yOAoXUCIoEglBpEup47ikFlw16KygADUPb4gHTvbwjQYEjYgtOXmz9pr8t1hiWCCKyiiTEMAwMpJc488TQ64uBD+Ts//C5uu+sO5Ip5FAoFrOxch4996ZP4zU8u5v33mEFKJxAygNYGJATSLqL0WjenGqC+MfRJKrb68tqfAtCkwWwA7XI0nYShMhpp/QoRbaHmQ0AiYAtapRt3FlTLYWdjAKNTn9SAA4pq9J8aSEXasdewKw4WAgzgprtuQa8uoUk0gTRAitGUK+Kkk06BACHRCoKCARqDgwjaDCZnPWg7Xm4YM7Gl0ZgWpDXWXKAenWBBYBKgwDaHgmGQFNBsADI7cE7zkGYtu+ecrlHarncyjgbTKz4tB1WIaRijtBhyoPagrZkRtWuzZFFDG9SIpCEAZKxRXrtzgpBykAdthjb5t1eWcyudlTHUPNqRtbvV+db/+dCA/b7/TxtrRWjrn9Uw39kwIAApCIo1WNgi77Q4nV3oihiQsF88mJeFh74f7mfQ0jaHYUecNQOHYqvrfLBpgLoaVvruoh+Lpq28nBtGX4BBtT1CGY3ucg8ikUCDATJgY4v4y6USqiqudS63x1Vde2roO+/fi5pdVjxtY6qZ2t1Rw7Y44HNYDH2rvD0PwuM/2JT3eG1dV/XVpLWGNgblpLzPV7/7zZPufnAmck15kCSUurvxtpNOxZWXXIED99yPtFZWlUEGNv84dY42nK0D1djES7nElKg38J20Vqp2pL+MAmca8CUGXKeQBCkkBAClFUa1DaeLf/gL+vLnLoQwQLUSI2rKYM3GdfjMlz6LhSsWcSBDKK0hXFFWOi7/fi4nGuJr+2C4P10QjmfRAM/cYBs5AYlkgjSANAIhSZARECwQCpsnG9ZUZ8QQJ8CW3UnS9BhtrELDstUr+N7770Uun4NgQghbZLzX9D1wyAEHk2JGEATY0SjQ9o/r9vwe1+cJ22gVAWANSAQIKQQpICCxjSN3W+ucGg5zeglnKb3Gc3QoTkD9DSCyJFI4IU1L7gnG5cJvnQG+vDUx+Hu82sO4PddJ/eYbtttk2zoXY6rPJ2EAYfr/ruBt2x5DXavZkir+W+2bzuXVoGxPO7gmB5AhIUABAQGBQldkLQWCMLB1Lk5+mPo9vx2ds7Sdd1g3K7acL74DrifuHq/x5lPfTIwxrVEQ4Be/ufjZW+64FcOGt4KY0NfVi/PPORc//96PaWTbCFJGQ8oA1JDHza/ylcqBhLrRG0Ov4gc3IJAB2BjEqtL04XM/SN/++kUIRQCqarQUm7Bs1Sp84etfQU+1dHIgA6uU4t7G8L8Bbe+359L2bfg8ND3YIWfhgG6qxCRNosGxhq4kUCUNU9VArGCqCrqawChnmhnu93pqePbccGFkQzr9HKN/veYa9GzsREZJmL4YXNWghHHm289ERgS2AVPqi2J+BTha/RtuIMdbNJOlAUQ69fIbDVO1Y4CqAsoKXEmAqoYpK+iqfukPnvt/UWpo8VaIGfq333m1Fhs3zhPqP0Y8YOYN3sPLzQimHWtYRdu/LnjLIRz0a4vXNdxf7WtHh3LIpdp/vlGDj5oGe/5brOA69dxeu+NV9RsMMC5pkM7LO/q1w3bONt4svS7B7svNO+Itx3/oa2n4vX6apdYPZRocUzXlPR4QmUrX8Vb/G+zGtozBYAA9F0jvZ+DKa/jy3P11C58q85oyOPRLM4iisPPB2Y/wVVdfhabWFihjUO7qw5mnn4Fvfu7rxMw2H4/kgE6h4tW7TAc5yD6bbpivxg7SL32Q6mMkBQEU9ZSTyoR3nPg20trwV7/1NRgSyDcXMfvZp3DJ7y+97Qsf+Qyl8pBsGJCvvY263dFL3sHvd+hZ2nEIgnDppz72KXT39iAIJIwxECTAwkApg3yUxciRo280xoAkbdVh1S9I7RiwlAEYwGFvPBS77DoFMrQziI3VST/6qKMvNPahwsB+Ng1oeLJFNgzt2NjuiH+L3Jraa/e98aPv/S8gyTWNNzVFnkRpTJwwaQee99bJ7tbG8lVzDr/KXiAb+Xl5XuRX+r4Hpnebhj3tlVrLtSfN2/NCGxalHXjvV3s/oq09g5dawLSdn0s7uk/26zi1ZdHuVl+8lfOKGn8l/ZO3NtO3f2MfKh1+yMtmsdXFsc30el/T4Im7x6tN6Gx6QXt3x30//OmPUI5j5LIFdHV34cB99sPXL/zq94it1jQx9T9x/hWVcgMdoWLQ7esVthmsvFljPqAtuhWAMQhEsCpWCmed8nZavHgB/+ryy9A8cjhyLU249I+/xyEHHsxHHnQY6URDSEsYX8v40o4Ex7khpaCWB5vKhL7EEdcDnlcgJN5y9LHbfDPtGjgNpkwxWFmDfUYMhoExwOGHHj7oZxhnhErhRNYMD1kMSxgiD5a246zeFjtJG4ORABtg3Jgx9Pa3nr7t9bodz4GGOLVtLUD935gb7r3fs96Ok/+Vtc+HvmfXoZNdsvRQrRLoJQRNtjvRwXD/NTJgPdBgOYJpeUaDn0QMWI+vCMsdinH3Gzdsec2DeE7/VcbathJ7eKhrp0aDd5BdbiA53gbH3drcpkHmYf2juL8DjIbYH7fzQXODp4hdJwLe1rPegX+nQX7er78dN9STmC0vujH1kbb3AXvy7om7xyvP5mzjJQ0ZBLj6umuOen7uHDS1tqBSqWLsqDH434u+i9Z889e00QiEdB7ufw1hTzMX6vt2WuwJGDauQ+er7Q3qf6NpOFSmoXOj8ekPffKEuQsW3PmPWQ+jOKwFpd5eXPq7y3DQ3vsdlw2z9zBsse5riVpBFA8ModfvzxZpktXuJwxK1I0xUEaHoaTk5cqwxCqBNjyFGa0B0RIQ+hSbXcFcDEguCMOgU0rRv3FqY86s03dPC7bYpb0YYyCCAAEN3lCc4ZqLKZ2B4CqRsLyVjev4yjUDYLCiZ4ZLaTHG1XekhoUrVBPuPQYwuLQZVNoqXpCwnn5jmR0RoJWC0mYKBG8Gm2ZiCpjNCBJyKYMkkdgUhYEe3MjR9tm5Q5i4/6mttXa9GYJ+83HgM060AlxXUZlqnRuuO2vFK1ycatKogitONmlHXtsUTkpZL2of5HkkKoZhbolC2cVb9VQObhDYrr5c61JptIZw982wBh6BamM7lAHLxu6lIKp3ZE01RmvE7iVyGvc+zE5md4Axm6YISWn3RG20LWyUtj5n0OJ9tnU76X3VrrexWJpf+efd+NxRa/jHtWEyA8Z7KOEBzQyj7Jy3v+IcS2hovEdDGIFpkyNBdh9xTQeFsFrqoLQTtH07bbR9pi7PvF8otgFKKQiXj96vaB79Y1/GGGhjQAIwRo/QhjZpY2CI634xZnctVNszlNaAo/Wp63tgcaqNHg6+VtJJw67ANXVgCCEgG8UT5GDrTNXWoRSy9j71seAGQ9Xn0Xji7vHqkGJH3IWUWL1pLV/1178gU8gBgpBUY3zw/Pdjjym7kdIKgQzqHO9fZEUTWVUXgbpLrKPU9eNKNf78qGHDax0104jBK010eTALxXlH60RWI58t3PXFz3wOz3zweZQShaamJjz6xCzMfPj+u0859iRKEgVmV3z0Gu5nRhvX5l1akpueSsKqCoWBXY691fKbu7u7760mMeJqAhkIhFGIlqaWi1rzxW9FQiQpUWRm1Ft275gxF1m50CX9fga82N9Q4P4ed0L/w8F1HDWsbAt2EUAKiYqJsamrk+NqgkoSQ7FGJsggm8kgiqL7moqFYzJhVLWfkbhDO6y9uTamX6Rl4LQXUtZVSYYw/Gz3YdixJrbefXc4Nr5SJ8YSaQJkEEAGtTHpcn8uHZRsDiDt/ToeM9eMnESpkSRpYxAEkLDRjw1dHctK5dJOiU6glUJWSkRRBrli4SfD8i1fSN+3mlRbAhF0iRoJFa/KXpQm9hi2kS5mRigCSKcMtLm745Hect+h1Upse0xEAfJRDm3DhlEmiACgK2EDnTaoId7udW6URvqS1DA3xhbqB0Fg9z4AMSt0dnRyXK3CjptBGITIZDOIMtFtLU0tb5UicKTSgLUGGViyRwMyjmkHve1E1sCRAnIrXgBlNLQ2yNi1hTIn6Gjv4Eq1CpXEECBkshnks7nnh7e07RO4NZ9oBQIhcI33qLG79Kugdc86lTXl2n82o1DUxruvWjqqq6fnvmqSQCUJiAjZKIMoiuIok/l+a774Lemuv2oUBGz/DNTWBw2axslgO4aiIXTr1nQ9uGKNRjjnQDpOJRW3lSrlK/r6ek/t6ysBBOQyGeQyWTQ3teyZjzIvAkBiFAQEBKUOHmOL7F1RiZACIk2flMEmAIhymbqLRduGdILIKrwIIJONEMhtJ1ile8DA44uZraGgndEgCYEIatfR3tt5TbnUd1aSKMRaA8KOdyYTbc5n8h9tyub/2vgZrNkJy9jdscYn+nsFPDxx93glSTEb66UUFOCav12LNRvWoNjaiu7OLhy8/4F4z2nv/KAxasuDYqBcDAxetUomZ9Gz1qAgxNwlCz6/bPVKvOctZ0CbBFIGO1aMtgPUnYaKnXKjd0PCqAR7Td2LznvXufzzSy9Gy7AWAMBVf70axx51bCYKwipew+Y+jV7NuieG7HMTtlNfd6Xv3MceeezKx2bNwoLFC7F6zWr09PSgXK0gCkM0NTVh7NixF+2y85SLDtp/f5x47IkzCsW81c82VkZUSAFtBpfTG3jcaKMx65+zubevF0FgddwFEQwxtNLIZ7I4YMb+Hynk8pcO7vlmGKPqJBohKqaK+x55kGc98ThWrVqJZUuXobO7G72VEpTSaCoWUSwW0VQoHj129GjeY/oe2H/GDOy/z75nFLJNNyq2hkjQMN/7hYed17MSVyY//s/Hl1TjKiCEa5JiiZUUAQ458A3vyEWZ6wHLc8ltcz1J76HLli17ZPWq1YiTBJEIMXnSZOw2bRolscoGgays37iBn37+WYhQ1rQ1wJb8xUmCceMmYMZue9KW67ne8TgdL+M6h4aZcCMDeGbeC/zQow9j7sJ5WLJ8GTa3b0alUkFcqaApk0W+UMTYsWM/P3ny5M/vvcc+OPTQQzF5zESyhkECIV49rXtj3PzRcRSE2ZgALFi+mB986AG8MOcFLF22DBs2b0RPqQ9sDLLZLIa1DsPOO+3E06dNw1FHHoUD99ifZCaEYoMdqC6wK8Gw87Iby1MFEMoQJV3NPfzwQ6VZTz6BpauXY/mKFejt6UGpVEKSKBQKeTQ3N6OpufmU0WNG816774X995qB/faZcXRTlL8fkpHESTEMwt5BQ3rbm5etLYFct34dPz/3BbC05JLI1mwk1QRjR4/GvnvtS4GQeHb+HL7nvrsxd8ECLF++HJ2dHSiVShBEaGpqxoi2tr2n7DSZ995zL7zpiCMxbeeptedMkK864Uq9+/W+IdbQ2NC1edXMmTPHPz/nOSxfvgxr1q9HT6kXfX0lCCnQXGxGc1MxKjYVL9ppwqSLZuwzAzNmzMAeu+5JIQgVVc0FQpaFm09bKBi65ngr167iF+e9CCEFDFsFMAKhWqli/NgJ2HvPvcgYgzC01/X080/zLXfejsXLl6GjqwMbNm3Eho0bIYjQ2tyCluYWjBs7bs4hBx+MNx16BPbZdQ8ysB5y66m3nn2wgRASz819nlevXQsZBdBaIRdm8OTTT7pIHSMQ1pueKIUoChFGAZ557lnc+cA9LCXVvCRpEWtAAipRGDV8BGbsvTcZspGWRiVdBqBUDJCo3de8pQv4/ocewLwF87By5Ups3LABlUoZ3ZUyZBiirbUVxXxheGtLy7W77TLt2v323hf77bsvJo2dSBBwEYDUKLB1Qt7b/jrgj8w+Ceo18b4qZ/kLYGP35pVn/897J8xfugS5fA5xXxm/+uHPceIxJ5A2CawXaajFaBqyPV+FIlE2jngqCBnhd7ddw089/wx+/uX/pUAn1ron+dqZ9sw2dE2E1ZvW8bsvOAdrN65HLpdFUk5w+S8vxZsOPIyMZgj5WjJ3e4gEQQBmhtYKQRAiVjFuuP0m/uOf/4RFSxejVCkjjAKEYQSSwobkmcGaYbRCtVRGPpfD9F2nY+99Z+CWO29HnFRsDwCncBwKiUpPBW/Ye39c94erSRuGrG3mNh2lElcmn3nuu5csWLIAMgprIV9y0Z5xw0fjd5dejqk770JaachAbjEvlEqCMMyoqqoGt93z9+TKq67EoqVL0N7VCRlIZHORNewEwIbSTr4whqFVAqM0RrQOw4gRw/Hud74b7z7jXW/MZ3KzqlrZzrfM9fQITg8nwvpN6/ldHzgHK9esRhSG7ucBoBSaCs24+fobMbyljUJhO0o++ew/+W83XI9/Pvs0esu96OnuBTGj0lPBB87/AL7+xS9TXI0nRJlo1T3338sf/+ynIbOhiyTBGRMSfb29OP20t+Fn3/ohDUV+U4+XTZuxRsXMR+/nq675M/75zDPo6OmEMgaZbGTvTQgIZkgQlFZQSiOOFcJAYuzosTjmiKPx3vPOw64TppBtlhW8KgezMQaKNSIZYuHKxXzFlX/APTP/gQ2bN0JphVwuCyEDe73OONFKI4ljGJWguaUJbzrqzegp9+KBhx5EPpcFtNPbJgIFIbo2teOSH/wcbz/5dFKJsl5Usp+dpugwLImsJtWWG/9+S+fvr7wCq9etw6aOdoS5EFIGkFLasRXCpjYpG+0pVyqQJDCsuRXjRozBeWefg7NOfTtFQQRjlDUM+KUllOtEQYYBbrvzDv7cVz6PMJeBYgUSEoKB7s4uvO2tb8NXP/dFfPcXP8B9D9yPzu5uQBLCjH3WgUs5UkkCowwqcRWCCSPbRuCYI4/GBe99P3bbeVdKTAJhADYIhRAJSRsxSFPVtLbr8bGnZ/N5H7sACKyOvjDGpm0EAfq6Szj56Lfg1z/+BUkR1LXdG9aSVlpywDoUIda1b+QrrroCt/79dqzbuAHlcgnZbAYyEwGCrPPI2Ain1howBtVqDCkEhg0bhj2m7Y6PXfARHH7QocQAtFENBnjdqaS0RiAlrr/1Rv7y17+MKJ+FkexU1QV6O3tw8vEn4Jc/uZhAwIOzH+ar/nwVnnz6KWzu7AAFAiKQNhITBAAYKjEwMNCJhooTjBw+AicffwI+9ZFPtY9qbRuujEJAgUvRsU3hPvWlT/MNt96K1uGtNtpBBG0UDNnuyWaAzDGBoOLYSuVC1oUanRNfSolybwlHHn4ELvn5/2vOBlFPzQKtpccYKKMRyhAvLJnLv/7NpXh09ixsat8MA0YmiiClTfNCYGtulDK1hoTlUhnNxSa0Njfj8EMPx0c//FHsMm5n0mzq6YXGRjM8efced49XAUJYrWtQgFlPPD5hwZLFiApZlCsVzNh9Txx52BFvYpeHO1ghVmMiCbazWO6lkE2bCqNBUqBqYsxftgArN6zFyk2reJcRE8gYhVclBXMIjxgPFrqQAVRSHTtp9Hg66c3H82V/uBzIZ1GOy7jt73fgTQceBmMUiIJXLV90e0Is0unKK6MRBiE2tG/kr33n67h75kwgEoiyEZqKre5kNTb/kTWEtPrCIYfIFbPQscKLi17EnIXzEESRvac013KQDXvLYk4GE2tDBgkMIBhEBlozSAbgQEBB10ZbDOzmBZvKEoYZtXrDGv7OD76Lu2f+AyITQEYBWka3wbCxhzwYkgkiBCCFy2kVYIQQQqAvidGxagUu+sn3cc/MmY9d+InPY799ZlCiNUIxhLICCWgJ+xUIaKURCIYmhhaMhG333PWbNvC3f/J93DXzXiTGeqxFJoAICZHIgCtVJK4tkAYPB7DKMKAFIAKCJpfvy7BqO4EZcsc0LtJhSbs1ynorpdN/ePFPbvzLNX9BAoMom0GhpQgGoFmDjYYgWzcSKwWRCRDlIkRsifHG7g784Zo/4c5/3IXPffIz/J7T3kk179oreDBrY1u7R0Lgjvvv5m9+91tYt3E9MoUscs0FGJsHDAgBNgztDCgpA0T5CMQGSZLg9rtuhwgDRNmM9eBv5zLXaWoB2Q6rK9as5G9+/yLc98iDEFEIBISWkS024oK0YNJAawUhBbJBCGYgm2sGAMRGYeHKJfj6dy/CXTPv5i987DOYsfs+ZEw9d36HtyO3b2hiJGxAgmGEgHFENChm8MyCF/DOD52LhYsWoqm5CU1tLa67qa1tSFiBGBABIKMAubw1mDurPbj2pusw8/6Z+ObXv8mnvvkk0mQgBCX0Ku3tttEYdChC3P/4I/y9H30P8xcvRJCNEBayiJqz9nxyriGllU1TDJ2uORGiojXOyqqCR2Y/iheem4PTTjmVP/Xhj2HE8BGU6AShDAbdvw0YihgyBBSs1z+UAlXWkNkIggR+8uuf8y8vv8R25M1lUWxrgYFtOGeMgYGCACEIASMDyGyEHOfQl5Rx1TV/xlNPPdX20+/+iPfYbXfSLvddGy2ElIaFFXnQZK9DCJvPLgk2kkhUS680bBteBZkQxATNqM/DtC6ANLSwOfIKZhwD89F/ywWDEMgQl119Bf+/Sy5GT6kPYS6D3LAmFxEwYGNgWLtoLCBDQMoIYCBTyIKZ0V7qwrW3/g0PPvkoPnTOBXzBe95LsUpCkpRYR5on7f/1/NEPwWvifIVJC/TY4PEnn0CcJAjCAHGpghOPPR75TP4ho5RNA9jqsVfXKtZc77qmXdoBttagczsC2WnxPiHA2u6NvHjVUnT0tWPOkvmo93KjHTkxGmIFA5o4NTZ7GkQZYsj7YEYggrXMjNNOfCvyUQ6sDWQY4Ok5z2JD16Y1Mgi20uHuX4eEDUIZYP7yxfyBj/8P7pp5L4qtRWSyGbAkJEYhUQrKGFusKmwaDDNDs4HSGiwYUTaDKJeBkLawzLAt9CJuHKzBBq5BS5hgG46Q9URB2lQZQ7axi0mjLbV8fHcPruZi0arF/D+f/DDu+sc9yDflEYQBDGvESQzNth07iKDZIFFJraOrdnRGGQUKBTLFPHLNTXhk9ix89HOfwPML5nAkpS3wG7TrqPXMkmBooSEiCQ1tO8myRr6pcP7idcv5g5/+KG66/RaE2RDZQg5BLgIF0hkmyiaY1VNc2q1NYNNRFDG0Ozw1NEja+0jHZMuNlFznUI0gCLFk9TL+4Kc/fOPv/nQFgnwG2WIeRjJioxAbZe/Nad4rrQApodiOiTKJPbyJ0dLWiq6+Hnz129/ARb/4PvdVSidTw7PZip7cEEslLQys61OzK7j53dV/4M9+8XPo6OlEobUJFAaIWUGzBgTsMxQEFoBi2xK+qhVibQAhkC/kEEgBQTu2zgIZwMAqHc1dMp8//OmP4r6HHkChuRkyCiADafdMraGVhkBjag1c8SrDKAWjFQwMwmyEfEsR9z30AD7y+U9i3rKFLISsdRTe0UBzOlaG2K4ZATcWdp5E2QxWrV2DlWtXoaWtBYYYsUmgYWy+PQFMDHYdp2OjoNheqwwDFFqL6K724bNf+QIuvepytvOyoZtvvdKy4aKc1jf3LylIlX36k0bUFGJSWeEwCHDznbfypz/3KSxetgTF5iKiTAhlEiRK2XWrk9TQBwk77wwYWhtX4GmjUvliAZoMfv+nK/DFb30VVZVkpJDucqn2udRQw2ICghZk1y7s/iayATb3dOEbP/0u/9+lv0SUzyJbzIIloWpiO24wgCua18ZdB2sok0CxhiBGU2sTXlwwF5/48mewaPUyljKAUqoobHaLjdawnbcsCcqJLTDbuhhykTN7za6GpbGXgACMsEY+B4AhY50dggAS3ZxqNjovvzF27/juxT/k7/3ofxEnCXL5vE0VMgpJEkM7RwenefUuAqq0gmb7PDQbQEoUW5rR3tWJb37v2/jl5ZdyGIZJuqZTA3fgHsBoWO/G7QHa5sqbhhTLRt7A6SldE/Np+D0YT+Y8cX8dEXcCDNnc4N5K70ee/OeTyOVyqFQTjBsxCkccfBicfATSAp8tvS7UQBcENLt8O2MXt4Kudyps5O87QOTZeYrTAsh5qxehs9INQwovrloABQ2C3EF1hvr1GNQ1leubnPXoGeeF0Vpb9YPapjRIIyKqtwzZdfKu42bM2Bc9vX3IZDNYuXol5i1cODYtHHzVIgMD6DIP/IGx6S6RkHh28Vw+92Pvw3MLXkBTWzNiFdsDwwDEwh7CxnofwQRhBCQkBAuwBgAJzVbZx7BVViHh8jeJay1zmOoHP0TqHUq1FUTJEFw+MkAsrWQmqHbY1jqmsrCFtQASk4AAbOxqX/zZr30Zz8+fh0JrsyW5ZPPkAwBSWz1vNta7RlLaQ8lwrcOrYIJWGkopGGNQaGvCmva1+Mb3LkJ7T/vfpRC1VK0tSzis543A0JzYlAuVIJfNYtHSxX+84BMfxlPzn0Pz8FZoVmCjXY6rLSBkQTZSYdKOqSaXRrUYDGHsF7SxIX8NkJb2xB7IhiwVsF7DIMCTc57hsz/8Pjz85GNodl5C5eoB6kTZasczC0AGVm2GBCQEpDEQzhuf6ApkViDIR/jtH36Hj3/1s7e193X+DmxgtALc2ui/tPv/rXGdWa9enbwnKoGUEv/v8l/yd370PWhJCPIZJKzss5bCHfBAAAHS9rUikK4IVcC4NA6ltO2Ayzuwzgyg3Biv2bSWv/C1L2LOonnItRStug5SlgQQSQgRINGACCJoCDAFIBHa+JBLt5F2I0SsYjQNb8WKNavwje9fhO5K7/mCyM5lZcdh+w9KqpFigzR7QTs1GUt8gjBAGIVItAanhfAGsKtXQpCtB2LncJEigEgNEq0hIwmKBL79k+/jR5f8lG2dp64J41ID8U43PsGoqRcN7H1F/YY5NTzttYZBiEeemsXf+O43UY5LyOez0Cax0SKye5AwhBAC0q1XuwdJCCMhEABaQJAEjC2oVQHQOnYE7n5wJn76659XBEnb+I4bfDN2AwOBoJ3nXcB+DhKDfL6Ix596En+89koUWguAsEpB6euECEAQMBq2wzEJm2SjCZIBsAaTQaJiFIYVMW/5Ynz1B99C2cRCCtnL3H8Ngmx3WUlWJJQ11xsfGe4nn2tM/TWNe1Ia6RQisHMUolNAwLg5lkaGfv3Hy/iSyy9DrqmIIAqtEaMMpBYIOIDkdMe1576BraOo+7bsniNYQCcGURAh39aMn1/+S9z96P0cBWH997Y8idyzMGCjwOTODSlALj3HwEBxAoayXkADGNj0PVvqY3tu2CZV7Im7J+6vP6REfOXa1ZcsW7EcYRiiUi5jwvjxmD5tN1LabMPbPuBBMhAY254+sPX0YKKaZyA9dHZURrJRuvDpZ5+BYY1sPoe5815Ee7n7D0KIHfLos6iLJARuAhomS9YdywgNgXTqRRaOcPKQ10dEICGglEImyqzdf/8DEFdjRFGEjo4OzFs4N/WqvqZRFgigt9x37je/exHWrF2LbCGHSlJpOAzcxiwCBDKEMAQkDFYMkxhL6klAyhBEEoa530HtfDRb5PHSS3jaW5gjZA98dh7SH1/8syn/fPYp5JvziDlBzApGMBQ0mBiGrXypdHNTMIM0kAmztdbh6TOR0uaXKlbIFwt46pmn8YtL/t8J/bp5DhppSqNC5NSZBJRR+OWvL8GCxYuQLxSQKOUU9qjWQjesEakGZYk6I9/xcXPzUwiBTd3tz33ju9/EilUrUWwqWsPTzXM7DraQLZIBLP2REAqIKLR/NwRmqneTJa55NZtamnDnXXfiZ7/6v/cLIW1Y3Un6beup1sfb5qinkZwwCHHXQ//gX/76V4hyOQRhgETFNbICVx8RkEQgQhjNdk7GBjpRILbGqIB0ecIGekfc2cKmDYIYP7n4Z3j6hWdRaC4g4QQsjfXGsqlFWYQkK4WntCVWhiHJFjYKIZwePteIbKISNLW04JFZj+GXl13yhzQlhyS98rKazFZWEQAZgwB2DZMCdCWBiRWEAUIKEYgArDTglFxsCp3N9S82N+NXl/4at91zBwsZIs1hTiNCvEMxFtQVe1yEV0qB9V0b27/+vW+iu9yLIJ9BlWOwTCMI1mgMJKz8oLHPWCsFwECQu2ayjgMjkKaIQOkExeYCrrjyCtz98EyWQtTkJd0WFwy6vlxxJdsBQS6Xg9YG2gBMEoKkVWABIDlAAInQ7YNo4NONe4bSGsViAY88+ihuvONWLQIJY3gSALDS0FWFpBxDxwom1lDVxDWOI7BLUbWGKLudlZFUqlCVBKqioCrKPtdyAq5o6HIMXalCMBk2dj9KlJoQhBEeefJR/uVll6DQXICCgoJGAgUWDBbW6SGllTlO90rSQECylrNuyTID0jpiqqoKe/wyvv2/38GqjetYCjH4WcmAZANmBUhCJ3VOX9Axl/+5ZjY/veZJXrRpHvfqjkMkuYgomZqMmFXjsQZialqkoswerw18jvtrQ+OsJ5EkFi5c5OSL7cLcfbfpCChAbJQMZLDd/dVTKTdo23AoJGtBJ07+rl7euv3yYnW1B4Geavfbl65aDsWMTCCxafMmrN6w+vxROw17b00rebscbKbmHQdTTcsWqZa3Qc2TKoIAmg2kIGhtieBg123VOwjMnAdQ2m3aNDQVi0iSBJlsBosXLQYDdU3sV90oG/ANA0xWzeC3V/3+ytlPPYHmYS3QrNyJ40L3TLWDsre3F/lsDvlsFplMBkYblKsV9JVLIKkQZkKreQ7eaufwBma5w/XDNX+KE3jWSrVFUdT+6JOz+LY7bkW2kIMRbFN6AgHlGraEgYRODLraO1HI5ZDNZqznnTXK3T3QRiNbKNgUFBKucNB6rJUBsvkc7vj7nTjr7WfxnlN3p1TfeSAVpbQtuDvQZCDR1duNR2c9gkIxZ+eFdB5bMALYotFKpYxIhkgqVZhUlYGo+pIfNFv5wUBI/PTin+/9/Jw5aGlrRuzSg6zRTC5GZqMmlb4SlNbIhFlIKRCXy1BKIQxDZHORjZcJcmlKGiArITqsbRiuufYaHLTv/nza8W8lpWIXaRE7sPvYnHUhJdZv3sg//flPwUQIowCxy+8lssXENgogEccJdByjuakFYRhA2NQDVKsV9HX1IJvPQobCrcXtvxbt0q7ue/whvuOuO9A0rBmJSSyBZFtQWmuHEzN6e/sQhREyUQZS2udZ7itBG4VcPl835PrVY1j1mZtuuRnvOP3tPG3SLpTEST4Mw9Irnz5u6w8EE3raO9Dc1IxcJocwDKG1RjWJ0dvbC0iBTC6CdgXNJMim0kAArJEp5PDzi/8P++2zL08YPYHStDFist2jUVeKtK/b+gM3bGpSmyDCH/9y5bCFSxej2FxEbBKYgBzBtnOUSKDSV4ZSGsV8HoIkskEEpWJUqxVow8g35aBY1+RsiR2Zd1HfK6+6EscceiSkELDOagYJUrUV3Ki40tBAiY1xaWy2AFkSoVIqI65WEYURAhlCG40kSRCGIQr5PJSJaxFim9qDWi+CIJD4y1+vwenHnXx0LpO5DwBGjxiN6bvsiqaWZmgXDevq6cbmrg57P84Qj2OFMAzAhhHJDKaM28nVnbnIudOsEswo95Uxccx4ENtD17CBDOSq7lLvFy6+7NcoJ1VksllX76BrcXR2UZtSbwkwjHw+h3yUR5LESKp2zgSBQJCNwOyUZASAwKYZRZkIK1euwF+vvw6f/fAnbNM8Cup7N+z5Q8SIUcGzK57nh+c+hLXda9Fd7YZkgVbZhLEtYx47YLcDsc8uB4zLSrE2bfgoBNnDQMApeOE1d4R54u7xWnF3AMDSpUsRxzGy2QiSCLtN282FBIU2bOrpCts6AMmAA0KIAGADThQokBD9OBuDxY4UO7kmGYHEgpVL/rapqx0yI20hDgjPznke++201w6GeKh/E3hOjRabtiEkavfcV60cnQmj+zQbFxIdqjU3pdrBJQDYaeIkNDU1oafcgyAIsHzFCsRaISNfm+mearfPeu4JvuLKK9BULEK7/FZIl4rE1mOoEw3JhNNOOhWnnXQKdtppEkaNHPWFSrX6vQ0bNkQPPvII/nbz9Vi+aiUy+Uzt0BmcsIsd8h33b7Y1gIwIApFsN2zw56uvRl+phMLwFlSTiguz2o08CCT6uksY3jIMJ771WLxh/zdg6tQpKBSasHHjBqxftwGzn5mNu+69B8y26NY0FmALgowCrN+8AQ8+/DD2nLr7VoKFtTYoMK6JTCAFRGALtGweb2QL6HpKCITEqBEjMGryVOSyOaxeuQaZMJPe/UuO+1o5PYkbbr+Zr7vhehRai1BsU9XISbUSCJIkVCWGgMDhbzgU++45AyNGj0RLawt6e3qxdOlSPPHkbLwwdw6iYg7a6TQLcpJ5RkCTAEUBfvCzH2OvPfbmKeMnDUHbaMi5yGxlSLVWuOR3l2L+kgUoNDch0TaEns6BQEgICFR6y5g4YTzOPP0dOPigQzBu/AQUC4ULOjs7L1+6eDFuvf0W3Hv/P1B1ew4Lm3KwPfOOSEAbhT9f9SeUK1U0F7LWqw9l0zLYStFWyjFGDBuJE998KA456GDsMnkycrkCNm/ahNVr1+Dxfz6Oe2feC0MEBFTT2rL3bBBmIqzduB6PPPYIpk3aBSSolOqyv6IhbLKeaQGJt731NJx+4qnYZeoUtA1r+2hvb98l6zasx+OPP4G/3nI9lq9cWis4tDUhpqYvH4YB5i9bhP932S/xnS99uxhI2ZvWAdXWKHFtTzS09ZUuhE2ViaTE+vXr+K9/uw5RJrKpkGQjnsJpsEsIlHtK2HXyLjj8sCOw/4x9MWHCBMAA69etx9q1a3HXfXdj1j9n23nKNuFFwpLKMAiQzWbxzHPPYt6iBbzXtN2pXidDQ8wD1HPgybVeYgYZoK+vD3tMn45D9jsIEyZOxPC2Nmze3I5Vq1bjkVmPYOHCBSi2FN342citIJs6CCERZiK8OO9FPDf3+ZmH7HcQJTrBhZ+9kD736c+NBaEUq/hdxTD/m1v/8Xf+9Fc+jyifra0DGdhIUqmvhFPOOAnf/8p3idm0gKjH7hkEmGRSKMQKGzC1jZTIReECGeDhxx/+0aOzHkPT8BZooaAT7aI99tzTSoETjTfsdxAOO+hg7LXnnhg5YiSSJMaq1WuxeOkS3HzHzVi5ZhXCnI1YKrbvYVW6rOPkgUcewP+87wPHFTP5e9KmVrVILBv0me433Pf0vY8/8sLD6A26oXMaspVhFKNHafR2dmPZoyuwfMPqNSe94a1vLQTF26xAhqz75XiIwKeHJ+7/7RCgWjh5/cYN0A2H7cQJE2qbMmj7PcRMwF/vuZHHjBmNg6fvc3AxKs4GGCLNp7X1KDAkduCh18POC1YuR3tPF4LmELoaQ8Fg7tIFtbw3uZ1hMzJbti9kV7UvIdDHVSxcu5Sfe/pZHLnfYZg0dnyt+/NWW80T1Tzq48aNfSyfz7+xs7cTUtjoQBLHZ2dywZ9faUWO7WlXnl73H/58JTp6ulBoaYI2ic07d4dxQAQVJ2gpNON73/gOTnzTsQ21ZQaUbf7J2JaRmLHrnjjjlNP581+9EI88+RhyxbzVfh6srTi/tNuhQfL2QYxQSGzs3Ly+s7sL+UwW3Zs7IAKBbC5vw+dSIi5XcOCMA/C1z30JB+yxX//hmLonAODdbzsL9x4/k7/0za+io6cbMmMLhzXZdAEhBIJMBs+9+IJVpUnTsbgePKhXiaUheHvRyjVCsg2EQsSlKoQB3vHW03HS8Sdi8sSdMGxY6+wgDP/a0937k7T0L5By+Q6PFNdTZHqrpeOuuPpKW6goJVRSgQisp1EwEAiBSncfdpu6Gy783Odx2BsOo4wIt3jXTZ3tK66/9YaJ/3fZr5CYxJGY1Hiyqy3MRFi+eiWuuf5afPVTX7TFmTSwI++W8zEttLPpKRKLVy7hm265EdlC3jZdciSOAEgiCBYodffhxLecgK997iuYOGosNUZiho0u/G7y6PE45tA34ea7buGvfeciVDhxqQu0zfln2EAKgQ2bNnF3VzdyURZd7V3QkpDP5WyKgAHiahmHvuGN+NJnv4wZ0/boP6d2tX+ce8a7cMf9d/JXL7oIXXEPRCjRKHWsjS0Cfe6F54GzUO+s+kpG2gjQ2u6FF331a3jXyWdS49i3ZJt/PX7EWBywx744462n8nd/8QPcfPstKDQXrXHmIrFEtoi2eVgLbrz9Npx39vk9e03Zndgp+9QPDJdQRbRNDmUFBuxvLFmyBBHZdJPOTe3I5HPIZLJg163UVGKc94734FMf/gRGto3s/7bOjj7rbWee++s//fbKX/32UoT5yAkj2LVrtAZIQKkYzzz/LPaatntNJnVgXUGtZsn1tjBp3xBmkCFopfDxCz6EC97zvpUjWtsmDbyvNRvW8W/+eDn+/JerEBRzNkpDAsQatqTJFnMqaNxz3704ZL+DapHNIIzWgg0k6DdWYlRCUirIYCMQwvWJYAaiIEJGhjAwXbLRoSaDFY29VIy2fxcub37pkiVoKTaj1NOHclJCvlBEmIlselSi0Zxrwqc/83GcdfqZU/Jhtl+ztwOdX+xdp72dv/bDb+EfDzyAfHMhrWKyOvVSIswEWLNuDZYsW3L3PrvtRbWu1s64U6Rx34L7Hr9vzn1AxiDKCsQUI1H27FAhrISNSfDEwtnIZ/O3Hrf/CRRShFquX7qh+ATrfwMO6fGaONvTM6O9s9NVt1uv8Yhhw2qh9e1NwWQXZ4xFjL/eeyMu/tvljz805xHu06WxggislC3G4kYll+3yt0MIQswJFqxYZD1ZRoPIaqKvad+AFe1r2aoHbN+7GmPTQtjqFLu204QYGk+vfpF/f9df+NJbrsCKzasxYviIY9JW9EQ0dM4/pRu/zYtvLjYfGkVRrV17V1c3Eq2P/ld72RmuI6IQWLZ+JT83bw7CbAQDXXv+BECKAEYBuSiLn/7vj3Him44lrW3nSDYMMsLpuGtU4nji+BGj6Gff/xGmTdkV5VLJdvMzoq56gB1ytG8XIREkoJnR3Nw8+rJLfrP/7y75LT5+wUdx0D4HINCEuKeMnk2d2G2nqfjd//3m2gP22I+0Smz+qGLXjt4gTpQsxdU9jj3sGDr33edAx8oVZUmQIecZVGAJrFy9yobit+VRtnafTS0RBBa2aC6pVDBmxAj89H9/iJ9/+8d03OHH0NSddqHhzcMPbsk1/3TC6HE0YfR4oq2kG22NdDYWCj774vN3z100H1EhZ5U4RBpJsUWn1VIVu0/bHZf+/Fc45pCjKKAAsVZWZccYJEohTuLMsNbWSR869wL6/re+Y8eFHRFIjRayyjO5QhEPPPoQNva237u9649ga0HS333osYfR2dtjlS3SvNbaM5co95VxzJuOwk++/cNTJo4aS1WV2GJmZwDYfgQaSsU47S2n0pcuvBBJJYHcTtdA6uEdMWw4/fHyP+526cWX4oLzP4CDZxwISoBydxk9Hd3YZ48Z+M0vfv3eGdP2IKUNVKJgEgNOGDrWiKvJuDhJwpOOOoHe/c53o1qNbYQItnjTpGUfRFi+ahV0A1F8eeuCGqIY1jhXlSo++8lP4V0nn0mxjqFUUit4TNU7lFIYM2I0/eii74894c3Ho7e719ZbuDoBZlsnoolRSaqYed9Ma3ywscXIDYpCYnu2XbJ8P5U2POTgN9JtN9563Q++/j2c985zsevEKUh6yki6Syht7sY573gPvvuVb9PItpGktIZSxnb7TAx0rFCtVqdmM9k/ffz9H2k9aL8DEJdi23ehUa1KEKpJFavWrnbrZev6Y0aberdY10QoqVTxkfd+EF/66OdoRGvbpDip5pRK7LVojUQpjBs1hr71ha/RO047A+XuXkin127Y9kghYgin3LRgySLLs4WwmvpMsOXg9lyRILA27qyhmgOgZvKk9QvpJssDqRSl0XLAdUQ3WuFD77uAbr7ub/j6F76Ct51wKkYWh6O8uQdxVwVcUfjOVy/C+848lyIRLLUa/7pWPK1UglK1euD4sRPoC5/5IkaNGAUdK5tSqq3EMFxEt6OrEx3t7XVOwHbcBYA1vWv4kfkPoZqtwESJ3aOYII0tNjbM0EgQyxgqE2P2/FlY3rGUBcgpXDU8PPK9f7zH/XWIxlSRWCc2pE62yUVk24fvcFqyBHDofm/As0texLLO9Vjyjxsxe9ELa4496CjsM246kasCH1yhZojNFLZNfE9f958XLl+CMBNCmaqVX4wENnRtxpI1K7BT2zinikHbNFg4IOjEIBA2BC7DECt615h7//kQ/XPBcyirKkgCB+x3AIqZ7H2JsTnu1oMw+NbfeD/E7Iq/bFMoY9i2R4cZ+a82zgCGNqYtlGif9cRsrFi5EoWmHLRRkFJCOaOFGSiXyvjA/7wXRx90OCll/50a0onS/TIQYmU1jkePHT6KTjj2OH7xV3NAhVwtT57ZTgZ+iR73ob3L9s0kEWQYPH3oAYfQoQccgu5y34cXLVvy6yeemI0777oTF7z3A2grtr6rGlfHCiMykmhZeoiQEIhCoSMELwLA2e86+9prr7/urA2bN0FmQku+2bjcfaASV6yi0CBtxpnqqyj9W62TJQPVcgVTJu2EX/70/2GPnadRYmJwzLvLQM61+fLkGiztmE42wzo8bTDfwHpBI9xy+62oJjHy+RBGWXUfo40tdtOMTBDhi1+4EDtP2Kn2fGVD6hYxQEJWjdaocJI7/ZhT6KETH+Frb7gOxZZiLdfd2DbGCEKJ+QsX4alnn3nzWw47xhEjGnzvaFDSYNdhV0HjrnvvgQwlQP3lPiUIupqgraUVF37uC2jK5G+PdYJMEA4Mw0A6tQ1tNE59yymnX/a73920at1qBJkA26e5aFWxclF2wVEHH05HHXw4Oiq9n1q0ePEvZj/5BO696258+AMfRnO2+MdqHI8ORLCeHcHTzmMvA7kmfbez3/UuXH3rtejo7kBGBtZZ6HLBjQDKceUVk4XlhtoCIkK1WsWe03fH+WeeQ7FOQBAI0mfMqJFBEQgkKkE+yK37wqc+j2eefw6buzshI9sgSrKoqQGxJNz/4P34yPv/x461ritDpY4dYjuPt2fBk4uotBWHvfNtJ52Kt510KtZsXM/zFy/EAw/ch7kvzsMH3/tBq4aitCQptN1brN6SkAGkDBYBQCBk1znvPgezn3wCpC1BrqXsCIY2BtVKuZ+RA6JBCbwQAsbYngaCCOVSCfvtuTc+8v4PHq+MBmstQhGW7VvYYkkJQCnbWfyTH/0EHn1yNlZuXmfntLEF9QRGqt/f3tWO7nLvR5tzxUtSQ2vwc5n7Zc4x85BRrH5RQDTeIoHTrq0ETBk/haacNQXvPes8LF2xjOfMexG33nY7WlqH4eSjT6BKkrRKRiwElYio1qguCEIEAZ4EgD12mkrHvvnNfOXVV6F1+DDEKoGENbpJAklSRSWJG4Mxtb/OW/Y8OvrWIyyESJSVwQQHIA4BMAKTlsMbIFLo7NuMF5Y8i6kHTLPOJZf4R4ArXhYg9n5fT9xfp6iFBp1UXtqwYkd8QVbXOcHObRNp32l78QMvPI5qqPDc6gVYtWEN3jhtfz7h0GOPKoaFB6omRiii7foES8aBNZvWvWdDx2bIooSJUdMM71JlLFmzDEfvdch2X68G4FTRAAk8Ou8xvn32TKwtdSLWCUIQJraNxYHT97lQsbGhS2Nsnt02LBkigoZBjfI6VqeMARj5f6lxViuMCtpjrXD/ww/Vtj5JAbQjb8bYdurjx47F2e98j20JLgYYV05XmKWABEOQWM/MOP/sc/9x0x03v3ntunUIs2EttPuKutvTrd/6Xpy2sYFWCsZwvjlXuHT/3fe+dP/d98YF570PStvCq0yUWTvwXRSA1evW8JoNa7Fh3TosWrkEVZXAEFvJOafcwLCKH6VyCQamCFBvf4Oyv8oQNXxvvbjW0/rhCz6EPXaeRqVK31uyUe4uijCXnEJCzeAjs2MGjlN8seohDCkDrN64hmc/ORsykEi0ghROps8Z4309vTj1+FNw+IGHUqIShDLcYnzJdVYUEAiYy8yM97zj3bj7nntQSmIIYbmIkC7tQVq2f8NNN+Ithx0zVEb7FvPARr0lnpv7DM9ftBAicnKuDSlkQhAq1SreesZZmL7TrhTrBCEFViJObFnYzgbQULmmqHjzh953AS78+pcQ5pq3W26RCDDakn8mxrBs8f8O2nPG/x205wx8+PwLEKukkLBBJorWD/RxJmCsWbuK123cgHVr1mDh8sVQSQLpknoIDfEUQSiXy9Yh8XLXB6GfepMMJEqd3TjzjLcjKyPX60DWZG5ryesOYRCgGlfGT5u4C53+1tP5V7+9FMVMk1UUaSCMYSbEkhXL8OQzT/Eb9zuYFBIwcxFAb+PjrRWpb6e3xzjvPwnGuJGjadzI0Tj6kMORQMMo278giLYUR+iLqzNWr1z9zNr1q7F+3QbMevYJCNcRVqeRGEoNaY1SueTuZRuehBqRrjsrTj35rShm8vfESZyRQlZrHvCG+wtkAK01xo0cS8cceTT/9uo/opAp2vdjkyqlIggl1m/cgNVrV/+qecpulwyWMrn9KYaDdwccOPQkbKoMGcBAw3awFpg8aWeaPGlnnHL8SYiNhjYaURh2Diy/FwA29nQ8snrNmkPXrV+LDRs3YeGSRQgzgZXINBqWg9u0nKpKEMdxvwVioCEgsXb9WsgATgrSdR3WtujbFi0bl7bEYKFhAoMN7euds0YM0J/wHndP3F+vaNDiTbu0cUPl0YD9adthZw6QIcKRMw7FC8vmYbPuQTWpoE/34sE5j2LZ5pX3v/Wok7Br22QyzFa9ZJscxV7LwsWLnFge19o9MRgiE2LJquWomhgZEW3XWUecIKAQnUnXO2958LZrZy94BnFGoIwYhWwWuarA0TPeiFFh649TGTybN6hdWHDLg6nmPSFq7BVhNcPFa+MVSDV/JRG6S703LlgwH5lctqbUI4V0hpFEqVLGwW9+C8aPGEtsTE0zutGTw66Y0EqgWW/u8OKwY/fZex9evXI1kAlth0+Gy1Xesrv7y+HtxhhIGyaxeeUCkCIoWQ12PYKk2BTKEFICCRTWbd7IGzZvxuKli/DignlYvGQJ1q1fh76+XnR2daCntwelSgWF5gLCKISBBrh+eAgQkiSB0upNkLij/2Fhas1s6ooU1rgDA5VSBYcdfChOO/5UipNqLhtm70o9ntrdR7+jl7Z/IGqOQylglPU8LVmyCBs2bkSYjaDJuG6rBCEkdGKVY44+8mhIWNWNge/JbFU0ZFocKCRipfL7Tt+LjjnqaL7u5hvQ0taC2Fgd7PSeSQgsWrYIJVUZlQ8yG9gMPFz7MTunvGS/XTB/Prp6upEpZmFYNRSfWf3pXDaLNx12BAQTJGyuOZyxMJCEMnNIgsogYM/dpmP0iFHojPsQNqTlDD2iNgVMCLLeaTZQcRIyIbHFzgFyQdhX4QQbNq3jDe2bsGjhIixYtAhLli3Dug3r0N3bje6eLvR096CaVBE1WaUeW6to16Fxe0QlrkIZhUhEL5t/pC3myXl+W5qbsfuuNgmcnApHjSDSls88oGA1M+PoI4/Bn669GiqxKj5MpqYSFgUhNm7chEWLl+CN+x3s8shlLwYheTsCQQSS0jZFUwnY6FYRyM5QhEAg0V3tO6OjvfP61RvXYMGihVi0cBGWLVuGdRvXo7e3F929Pejq7QIzo6ml6BRpBAbOvtQDTAMid1seh1zzpGut0dLSjAMPOiAt8KwaY6BdiuZA/pwWtu6z556InHqPMC6a5vYqhBI9vb3YtHkzMKVeVwVsqX1P2xBJqxlJNIQXPnUkuL4RJO2pGQT2/pNEg9m0RlHYGbm6rPbejr9u7mw/c/mq5Zi3YBEWLl6IlStWorOnE719vejo7EBvqQ9hFCKXy0HpGEKS9XqnfSQMo6rjRm+G5RbQ6K2WYDQhiGRNOtmmoXLNGZKaTYoNIBk9pR639qmfmowNjcIXp3ri/vqF7eRnN1KBeoc+uO5+21s/RcKmoExqnUBHHXAo3/jQ7Wgq5lDu7gZHeSzetAK/v+VPOP2wE/mwXQ8mu1EOzVq4wYWwaNliJEYhQAjSxuaNGqsHvHTFUpTi8oWZbPQjdpJfQytaaIQksXzTcv7bzJuxsH054iyhJ+5FMZuHqBjsMXEaDpl2IBmtIERQ6/I2lKFRy0B049Xoce7X5Y15+L8uimLS9togkkji5PSOjg5LHBsMM0ECQggkcYw3HPAGCABKs1NFqXuX0z+FDKBZpyJiECDsucceuOnmm5EXBduPdMgQ8Mvi7Q16xq5FEQHKKARBACDYlCDB7Oee5Kee+ieef3EO5i+cj6XLV4BB0KQtySbrGQpCgTCfQWsxA8Pa5rQTINk1RJKoabMrpU5EhDvAqa6wbLgj08/7xQybBpIovOWY45CREhoop0ad1sZpRdcPqh0dH24wvJlZADBd3T3o6e1Brq0JqXQlK20PVSZkogj7z9i3/6c1ZEERWbk1k6ZeMEMwC0kC06buikBazfbUKmXjSIckxJUYm9s3r8+PGk9DbhiNihBu/rV3daKaxMhSFjD9m5mpRGH08FGYsc+MezSZeqSLXYQCTrYwPcelTIxrFDRl8pRzJ4wd96eNC+Ygyue2SdytZGeq4mfTK4IoTABAcYLZT8/mWU89iXnz52HOvBewau0aaOZaMSQLgTCQkAIICxEyIoNYq373ZG+MawTPKHUYovARS8B2kPIOoq5BQqBSLmPa1GnYacKkOql366V/1wHX8AwC0hnm03fb7X1trcOuWLdpgzNebFGhNTYFlDHo7umqR4kaLsI2hBpct3vgj2mLSK81moIgBBB2dvV1/PyRx2d9+pnnn8OceXMxf+ECbGzfDMjUEQFACAROaSXf0gRBBsYoQJBrBFVXUyewJYhurdrmcoMMoE0Tsw4CWOKeyeQwZeLkw8g9OyFtfn6j2Gh9qtsUpL322AuZyEqpCikA3dh6TCBJEpTLZfeRNu4ytIMJW3QFZxogkZvGUJnqBkS/g8nVXbm30U62OAwlANm5fM1Kfnz243h+7gt47sXnsXDpYvRW+qyh6eqzQICUAYKQ0Nza5GwfUytUJ6S1X9ZAbPS41xyBBBRzRVB3YFWclLKR21RuNn1CzuEjJMEkjEK+UGvw2O9Zod52xMMT99cV0jBdQLaHHIPtwkm1xolAO2DSpvmQZDSO3P2QXRcvWbRwztqFyDe3oK+3FxICvZrw539cj829vXzcfkdSxliiJGRgvQ6MmoyVhkFAhD5dbVnevQFGaAQUOI1d60kLINBV6cGqznU/HDam5UcKidWLZwKMdHmlBM0AqViEYWSeXPUsXzfzZnRVe1ENNEqlPjTlmyANoTkq4ITDj0eWcjaM63JCt+YCoQb3FjXk9lqyIaDBiAgICQv+Zc/Wkdu09XtHbwd6y32QYf9QLwOABgq5AiaOHTfoCSsaPWQpXScr7QYAE0aPtwcapS0xnJLQwOjOdlY6Ew8eDCUrigyW5LT2NQIZorO3+zd3PnD3/1x34/VYtHgx2ts3gZmRy+cQNrkoDIc149IevgbKWNlLm62inNqQraJjV1Dl0nbz7sW1hytAkKbOJVM95bQLIhnGpPET6tcu7WtlKGuRrIZSsh0I/9rnKmsGtnWft3d3IU4Se6HuICQRQBGgWWPiyPEY2Tbi7DTsDGr0cNn/11oUGJdig6AXAMaOHmt1/I0GyLZjtxWJ1nArV8rY1N6OiaPGg0k7VelGPShHFN3npknI7Z2d0NpqcJMR9QAgbBrF2NFj0VpsOd5Nvob1J/qNFsEaS8Q2ItSUbbqqUGz+k9Z6u7YuQbYrrwZDQyEKQ2zq6phz+3137XHDTddj4ZJF6OjohJQCmVwGUT4Lw6bm9be2iE2P01qD2Xa3TYs2rYiVgWBh29iDQIbbUG8JtGOE3b2nEYBwLVQFAawN2gotGNY6jNI5NzAVo998I0e4iZCPcn+YMnnKFavXrgbCoEb4hZsoIgqwYeNGO+4ycITUvpMWaU0IoTHZRLp9UVPDvKrpWzEMKwgQgiDEktVL+fpbbsLtd9+BNevWorunG1GUQTaXRTYfgSTBkM3TYhhoZVw9UwKjCcSy3kG0FpcVgCu2Tc87q1xk71+7ZycZMLD7tN3qbVFmSAKhCB9FjZgSgiHqvsg5a8aPGXf0hFFj7luychlENnSNB63HWApCrDXiWgRAbJF6yTXve5p2ZKMfTMY2Sao5m2V/hQnacgdpLFwmGChjEIgQDODJF57mq669Go898Rg2bNqEOK4iyoYIwgzyhSawa2LHxLZjsxMd0M7ZppVBKAVI2/3ANksKnCIUNdyLdbCECDGxbQJmr7b/GsgAytjaOoaNVHJDd1zSACUSY4aPq6nGCcjaxklwlrZPcffE/fUKgXqOLuOlKx040QToRI0oRvlFpx91Mtbf9EdsqnYhV2xGX283dFxCMVvAHY/ejb5yH5926AmUEYGrPKd+2TuSGUQB1rav6dzc1wWZCxHDtvI2ICAIACNQSWIsX70Se4/ZzRIxGFs4KGxeNLue1yKMzGMLn+Sr778JFRFDcYyqilEsNCESIdBncNKbj8POwyaSDZ3Lxl1whz1h5IrnUgePAPpelQfIA7ynjREA9ysbN2+yHhS3QTZestYaxVwOhVyhRtDBWzhmtzgQ0n/JBBnr3UvVGNjU2Ld5CTsrpYV81H/42TDIebwAhpQh7p/1AP/wFz/FiwvmwRCQyWZQGNbk0r40DFT9WpkAV1hnD29bEElpK3vXTMc5qRqI9SCHIrY8bJnrxWrDh7Vh+LC2/uPVvzbuZUUhaABhWL9po9MDN/1JrbCpOcNaWxAI+RTQv7sjbUGBt3zO48aORRgESNxY1skRI5ASfX19dSWJIRZErYeD6xUAAJ0dXbZwtkERJW1gYwzQNmyYy3/lLcaw8YqpYZKknxSEwfYVgJKt7xCCoAFEIsCdD83kH//yZ5i3cD6CIIAMCa0jW2zXXmYkjX0LalKgsGkUQrocflHbUQ2liv8DLNOXOAmowftKruhawjaeymWziERo6x/Ets0CEuT8vgKtra32HmuuXm7wRhPa2zfXimEN6X5jgMYnTdQ/wIJ6Ohk7dRk2QBCE0DC45A+X8u//9Ees79wEEQiEmQjDRg63Dpq0YyvbCItKqmAQwsAaD1LI2scbl6dlqPHhDrpNbjGiXBtPu//JUIKVgWBqdBsM+cjS6SmEnD+subXmgTcN3mEaMnQ2aBBlu/f9ulJ6/09JpVeJCIlRCGWE9Z2bSj/9v5/mbrz1ZpRNgigbIcyHiAqR84Rr24mW2Tbso7oyFaSs9TwQoQQbp3oD7dZe/32DwCAhaxGePSfviXsXt6C32g0ZSEiXfgrXaVUzIxASbDREEqE5aMLuO+0JajC++jlxQD5N5jXmjR7/DR58wxAaCINokzIJJjaPo7cdfQqy2h4k2aZmCClQKvUiyAeY+dTDuOahm7kPCtqlHNQU0ti2XQeATR0b0dvXAwYhYUJFM6qxhlI2fcUYg43r1tmLUAAgoUHQZL00ghmRFHhoyWy+4oEbkEQaxijoRKGQzSOUWSS9CY464DC8adobSKdSev8Fm0KaJtDT1T14bqfbmDOZLLK57Ev+HG3qHsj+8VrzityHSb2uwulhS4nfX3UFf/TTn8DchfORby4i11QAQgmltCNZNutFs/XQCCEhZYhAhBAGkC7aYy9dIFGqn1ThS1oDwpL/5uZmFAvFV/fZNhySXR2ddYOrkdQyAdogl81BSjmvv3E3BIsYwCaGj2izIXPDGKijI6VEtVpFb0/PFiRuKJojBEExo7enx77vEE+8UCi6As56ru4W95deujPOjdEtgPU+b+8gCmlTlwIhcekfL+NPfv6TWLxkMVpbWhBlQgQiQBzHrquutk12BIMkuTlljT64SEEq5/eq77cN3SPZ5WWHmciRZLNtTpOm8rhoQbFQGCTNzSZ0kCD09PQgUUlu4HMlbJ2A1uoh0u7H2oBhUIore33yS5/h//35j9FV7kOumEeYzYCJEGvlOrraNAl2eppRkEUkIwhNIENQsYbRxk67l1tLlDZnIiCJE+y8884uhWf7IaVcmy/kG/aQ1+4QYffstDEIZYR5Sxfy+Recn7vm+usgsxGKLc0QYQAIAa2N7T/h6phsT5IAxLaZUyADkAaMUhAsrMY8GCyo5jwYaMgxc2gjlzZlc2TzSDpkz8MQVLOQKrKSrZJghIGWpqZEJikDlCUO3PUNmDp8VzLG6un336Jo0FQsD+9x99hhklj3Mgdkq873m7gXbTq0i2949E5wDoiyWTAl6O7pQLZYxGNzngQB/J4jTicrpSdr4VZ2xVVdvd3o7uhEpiWPEcVWjBwxGcYAJZVgTft6JOUqNm5c38/tX2v0wgpChpi1+Em+7t4bkOQZ1VIvBANNLU1gTVDdMfabujdOOvD4UWTsh6ZqVf/pkzM9hAuFAgIpsYXIBjMEGEmSIK5WX4Lbp04g006DaGyDnnpIXQOul+tmNsyIpMTNd93OP/jZjyFyITJhHrFJbPGyKwZOCaYgsulKsUJSSaATBRlIRFGIIJAIozwSk0AZDQhZk0Xd4QMhLcJydQMvh/zvyHik5K252OREVmkLX6IUAt3d3UiUOiqS0f1beEwaPXeMAR47Qnd3N7RSNg2opqphiyING2QzWeTz+a16hxu/T2Vbc/l8LXWDBhp4VFdfIWxfa3Oba0tdO8qXEqMQigB/ueVa/uEvfoJMPo9sEKIaVyECglYaYRBCu7qRtP16EiuouGxztGWAMIyQCSJksln0Vsv/mvWdpq+5qETi8osF02C5ZoM8jHq6V7VScekn/V/Iwo5tMV9AIIOyHsRAS5sYNf7YpJGoflabK84WhK/94KLnr7/9ZrQNb0NsEpuqUkumqaf1kBAQBojjGKVqH8BALrRyu9lsDiIKUKpUYMi8PC+gszDI1bYMcxGfHX0eqcpM2nQQ/K8j8P2eHgFaaQgpsHrjOv7clz6P+YsXodjaDEUMrWNL7F1zNnIJ/pkwC6UV4nIVSTVGKCQiGQAk0NxUhCKD3krZ5riza7LE3F/KsrbH2JRKIpvOdMy043ZLesz8WS8+goruA+c1dJhAsESgQqAiASVx0NRD8OZ9jz9FcmgbKw5Ms/SFqZ64e7xShwgA6fReSNqd2zCO2ftwKsdlvnP2TIicAKIIJBi95W7ks0XMev5xFIKQ3/bGU4iNghChTbkRtoX1+g3rMCo/DO8+9Uwcud8hl0OZGZW4elCx2Hbes8vmXvnnm67Gho2bbVFRIF3o2JF2IfHPFc/xdTNvgZIKSW8fAknI5AvQTDAlhX0mTcd7jnnHGVnKbDTGqqxIJ0P5n2xFcYNLYuzo0bXwIqVJBO5UkYFEX18vent7HMneMdKpjWrwtBm8bGdjgx50rQTUMEhY4rRi0zr+6cU/sw9ZWk1fA4Zgp4jiCGYSJ4iTGDoxGDNyDCbsMh7jx4zDLjtPxrTdpmHqLrugqbUZZ3/gfCxbswJhNgKMflknAqeNaQYhQK/GIa20HZPRo0fXVBpEY5yDbev61WtWoxJXvlbI5O/flqN9INFbvmIlEhWDQolav3uyDaZUrNDc1IKRI0b0MxS36ujVBkEgMWLECMRxbPPy0w7GqOddt7dv7h9+5wGWxiBI03DYFeFt81qMQSAlFq9dyr/4f/8PQSYCS2uQILDFxEFg62ok2aLjUqUM1sDYMWMwbswYjB87HlMnT8Wuu07F1F2mIlfI4z0XnI9169YgisJXbB5wI0lOAxDsGitZ2VeUKmUoKAQuBYkGtjPuV5DsDDaSSKDR2dmJtL8cDzCIEqUwfORICCGhePBmYYQ0r5/7zX9yjYisLrhGJCVuufc2q1Q0fBhiVrZpmduzBICAbOOvOE7QVy4jlCEmTpiAMaPHYOL4CZi+y66YsssU7DF9Tzyz4AV86JMfRTafs4pTL8PJwS41p17Y+xKeEvWPPFBddupV3A3EFs+XXeOvUEhc+vvf4OkXnkfryDYkqgpD1lsunWkiyRaDqjhBT2c3ik1FTN1pCsaOGIUpO+2Mabvshp2nTsHuu+x2yyVX/fbUiy/9FVraWqBdOhMN4iwiEklNqQeMAAGaMWzBKQeeRhNHTeKH5t6PtT2r0VfqARTQFLVgVNM4HDj9DThw6kEjMshsJraN/yiVgE27l78U54qHJ+4eW/ECkvOfCQkBhmTGqQccR1IZ/vuT94HzAmE2i4IU6OvrQy7M4YFnHkNTsYmP2/toAitb4EWEhDVCI/D5938ch+x5EMEoIBJAQcAIgyN2O/BPUz6x89w77rx9+vqejoXDm4btCmNcp74A89Yt5GvvvQEd3Ic4LiMT2s8GCyR9Vew1YTrOOf7Mz7SGTTdqNiBpg/MiLd//T03kcp64VG2gudiEMAhgWNc8JGmRaqpXvqF9k9v0B9cBTXN8pZQuF9yaABs2rocMnK4vc41YvDyK0r/awhZE6VYZhZ033HojFq9YhtZhzUiMskoxLqc/IAEoRqm3F2PHjMUhhxyCN77xjZg+ZU/sNGnS51tzhZ82flJ7ufMHEvRFcgVYhvGy0xzq5+erc1BzrRqlTtGHNQ+znRgdmWMStmCQrUZ8uVpBZ0/Xm4c3tdVqHepEI1WP4n41JlZVKcKGjeuRKIVcJoRm5Yp362lY+VwOLS2tdYK9HUYlADQ3t9SSgxulZ9kR8A0bN6K32veepkz+6jRUlIrWDNbYCa4pS19cOqi3rxdSyu3qv0Qg3HDzjVi9YS2ah7dCGWU7NbJV0xAAtAYq5T6MGzUObzz2EBx26GHYbcqumDRp4vubs01XNL7f+q72tUaZMTvcwe4letxTEx2BRG+phI7Ojs0jW0cOrzUdc+mEQootrscYY5WBkupBK1ettJ02WfdLpHdrD22uo7btaYGtzvD+HQ6cRC4zSAh0l/s+/Kdr/uwcPHYfSusM2BVQJqUqoA2mTZmKw494Ew464CDsPGknTJm0M4UDlFjm0FweNMLwEsfTyhqal3j8NRSy8GBuYd4O3p/mx9cPoHStGW3dFGSsoWSYrVEpBk85i4IQ85cv4tvvvAPFliKUTlwiv/Wws2EEIkCluw+FbA4HzDgAhx1xOPbbe19MnDARE0eN32JFkzZM2tT3+IG60Y1V5qh3FIex6jd5kccbJx1Ge0/cu3nd5nVdpXIvjGEUcgWMbBt5Wksw7BbjFIAEiZqIFxPXVNoIYrvFDjw8cffYqtHfv9TNkCXApBkBMU47+HiSmYhvffweVKEhZYBCsYi+UgUJFO545F6MyLfwQbvsT9poBJCItW479tCj20e2jhwe6xiBdiovLkSXSI0x+eG7v/3E0y42CgcJrovErelZ33HdP27GpnIn4kAjyGVcY6EQSXcVB+y6N9599Nvf1xK1/ME0dCDcnv31P8Lp3kCkojC6f0TbiKNWbFgNGYq65jw5GTQh8Mxzz+DtJ55m9aeHONSICErZSAY7ZY1nn38eJOotxVOt+1emK3W9JCwMws6KjvHgow8hk89COUOC054AbElFPsjgPee9E+895zxMGjOJGlUOtNbubNEQMsD8ufO+2N3RiSgMrWfn5fbEcYfUq5sp4zoZNHhUm5ub0NTUjCTRkEEArU1NID4IJKqlGM+/8Dx2GTcZBsaGn9MIgSNUzHZ8ZErMQVCsMX/hAignYwnligCZEIQBknKMTJjBqBGj99z69XL/yByA1pZW5DKZhtz5+rwNggCb2jdjzotz/nzofgdfrY3VF7d61A2EyBUt28iP9Y4vWbl89up1axGE2/B2M4dCiqRXVSY/8MhDyOZsioBxWhfCqRgliUIuk8P5Z52D9539XowbMbrfLInjuE0I0a6NGR2FwfqF8+aP6enpsc2PXuVZYIwtIEz15pevWIFVq9e0jWwdaZuvkVW6qfWfGMQIJABLVyybvWbdWoRhaHX+G9M7mBEIgbbWtjT6NVwK2ox+T2LLhZNy6dSzr5UeHmaCzfOXLvj13MULkctlwVo7wS7rKAkoQFKqYKdxk/D+s8/DGae/7ZBCVHi88Xp1omoKMUJKzH3xxVpRqeGXs19yvUUAvTaksF7YSc6RkDqhRG3vrU9frhUOG2wpV5ymrzz48IPo7O5GWMxAGw1RU/0iSBKo9pbxhv0Pwoff90EccfBhFDbk9SdaWY0Hy/URsyosXrgImUzGfl6iISXV5UB5MMPSRQScKk7a+rmI5u6pI5q3yIExrCApHBBMMDWHBQBbZ4K0CNwT+NeE7vkh+O/AQP9C7U8me+Brg+P3PYpOO/IUBByAEyBAgGKxCToQ6Er6cOPM27CyfSVLGQBGIxtEjrQrCBmBowAIyH4RQbIEtEZbpvkTI5taD5FOa7qXK+P/9tDtrYs3rYQijWwYIpvJwYgISa/B4XsdgnPffNY+w6KmP2itUhsewtT7u/ynzsxGSbGUnDUXikdPn74bqpWq1fh2W6Bmg1jFyGQyeHz24+iu9H6on9dkC67DrjW49a73lHq/9sKLL0KEYU0n3RgNIvOyfc79xDeIQQLo6GjnhQsXWgLnJDqFENYgMwyhCZ//5Gfxzc9/nXYaM5G0TqB0YotnnWfKduGzeu6LFy/Bpk2bEIZhw2f+e1ttjUrVKQveeefJaGtrg0oUjIHVXU+fFRixivG3m25Eb1LehwXVoieppjyntSkygDEGyiRBIAPMWTSXZ95/H7K5HLRWLmRNToFHgZkxaeIk5KPMi2x4CMJDg27503fbDa3NLdCJ6p9LzAwZBOjt68Ojs2c5EsjQ4AZPaCNRsORAGzMeAOYvWoi1GzYgiqKtdk5lIASAjZs3LlmybCkoEI4scU3vn41GLsziaxd+BV/91Bdp3IjRZDQjriS7qkSDlUEoo3ZheyVXiQTmLZiPzs4Om2LzKtc6iIaCzzAK0dHZgXmL5oOZoY0uKkf8ailcA6DY5AUJPPjww+jp67Xrqr+mIJRKMKy1FbtM2cV+pqDN2nC28flyqgjU8LdG8u6CeDEALFmxFBs2b4R0aY2pdK4kgqokmDR2Ai75v4tx7jvPoUKUe1ypGElSDYwxVulFSNvunmwNy9PPPAPN5iV7yf99VjUgAlHzthOR0znnWsRC1+6R0r6JbkXVn1s9Uml/sGDBfJQrZZCUrmEcgQwgWKBaquDNRxyFP/zy8mOPOewoEoKgkhhKxbaJlNsnpRQgIdHZ09X7wotzkM1lkcRVBBK1uiZyCks0WL5VKo0KBUMaLLXtjmoUjLYFxrYPA0NQ0E82ypJ2UxMSrTti2GfLeOLu8UoRivShuhRk68GRNnQvGDhu+hF07nFnYUTYApQUpGHkszmIbIjlnetx3czb0B33nGJD+Klmr+2YqZkRw0ClQsFsbHoEKyBJANcQ5a5/3r9q1otPIYkMMvkIuSgH1ZsgrEicfPBxOOuot1Mko+e1NpAQAxQ5rEbgf/S2kHpjmaG1QiBDHHrwG+u69P08YwZRPsKCpYtx0603X0okkGg1yFvWde2NMW1BEGDm/TO/s2TZUkTZqMGbzS8rcjGo7KL74YYN66G0sh5+mFqxG5iQxBoH7H8AznnH2aRUFTrRkAgQkJUeI5c6YlUyLGF9bu4LUDAw5I4GeulyqP9qA1k4oyVONO08dgIduO/+iJOqbf3uut9ahQiDQlMBj8x+DA/PevTZSARQWrWx4Rq5r3m7YFybcm4iIlx3w3XY3N6OKAqdcIvo5101xuDkk0+pHaRDXWs/1Xqn3LPvHnvR5J2nQCVJfy1rAjQMwmwGN992C9Z0bGQpAyRaTRRCYKC0THqMB0G4ugqFm267GXJ75CCZmwBg7fq10Ea74mdTKz4NRIhqOcaB+x6As05+O5WT6litNcCMMJQLhSCrwsHKioELdDKA5+fNedV3jlRKPyUyzAzNBrlCAVdceSUqWhUoCHrTtLfB6lS1ze8vre/avOHm226xY+ZkMRs9ptVqFZMn7YwD9tm3Fa7TMhFVtjq0A+RcYT3iPXa819VUePobIQEq5RLOO+d87L7zblSqVt5gNCCFRBhEitjJC6Z67AA2dG+ev2L1SiuFKv/zz1ApZb9UxtSgTpuqdXV12WJPAae4Q4M3BmQ7brGJ0d7ejjAKreGdZi65FtdRGOHTn/wM8tncPxKVQEJCigAC1jiSNalGmxo5f/EibOpsBwT16whOENtRUyKs/joIGgYJxUhEAiUTaJm4br08aCTEVVC4/9f/8/DE3eOVYhTOg0KuOJUFIQkImgQEC0ilcfjEfemDp52HXcdNge6LQcogyEUQwwqYtWQObn/ivluFDGsqH8IwpDEIYRDAaryz0m7TsvrJhgCWIZ5ZMZfvfvA+RPkIuaY8jCT09fVhVL4N7z3unTjtgONIKliNdyHtpqPRIIXLrh3VfzJv55pHNaVkbzzkEIwbPw6Vctl2TCVRa8XOAhBBgN/+4fdYvHwJh0EIpXXDAWKLjLTWiON4ahRF7R0dHQv+eOWVIEGQQWAPHKSFXSmxaPCe08u6IQBAX19fLUXEMCMxBpDSNs/RGntM393KwzEJIWRdVrQhW0OzLUic9eyT/Pd77kKxpRmabZMT+g9ox5eaFsZ5k6WwAkwnnHgiMmFkx8apWgD1jpMM4De/vQzr2zdxFEXt1ihW0E7i0DC7BkJAJsx2zHzkPr751ltRbCogSeKBjwJaa+y00044+KCDayRv4NAxtlRtI7KkMSSJY446ClqpWppaqkqiYb3uK1asxG9+e5ktoJNypR4wJ62yjbZKNULi7/fcyQ8/+ggy+ex2e2BLfSXbI8A1xEkJiFYaUkjsPn13aK0RCLmWhGhonGugoSEkoazKe0dBiAf/+Qjfc989KDYX/yUeYDsOrlOusfUnS5cvwy133NobkegXOGsct9RzK4XAb39/+cgFixbYNvZKo58quyN4Rxx2ODJhpksnLkWBuDHgUfeuDyVmQ7X+negr9Q049W3bNq00WppbsdOEnaCNRiYIZ1PtjW1BtM3O0LU1/Oe/Xjtt8bJlyBazUKz/4z2wNnrodMtdioxwCz4MQ8ybNw9dXV3r7f6nYQzDsE1T7Lcu3D6cJMkxlUrFGcuuay/byKNKEowbOx6tra7uRQTQJn19veJEg2GYUDEJLvv95dYgI+vwMaxrzbq2uWkxbN46S0iECJBBiAwCRAgQWnlIlgP6AhjXN1XUu96mXyD4ClVP3D1eKfLeuKE79ma0trrZCUAJNZuqElNaJtL7Tzrnrcfu/ybkTAhVjhFlM2geOQx3z7oPjyyazVJIGGJQQK4lNUE6mS0hpNV3NQJsBGQQYmNf921X3/k3JLkE2ZYIrKoQJY19Ju6OD771fLxh8j6ERNuz1wDQdqMyur4B2Fxtg/6+p/+8AwCuoZUQEmwYU8dPoT13nQ4T2wiGNrpWvJYkCplshDXr1uBTX/oslqxYxoGUNQ87NeTRZjKZRZ09ndd86Rtf3vW5eS8gzIZQceyazLiu9wO6W/KgTiHO2owkd61b2fxTMlUsFp3comWAqdiAIAIJYPXa1RBSQLGZquyRA2Ns1CZJ4tGaGKEMMGfZQv7qd76B7kovWJLL/RTQTPbw2Ma2tMVxQY3dYvmVWURpoQAN/DfnuU7D1G60D97voB9NHj8Z1VKMKIygBcMIS4Jjo5Et5vDUC0/jE5//FJ6Z8yzLMEAQRpAihKQAUgibMhQIXHfHDfylb34N5bgKI2xHZOsJZ0AKSBGgr6eEow87CmOHjaRaCJ8GP7MHks3USXjMEcegmClAaW3fm8imPLk1WGwq4k9/+RN++KufM0uyHklKv6zHW0iJIAhw96P38Te//23IbNi/OJJpCwnoRjQ3NdfMoVSHn6QtfjNa2+JrKWEMskpruLIAG8A3NlpTCAvPP7v0Rf7SRV9FSVdBUjhjsK5jXpvFTGBC/FIMti1/WG84RLDjQYHA93/8Q9x2390cBQGkkDZH2kUIiMimlgmBX/zu13zFn69EtmBlUdM0OpvuIABNiCiDE489wX6GFJDkpHrTT21IdyHub17anp0i3ZQAAE2FYl38pcEDLCShr1zCxvaN1lucJIdrV3xpnHpJrBMEoUQYBLj29hv40t9eiiBjazoCErWCfALVCvOH8i7Vuxe7PqvMdU74ChjXIB40A5uHbpmAYq6ATCYDbQw0gAQKMWtr6EYRNmzehB//4iejKkl1hAwlhCQXeas/W3I5NNoYRGFmZqFQgFIKMqinxTFs/4LOzg6UK30QQiBRyWhyckUEQCmVT4xBKAOwZHzzx9/lh2Y/ijATulRJwHamlQMO/m3vf8QEYYT9YgEyYsuBp0Y3BQ1xJvj89tcKvjj1vwUDOnFoWGk9iQCZNDRqNRa7U2LXGhZvO+OQU2jPqXvwzCcexrzVSxDrKmQW+POdf0Hx9CLvOWE6KZ1AcAB2hFTIuoecbA96bOzruOn3N1x5ckffZgR5AVWqYudhE3DowQfj4N0OHJYVuU4GIEIJQNcK9Bph1SScEHnaov0/aNz7PQIXF027jjKAc951Nh5//HEY5dJehACz9c4q1ogKWby4eAHO/p/z8M4z3smnnHQyCoUCMpnMr1U1/kilXMEDjz2Iq//6FyxYOB/ZlgISo+0BZepSiDxAdcLUDsl60SSDM8Q23xIgGGF1hNMOhq4Hrj0PjAkBmYwfN35OKOSelbgCEQWpxhyYgGw+i4ceexS33Pd3PvXoE7d4chJyfdUo/P3+v/P3f/4jrFm3BplcxnbqSw96lxMu3AnOTGCiauopNoP4eQi2oys7HWnDL7Myl7hGeRhp0YWsNX9tfGfhDmljDIblm7947rvPufAr3/46MvkcElO10Sj3nkor5JoKmPXME3jfxz+IIw45jA9946GYNG4iokyIrlIP5s6dj/sfeRBPPv0UZCgR5jNOZYUbpBaBRCmMHT4aZ576Nqd93aiosRWvTINaiTIG03fahd56/Cl89W3XId9SgE6U7TegNZgImoBMPovLr/wdnnjuaf7w+e/HHlOmIZPLPk+CVpYr1ZM2tm/AX67/K2678zZUdWJVj2BThbjO3Wt9Bbg+eOsBYMyYMQhlgMRYWUIIW6chAGRyWcy8bybuOeZePu5Nx1J/j5O9u1jFuHnmbfy9n/0QGzo2IcpFSJSClE7Vx7iOqkwgY19l6CVMEAPXpCYlpU69y6XECXYFlpFEnyrjwq9/Cf84+h4+7z1nY8yI0chmszcBQG9f6fT5ixfij1f/CY88OQsiG8AItl5b2CiDTgwyYQa9Hb04+cSTsdeU6cRO1tFy8PpQBPYWYRpkXPtrQvXPRp4wdgJIW9UvZWxsk9lASAlIwp+uvQoH7r8/Tx03ebA1jM29nddf8Zcrz/jN734LBC4PHAzoBjUnxhaELzXfavU3XO88K9i4LrcM4wyAVJ50x46ANHLkzhCksqQNESUaEDpDvQPy6DGj0DqsFd3rV0OEgRsXV8dgDKJ8Bn+95Xp09XZvPOO00zF96nREgf09xRrVchVEASZP3IkMW9Ld0tIKo5SbLQxIqwAmpURnZwd++7vL8O0vXdSWjaL1bpDT+V0CgIUrl/IPf/lT/P3uO9HU0gSlEgRSQmuqq342LH3aWl0HbcffB3HYDO0U8MTdE3ePl+8pJK5tkgJAOansPnfZ3BdLSRkcGcQihtGMIMxgZKENY5tH/l9bpu3Te47YlfY4cVc8t3oBP7d8DlZ1rML6zetxy723Y+zbRz89vNCyHxuGINhwniCQsAeFdl6vvz95x2nrulZht0lTMGLEWOw6bhfsO2XPKc0yuzRBjF7TfsiGrg2Pbe7cjGpSBZG04TkDQAFTd9p13vDiyN0FW09TPST+X2BTCdv2+siDj6CzzjiTL//T71Ec1oJYVft1HNSsEeYCrO9qx09/8//w6z9chlEjR2F4W9tHent6sGbtWvRV+oBAINdcsN1GG3IsuUGPu99hWXPEOAlDamQjjg1SvfBqYNidhEwMGzQ3te41beo0/ucLT9UItLFdfSCEQFXF+MJXLsRz736WD9znAEycOB75bBYdHV1YsGgh7n3oPtz/8INgwcjlsjXFDVvcyDUClM5lIgYxZ/pNbxpCRaPhcHlpvJ37vZZpgJO9VgDGWxAKch6297z9nTTrn7P5ljtvQ1NbC3RchWygTcYoFJry6I0ruPHu23HzPXdY75eTh0uSBEEYIpvLwhBDqRgkbVqVMVayLyCJcqkPn/76V7D3bnuS0gZBOodoe+/U5u8KKfGxj30cDz/1KDZ0bIQUwqaYuFQoA41QhBCBxOwnHseTTz6BlpZmjBs9Zu9Ayr03bdqETZs3IU5iZHMZRFJCa4aU5IyeRs8wgbhePEmMEEDS1tK299Qpuzz//Nw5CMMMCMalGxlIKVCKK/j8Vy7EOe86hw+YsT/GT5gIKQU6OtuxYNFC/OP+mXjwsYfBkpDLZRArhUwQQanEFhCmBg9ZI4wYkMyqn0X7CgY8DQxYAgkZ/O2Om3HLXbdj5LDhGDFixOmagVVrV6O3txeGDTLZLODqO2zKoYDRGmEYIIkTjB49Cp/+xCetMWWcshDXrYh0/TEZ1/8hHV9To7HGaAEhTEroJk/YCaOHj0RfXKnVFYRhiEQpZHMZzJn3Ij7wkQ/ive85j3edMhXjxo5DksTYsHEDnnvxBfz97rvw3IsvoNBUtFENmFrkEFz/bOvrT9dzfXoy93fYmEHavfKQft6tDDwNiBsSb6myMrjSbq0uZfyocTR6xChetnoFgiiwQixcFxtgGES5HO558D78feY9aG1pQTFfsN16wVizag2OPPxI/OaXvwkDIRIAmD5tOrKZjFXNArm0MJtnnilk8dcb/ob1G9ZvPvX4kzFp0k4Y1jYM5VIJa9aux6ynHsftd/0d6zauR1Nz0dZLBRJGJwDJWoE81/q0oj4CZPBfUXjg4Yn7fzfcLgMBsASBEYns3DAM8dSLD6GDO8B5jSoSBJxBTmTQLLOfGt004lM7j56E8W07Ye/xU2jG+GloV9Wj4iR+P8f6lOZs/s22PbL1HJNo3A/ZeshgcMKBx888dv9j9w2i7G8Kmaav5CDQmXSc/9zGeUuWrl6ADX3r0RV3ok/FYANIBOCyQWAi7L/bgYii6GLDBpICe+D+l6XPSbIqDh/54IeXPfTowzsvWr4U2WIeyiTu8HUHv2FQSMhmsmAmrN6wBqvWrrJqDoFAtqngsnt1TVObG4imsU5LlybA2+BzZDf4Wv92A0ZdY5wbtIC1UgjDEKeccBIenfUoWnI5VDmpkVwN650iQbj0isuQzxfQ1twCMCGOY2xubwckIZvPWgk1ZQlKuVIBiBBksjBabddh3d+faLtLOpWzLaINLyeS4spEtvlels7bvPELP/05PPf8s1izYS3yuazzXtevK9HWs5xrylvDJZAw2kAwIypkXZje5QsLAaU0AiEQCKsw0dXeiXe+7Uyc/bZ3kXJyhFtlM4PORQFDgDIGO40eR5/86Mf5C1/5oqs30FYGTwqwMVCkIAQhX8zDMKMvKWHusoUgw5BSQEQChVzB5e9y3RAchNL2M6qIEq01imH2hROPPwFPPf0UMtmMK1y2+4w2gAwIVaPwy8t/jVwuj5amJggpUSqX0NXdDcMGhWIBipVt6CQE4krVWgZRYGU2WUGIoCZjB0bhlZkkg4w6sVPhMYgKWQgQNvZ1YF3XRjAEwiBAmMvUNdRRz4lmbRAIiQAhuns78bHPfhG7jZ9Mtttpo3HWoOxBdWJpnGEinOeVAUghDFjbY8Fo7LPbnrT/3jP47ofuQ2tbMypx7JqHMRLWyBXzWLl+Nb7xg2+jpdCE5qYWMAy6envQ092DMIpqpD2NKmqjnNIMtllQwwMcuJQaHw3/JngHHw31d1Skp6Eh9EuX2dqZoo1GFIQ47eS34rEnZiHM5/vVp6SRDJIMKQIE2RClpIK+zjIAg0AEoEyIMBOCybAUVtXohBPegkt//xt0VnvsxiwBrdOOxEC2KY+ZjzyAh2Y9gpamZuRzecTVBN29Pegt9SJfLKDQXLCiAGCoJLbFsoF0MpTWWEujWkYYT4VeB/A57v81/nZhSReL2q4lhcQ+O8+gM45/27qdRk4ASspqsUuCpgS9uguLN87HzOf+gese+xtuePZGnrNxHheC4P4xuabzxra0tkUiaodmm49OVhpQpGzNSAiWiEyEUbmRbx7XNHr4sEzxK+sqy/XfF9zG18+65g93/vNWzN3wAjb2rUPMJXAUQ8sK4moJLYVmnHzUiTh+nzfTsKjlkqAmaYX/uvQ54WTGRrYMn/yNr3wdzYUiqqUKAhH2P1Ccmg+5lI8gIGRzEYKIEAQErRIQG1CaYlLLZ7epDUYMUJRo9KwPcogyUPPWmQGKIdzoqoKAZsYJx74Fe0zbA9VSFYGQ1qOWFmISQ5FBcVgzEAAbujZjY/cmdFf6kG0uIFvIuZOaEUiJSm8JO0+chNGjx9g80AEWm1PlKKHhGmueM+5/dybN5yVyv/sSD7AGI6rRKNhWjxkJgdgoTB4zkb719W+imM2jVCoDoawRE5PuuMRgVhDCNlpi1tDCIOEEijQMGRhWVkHF1ToISPR0dOPQgw7Glz/zxUQw1eoa+nsrucGIH/C82eaFKyclKcBItMLpx781f947z0ZvRxcCBBDC5ohD2meuiRHrGCRs1C0TSUTZACKUEIFEAkaVDTiU0BIwgqAdge1XM9DoEUS9gdFJx56AKZMmQ1UTBBB2rwFgyFilFWLkW5tghMLm3nas696InqSMTHMO2ZYCNBm3bxDicgU7TZiIUcNHQie6HkEgq1pkXkWPAAEQ2iBghmADsAa7AtooGyHKSMgQYJNYEsbKFQBaj20gAgQQ6OnoxJmnnYGzTnvHRD2IcTZwRHmQaFu9D66rXXDPXgqJs95xJrJRBkmirMZ8asMLoJyUEeQiFFqKiEljXccGrO/ajAQahdYiwnwExaqmvmKUwdQpuyKKImhXoDpYUTT6J3Q17D3p+h2QyrLDwbIBelhk486Da6UMeLkxkM74PuktJ/xsz2nTUe0rg0IJ5RR6DFAzyCAZGgpBQAhCARFJcEhIYFKT2ykHKYwfPpZOO/U0VHrLiIKw1tjWRmETaCjkmvMIciG6qz1Y27Ee7X1dMBlCYVgzOCAkKrZRAaWRz+Uxbequzrh1AgdpNKPfnr2FXePhibvHvx8IA7XHiAlGMybkxo99xyHvOPCIKW9CW3UYuCeBLidQZQ2tCYkU6NQlPLPyOdzx1C24adbVvLjzBa6gCshU+o8hRH+2xLak3vI2YbC2tPqZu164nW+bdb14fOHDWNm7DCXZg7IuI0kSVPsUdG+CoCIwfcyuOPPwt5f2GTmDyAiQFrDCgQaQGvxf6DmQEEhUgiMOPJQu+fmvMGbkKJR6ehHKEAFZDycBCIhAWkO473XaiENpSGYIQ4goBDEhrib1fHBHzmqHIg/tnaofdcJ5q+v9QF0WVEOKh1XMYGMwetgI+tqXvowAAkklRigDSIi63jEIsU6gwRChAAIBhGTJKKwCR0gSpa4eTN15Mr7zzW+jtWkYdJwgLegdcCaHA71ptVQeU+/8mXaZTKXqXio9a/Su2R709fbrtLVugQQETgLu2EOOoj/8+neYustUdHX3WBk9IWtGgIAtGCejIdiSYcPaeYQZbHStFbokS2RL3X14+2ln4Ne/uOSp0a3DIwNbpVnrtEtD+TTRjygLIZwWN2qFk5EMyhd98Rv0ofd9EKWeXsAQIqcpLxwxkFLahj3GgLUGG5tcnWhl7ymQ0ARUtUZVJY35WQ3pEv2ZmRACyjAmjZlAX7nwyyAGTKxrBEe4SgMIgjIxIAERClBAkFmJ2CibGw8gCEJ0d3Rh+m674Tvf+jaai00wmiEC6eY41es7BDpfrTUegJBhQshASMLWnnDDlzYQMLa2Q8haYWkkAghDKPeUcP7Z5+IH3/o+RTJclT63wWdpzSJztrUNt1E/gmwVYSAIUtoeECcceTydf8656O7ohjBkCyBd36cgDJFohcRJdIpsAIokmBiKNQzbKBHA6GjvwNtOfxs+/qGPQSf/v70zD5Pjqs7+e+6tqu6efUajZbTvuyVr9b7b2IBtbIONAcNHACcsSYAkkBACXwgBEpYk7JAACXtsPhsDXuJ9t2VZkmXtsiRbq7XMPtMz091V957vj1vVy8zIGhtLMs758egxM9NdXX3vrar3nHsW47oFH8XA5bg6SmXpUYqFbmXgOb/cJkxUMmESc8XGxy/dU8oKrw9+u3LhaFEYeg1VdX/5D5/+e9RW1aBvIAfle+59Kq6Xn+RNMGCiCBy5nR4TexOsax4WOcPYvf5P3//BH5229DR0t3chUBo67lKrtYIBI2LrjE9fu/UduB3MkCNAubXNoYHNhfjrj30S559zAXLZfnd8Yyv7MAgi3IU/ONmO2A1X+gcArFGj6tdevOjN9PZzr8epkxagTtdAe1WwfhUi8hEaA60ssvlWbDq4Dr949Cf4zfpbeE92N7MfOgHPFta4Um3McbUZTei2Xafdv+Ne/vmDP1n81PbHcaTnECIKXbwnawReBp6XQiZVjWl1s3Hl8rfh6jOupbE1LdUcUZzVXvomDPu6a+/g6na75jz5MKw6a9lp9IPv/DvmzZmL7rZO2NAi7Qeurj3HyXdc3nTJQikPnp+ChsZAXw5sGAvmzUfKTyPwfPjkI9ABAu0qP6jYm1YULUVPMrlWG9qDpz0EXhqBTiHtpRCoACkdINBBcfkkHUkVKRRMhPNOO5s+8zefRnWQQV93FgoKgfKhSTkhysqFWCaJk+wEqCaFcKCA3q5eXHjOBfiPb/wH5k6be5PNF5D20gi0j5QfIPADaK0RBH4xrIErtChBaQ8pL4AijcBLIeW5c077KWjtg1/mra1U/94JW0/58HU8nl4AX3sItAetvWEuOhSbBgXKR2RCLFu4hH78nR/hsosvxUBPFmF/Htq4GHUFDY9814gqLhXn6t0raIYbfy8FjoBsdxaB8vCJP/84/uUfvkyja5uWMcf9D8pK12GExkpS1UTFSYCa3NrSWuHvPv4p+pu/+ARswSCXHYDH5NYVlMs/iOvvEykQaXfeSiPleaCI0dvegwljWjBrygxo1vB1Cr4Oiv8Czyt2BiZydaOUIoQmwqXnXUx/+4lPQROhL/7OmjR0WRIjxw2aFErlIj3SiPIRert68caLLsX3v/ZdTJ8wDWEhRMqPP9sP4GuNQAeuMRPouAX/WmPR19MPGFcbXcUhcszOyWGtddcjMzwm+MqDhkYum4cZCPHxj3wMn/vkZ0mBYa1xJX15sO/anb4mhUAH8JXv1r/y4akAvvbhewEC7cdhXEjcvK6srGV87AN/+skbrnsH+nuyMLkIGS8FX/lABPjkQSVdN2PnDMjt4Com5LID4NDizz/8EXzur/6uymMFnzykvJS7XuJz8Dyv6NG3scVa9EhrBd9L7lfumg+8lFsznv8yu6dSXPkGUNpD4AVu3ark+nXr0BmsNNRIj0t0+l4QRVGIlaeuoC9+7gtoGTUG/Z09QMHCY42U9uP7nI4rQWlXPhIKHty91NMeLNtGIgVFGsaEqKuue/8XP/cFLFu0BL0d3eACI+Wl3H0yqYlOrq5sUpVHM5DyfHBkke3uRVNDE778xX/Guy5/O9mBCNWpKqSUj4xOI6Xi+5PnI1Dx/YnV0cw84XWAxLi/fqRh8RJlKiWqWMVQpF2ujgEmNE2jy5tGYfuhnfzs3s3Y33MQUZRFVTqAMhGgUwDSiCywbvcz2HlgJxaNm8eLpy3F+Map5JU17+jMt/71xt2b/mnzno040HMAOqMR1HhQXgoE1yEToYIXaYyqbcDcyfOwePLyObW69jkn6gHEZbJQ5ulk+K87H4JL3nIdM33P689FoT9/6mz6r+//6MUf/ucPW2773W9w8MghBCkf2vfd9jYBIO0SN0kjzIcICyHAjDkzZ+MjN34Q9Q1NuP5d10P72oVAwYJIYSDbj+7xXfFD08YNNMpsdebans5udBxug59JwdoofjADUT4CRQQblW/Kx91ySSEyBjdccz3NnDGDv/wvX8EzG1z3xExVVbEmOMqqisAy+nP9ILaYPGEyrr3qrfjgH91IgQ6w98gBznb1ovNIK/yUa1SiPQ9hPgTnTdHjngjxpNV8d1sn2o+0wg8CWFgYjuNRjUVgXJJfpSA/1vy44+fzOXQcaYOXDlzIUSySCYTebB/6erIlYwgVIcfF7+1pH8ZGGD9qLH33S/+KX595G9/0/36Fzdu2oD/Mw0ul4PkebLxLokiDIxOfPyMX5pAfyGF08xi84dIL8O53vRunLVpOEbsim14sBkd0S6Cj/lj8pafcuEcw+OC7b6SF8+bz937073h67Vr09nQjSKehlUKkrOsAad15AkBYCNGf60N9TR2uuuhSfPIvP4mv/du/4KnHnkRDXR3YWBgFaM9Dx5FW5AYGimuS4ISgjpuOvfe6G2j6tBn8la9/Fc9uXA/laXieD6Xd2lWeLpYmJGbkc/0gEKZOmIzrr70W73v3+yhNPnYe2MPd7Z1oO9QKL+W7a0Ir5PpzSBmCtWYOgIdcUja9atd3IV/A0kWLMaFlPB586CF0dHbCCwL4gfsOKKu/zoYRFUKE+TxSQQqnLVmOP3n/jTj/9PMosgaAgldmmJXPXTL1UWTQ0drudrNcXVYYZnhKI9fbj96O7uIbi8UR49yX6qrqr/zTZ7/wlQXz5vP3f/Dv2H9gP/xMynl3yRarGJl4R9VGEXK5PKrTGSyauwAf+ZOP4OJzLiQNQq5vAB2H2mA815MCTPCVRkd7B3q6ektGjat57gMIc7k8Wg8fQboq40L/iBDF1W0Gsv3o6ep52a4rZovezm60HzqCTH81jHHrRJOrCtXf14/CQDhEzBIodo4wPOV2HN50waW05JTF/O3vfRuPPv4Y9h86iNCE0EHc30QrKEVx3wqGoQjd7Z3IdnWBgAKzjRNRPRhrMXvSNPrhd3/w0De+9W/n3Xb779DV2ol0dZVzrii3Q6KVdl58V/Qd2e4e1NfV4aILz8Vf/vlfYM6UmcSWMdCbReuBQ6iur4ONIjAByvdx5NDh4vcTXueO2uPdFloYnqSixh999Ea++5H7UNfYiN7efjxw0+8wZ/osMsZ1ERy55yGJFEzy38u3/b3Yi+uy541iBKRQQA5723fz9gPbsOvQLvRxPyJEUAA8pRDCQhUUMgMpvPHMKzGzZR7d+8CD3NXViUsuvmC3CsIHb3votj86nDsMU82AsiDrGrNo9pDiGkxsmoR5k+Zh6uipb6kL6n6L+KFvCFCaYJLyYMXKsPQKtoJK5SGSBkGXXXs5b967A0E6hSoEePz2+35UV9vw/uTvJ8fr7uJtk3OIrIHWHhSAHXt38oOPPoTHVz2BHbt2oasnGydImqJnc+yYsVg4fwHOO+t8nHHa6RjfMIoOtrfyqlVPupjTeCxZK9iCxajGJpx7xlkukqk8q5iAyBo8+OjD3NPXC+3puP57XIyBGSk/jTNOP/17tVU1HyIknn8qhuLYOP66s7/7K0+uWvVX9z54P55esxq9fX3OU8gMpTW0UqipqcHC+Qtw/nkXYsXS5ZjWMolMXJA7ny9c+ehTT/wm258tJmomCiXwfFx43oVTM35qT7mTuy+fO/uRJx97dGBgAJ5ygqAY48uMTDqDM1ae/rXaTPVfEVDRZfClrkcQ4cDhg7xm3RoXYhEbW0mBijCMMGXyZKxYvIwG73YNEcxAXG/ZQns++vJ9F65++un7H1u9Cus3PosX9u5GIQphjBOiPhE0FOrr6zF71mysXLESK09djkULFpECENoIiqiY5Dx4u42LwpyL9coHn1xFEM2gKh42ctvyli18L0De5vH4k4/zQ48+gmeeXY8DLx5EPiogIoaOw7pqq6sxZcJkrFy2AueddQ5WLllOAGHN2tW8+9CLcciLu9ZBhFwuhzOXLMOUCZPJssvHICYXBqaByBgE2kNHtudnTz696l333HcP1qxZjYHcAPL5gov40Bqe9lBf14D58+bjovMvxIplyzBpzAQKbQQCoT+f++CTT6367kCuzzWcipucmdCiKl2FS86/kALlO0++Gtm9wIQG2tf4zd138Mc//Qn41Sm3zpNwIKWQzfbjure8FV/57D/R6g1r+LG4tOeu55/HQD7nkn7jxmye8jBx7DisXL4S5555Ns48/YymjJfuzIf5et/zupNumByfY3nlP8sMRYTW9jZ+4qmnXIiV2z5xFU5IA8agZcxYrFi+ghJjuvybJg2TfNJ4ft8efmTVI7jn3nvjcx2I6+UztO/B1xqjGptw1pln4Zwzz8ayJUveV5eu/c98lAt8nSocPnKYV6992oWCxfdWIkKUL2DShIlYsWQZ2aSAORG0Irywdy8/veEZKE3wyYngyLDrWRAZTBw3DqcvXUkjidDmuN48E7BqzdN8qPUwtK/d+XNcdYUIYWRw+pLlmNQywbm2KKntH+8qsOuTwHFDOd/zAQD7DuzljVs3Y92z63Gw7TBa29vR0d0FrTWqMhlkfB8TxrWgZWwLliw+FeeecY7bz7IuZ4cBhNZCewoeFNZvepYfevwR3PvA/Th05DAKYcHpAaXhaY1UKoVJEybgvHPPw5krz8DihYudgVTITUsFqRc2b97EO1/YBfaSDqYWTB7y+TxOX7IckydOIliOnwlHuUcJItyF14JwHxoc7Mq+xV0JFRW7PaKYA+hKjEXIo6vQ8393Htn19/vbD6CrtxXGRghUBi1147Fs9pIfj063vPenv7mZP/ePX0K+vw9vu/pKfOXzX6CQClj3/Hp+oWM3+vuz0JZRk6nBuFETMHX8rIHmzOiqNGWgAXBk4w6fldWFVRwbWYo8eLkVfF/7wp3ZFhsXUTw3LvyUENkQvg6cB5NDZPv7v3Okve1D3d3dCE2ImpoaNDY0oKG28eqaVNVtiQwtRBECzzvGOosrUgwtgD6ykWVXvsxa19mUiJxXPE5gVNorxiL39vf9bX8h94XWI4fR19+PxoYGjG4efWugvbsymaofeFAwcDH7HsUPVq2OMbNcmYBJI78a2Nhh27sf9eFfVi/9ZVxpRxXubootjI2gPb9olOaiSGcHeu9vbW87r7enF1EYIVOVQl1dPZobmz+dTqe/mIq3vCNrYCPb4GvdRaTKwt/Kk1movKbUoGTnYwj3uMQrrIVWbpEYa5xIVm5N9hUGlnVns2va2tvQ398HAlBX34CmxsbW2uqa+VVeqi0xVKw18LzgWDe/Yjx0aZzcNWIZ8DwX+23A6BvI/mlff983W9tbkcvlUd9Qj+bGUfcHXuoXNZmqHxU7rYZx46Y4aY+OtRFR7NQ8wvv1CIR7X98A3nLJ5fj6F75GXmwQFEyEnt6evR1d7ZO6e7oRWoOa2lo0NjRiVO2ouVVBsN15tks9LJgZnqdd4qa1rg498Mpa3jCGeuxjkcrkOhn7cfhX3kbozw18qTeb/ZtDhw4BIIxubkZjQ/0/eEo/U5Ouui05qDEmTrjnyvCxo9z7wK7Rmta6eN8biaODRnI9xsJdxcmaIxmT8gR0FSfuKpAzPCgJbXIGUfn3C2ERWQMTmdPcvNMuj6gt0EHFPRNx2cdiHopWxR3X5HjZ3MCVuSh/Y1dX1+Xt7R1IBymMGT0aNVXVfx743k9SfqrbrY343usWBMg7RqSXKS2WpFCBxES/vpBQmdcJxa378saPoNIDysTJpeSSa1gRIhAsR1Dw0Bw0f6554ujPYSKjK+y6LmfNZdV+9V/XqqpWY0KAgc2bt6CAPDK1aezY9hz6+nLfqa+p//BZ08+hJdNXIlfo+1MydkptpvYTHlKI4jZQEYewxFCeO08NgFhDcckLXKoiVl4y5PXlJ7AwII67TrIzythaF6pgI9i4lXhjdf2HG6vrP3y0h44JTRxP7bl8A2t9sGmEUkfcS2xApApg12XzKNliMMYUDYhktJnZByFkArwkRrbM2140KBVBWx8cGYTsBHJ9Vc0X66tqvtjS0DzMs4SRj0JopeFrL16XbqvZWBcSQ5abGJwiog4QZZ1nUg9z6owoir36g1SJjUvrae0SL0caDkFxKJCNPeDMyYPXZAAVWeaxpGi/UqpYe36QNhp6nrG3DUojsrZYUSLleSZd23h+c23jUc3QyLjvp5WG1tSVhPK4D+NB1XdKO1WvRNhpFVfgiIWSpmSdFaA8jaogs7a6KUPjm0YPO6+RtUhKFpLyXHlBoNg90xW6csmZXhz765qTsQunS5J/oeDpxABwHsq6TO236jK132oZNW7oqcdrh0hDuVa27ngWiEwUi3iA2cS19pEhogGtvGJo1Kt8E4ZPGp4ihIWwioj6A89Dc0PT5OaGpuHn2VqXqKich520KiWYWy4KVxrGMOQkZj5JiiRXUYyZ0wSEisg4w7WsWU/sDY/jwOCRhjEGhhm+p9FYVfupxqraT00e0zL0fI0pnpOO64gTW5gwgmWuUkr1l2/2JNenUrq4lpN1Ya1bNwQLMqgnhW6AYeJrVTNBeyOTJ65jqXuWWBuvCVTuUiTOouS+MKh3UdnORslFzdp1YQjjTqUKgNbKVQIL/KfKLAzA2jiksdR8D0XDRse7LS6i3USuqVp1OvPbamR+21zTgJkTpw69tuJcMq11qVAUE6J8oYmV6gDZ4j61jXdyfdIVyariaRfhLryWt06OdqUmjYyYSnUWldtS96BQnqfFcS/tBr/pZgA3F29osTvcPUOsE6AeAUS9iUcgrVKoClLfSoSVq8muoIvVOcpNjLIM/yEd3F6frZSJFLzycSh+ffc7TV6pgnosZAbvDiTxrtovlXDT0ADrEPCPlD2NCiNxFevhPTfhcA/G5L/lDjBSACmXbFlx3mUPy+TlmgAdbz2Xu4AUVOIVDwEcHtlaJ/jJQ32QatZHvzKOeQG5lAJV7MrpxssbiA+xf8RHpdJ5EmhINEYizMrHrLhtD1c6NEksrjggD3+N0LHuAcP9enCHc0WgxEiKm+TosnNIarQn9cGTNaGJwIpKTaCcG3KIi5/dnWDQGowFpa5sqaVJF0Ve+Y4wx0ZYMcFQkfNelmrDF4/jqfJHmw+AoTUNnKj7sPa9fkKysxZ7XuM668m9j+BCEjHIq1x+vb3k+tJUMUdlF0Bu2N01qnxdcQ7L+liXX8Mou/9QsibLPo4YRe+vhivbetT7jiqbY+XWeKC0e6dGd/LHV5w1rJIQSyrtsh1jh1GV7Vh5g4wEKu79Upndz8PuZsQPVAy38ZDU31dl934NDypO3C/eCwbdx4ho6P05XjseBx2Dv8/RdtNEuItwF/4glfzRnupD+08mXigu84A7b0ap4UelW790k1EoC/+gwSE+R/n/clc5qgdpJA/uYw3vK9Wwv/d5n8jppT+8Yw8xxl4L3/UYn1MUy0QvufyO9gd6hd/hpcaK6OUE8NIJGbeKypdcfs5UUQHopF8XNIJr+Fhrk17hudAJmhp6tQ9Bw/+RXvk94GWt4Zf4PDoZ9wlBhLvwGtP8r+RmJCa+IAiCIAjCcUNyFgRBEARBEARBhLsgCIIgCIIgCCLcBUEQBEEQBEGEuyAIgiAIgiAIItwFQRAEQRAEQRDhLgiCIAiCIAivJ6QcpCAIgiCMgKRHRalXRVKPWw3Tv0IQBEGE++uPsp5GquwX7pkgD4GRjSEVm5+UGtDFP8Vd+wzQ8DpdOsMLjN/3oFQ2lklrP6p8GUnR/ld5Nmm4aXjpGedBDVz4lSyC+DrBMM1giifCv+/KehXX+6AGcCfgnDj+/iaMUOjPg0CwMMWmdJo0ov4cokKhOFxJ5+PBHZAFQRBEuL8OIEjvot9v9IYKoPIGrwyStf4qSSc+yQLuf4NwP9prhrY2fzWano3ss187c04A7PDX//E4TXZOAGbGwgUL8Nm/+TSUp0GKijOiQIjCEHOmzXJt7JmhlIK1VkS7IAgi3AXh5WiS/22PTRqqtV9xe3JGsvEjpuXxRQ2dhiEiVL2EORW/j17hZ9Ox1oN6ba3ro53P8ViiRNDKA7PBrKkzaNbUGS99yykT6xI+IwiCCHdBEI6tV/j3snXw+2h/4ZWNOR1j8HkEIvWVzBUPZzCg8nP5tWC6nUSnPxEB1nnQIxOlSKm8s5IYYC6aEcwErT0QAdbayvcLgiCIcBcE4dUQ60cVccPoJpEgrw0DjY/yN36ZGpePJtpfa8YbHeX8jnOkDBiATbI6CL728xYWSmkAXBGSBwCWWcS6IAjHDSkH+Vp4GFMpTjXx0rAMyyt4vnLFw5wJIFWMd/f/140H8ytWW1SuAONjFY/HskBf/bkqW7fMANuKgR489snPyX/pJQyukc11SYCyNaXPte73peT5k3dt8+CxOJEGgyIkHnYiJ+CJOU6MLftHVAxXSpJSRcALgvBqIh73k/UgsgxoIEgHsGyLor0/11+86Vu20CS21UhUT/IoZ2IMmFwQRZFLYbMWqUwKWulNsZX0+jP8hhOB5MSOYQsFgnoZ62g40W6RJOgpwFqQVhDf+6sn2pkZIIJlC6XIGfAcG/XsYtCtBRQYsBasqCTaiYZslbycmSEGwARjLZwPwbqkSigQKWdDgAFNJ3GNEyJrYnlMcRy5OnGimMpzPVB5PQ3aCSiPbxcEQXi1EVV4sh7W8Z1+1KhRUKTADChFaG9rjx8MJOX2XoGA1dDo7OrM53I5aK1hrUVjYyM8z7vr9biKitU1ymMZiGHYOL2nfo+qI4nDXhFIJf9lkKt1Jwvu1Vq35K53ZgYBiNgASkEpDyACk42nlkHWgMmCyUIpBfNqbH+wsx5IASALVgpK+4AGDCIwWyiiykIuJ+F+SQrQSoOU876fSGHMR/lXcfOR27UgCCLcX8cDH3tsxjSPgfZcrKS1wO49e9yDwlp5ELwM5UMMRMYAAA4ePIiBXA6e58EYg+bmZvi+/yBeZ89WZ9pVXsLW2Nh7C+TC3IL2nvbn+/J9V7+UuBscelD5kwXDIgKjs7f7npwpEBTAJ1PFvR7tr6TmN4CILXrzfTe09rY/NRDlx7kQawsCg5UTsAYWbdmO+6DI7YbQS83hCE6AyJU3VEBEBh3ZzpvzJiSCAmnEu1p8EofIIh8OzGvraXt2oJA/lcGwbE6oU2C4f5UGtIXEkAmCIML99ao149jr6TOml7ZdCdi+bVs8M0o87i9D9JSHwOzdsxfdPT3QWqOQz2Pq9GnwY+/76/6C1gqGLTzS2LNvz6avfv0r055+Zs2tAB01Nrjcc1khPciFHhEUNm7bxF/42pcuuev+u60lgiUR7q+mKnRhXQaGIwTKx6q1T//0K//21ZUv7N19UJMGWwtrDCwsiDQeWfUof/nrX73o4dWPMEEVEyLxSuQjEYgYEYcgaKzb/Cx/4atfuva+Rx6wUATLBobNSbN62TIUNNZuWLvly1/750U7n9/xjKd9WJghBsvxvc8M808SPgRBEOH+v+hpDWD+7LnI+AFMZMAEbHthJ3JRrprBsOYki6OySAygtEsw6Ncnv9IEkUuii3+1eftmZPt74fkBrGXMmjbTnffJDO94yX12rvhP8v+LscUwcSD00JcN+ZiyLo2sLTr7utCf7x/6vlh0RIjQ0dPxSCHMZyr+SHEBfOvmfGCgD919vejt6XEGJZc1wSnPmzxaAmsx4bL8U5zfnrlMbSYVPLjs7Yzfy5npEmtL/62IMGKuHPPy87bDfaAtzUWcW2GTA7Jxc1WWRMmDvm8pqXToNZaMqwIhl+tHW08bTBQnqxNDaR0b8wrdXVlks33o7ewpdVyO56zCG2y5cuzKncPxuXPicWd3/P7eLLq6u5DN9sYdQjVIqYr3WuZhx2/4dc3DXwt28BwNv3aSUQxNiI5sBwomjB9eCkO7qAqCILy+keTUk4SNqzRMGDX29DmTZ67a+Px2ZDIpPH94H9Zu2Zg9a9EKMoUQUCVvvHueWZQKk1FlCbfj0TGQS4lv5NQPLClECjDMkxItA338de/RdLuxFmwtPF8jm+u9bs2z6xDUZJALC2huGoU502cdW/H+HudV6a8GGARm5+F2uQpuHNmW5s9YW6c0eqhYpUKB4iREQwBZF9McmTzADK3SLgeO3BE0FGCBiCMwWXjWd19PA4rcZISIYFMWHM+NjROiCQQYF3axv2s//8d//jsuv+SK/tMWnkbMFqRizWqVE0cWWHnKcqr+k2qeNm78f8MSiBQiG0GxBwWFAoeAYnjkAzZ2hCp3rsQKbCLAGpBOxUmOFsZaQHkgBrQ1sMqNEUW2lj3ujZQbl8C6zECnGS0UJaJtZKI9imyxy6Uy1o2zchKbWLnTYQNjrG+ZRimlDikFECIQe7Cs3NgzQ5FxM24JlhlGK0Qw8NhCxyFKVmkQaxcXzgwml2yqFMEwQzFATCVDJw5DIcVggwZodBFFYG2hYyPMEOApAqwHZuDS8y+9fubMGf89c+L062ABUgoRLDRrN/bxZUsMsI1gLVcZcJOnvP1knYfdkkGkAa18KAt4rAHDOHvpiinNzU17Jo+b8iMyLoSGCIA1gFVgMCIwSCloACYMfSgVquTztCom2FJy31A6HgcGMUFZ62wK7YwpYrdoiHSckO8sEDPowo1SgNHxz1ZXdKpiAggm9ke9yjdDeknPgTzQBEEQ4f56hwgwxiCTqnrqzDPOxKoNa9E0bjTa29rx0GMP48xFK8Dxgx+KTspjIq51A4u4wQgzVHwGxlowITxh4zWCFzATNmzddNOGTZtRVVeDnt5eLJ1/KhbMmf/nbBlK0QmfZGaGtQYMA+35RcGpoXrc6EauSkhRyKFYwYKtheelSt8+TntQsK7SiAK8+BJ2nnbnQaXiiCVezDi5UdnYENNxoikhO9CPg51HkEMBSqni+RmKitVK2DC0p7Bk5mICDIwxsExQSoOs+8zA82FgwTCA0bHX3+UeGGvheT4A31VTsgCTq2CiABi2CJWBpwJnp3qqF3Bx3JExvmYVaqjYK/zyyusREXxfI2IDhoXWpaqg7rMjsCVAWXjaDwEcKrdbLRuo2NtMsWVk40RNikO0PM8fUmuUjTPILFtAu3O2oDjJ08Q2MUN5XkVInK/RxexEtVWl8JTETGe4HIbqTPqmxbMW3uQmy72CB10lxrq4eO1raFC/BvqL17Zxaa2uI2hS+tFZjEGQ3rto5mJ3sMiAYquciABlQMpDACCEhWULL/Ar7gMRIpBRUFqV1jTijqIgMAyMts5gKL5Lu6vBGoD0sMXo47pG8vAQBEGEu3DiUeS8bwBh+bIVqK+thwkNMukqPPjIQ/jge9//743phj9OvGaJ2B+2C8lx0qMuWa70qCSlinaEpzWIqP2ED9yQzpIMDYKJ6yf/5s47EFqDNBQ8Vlhx6lLUZ6q/aUwErV/95T506FWZkCYwsdPYSqO90P6ZzVu3/8P+F1+EZWBKywQsnDv3X5syTX8RGgOV2GnxlySlsGH7Bu7L9WPp/KUNKT/Vzcwu7pyAgfzAsme2PLOmob4e86bNJy7G3NKw50eWi17Nzp7Ox7e/8NyZzx1+Dn7Gx679uxEgw2EuxOQJ4zF1wmRiwHmIFdCZ7XriqS3rzpg3aTqmj59Jhm3s/Sb09/d9ee3W9Z8Y3dKMeZNmEhTDWnK7BuRE+tNbn2FmxqLZi9IpFeTZuko1bC08rdBjotmbnnt2+4Hde4B8Hg3NTZg5dwEmNE6kiENPKT9SsTHAttKYHXaZxOPfm+381w3bNn5s6uw5tr6uXm/YvpFf2Pk8VOBh1pw5mD15BgWaYBBi9ZbVvGvnXtRU12HKlAmYM2MmecoHWwMNXbSoImKQDyhmeErhhSP7eeu2Lejs7kIqk8bMGbOwaNocYuN2XIwFrKak4I8zIMnAAth5ZBdv2/kcutvbkUkHmDljHhZPP4WssjBUuvoUVJJDCiLgxfYjvGXXZiycPg/jRo2jxHArVSx052bJYOPeLbxt9zZ09/ZgVOMozJk2G3NbZpNiBkxS5tFVryFFaOtu3b9u2+YJMyZNx4yWqWSsjecqgtIarW0v8pZ9z2PO7DlPNVU3nr5q81reuXsXajNVmDBpAmZOm3V+g1fzsI3niamsVnxcEN5CYePerbx7zz70dnShsa4Wc+bNxZRxU8myLX5fDcAyHc/bnCAIggh34dhYy1BKw7LBiqXL3j13ztyfrt+0AVW1NXhu+3O46567b7zhquv/2FgL/Xu1V/l9NDLDcukTo8hAgaBZISyEYLajS2r6pPUihzUGShM2v7CD73n0QXiZFKJChNpUFa568+XOU3cC6+FTmVFhYBAoH2uff4Zvuv0mdBxpR1NNI3w/haeefBR31dd9/Jorr/34itmnUmjdBUnkYoiVUrj34fvx4pGDmDt93o9Sfuqt5ZZLrpD7u1t+dwumT5+GOdPmgoiKpUXdeSiAqdRYJwkcV0DrkdYzb739FuSDEOQRnt20Hls3bEOhK4fLLr4E0ydMQ96E0MoDKcLh9iNn3HzbTbj6ojdj+viZrsoJW5DyAEWH7n74Xnhphb/+0MfnVns122wi1BRh76F9/F+//C8sO3U5ls9bmod1OzeWDbTysefwPv7F7Tdj2/PbUF9TjWoVoKenB+q+e/CGi97Abzj9QrIcgVi78B1v5GvtUGfrx37865/j0iuuVIdePMybNm1EfX0denqy+J/HHsD5557LV5572Vk3//YXj69e/zTqa0fBhox7Hu7DiuVL+W1vftvMKuXvcjXUAWYLIgsDg4jh3fXgHeGDDz8IcITa+gYMhDnc88j/4LQly/mGy9/RkqLgEJGKcwLc+xmM0OQzdzx0V//9Tz6MvkIOTXUNsIUIdz/wAK5+yzXMcTjIMHYqiAg7d+/EzbfdhKq3vRvjmsfF+QNlvVMJ6O7r+tpNd9z6F6s3Pg2dUqirq0FuIIf/uecunLnsHL7uzddQhgIX0sIEY6Kxvhcc3nfwwIQf3/wTvPPK6zFj/DQwbLJ/A0Bj177n8bObf4b3v+/9pz3w3P388GOPoq65ESafR+9DvTh1yfKHbnjzOy+v86vuYBPvdMXhQJYZPYW+j9xy16+/tWbdGvipKlSnqtDX04W7HrkXV195FV+w5FxixCFNww2CIAiCCHfhRKNUkrzGqE3X/uyqN1/x03Xrn4FiwPN9/PjnP8UlF1zUMbquuWlozeITI5IJBK2AJEd24dz5SCsfA9l+LJqzADWZ6ndba0DHQRQPCdvnl3ihc2Pix7/8CQ61tqKhsR7Zti5cdNEbcMqsBc4b6SLNT5x5wYyQI+Upbbft287/+Ysfw6sK8N63vwezJ05HKgi+t/vgix/81V234T9+/l+o/+DHeFbLVEJowYpL+XyBBrtY8dohs6/pefYslK/iMBkX1qCKr0gCq1TxZ6UUrGVMnDjpLR/5o4/8Zt3utbjjgbtw/rnnY8XM02CjCPV1tTAcgVTpSCoJ80iahTH7nvJCjiyqq6v/ZcmyJV+76/47sHP3rq2LZy4hCycGFYBnn9+IAhewdPESKFLOi08MRRqd2e7/+s+bfooDrfvxljdegVPnLEJVENi29nb12/vvwi2/uRVVQYovWn4BhVEIXexgOTIiskjVVeG+h+9DS+N4fPC9N2LMmObfdHX2vuWXv74Zj655DC/s3fF4T2sXbnj7ezBr8pw2E9rmOx+5A488+ThGNTXvvOLsK8nAhTORYvjM8MnHrx+/M7ztnt/irBUr8YaVF6CmvmZrZMy8Jzevw5133Y6qVPrgtW96GynLAHtuJuK6+nc/cn//nf9zJ6bPmYkLzr0EE8ZNgMnlsWXXDtz30P3wqhmpTArWuijvJI+TKU6IZbdOSA9eds7znjN5+s/bf/EXq9etxWUXX4Kz5i9Hc1Ptl3q7+z/18JrHce/DD8IP0vz2S68h2AhKaSjtHXafAeiUB3hl68iaYkiNYUaQTuGOu+9AY1Ud/uzGj6Bp7JgNhb6+Rfc+cR8eX7MKDXVNt7/joquImEEhAE+Byb33Z7fc9K21G9bgzRdeimWnrEBtY+3X244c+uj/u/NW/Oq2X2FMYzMvmDqfLFuAVHH5in4XBEGQqjInDSInolScNHfVG9/y43kzZyPfn0MqncKW7Vvxw5//V6MiQmhCWDZgNsNWJTluBcniAzuxZfG2q66mr/3zV/CFz34ef/sXn0BKeS5s4XjL4UHVSZgtjHWl8SIbQXkeHl/zBP/6d7ehqjqDqBCiOp3Gu6693u1qRFGcAHr8Ts/9KykMIoAUWVbA3Q/egyg0eNc1N+DsU86hMY0tVF/d9KHFMxfT9ddcj+pMBs9ufBaWTSzESuUtIzawHmCQ7G6grIqLrbKKYYkRwcam1vAmmLvaPYA0lCJUZTK/nTJhCrWMagHyFhNGjcWMCVNo1pQZNKZxDBEBvlKxuTN0hjWpkABAuc+cP3ce/MDH1p1b4YJo3N/ynMfTm5/B+HEtWDB1DjEzlKb4Kyrcu/qh//PC4T24/NJLcfXZV9LU0VNpTH2LXjj9FHr3tTdgfMt43P3QfWjtP/Ib33Ox+S+nOBABKORyqA3SeO8178TiyfNpbKr2qnktM+gtF74RnmHs27MXV1x2Jc5ZeA6Nrhs1esKocXTVG6/6dvPYMXhmw3pk89k3aa3iZFsA7KOju2vNI48+hqWLl+C917yHpk2cRc21Y+ePbZhA15x1JV16/mV48IlHsHXfdtZKQ8GCYgPyQPdBvufxhzFh4iS856034PQ5K2lcfQtNGjuV3nTmpXTFJVcg25V1Bli55UooJaR7LrQlqadv2YliF+5O2LBjg12zcTXOOfssXHfJW2nGhJlUnxr9txPHTaPrLr+OVi5dgW3btqA92/5YEuee2EOW3JpKfqEIgNJORMM1QWICokKI6996PRZOn0/N1Q2Lp46ZQm+97IqvTBg7Dus3r0VHX/vvyFNglaTqKPRkuzZ2d3fh9JVn4po3vJWmt0ymxnTVx+ZNnkeXX/Ym5MIctu/c7gwEWOSZT1wijSAIggh3YSRTYKxBY039e//PO2+ALYTQDNTW1+Fnv/w5Hlr1MAdegIgjJLW4K8qmnQDFTHGSoUce3nThpfSut11Po5tGkWUDrcklPZ4oRzbipLu4QoXWCq2dRwr/9NUvIzQGvuehL5vFJedfiNOXn05sLZTyjp9pwUdT8oRA+djXtp93H9iDOdNmYfHkeWSthY0YbAlhVMDMlin0yQ99FOeednov2yiu013KYxi+8yklwqYZimDiMAlXDZCGnBMPNvDihFPLFqZg4FkNm3eJhsYY1ymzuEdRaZ6U+/J1HHMeWYsZLdNo8vjJeGbjs+jJZ9+vFcFTwHP7d/Keg/uw5JSl8HUK1nASNYKQQ2zZtRVedYAzTj3tGTC7vxtGoRA2TGoYT4sWLkZrZxu27dh2JaBgOCy+f0RXl1IITYSxo8dgcvMEsoUBRZbA1mDmpGlf9XwPtbU1mD9vwQcsMyhSCE2IpnTjn45qaEZPthe5MPdxwCXhRuxiZjY+/9yyjv5uLFywAMoAPbnuG7ui/ktaCz2f6w3zixcsWACrgeee3xFfQey2rgjYvmMHsvkBnHrqEkxomkKFMJ/RlmCNRWgsli1avnTy+EmICqaseg4P2TFiYtjEJov/pxXBwmLzlvWo8TXOOnU5fPZRCA2xJYSFsMpahXdc/fa//uN3/h/UBen3I9nRo9LcurU0qNRi0b2vUMjnMXvWHIyrH0PGRPCshokKaEo3f3Jc8xj09nZioJC9HECpg69l1KWr3vgn7/7A/e+85p0UIkR3vuc9vQP9X+jNdb83XVODmqY6HGk/AssFeEQIQNDF0C+JchcEQZBQmZMOQZMGs8XVb77qrDvuvOPxp9atQbquGn0D/fjM5/8eP/vRT3jy2IlUiEKlSVutTqS9FXveYo9ZFEZga8cqTYe1p115SMs4IadEcUk+pWDjRE4D4HP//I/+s1s2onZUIwr5AkbXN+KP33cjPM9HFEXQSh/v0xqq39nVyOzq6kZ3XzfGNjcjIFfKz2o3WJ72oTlCS/1YAoDQFMBxjLo1DB1XtbOWoYA+xCqIVVxmj/QREycAqqTeD1MxoZGOoXAVqWJtfhcKo+JW8olQH/TNqCQdXQAOw8Ye9zQFOH3pCvzilpvw3K4dP1g+f8kPGcC6zeuR9gMsnre4aDkYMHxPo6u38+lsXw8mjB+PdCr9KSKCYpe4DUIXGBg3ZhwKJkRXTxdc1L56Wd6GyFqwJjSOGe0MFtIW5L67F6S/D0/9VVVNDTJe5ocAgQw7j7IG0uk0cvk8jLXzk+PZeDz2db8ImwHuuO92PHTP/zBbD5H2EIIRKPosmTyiKERXR5ebNmaQdmN3pO0ICjbE5ImTwczwKBhQTCDyYMGo8lLPjB49Blt2bh/GaFNlpltpr80ahvJdWrNhg8Oth5HJZDB21JgHiYCANDMBnuf3R2xQl67+cmO6/svMrsINDTJCacgap2LtdqUJ1hqMHTsGCh6MieI1owEoVKerEEVhHFVFiJigCdCGEQTp/Q2Bf/G9qx/jXZu34+CRw+jKdsFqCxO4JlQD+QFYG8EjDWXc+R3vcrOCIAgi3IURiz7EdZ6rUlVPfOZTn8E73/9u9OazyFSlsP/Qi/jM5z+Lr//zv32nobr+w1EUnbBcUFIEYzmuDOI8ZlprkPYOAwy2xv2eTownjOPuOGFkxrKmw2nt42vf/yb/7t67UN1YC4CRz/bj7z7zSZwyeyFFhUJKKS9PQ3yHx8W8qRQ8nHjMgTwieGm/mEhrtatR4upXayDu6KrId0KaGZ6mYiyzE3XUUfos9ymFKLyuKKpgoeFVaG0adHZUvujiH5icB9yqciuEAFKuHn3STIgq+/gkx7IEIGLAYyycM297dV3dnKefXYeV85eho6/tFxu3bcScSTMwedREggFIK2fUEAHEOWUMfAY0+TuQVOKJz5kBeL47BxPF7e1NnKugRnp9EZgNMpl0scY6UwifAK39nZYtUkHgwkEsipWACHDdYbWChj6cGELJ9/YUocARFiyej6m1LeCQYMiHVQrW5KHJIgJj8ujJSArsW46DqZSNy2FSMg5xEyS3EwKPoXX8+WV7HISycqFcWRhWK0IEhmKChQsvsX4APwi+r9jt8FBcaF0r910t2ZIXvewCUUkvp/J+SFRWhtO63Zl0OiidG7neBc62VGAo6LiBgFKuBr/WhILJ4Qe3/oTXbNiAJTPm45ILLkSqOgN4Fp1hFnfdc1exmhXi85TgdkEQBBHurzkUaRhTwLwZc+mjH/kz/vsv/gOCdAqZmmo8+Oij+Pin/upDX/38P1/QXN80z0SVpQ2PW+w2uyYrLjQFFQmyTkC4OtVanaBlxC48JgiCwwDwzR99n7/zve8hVVsF0hpdbZ24/A2X4R3XvJ2MjUBK5cs09IktfBOPVVVtBnW1dTjYdsS1jVeu2UwipZVW6BvovxaWx2XSVd9MxFIi2eqq67AnvxvW2MXslD6sdY15jrS2NUdh5LztSWjDsAkPSUlB6yrNlLeMYhduYeL5LvXSomGOQKUkybjckCtSQ2ATYVRN89z5c+bzc1u2o7u/8x/3Hdr7jtaOVlxx/qXQSsNaCyblchPAqMpUva02XXWo9cWDyIeFD1bpqk8yGdel0zpR+eKhA/B8Dw1NjcmIvaxp9BnwjWv4E5+4E6sMsInGegykWEEzu5Avj8A2AqBiY4WBYgsrgh/fMltqxsILNSa3TMXF8y6kl7SmCwzyqeglHzWqAR4YB1/cjyUzlqIAg0C5KjtQGnmTG9vW3grP95JsgVII1ODuuihVn6G4SqYPjaamUTjQcQQdHZ3/3TS68SZWBtYjRBzCiyPlB/rzH/KC4IcpXxeGLF8+muHslD0pdy0CAMVGZvIWQ4SICBxXhVEGMMolkD+zZQM/+ewanH32OfjAZdeTRio5e2xv38VRvhAbTc4YNZ4HYxnpikuYT/jlLAiC8JrRizIEJwnGkERTRT5CE+G9176bPnDD+9HX0Q9LQHVTLR5+8lHc+NE/mbtl51bWngdro3g72sUFlz/QbSxSytuRJ7HxzDz0s4/2L/a++aSgY8lX6bRV8Mhz3r+RHvNo/yyXWt0bC7BzRFuDuJu8hTUhPM9DdqD3j//mH/+Wv/bdf4Wq9qChMdDZhzOWr8Tn/+4f8inyQaSgtStlSPo4PuWpdCEpTsSU8yxHHGHSqEk0o3kynntuB7a37matNIhzsLZfa0XYemgn/+P3vnrz3U/c/w2lCBy6JknMBgzGxDETEBZC7Ot8cTIRoY/zdU57Ezbv2IB8mINi15yIAecCLxoq1iXzJjkIZV7aJIqmKlUNDx6MDZ0hpqw7hGVQRUt6C21QlrDogmU8ArTnPKweAiyZdyr6+nrwzK4Nn16/ayPqqquxZN6S94BdXXrFQBCHhlXr6sMzp81GX3YA67Y/8wmXsM2IbAHa99GWO/LtDZs2YFRNA2bMmB2FsIi0Le0OjABDBqw0yDrtrZUHzU58azYEoxHFOxYuXMS4zrEg+MoHGcDC1rtF6OqcIzKYO3kqmtK1WLvuWXSb7hVACFPobUDUDyDCXavu5e/8/Afc3t21DkEiN93ELJi+EE1BPdZteBZHBo7c7GkPBbKwSsFTGs/s3HDo+f374HsBQhRiIW0rhTpZeKTdDkbsrffY7YopaJwy9xR09WTx9Ka1bm14EawdQCreUfjZrb/kr//k299pHejKls7N7WqErses62wLgKKoJtmNAIDIAiqyxdhzRtz9NJ6XgDTIsGumNMj06+/NwgdhwrgWaAQYiLqn5E2fF8Fg9fqn0Z/tB3keIrYtcfNdqKRBlGJoU4q9t8qWCtsXQ/SP58UuCIIgwl0oE9bOe61gLOOTH/0Evett70BvVw+sZaSrMli3YT3e88E/wm33/JaV9uD5PkJjtDFRFVsGWxs/w+MmNRUxq6X/jdRdVe5hT7b1S+9PQmRoiIgdkdiloR7qYmw2xbXHLeKa12EVKQXt+9i4dRO//yM3fv9nN/0SqaoUPF9joKcPi+YvwL/841cwpmF0OuIoFpal70An1NvuPNnGWvjKwxvOugQwhF/e+its3reVWTO0p83OQzv4pt/+Coe7WjFt9iwnppVFMWSEI0ydOBm+CnDnPXdi26FdrJTu6enPfu+Oh+7kzVs3oCpT7eLTUWoTn4hytoDneWXzOHQQxo0ZB20V1q17Blv2b+ZDXS9yf67vmmLX1EScKSCtg7gdPSo6owKA0hoGFvOnz7moZex4PPn0KqxZvxaLF56KmlT9T8ubByUhJwYG5511HpobR+HXv/017l/zAPeFucUFZbDjwA7+8X//7MMH9h/AhWeei/E1Lb61cVUlM/LYCaUVtArgURBfZ06Ux9fIpLRfBVCcM2GpOHcKCmQVUl46LsUZxyBZBrPB2OYWOnvlGdi0cTN+efv/W32g4xBzYLuypv+dd6+6l395282I2KCmunppZG3c+Mo1XWtpHE/nrDgXu1/Yi5/e8vNrt+/dxhEb9Az0/uuDzz7Mt/z2FqSCDDJ+2oWiIanJX37jtgiU50JrkpmNw0qYLU6dufijS+bMw8MPP4TfPXE794b9byPloSff/+477r+TH378EUwYPw6j6xqDQmTAxlVrcnOt4Xs+tE6MHZWlMkcAERBov8yUj7v2xh54ZYGM8opCnomL+RZTJk1Gxkth3eqnsadjHwde1Z4CzOzfPX4Hr9+4AfV1DSBoWKBagaCthccl8Z/2UlDxnpCVPqqCIPwvREJlThbDNkCloldNaYXPf/r/EgXgH//8Z6htqEd1XT06+7L4809/Enc/8gD/2Qc+jPlTZxOAfmuNi1vlqCislFJgUxZLiyT8ZeTifZgstZf38zAbDYNfW9ab1TWoYU46zUBrDa39/sMdbfzTX/0CP7/p5+jo6kLDqFGwbJHt6sGyRafiX//pa5gyfjLlbQGBOtnL2hlNHilE1mDR3EV03VVv5d/edSe+/e/fQ/OoJmZj0dnbBc8P8N5rb8CiKfOowBF8DcC40CQDxqxpM+msFWfwY6sex3e+9200N47i3u5eZFIpvPPtN+AHP/shst19RYOKyyI2bMTo6+xDob8wVNASIeIIYxvG0IXnXcQPPfEQ/uNHP0A+W8A7rnr7LeeeeS5F1pTWSkTo6uzCQH+uuI4Gt6MHA9VB1QOLFy7Gbbf/GjqtsGzhMhdKA66oCqLhIeIQY+vH0Xve/h6++babcfOtt+Lu+x9cH6R9dHZ2QDFw+RuuwEXnXEywIQKrQJaO2TW1nChv0dfVi3xy3mAYZnikoDWt7WrvQiqIvfBxnLaFhQdCvi+P3s5eeKy6in5epWCVh4gjvPGCy+YM5Aa2r3pqFbZu2ISm+gbu6+tHTzaL5YuW4forr3vY93xExsR5Cs4oYDDedMkbM/25voFVa5/Ct7Z+E2Mbx3GuMIC2rnZccOEFSFelcestt7oa6GVuForLyER5i+62bkSFKDbYSuUiwYy6TO033nf1uz7381/d1HDn7+7E40+s+pWXSqOvrw+5nj6cfcY5uO5NV89IsUUUl0q1iREWWXS3dSIcKBSFN1SxhD9MwaCnqzf+bBRn1jJrACbXn0N3R4/bCQJgDTztIbImwpSWKXTxBRfzXffeg2984+sYVd/I/fkB9OT68Jar3oqHHnkInUfa4EPtcZuDJYM+Klh0tHfCRskOEotvXRCE/33ykVl8FidJ2g2p5ACOEwU57lGoFAwbfOP73+Kvf/dbUOkA6eoMIjYYyPahqbYBV176Jlx12RVYunhZRb4es/PAl4XN1IAoW0r+O5nffOivSCkorYZEMO85tI/veuBe/PLWm/HcC7uQTmeQTgUwhRDZ7h5ceM55+PLnvoTxo1soZ/IIlI53HTy8hKP5Vfw2NpYtpRCVJP7bJR1aGLbwVYD9bQf42W2bcLDtMBhAS/MYLF2wGOMbx1HBhgC5gCSP3TFcciSjYMKGHTt2de7evxvtbW1oahqFJYuXYNLYSfTAkw/yqIYmLJq3yMkvU6r8cbDjMD+zcR3mzpyL6ROmVtSVZGZXRpIAQxY7d+/kw0cOo7+nDwtnz8fkiVOIDaA817K+rbvt0Jp1a8ZOnTQFs6fNIa1UPL6V8fJEQGt3+4vr1q9rqa6rwsKFC9/R4Nf/N5WstJKxRkDeFpBSAdr6O27asHXzdXsO7IcNIzQ1NGDu9DmYM20WMRsow1DkxYmwCtAjm9QjnYf5qfXrMHPGTMybOJ0MCIYAn1xc/gOrH+ea6mosX7SEFHuAMYBykeXrt27izo4OnLVy5YUpr+pB5+UlsCIwDBS7rqCbd2zlLTu3oXugDw119ZjcMhGL552i0irFkY3gKx/WGFetBm7clXKG2ebnNvOu3bvQ15NFOl2F6dOmY8mCpbS/bT9v2rQRp56yGGMbxpALsYrHWCnsP7yft+zYhDmz52Ly2EkEQ3GFoCT3wFV6KZgQz2zZxNt3P49sPoe62josmDYbi2fPI8UWMABrP+7H4CrwH+o6zGvXr8f8WXMwfcI0IiiXd+CeGDjQup+f3bwRc2bOwoyJM4gNuags5a6HTTs3875D+3DOirM+X5uq+yyxiitCRYDHKMBgy3Pb+cV9e9HZ2oHqulrMX7gQsyfPpifWP8kBaSxduMh9LnSxCdPug7t569atWLxwEcY1txBbhu+J70kQBBHuwgmUr+X9VdhaQLkKMyiGeFgo8vC7e+/kf/nON7B113Ooa6iD9jSiQoiBbB/q6+uwYOY8XHLhxVi2dBnGjB6DxoaGKdVeZu8f0phEiNDd3b2ptbV1wbZd23Hfg/dj1drVONzRDuX7SFdXwRqLgWwWdekqvO9d78WHPvAn86r9zLbQRvCUAlsLlVRXwfEX7qWelnDKpehwL5V2YTaw1sLzfACu+oczLWIJG7nuszYOc1FMRY+24RCKCFoF8adZKLiyfyEbBHFVEJO0f2K3lWOtBVUYQhaDI+Ms2zjcgOFTpQAykROaUEDEFppcuAbHhokr2WhQ2ZnVHZOo9KkFDuGRX1H/3YVzcLFySGgKUErDJx+upZCBF4+OLXbsjLMqVOzjJT3C68wWQzrYhGClEcUeddfgyP3NJWArVymJXXlTpbziMZLShm5OrEtmZcAaW6NTQRYA8jBIxWEcbKJ4ObhJVUrFxrSr1mQ5AgjQ8bgbRK4qUHHMvOLcGWvdJgMnFYRcSdTkGxpEIKNduJSCy20AgzkCk4aChwhAiAiZ+DNCUwBZwPMC2KTiK1swImjlFy8aayO4ijiucg2zdd1f47wAwxYeaxfWxgxoFM+NYQGThNcxDBuwsjBkkaJ0pQMDQD/nUBX/3kQ5N/6k3Zpghq908Rpw0UfkOumekOtcEARBhLsI98HCnZNqDbbo4bI2gmXA1x72vLiPv/7db+J/7rsH2Vwfqmqq4ad9DAwMIMoXEBZCVKWrMGnSJLS0tGD06NHIZNLwlVes761JgWzSEqYUvsBlzZZG8vPLf497RDNscWefy0Jlevuy6OzsROuRVuzeuwcdPZ2gQCGVTjvBawm5gRwUE5YuWoqPfujDOGfFWWRdNmtRyLmY65cRCnQ8hHtRkVTWQreRcW3qlYqFFbtGR5zEp5c5xYta1cbiLXLjqJTr4xOX50vyGpTWSGp7xFUzXfiCdZ+n1PAD4kJc2Ikwa0FgaBXXHSGqEOTGmLj2uwYRg8lUVqmJJ9SyjSvIAJ7yhk+D4JLnP1HzliMnUInARrlYeOXEqAttZzBxXC1cjfhCC42BUgQdVyoBxe9nIIzLbao4nIzhjJJkx8pdk7pYVak4rVzKIbHsDO6krCvF11kpl0NVXvSxYUcEGGuKoSg2zkvxtR8nZ7tzISpdPbCx95oYkY2glZuPyptKqaAmcyk2XZFy5xfvlBCpWLAXWzW4BFwwjDUAKbfLQUnn09ioiw1RpRQ06TjGhop9FiyME/TJOuJi+SFXfhQWURS5taR1KTZeucZYbgnEZgvpUiUjtmDL0MolYw+pfCPCXRAEEe7CCRPuR/NCW5ewGkYhAs8DQHhy9ZP841/+FI889Th6+rNIV2egfQ9Kue3ygYEB5HM5GGuRJPRxWanAl1tS79X93rYyvr+Y60rwgwCB7yMIApDv4ohNwYALEbhgsGThqbj2qrfibW95azrwg3wUhtCeVxmywSf6QX4U4T7s1Va00FBWBgPMx+gJSZU1ALm8CU98qFJRwGKhyUFjMbLi/1ysEk8vvXhjAUblvnQ+uveTjyLcK7+ndePJBEBXvqlYR979Uo90csuPUTzvZOxoyFocNoStZJPEor1yuRENXXeJGB7y4qPMr4UBypOM+Whrp+wkabh5OcqYH0PkVmr+sncetdDloEEbxjIrugVs5TyWr1YM4w6o/MBSqckhX1mEuyAIItyF15pwL3rIkvAJZihPg2Hx1Lqn+Td3344HH3sErR1tyOdzYAbSmTR834eK48Yp7orpunBamDiRbdgHLo/w51fyHipTQRWeZdeJ0VqLfD6PsBDCWot0EKAmVY2Vpy7D1W+6Aheefe6HqqvqvgdYhIWoRmsvCzDUcJ1RT9hDvEy4DxbLg4RfEqxS/tVN2emq4U77WIZIhS4cRrgfTeS9CouWizXGy1QZ4+XNRZkXGqr8mOolhO4rPOfBCnSY5rBDBPqgaS02JYq/ajL7eph5VXiJsl081GjhooR9CeF+1L+NZL6ObjgxDfoYrrTFKuy+Y33+oDFSQ7p2DV0udJS1/pLLX4S7IAgi3IXXnMC3pui74jhEIolL9uImTK29nY+vXrv6zNVrVuO5Hc+hraMDrUeOuAoShTyscVv+7kHqGu6cvBVHleEscGXygiBATU0tGhrqMXr0GEwZPxHLTl2Kc886CxPHTiQfLrwkCg20crHWSUiDq2X92jfUBmvocuFXHgNO5coGI2uUe1SBM1ILcVjR5EwNGnKckl9+RLppsDd6OD1aJvQQjwFVqMpB6pN+j4kY7oRjb7yNPby6TLizSowuBrGzMBJDrMxkq9ClnPyOj6HDX7boHMaDXzZfwxo8VLn+yg2QYQ3Lshcn9wpVbrkwDTlYxU5N/Her3ErRsRedk/AXWxrXZJyOZki4I3LZiL4K3hBBEAQR7sKrJe4GP9zZRnFNbwZIuw11IhhjQXFVC61KDzQDi0MHD3JHTze6u7uRy+WKyV1xpDX0yVturnV6MZbA/Y5ASKdSqK6uRl1dHVrGj59Q7aVeLI0LI4oiV1fa1dQrxV8zSiULT9ak0dFkerlyomNdicOuAB5GtlCZ0OQhAQfl8hGDpOVLnF+5ulPlwp2KNbhLItAW542POeMvLdwrv0/5b8urdHMcS69ewfRUnisN8q5T0Qxx4tISYKGgufRaq9zZaMRNqWjQuB172SfZByjv+kmDY99p8HmXXknDfJ/KaJVhdipouKVqhy5dC7AiJBkLqky4m3iMVFILksoUdzG1wZmglKyzWLibeAfFi19skkCgCuFunWnIlXkpld9ehLsgCIII9z8Q4V6MiSbAMhUbsrgaxs57zXGHQssMz399lEczkXFhQVqDFKGUbofyNlKvjUk75h4+hnophzsQDfdbGvK2SuE+eL2MJJ6Bj64uy15akVxcIRJLv39VhfsgQ4aLEk4N+w1HNj2V5zo44qQk3FEWQh5L6gqBySXPcHl4DdOxT6gsB6HCUX0Uz3n5eQ965YjmZHBEDQ2zNnkYo6lY2LS8C3PR485lwn2wIceVnxOv9Ypxi9dyhY1a7movE+5DdgdGqshFuAuCIMJd+IMT/8zFKhJ/aHNLZd1OieTpKwiCIAiCIMJdEARBEARBEP7AUDIEgiAIgiAIgiDCXRAEQRAEQRAEEe6CIAiCIAiCIMJdEARBEARBEAQR7oIgCIIgCIIgiHAXBEEQBEEQBBHugiAIgiAIgiCIcBcEQRAEQRAEQYS7IAiCIAiCIIhwFwRBEARBEARBhLsgCIIgCIIgiHAXBEEQBEEQBEGEuyAIgiAIgiAIItwFQRAEQRAEQYS7IAiCIAiCIAgi3AVBEARBEARBEOEuCIIgCIIgCCLcBUEQBEEQBEEQ4S4IgiAIgiAIggh3QRAEQRAEQRDhLgiCIAiCIAiCCHdBEARBEARBEOEuCIIgCIIgCIIId0EQBEEQBEEQRLgLgiAIgiAIggh3QRAEQRAEQRBEuAuCIAiCIAiCIMJdEARBEARBEES4C4IgCIIgCIIgwl0QBEEQBEEQRLgLgiAIgiAIgiDCXRAEQRAEQRAEEe6CIAiCIAiCIMJdEARBEARBEAQR7oIgCIIgCIIgiHAXBEEQBEEQBBHugiAIgiAIgiCIcBcEQRAEQRAEQYS7IAiCIAiCIIhwFwRBEARBEARBhLsgCIIgCIIgiHAXBEEQBEEQBEGEuyAIgiAIgiAIItwFQRAEQRAEQYS7IAiCIAiCIAgi3AVBEARBEARBEOEuCIIgCIIgCCLcBUEQBEEQBEEQ4S4IgiAIgiAIItwFQRAEQRAEQRDhLgiCIAiCIAjCK+X/A8PIaROHbWU/AAAAAElFTkSuQmCC";
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
.dp-logo{filter:invert(1) hue-rotate(180deg);}
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

// ─── Virtual List (windowing for long lists) ───
function VirtualList({items,renderItem,itemHeight=320,gap=16,overscan=3}){
  const [scrollTop,setScrollTop]=useState(0);
  const [viewportH,setViewportH]=useState(typeof window!=="undefined"?window.innerHeight:800);
  const containerRef=useRef(null);
  useEffect(()=>{
    const onResize=()=>setViewportH(window.innerHeight);
    const onScroll=()=>setScrollTop(window.scrollY);
    window.addEventListener("resize",onResize);
    window.addEventListener("scroll",onScroll,{passive:true});
    return()=>{window.removeEventListener("resize",onResize);window.removeEventListener("scroll",onScroll);};
  },[]);
  if(!items||items.length<30) return <>{(items||[]).map(renderItem)}</>;
  const offsetTop=containerRef.current?containerRef.current.offsetTop:0;
  const relScroll=Math.max(0,scrollTop-offsetTop);
  const rowH=itemHeight+gap;
  const startIdx=Math.max(0,Math.floor(relScroll/rowH)-overscan);
  const endIdx=Math.min(items.length,Math.ceil((relScroll+viewportH)/rowH)+overscan);
  const visible=items.slice(startIdx,endIdx);
  const totalH=items.length*rowH;
  const offsetY=startIdx*rowH;
  return(
    <div ref={containerRef} style={{position:"relative",height:totalH+"px"}}>
      <div style={{position:"absolute",top:offsetY+"px",left:0,right:0}}>{visible.map(renderItem)}</div>
    </div>
  );
}

// ─── Badge Display Components ───
const BADGE_RARITY_COLORS={common:"#888",rare:"#378ADD",epic:"#7F77DD",legendary:"#f59e0b"};
function BadgeChip({badge,size="sm",earned=true}){
  const sz=size==="lg"?{w:"56px",h:"56px",emoji:"24px",border:"2px"}:size==="md"?{w:"40px",h:"40px",emoji:"18px",border:"1.5px"}:{w:"28px",h:"28px",emoji:"14px",border:"1px"};
  const rarityColor=BADGE_RARITY_COLORS[badge.rarity]||"#888";
  return(
    <div title={`${badge.name} — ${badge.description}`} style={{width:sz.w,height:sz.h,borderRadius:"50%",background:earned?(badge.color||"#1B9E42")+"15":C.surface2,border:`${sz.border} solid ${earned?rarityColor:C.border}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:sz.emoji,opacity:earned?1:0.35,cursor:"pointer",flexShrink:0}}>
      {badge.emoji}
    </div>
  );
}
function BadgeShelf({userBadges,allBadges,size="sm",max}){
  if(!allBadges||allBadges.length===0)return null;
  const earnedIds=new Set((userBadges||[]).map(b=>b.badge_id));
  const sorted=[...allBadges].sort((a,b)=>{const ae=earnedIds.has(a.id)?0:1;const be=earnedIds.has(b.id)?0:1;return ae-be;});
  const list=max?sorted.slice(0,max):sorted;
  return(
    <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
      {list.map(b=><BadgeChip key={b.id} badge={b} size={size} earned={earnedIds.has(b.id)}/>)}
    </div>
  );
}

// ─── Sentry helpers ───
// Report an error to Sentry with tags and extra context.
// Used in catch blocks where we previously had silent console.error.
function reportError(err,tags={},extra={}){
  try{
    console.error("[reportError]",tags?.feature||"?",tags?.op||"?",err);
    Sentry.captureException(err,{tags,extra});
  }catch{}
}

// ─── Action Rate Limiting (client-side, in-memory) ───
const _actionRateLimitState={};
function actionRateLimit(action,maxPerWindow=10,windowMs=60000){
  const now=Date.now();
  if(!_actionRateLimitState[action])_actionRateLimitState[action]={count:0,start:now};
  const s=_actionRateLimitState[action];
  if(now-s.start>windowMs){s.count=0;s.start=now;}
  s.count++;
  if(s.count>maxPerWindow)return false;
  return true;
}

// Server-side rate limit check via RPC. Returns true if allowed, false otherwise.
// Use this for sensitive actions to prevent client-side bypass.
async function serverRateLimit(action,maxCount,windowSeconds){
  // Quick local guard: if in-memory count already exceeds, skip the server call
  if(!actionRateLimit(action,maxCount,windowSeconds*1000))return false;
  try{
    const result=await sb.rpc("enforce_rate_limit",{
      p_action:action,
      p_max_count:maxCount,
      p_window_seconds:windowSeconds,
    });
    // RPC returns true on success, null on any error (including rate exceeded)
    if(result===true||result==="true")return true;
    console.warn("[ratelimit] blocked or RPC error:",action,result);
    return false;
  }catch(e){
    console.warn("[ratelimit] exception:",action,e?.message||e);
    return false;
  }
}

// ─── Mention Autocomplete (renders below textarea) ───
function MentionAutocomplete({text,setText,onAfterInsert,inputRef}){
  const [suggestions,setSuggestions]=useState([]);
  const [show,setShow]=useState(false);
  const [selIdx,setSelIdx]=useState(0);
  const [mentionStart,setMentionStart]=useState(-1);

  useEffect(()=>{
    if(!inputRef?.current)return;
    const ta=inputRef.current;
    const pos=ta.selectionStart||0;
    const before=text.substring(0,pos);
    const m=before.match(/@(\w*)$/);
    if(!m){setShow(false);return;}
    const q=m[1];setMentionStart(pos-m[0].length);
    if(q.length<1){setShow(false);return;}
    let cancelled=false;
    (async()=>{
      try{
        const rows=await sb.from("profiles").select("id,username,avatar,avatar_url",`&username=ilike.${encodeURIComponent(q)}%25&limit=5`);
        if(!cancelled){setSuggestions(rows||[]);setShow((rows||[]).length>0);setSelIdx(0);}
      }catch{}
    })();
    return()=>{cancelled=true;};
  },[text]);

  const insertMention=(u)=>{
    const ta=inputRef.current;if(!ta)return;
    const pos=ta.selectionStart||0;
    const before=text.substring(0,mentionStart);
    const after=text.substring(pos);
    const inserted="@"+u.username+" ";
    setText(before+inserted+after);
    setShow(false);
    setTimeout(()=>{if(ta){const np=before.length+inserted.length;ta.focus();ta.setSelectionRange(np,np);}},10);
    onAfterInsert?.(u);
  };

  if(!show||suggestions.length===0)return null;
  return(
    <div style={{position:"absolute",bottom:"100%",left:0,right:0,marginBottom:"4px",background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"10px",boxShadow:"0 4px 16px rgba(0,0,0,0.12)",overflow:"hidden",zIndex:50}}>
      {suggestions.map((u,i)=>(
        <div key={u.id} onClick={()=>insertMention(u)} style={{display:"flex",alignItems:"center",gap:"10px",padding:"8px 12px",cursor:"pointer",background:i===selIdx?C.accentBg:"transparent",borderBottom:i<suggestions.length-1?`1px solid ${C.border}`:"none"}}>
          <div style={{width:"24px",height:"24px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"12px",overflow:"hidden",border:`1px solid ${C.border}`,flexShrink:0}}>{u.avatar_url?<img src={u.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:(u.avatar||"🌱")}</div>
          <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>@{u.username}</span>
        </div>
      ))}
    </div>
  );
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
// ═══════════════════════════════════════════════════════════════
// NEWS PORTAL — Portal público de notícias sobre cannabis medicinal
// Estilo inspirado em High Times, com identidade visual Diário da Planta
// Lê de news_articles (público via RLS). Não exige login.
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// NEWS PORTAL — Portal público de notícias sobre cannabis medicinal
// Layout inspirado em Covid-Stats Pro (tagDiv): masthead, menu de
// categorias, mosaico de destaque, duas colunas (Últimas + Artigos),
// blocos por seção e sidebar.
// Paleta: Índigo (#1a2b4a) + Ciano (#1cb5c4). Tipografia serifada.
// Lê de news_articles (público via RLS). Não exige login.
// ═══════════════════════════════════════════════════════════════

// ─── Paleta local do portal (não usa o verde do app) ───
const NP = {
  indigo: "#3d3528",        // marrom terra (estrutural: topbar, nav, footer, texto)
  indigoDark: "#2a2419",    // marrom mais escuro
  ciano: "#7a9e3f",         // verde-oliva (acento principal: labels, links, nav ativa)
  cianoLight: "#a3c265",    // verde-oliva claro (borda nav ativa, link CTA)
  amber: "#c47f3a",         // âmbar (destaque: badge da matéria principal, números)
  bgLight: "#f0ebe0",       // creme (fundos suaves)
  border: "#e0d8c8",        // borda quente
  text: "#3d3528",          // texto marrom
  muted: "#7a6f5a",         // texto secundário quente
  dim: "#a89e8a",           // texto terciário quente
  white: "#ffffff",
  serif: "Georgia, 'Times New Roman', serif",
  sans: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
};

// Rótulos e cores das categorias
const NP_CATS = [
  { id: "todas", label: "Início" },
  { id: "medicinal", label: "Medicinal" },
  { id: "politica", label: "Política & Lei" },
  { id: "cultivo", label: "Cultivo" },
  { id: "geral", label: "Geral" },
];
const NP_CAT_LABEL = { medicinal: "Medicinal", politica: "Política", geral: "Geral", cultivo: "Cultivo" };

function npTimeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const h = Math.floor(diff / 3600000);
  if (h < 1) return "agora há pouco";
  if (h < 24) return `há ${h}h`;
  const d = Math.floor(h / 24);
  if (d === 1) return "ontem";
  if (d < 7) return `há ${d} dias`;
  return new Date(dateStr).toLocaleDateString("pt-BR");
}

// ─── Manchete em formato lista (thumb + título) ───
// ─── Carrossel de destaques (portal + RSS; fixadas primeiro) ───
function NewsCarousel({ items, onOpen, canEdit, onPin, isMobile }) {
  const [idx, setIdx] = useState(0);
  const [paused, setPaused] = useState(false);
  const touchX = useRef(null);
  const n = items.length;
  useEffect(() => { if (idx >= n && n > 0) setIdx(0); }, [n, idx]);
  useEffect(() => {
    if (n <= 1 || paused) return;
    const t = setInterval(() => setIdx((i) => (i + 1) % n), 5000);
    return () => clearInterval(t);
  }, [n, paused]);
  if (!n) return null;
  const go = (i) => setIdx(((i % n) + n) % n);
  const H = isMobile ? "260px" : "360px";
  const arrow = (side) => ({ position: "absolute", top: "50%", [side]: "8px", transform: "translateY(-50%)", width: "38px", height: "38px", borderRadius: "50%", background: "rgba(0,0,0,0.4)", color: "#fff", border: "none", fontSize: "22px", lineHeight: 1, display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", zIndex: 3 });
  return (
    <div style={{ position: "relative", borderRadius: "3px", overflow: "hidden", marginBottom: "8px", background: "#111" }}
      onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}
      onTouchStart={(e) => { touchX.current = e.touches[0].clientX; setPaused(true); }}
      onTouchEnd={(e) => { const x0 = touchX.current; if (x0 != null) { const dx = e.changedTouches[0].clientX - x0; if (Math.abs(dx) > 40) go(idx + (dx < 0 ? 1 : -1)); } touchX.current = null; setPaused(false); }}>
      <div style={{ display: "flex", transition: "transform .45s cubic-bezier(.4,0,.2,1)", transform: `translateX(-${idx * 100}%)` }}>
        {items.map((a) => (
          <div key={a.id} style={{ minWidth: "100%", position: "relative" }}>
            <a href={a.__post ? "#" : a.url} target={a.__post ? undefined : "_blank"} rel={a.__post ? undefined : "noopener noreferrer"} onClick={a.__post ? (e) => { e.preventDefault(); onOpen && onOpen(a); } : undefined} style={{ display: "block", position: "relative", height: H, textDecoration: "none" }}>
              <div style={{ position: "absolute", inset: 0, background: a.image_url ? `url(${a.image_url}) center/cover no-repeat, linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` : `linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` }} />
              <div style={{ position: "absolute", inset: 0, background: "linear-gradient(to top, rgba(0,0,0,0.92) 0%, rgba(0,0,0,0.25) 55%, transparent 100%)" }} />
              <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, padding: isMobile ? "18px" : "24px" }}>
                <span style={{ display: "inline-block", fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", color: "#fff", background: NP.amber, padding: "4px 12px", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "12px" }}>{(a.__post ? "Original · " : "") + (NP_CAT_LABEL[a.category] || "Destaque")}</span>
                <h2 style={{ fontFamily: NP.serif, fontSize: isMobile ? "20px" : "26px", fontWeight: "700", color: "#fff", margin: "0 0 8px", lineHeight: "1.2", display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{a.title}</h2>
                <div style={{ fontFamily: NP.sans, fontSize: "12px", color: "rgba(255,255,255,0.8)" }}>{a.source_name} · {npTimeAgo(a.published_at)}</div>
              </div>
            </a>
          </div>
        ))}
      </div>
      {n > 1 && <button onClick={() => go(idx - 1)} aria-label="Anterior" style={arrow("left")}>‹</button>}
      {n > 1 && <button onClick={() => go(idx + 1)} aria-label="Próximo" style={arrow("right")}>›</button>}
      {n > 1 && <div style={{ position: "absolute", bottom: "10px", left: 0, right: 0, display: "flex", justifyContent: "center", gap: "6px", zIndex: 3 }}>
        {items.map((_, i) => <button key={i} onClick={() => go(i)} aria-label={`Slide ${i + 1}`} style={{ width: i === idx ? "22px" : "8px", height: "8px", borderRadius: i === idx ? "4px" : "50%", border: "none", padding: 0, cursor: "pointer", background: i === idx ? NP.cianoLight : "rgba(255,255,255,0.5)", transition: "all .3s" }} />)}
      </div>}
    </div>
  );
}

function NPListItem({ article, showImage = true, showSummary = false, compact = false, onOpen, canEdit, onPin }) {
  const cat = NP_CAT_LABEL[article.category] || "Geral";
  return (
    <div style={{ position: "relative", paddingBottom: compact ? "11px" : "14px", marginBottom: compact ? "11px" : "14px", borderBottom: `1px solid ${NP.border}` }}>
      <a href={article.__post ? "#" : article.url} target={article.__post ? undefined : "_blank"} rel={article.__post ? undefined : "noopener noreferrer"} onClick={article.__post ? (e) => { e.preventDefault(); onOpen && onOpen(article); } : undefined}
      style={{ display: "flex", gap: compact ? "10px" : "13px", alignItems: "flex-start", textDecoration: "none", color: "inherit" }}>
      {showImage && (
        <div style={{ width: compact ? "70px" : "100px", height: compact ? "52px" : "72px", flexShrink: 0, borderRadius: "3px", background: article.image_url ? `url(${article.image_url}) center/cover no-repeat, linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` : `linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` }} />
      )}
      <div style={{ flex: 1 }}>
        <span style={{ display: "inline-block", fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", color: NP.ciano, textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "4px" }}>{cat}</span>{article.__post && <span style={{ display: "inline-block", fontFamily: NP.sans, fontSize: "9px", fontWeight: "700", color: "#fff", background: NP.amber, textTransform: "uppercase", letterSpacing: "0.5px", padding: "2px 7px", marginLeft: "6px", borderRadius: "2px", verticalAlign: "middle" }}>Original</span>}
        <h3 style={{ fontFamily: NP.serif, fontSize: compact ? "14px" : "16px", fontWeight: "700", color: NP.text, margin: 0, lineHeight: "1.25", display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{article.title}</h3>
        {showSummary && article.summary && <p style={{ fontFamily: NP.serif, fontSize: "13px", color: NP.muted, margin: "6px 0 0", lineHeight: "1.45", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{article.summary}</p>}
        <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginTop: "5px" }}>{article.source_name} · {npTimeAgo(article.published_at)}{article.source_lang === "en" ? " · EN" : ""}</div>
      </div>
    </a>
    </div>
  );
}

// ─── Card de seção (grid 3 colunas) ───
function NPGridCard({ article, onOpen, canEdit, onPin }) {
  const cat = NP_CAT_LABEL[article.category] || "Geral";
  return (
    <div style={{ position: "relative" }}>
      <a href={article.__post ? "#" : article.url} target={article.__post ? undefined : "_blank"} rel={article.__post ? undefined : "noopener noreferrer"} onClick={article.__post ? (e) => { e.preventDefault(); onOpen && onOpen(article); } : undefined} style={{ display: "block", textDecoration: "none", color: "inherit" }}>
      <div style={{ width: "100%", paddingTop: "58%", borderRadius: "3px", background: article.image_url ? `url(${article.image_url}) center/cover no-repeat, linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` : `linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})`, marginBottom: "9px", position: "relative" }}>
        <span style={{ position: "absolute", top: "8px", left: "8px", fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", color: NP.white, background: article.__post ? NP.amber : "rgba(26,43,74,0.85)", padding: "3px 9px", borderRadius: "2px", textTransform: "uppercase", letterSpacing: "0.4px" }}>{article.__post ? `Original · ${cat}` : cat}</span>
      </div>
      <h3 style={{ fontFamily: NP.serif, fontSize: "16px", fontWeight: "700", color: NP.text, margin: "0 0 6px", lineHeight: "1.25", display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{article.title}</h3>
      <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim }}>{npTimeAgo(article.published_at)}</div>
    </a>
    </div>
  );
}

// ─── Cabeçalho de seção (faixa preta tipo jornal) ───
function NPSectionHead({ title, onMore }) {
  return (
    <div style={{ display: "flex", alignItems: "center", margin: "20px 0 0", borderBottom: `2px solid ${NP.indigo}` }}>
      <span style={{ background: NP.indigo, color: NP.white, fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", padding: "8px 16px", textTransform: "uppercase", letterSpacing: "0.5px" }}>{title}</span>
      {onMore && <button onClick={onMore} style={{ marginLeft: "auto", background: "none", border: "none", fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", color: NP.ciano, cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.5px", paddingRight: "2px" }}>Ver tudo →</button>}
    </div>
  );
}

// Hook simples de responsividade (usado pelo portal)
function useIsMobile(bp = 768) {
  const [mobile, setMobile] = useState(() => typeof window !== "undefined" && window.innerWidth <= bp);
  useEffect(() => {
    const onResize = () => setMobile(window.innerWidth <= bp);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [bp]);
  return mobile;
}

// ═══════════════════════════════════════════════════════════════
// EDITOR DE POSTS DO PORTAL — estilo Gutenberg (WordPress)
// Blocos: parágrafo, título, imagem, citação, lista, separador, YouTube
// Posts públicos, criados por admin/editores, misturados no feed do portal
// ═══════════════════════════════════════════════════════════════

const sanitizePostHtml = (h) => {
  try {
    return DOMPurify.sanitize(h || "", { ALLOWED_TAGS: ["b", "strong", "i", "em", "a", "br", "ul", "ol", "li", "span", "p"], ALLOWED_ATTR: ["href", "target", "rel"] });
  } catch { return ""; }
};
const ytIdFrom = (u) => { const m = (u || "").match(/(?:youtu\.be\/|[?&]v=|\/embed\/)([\w-]{6,})/); return m ? m[1] : ""; };
const newBlock = (type = "paragraph") => ({ id: "b" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), type, html: "", level: 2, url: "", caption: "", videoId: "", productId: "", product: null, settings: {} });
const PP_TEXT_TYPES = ["paragraph", "heading", "quote", "list"];
const slugifyPost = (s) => (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);

// ─── Renderizador de blocos (visualização pública + preview) ───
function renderPostBlock(b, key) {
  const s = b.settings || {};
  if (b.type === "paragraph") return <p key={key} style={{ fontFamily: NP.serif, color: s.color || NP.text, fontSize: s.size === "large" ? "19px" : "16px", lineHeight: "1.7", margin: "0 0 18px" }} dangerouslySetInnerHTML={{ __html: sanitizePostHtml(b.html) }} />;
  if (b.type === "heading") { const H = b.level === 3 ? "h3" : "h2"; return <H key={key} style={{ fontFamily: NP.serif, color: s.color || NP.indigo, fontSize: b.level === 3 ? "20px" : "25px", fontWeight: "700", margin: "26px 0 12px", lineHeight: "1.25" }} dangerouslySetInnerHTML={{ __html: sanitizePostHtml(b.html) }} />; }
  if (b.type === "quote") return <blockquote key={key} style={{ fontFamily: NP.serif, fontStyle: "italic", fontSize: "17px", color: s.color || NP.muted, borderLeft: `3px solid ${NP.amber}`, padding: "4px 0 4px 16px", margin: "0 0 18px", lineHeight: "1.6" }} dangerouslySetInnerHTML={{ __html: sanitizePostHtml(b.html) }} />;
  if (b.type === "list") return <div key={key} className="pp-list" style={{ fontFamily: NP.serif, color: s.color || NP.text, fontSize: "16px", lineHeight: "1.7", margin: "0 0 18px" }} dangerouslySetInnerHTML={{ __html: sanitizePostHtml(b.html) }} />;
  if (b.type === "divider") return <hr key={key} style={{ border: "none", borderTop: `1px solid ${NP.border}`, margin: "24px 0" }} />;
  if (b.type === "image") return (
    <figure key={key} style={{ margin: "0 0 20px" }}>
      {b.url && <img src={b.url} alt={b.caption || ""} style={{ width: "100%", borderRadius: "4px", display: "block" }} loading="lazy" />}
      {b.caption && <figcaption style={{ fontFamily: NP.sans, fontSize: "11px", fontStyle: "italic", color: NP.dim, textAlign: "center", marginTop: "7px" }}>{b.caption}</figcaption>}
    </figure>
  );
  if (b.type === "youtube" && b.videoId) return (
    <div key={key} style={{ position: "relative", paddingTop: "56.25%", margin: "0 0 20px", borderRadius: "4px", overflow: "hidden" }}>
      <iframe src={`https://www.youtube.com/embed/${b.videoId}`} title="Vídeo" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", border: "none" }} allowFullScreen />
    </div>
  );
  if (b.type === "produto" && b.productId) return <ProductBlockView key={key} productId={b.productId} snapshot={b.product} />;
  return null;
}

// ─── Visualização pública de um post do portal ───
// ─── Publicidade: fundação de ad slots + house-ads ───
// Fundação agnóstica de rede. Hoje renderiza "house-ads" (anúncios internos).
// Para plugar AdSense depois: AD_CONFIG.provider="adsense", preencher adsenseClient
// e o adsenseSlot de cada posição, carregar o script do AdSense uma vez no index.html
// e completar o push marcado com OBS abaixo. Nenhuma outra mudança é necessária.
const AD_CONFIG = {
  enabled: true,
  provider: "house", // "house" | "adsense"
  adsenseClient: "", // ex.: "ca-pub-0000000000000000"
  slots: {
    top: { enabled: true, adsenseSlot: "" },
    "in-feed": { enabled: true, adsenseSlot: "" },
    sidebar: { enabled: true, adsenseSlot: "" },
    "article-footer": { enabled: true, adsenseSlot: "" },
  },
  house: [
    { id: "comunidade", emoji: "🌱", title: "Faça parte da comunidade", text: "Crie seu diário de cultivo e acompanhe outros growers semana a semana.", cta: "Começar", url: "/comunidade", bg: `linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` },
    { id: "newsletter", emoji: "✉️", title: "Newsletter do Diário da Planta", text: "As principais notícias de cannabis direto no seu e-mail.", cta: "Assinar grátis", url: "#newsletter", bg: `linear-gradient(135deg, ${NP.indigo}, #0f3a86)` },
    { id: "guias", emoji: "📚", title: "Guias de cultivo", text: "Do plantio à colheita: conteúdo prático pra evoluir no cultivo.", cta: "Ver guias", url: "/categoria/cultivo", bg: `linear-gradient(135deg, ${NP.amber}, #c98a0e)` },
  ],
};

function AdSlot({ slot, variant = "banner", style = {} }) {
  const cfg = AD_CONFIG;
  const slotCfg = cfg.slots[slot];
  const active = cfg.enabled && slotCfg && slotCfg.enabled !== false;
  const [pick] = useState(() => (cfg.house.length ? cfg.house[Math.floor(Math.random() * cfg.house.length)] : null));
  useEffect(() => {
    if (active) { try { trackEvent("ad_impression", { slot, provider: cfg.provider }); } catch {} }
  }, [slot, active]);
  if (!active) return null;

  // Gancho AdSense: quando configurado, renderiza o container da rede no lugar do house-ad.
  if (cfg.provider === "adsense" && cfg.adsenseClient && slotCfg.adsenseSlot) {
    // OBS: carregue o script do AdSense uma vez no index.html e, após montar,
    // chame (window.adsbygoogle = window.adsbygoogle || []).push({}).
    return (
      <ins className="adsbygoogle"
        style={{ display: "block", ...style }}
        data-ad-client={cfg.adsenseClient}
        data-ad-slot={slotCfg.adsenseSlot}
        data-ad-format="auto"
        data-full-width-responsive="true" />
    );
  }

  if (!pick) return null;
  const isSidebar = variant === "sidebar";
  const onClick = () => { try { trackEvent("ad_click", { slot, ad: pick.id }); } catch {} };
  return (
    <a href={pick.url} onClick={onClick} style={{ display: "block", textDecoration: "none", borderRadius: "4px", overflow: "hidden", position: "relative", ...style }}>
      <div style={{ background: pick.bg, padding: isSidebar ? "18px 16px" : "16px 20px", display: "flex", flexDirection: isSidebar ? "column" : "row", alignItems: isSidebar ? "flex-start" : "center", gap: "14px" }}>
        <div style={{ fontSize: isSidebar ? "30px" : "34px", lineHeight: "1" }}>{pick.emoji}</div>
        <div style={{ flex: "1", minWidth: "0" }}>
          <div style={{ fontFamily: NP.sans, fontSize: isSidebar ? "14px" : "15px", fontWeight: "800", color: NP.white, marginBottom: "3px" }}>{pick.title}</div>
          <div style={{ fontFamily: NP.sans, fontSize: "12px", color: "rgba(255,255,255,0.9)", lineHeight: "1.4", marginBottom: isSidebar ? "10px" : "0" }}>{pick.text}</div>
          {isSidebar && <span style={{ display: "inline-block", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.white, border: "1px solid rgba(255,255,255,0.6)", borderRadius: "3px", padding: "5px 12px" }}>{pick.cta}</span>}
        </div>
        {!isSidebar && <span style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.white, border: "1px solid rgba(255,255,255,0.6)", borderRadius: "3px", padding: "7px 14px", whiteSpace: "nowrap" }}>{pick.cta}</span>}
      </div>
      <span style={{ position: "absolute", top: "4px", right: "7px", fontFamily: NP.sans, fontSize: "9px", color: "rgba(255,255,255,0.65)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Publicidade</span>
    </a>
  );
}

// ─── Loja (afiliados): card de produto + bloco de produto ───
// Sem exibição de preço, por design: evita preço desatualizado e as regras de
// exibição de preço dos programas de afiliados (a Amazon só permite via PA-API).
const MARKETPLACES = {
  mercadolivre: { label: "Mercado Livre", cta: "Ver no Mercado Livre", color: "#FFE600", text: "#2D3277" },
  amazon: { label: "Amazon", cta: "Ver na Amazon", color: "#FF9900", text: "#131921" },
  outro: { label: "Ver oferta", cta: "Ver oferta", color: NP.ciano, text: NP.white },
};

function ProductCard({ product, origem = "loja", compact = false }) {
  if (!product) return null;
  const mk = MARKETPLACES[product.marketplace] || MARKETPLACES.outro;
  const onClick = () => { try { trackEvent("produto_click", { id: product.id, marketplace: product.marketplace, origem }); } catch {} };
  return (
    <div style={{ border: `1px solid ${NP.border}`, borderRadius: "6px", overflow: "hidden", background: "#fff", display: "flex", flexDirection: compact ? "row" : "column", gap: compact ? "12px" : "0" }}>
      {product.imagem_url && (
        <a href={product.url_afiliado} target="_blank" rel="nofollow sponsored noopener noreferrer" onClick={onClick} style={{ display: "block", flexShrink: 0, width: compact ? "110px" : "auto" }}>
          <img src={product.imagem_url} alt={product.titulo} loading="lazy" style={{ width: "100%", height: compact ? "110px" : "180px", objectFit: "contain", background: NP.bgLight, display: "block", padding: "8px", boxSizing: "border-box" }} />
        </a>
      )}
      <div style={{ padding: compact ? "12px 12px 12px 0" : "14px", flex: "1", minWidth: "0", display: "flex", flexDirection: "column" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px" }}>
          <span style={{ fontFamily: NP.sans, fontSize: "9px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", color: NP.dim }}>{mk.label}</span>
          <span style={{ fontFamily: NP.sans, fontSize: "9px", color: NP.dim, opacity: 0.8 }}>· publi</span>
        </div>
        <a href={product.url_afiliado} target="_blank" rel="nofollow sponsored noopener noreferrer" onClick={onClick} style={{ textDecoration: "none" }}>
          <div style={{ fontFamily: NP.sans, fontSize: compact ? "13px" : "14px", fontWeight: "700", color: NP.indigo, lineHeight: "1.3", marginBottom: "5px", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{product.titulo}</div>
        </a>
        {product.descricao && <div style={{ fontFamily: NP.sans, fontSize: "12px", color: NP.muted, lineHeight: "1.45", marginBottom: "10px", display: "-webkit-box", WebkitLineClamp: compact ? 2 : 4, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{product.descricao}</div>}
        <a href={product.url_afiliado} target="_blank" rel="nofollow sponsored noopener noreferrer" onClick={onClick} style={{ display: "block", textAlign: "center", background: mk.color, color: mk.text, fontFamily: NP.sans, fontSize: "12px", fontWeight: "800", padding: "9px 12px", borderRadius: "4px", textDecoration: "none", marginTop: "auto" }}>{mk.cta}</a>
      </div>
    </div>
  );
}

// Bloco de produto dentro de uma matéria: busca o produto pelo id para que o
// link de afiliado esteja sempre atualizado; usa o snapshot como fallback.
function ProductBlockView({ productId, snapshot }) {
  const [prod, setProd] = useState(snapshot || null);
  useEffect(() => {
    let alive = true;
    if (!productId) return;
    (async () => {
      const row = await sb.from("produtos").selectOne("*", `&id=eq.${productId}`);
      if (alive && row) setProd(row);
    })();
    return () => { alive = false; };
  }, [productId]);
  if (!prod) return null;
  return (
    <div style={{ margin: "0 0 22px", maxWidth: "520px" }}>
      <ProductCard product={prod} origem="materia" compact />
    </div>
  );
}

// Seletor de produto usado dentro do editor (bloco "produto").
function ProductPicker({ value, onPick }) {
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    (async () => {
      const rows = await sb.from("produtos").select("id,titulo,descricao,imagem_url,marketplace,url_afiliado,categoria,ativo", "&order=ordem.asc");
      if (alive) { setList(rows || []); setLoading(false); }
    })();
    return () => { alive = false; };
  }, []);
  const selected = list.find((p) => p.id === value) || null;
  const boxBase = { border: `1px dashed ${NP.border}`, borderRadius: "4px", padding: "12px", background: NP.bgLight, fontFamily: NP.sans, fontSize: "12px" };
  if (loading) return <div style={{ ...boxBase, color: NP.dim }}>Carregando produtos…</div>;
  if (!list.length) return <div style={{ ...boxBase, color: NP.muted }}>🛒 Nenhum produto cadastrado. Cadastre em <b>Admin → Produtos</b> primeiro.</div>;
  return (
    <div style={boxBase}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: selected ? "10px" : "0" }}>
        <span style={{ fontWeight: "700", color: NP.muted }}>🛒 Produto:</span>
        <select value={value || ""} onChange={(e) => { const p = list.find((x) => x.id === e.target.value); onPick(p || null); }} style={{ flex: "1", fontFamily: NP.sans, fontSize: "12px", padding: "6px", border: `1px solid ${NP.border}`, borderRadius: "4px", background: "#fff", color: NP.text }}>
          <option value="">— selecionar —</option>
          {list.map((p) => <option key={p.id} value={p.id}>{p.ativo ? "" : "(inativo) "}{p.titulo}</option>)}
        </select>
      </div>
      {selected && <ProductCard product={selected} origem="editor-preview" compact />}
    </div>
  );
}

function PortalPostView({ post, onBack, backLabel = "← Voltar ao portal" }) {
  const p = post?.postData || post || {};
  const blocks = Array.isArray(p.content_blocks) ? p.content_blocks : [];
  return (
    <div style={{ maxWidth: "760px", margin: "0 auto" }}>
      <button onClick={onBack} style={{ background: "none", border: "none", color: NP.ciano, fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", cursor: "pointer", padding: "0 0 16px" }}>{backLabel}</button>
      <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "12px", flexWrap: "wrap" }}>
        <span style={{ background: NP.amber, color: "#fff", fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", padding: "3px 9px", textTransform: "uppercase", letterSpacing: "0.5px" }}>Original</span>
        <span style={{ background: NP.indigo, color: "#fff", fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", padding: "3px 9px", textTransform: "uppercase", letterSpacing: "0.5px" }}>{NP_CAT_LABEL[p.category] || "Geral"}</span>
      </div>
      <h1 style={{ fontFamily: NP.serif, fontSize: "30px", fontWeight: "700", color: NP.indigo, margin: "0 0 10px", lineHeight: "1.18" }}>{p.title}</h1>
      <div style={{ fontFamily: NP.sans, fontSize: "12px", color: NP.dim, marginBottom: "10px" }}>
        {p.profiles?.username ? `Por ${p.profiles.username} · ` : ""}{p.published_at ? new Date(p.published_at).toLocaleDateString("pt-BR") : "Rascunho"}{(p.tags || []).length > 0 ? " · " + (p.tags || []).map((t) => "#" + t).join("  ") : ""}
      </div>
      <button onClick={async () => { const u = `${window.location.origin}/post/${p.slug || p.id}`; try { if (navigator.share) { await navigator.share({ title: p.title, url: u }); } else { await navigator.clipboard.writeText(u); alert("Link copiado!"); } } catch {} }} style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: "none", border: `1px solid ${NP.ciano}`, color: NP.ciano, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "7px 16px", borderRadius: "18px", cursor: "pointer", marginBottom: "20px" }}>🔗 Compartilhar</button>
      {p.cover_url && <img src={p.cover_url} alt="" style={{ width: "100%", borderRadius: "4px", marginBottom: "24px", display: "block" }} loading="lazy" />}
      <style>{`.pp-list ul,.pp-list ol{margin:0;padding-left:22px;}`}</style>
      {blocks.map((b, i) => renderPostBlock(b, b.id || i))}
      <AdSlot slot="article-footer" variant="banner" style={{ marginTop: "32px" }} />
    </div>
  );
}

// ─── Lista "Todos os posts" (admin/editores) ───
function PortalPostsList({ onNew, onEdit, onBack }) {
  const [posts, setPosts] = useState(null);
  const load = async () => { try { const r = await sb.from("portal_posts").select("*,profiles(username)", "&order=updated_at.desc&limit=100"); setPosts(r || []); } catch { setPosts([]); } };
  useEffect(() => { load(); }, []);
  const badge = (p) => {
    if (p.status === "draft") return { label: "Rascunho", bg: "#efe9dc", c: "#7a6f5a" };
    if (p.published_at && new Date(p.published_at) > new Date()) return { label: "Agendado · " + new Date(p.published_at).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }), bg: "#faeeda", c: "#854f0b" };
    return { label: "Publicado", bg: "#eaf3de", c: "#3b6d11" };
  };
  const del = async (p) => {
    if (!window.confirm(`Excluir "${p.title || "(sem título)"}"? Essa ação é permanente.`)) return;
    const ok = await sb.from("portal_posts").delete(`id=eq.${p.id}`);
    if (ok) setPosts((prev) => (prev || []).filter((x) => x.id !== p.id));
  };
  return (
    <div style={{ maxWidth: "880px", margin: "0 auto" }}>
      <button onClick={onBack} style={{ background: "none", border: "none", color: NP.ciano, fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", cursor: "pointer", padding: "0 0 12px" }}>← Voltar ao portal</button>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px", marginBottom: "6px", flexWrap: "wrap" }}>
        <h2 style={{ fontFamily: NP.serif, fontSize: "24px", fontWeight: "700", color: NP.indigo, margin: 0 }}>📝 Posts do Portal</h2>
        <button onClick={onNew} style={{ background: NP.ciano, color: "#fff", fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", padding: "9px 20px", borderRadius: "20px", border: "none", cursor: "pointer" }}>+ Adicionar novo</button>
      </div>
      {posts === null ? (
        <div style={{ fontFamily: NP.sans, fontSize: "13px", color: NP.dim, padding: "24px 0" }}>Carregando…</div>
      ) : posts.length === 0 ? (
        <div style={{ fontFamily: NP.sans, fontSize: "13px", color: NP.dim, padding: "24px 0" }}>Nenhum post ainda. Clique em "+ Adicionar novo" para escrever o primeiro.</div>
      ) : posts.map((p) => { const bd = badge(p); return (
        <div key={p.id} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "13px 2px", borderBottom: `1px solid ${NP.border}`, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "170px", fontFamily: NP.serif, fontWeight: "700", fontSize: "15px", color: NP.text, lineHeight: "1.3" }}>{p.title || "(sem título)"}</div>
          <span style={{ background: NP.indigo, color: "#fff", fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", padding: "2px 8px", textTransform: "uppercase" }}>{NP_CAT_LABEL[p.category] || "Geral"}</span>
          <span style={{ background: bd.bg, color: bd.c, fontFamily: NP.sans, fontSize: "10px", fontWeight: "700", padding: "3px 9px", borderRadius: "10px", textTransform: "uppercase", letterSpacing: "0.3px" }}>{bd.label}</span>
          <span style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim }}>{new Date(p.updated_at || p.created_at).toLocaleDateString("pt-BR")}</span>
          <button onClick={() => onEdit(p)} style={{ background: "none", border: "none", color: NP.ciano, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", cursor: "pointer" }}>Editar</button>
          <button onClick={() => del(p)} style={{ background: "none", border: "none", color: "#a33b3b", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", cursor: "pointer" }}>Excluir</button>
        </div>
      ); })}
    </div>
  );
}

// ─── Editor de blocos ───
function PortalPostEditor({ post, user, onBack, onSaved }) {
  const isMobile = useIsMobile();
  const [title, setTitle] = useState(post?.title || "");
  const [blocks, setBlocks] = useState(() => { const b = Array.isArray(post?.content_blocks) ? post.content_blocks : []; return b.length ? b : [newBlock()]; });
  const [selId, setSelId] = useState(null);
  const [sideTab, setSideTab] = useState("doc");
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState("");
  const [category, setCategory] = useState(post?.category || "geral");
  const [tags, setTags] = useState(post?.tags || []);
  const [tagInput, setTagInput] = useState("");
  const [coverUrl, setCoverUrl] = useState(post?.cover_url || "");
  const [excerpt, setExcerpt] = useState(post?.excerpt || "");
  const [featured, setFeatured] = useState(!!post?.featured);
  const wasSched = post?.published_at && new Date(post.published_at) > new Date();
  const toLocalDT = (d) => { const x = new Date(d); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 16); };
  const [pubMode, setPubMode] = useState(wasSched ? "agendar" : "agora");
  const [schedule, setSchedule] = useState(wasSched ? toLocalDT(post.published_at) : "");
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState(false);
  const [slashFor, setSlashFor] = useState(null);
  const htmlRef = useRef({});
  const elRef = useRef({});
  const focusNext = useRef(null);

  useEffect(() => { if (focusNext.current && elRef.current[focusNext.current]) { elRef.current[focusNext.current].focus(); focusNext.current = null; } }, [blocks]);

  const isText = (t) => PP_TEXT_TYPES.includes(t);
  const commit = () => blocks.map((b) => isText(b.type) ? { ...b, html: sanitizePostHtml(htmlRef.current[b.id] !== undefined ? htmlRef.current[b.id] : b.html) } : b);
  const setBlock = (id, patch) => setBlocks((prev) => prev.map((b) => b.id === id ? { ...b, ...patch } : b));
  const addAfter = (id, type = "paragraph") => { const nb = newBlock(type); if (isText(type)) focusNext.current = nb.id; setBlocks((prev) => { const i = id ? prev.findIndex((b) => b.id === id) : prev.length - 1; const c = [...prev]; c.splice(i + 1, 0, nb); return c; }); setSelId(nb.id); };
  const removeBlock = (id, focusPrev = false) => setBlocks((prev) => { if (prev.length <= 1) return prev; const i = prev.findIndex((b) => b.id === id); if (focusPrev && i > 0 && isText(prev[i - 1].type)) focusNext.current = prev[i - 1].id; delete htmlRef.current[id]; return prev.filter((b) => b.id !== id); });
  const move = (id, dir) => setBlocks((prev) => { const i = prev.findIndex((b) => b.id === id); const j = i + dir; if (j < 0 || j >= prev.length) return prev; const c = [...prev]; [c[i], c[j]] = [c[j], c[i]]; return c; });
  const convert = (id, type) => {
    setSlashFor(null);
    const initHtml = type === "list" ? "<ul><li><br></li></ul>" : "";
    htmlRef.current[id] = initHtml;
    if (elRef.current[id]) elRef.current[id].innerHTML = initHtml;
    setBlock(id, { type, html: initHtml, url: "", caption: "", videoId: "", level: 2 });
    if (isText(type)) { focusNext.current = id; setBlocks((p) => [...p]); }
  };
  const transform = (b) => { const order = ["paragraph", "heading", "quote"]; const nx = order[(order.indexOf(b.type) + 1) % order.length] || "paragraph"; const h = htmlRef.current[b.id] !== undefined ? htmlRef.current[b.id] : b.html; htmlRef.current[b.id] = h; setBlock(b.id, { type: nx }); };
  const exec = (cmd, val) => { try { document.execCommand(cmd, false, val || null); } catch {} if (selId && elRef.current[selId]) htmlRef.current[selId] = elRef.current[selId].innerHTML; };
  const uploadImg = async (file, cb) => {
    try { const path = `portal/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.jpg`; const ok = await sbStorage.upload(path, file); if (ok) cb(sbStorage.getUrl(path)); else alert("Falha no upload da imagem."); } catch { alert("Falha no upload da imagem."); }
  };
  const addTag = () => { const t = tagInput.trim().replace(/,+$/, ""); if (t && !tags.includes(t)) setTags([...tags, t]); setTagInput(""); };

  const ensureUniqueSlug = async () => {
    const base = slugifyPost(title) || "post-" + Date.now().toString(36);
    for (let i = 0; i < 8; i++) {
      const cand = i === 0 ? base : `${base}-${i + 1}`;
      try {
        const rows = await sb.from("portal_posts").select("id", `&slug=eq.${encodeURIComponent(cand)}&limit=1`);
        if (!rows || rows.length === 0 || (post?.id && rows[0].id === post.id)) return cand;
      } catch { return `${base}-${Math.random().toString(36).slice(2, 6)}`; }
    }
    return `${base}-${Math.random().toString(36).slice(2, 6)}`;
  };

  const save = async (mode) => { // 'draft' | 'publish'
    if (saving) return;
    const cleanTitle = title.trim();
    if (mode === "publish" && !cleanTitle) { alert("Dê um título ao post antes de publicar."); return; }
    setSaving(true);
    let status, pubAt;
    if (mode === "draft") { status = "draft"; pubAt = null; }
    else {
      status = "published";
      if (pubMode === "agendar" && schedule) pubAt = new Date(schedule).toISOString();
      else if (post?.status === "published" && post?.published_at && new Date(post.published_at) <= new Date()) pubAt = post.published_at;
      else pubAt = new Date().toISOString();
    }
    let slugVal = post?.slug || null;
    if (!slugVal && mode !== "draft") slugVal = await ensureUniqueSlug();
    const payload = { title: cleanTitle, slug: slugVal, content_blocks: commit(), excerpt: excerpt.trim() || null, cover_url: coverUrl || null, category, tags, status, featured, published_at: pubAt, updated_at: new Date().toISOString() };
    try {
      if (post?.id) { await sb.from("portal_posts").update(payload, `id=eq.${post.id}`); }
      else { payload.author_id = user.id; await sb.from("portal_posts").insert(payload); }
      onSaved && onSaved();
    } catch (e) { alert("Erro ao salvar: " + (e?.message || e)); }
    setSaving(false);
  };

  const tbBtn = (label, fn, title) => (
    <button key={title || String(label)} type="button" onMouseDown={(e) => e.preventDefault()} onClick={fn} title={title} style={{ background: "none", border: "none", borderRight: `1px solid ${NP.bgLight}`, padding: "7px 10px", cursor: "pointer", fontFamily: NP.sans, fontSize: "12px", color: NP.text }}>{label}</button>
  );
  const blockBar = (b) => (
    <div style={{ position: "absolute", top: "-36px", left: 0, display: "flex", background: "#fff", border: `1px solid ${NP.border}`, borderRadius: "4px", boxShadow: "0 2px 8px rgba(0,0,0,0.12)", zIndex: 6 }}>
      {isText(b.type) && b.type !== "list" && tbBtn(b.type === "heading" ? "H" : b.type === "quote" ? "❝" : "¶", () => transform(b), "Transformar bloco")}
      {tbBtn("↑", () => move(b.id, -1), "Mover para cima")}
      {tbBtn("↓", () => move(b.id, 1), "Mover para baixo")}
      {isText(b.type) && tbBtn(<b>B</b>, () => exec("bold"), "Negrito")}
      {isText(b.type) && tbBtn(<i>I</i>, () => exec("italic"), "Itálico")}
      {isText(b.type) && tbBtn("🔗", () => { const u = window.prompt("URL do link:"); if (u) exec("createLink", u); }, "Inserir link")}
      {tbBtn("🗑", () => removeBlock(b.id), "Excluir bloco")}
    </div>
  );
  const slashMenu = (b) => (
    <div style={{ position: "absolute", zIndex: 10, marginTop: "2px", background: "#fff", border: `1px solid ${NP.border}`, borderRadius: "6px", boxShadow: "0 4px 14px rgba(0,0,0,0.14)", width: "220px", overflow: "hidden" }}>
      {[["🖼", "Imagem", "image"], ["🅷", "Título", "heading"], ["≡", "Lista", "list"], ["❝", "Citação", "quote"], ["▬", "Separador", "divider"], ["▶", "Vídeo do YouTube", "youtube"], ["🛒", "Produto", "produto"]].map(([ic, lb, tp]) => (
        <button key={tp} onMouseDown={(e) => e.preventDefault()} onClick={() => convert(b.id, tp)} style={{ display: "flex", alignItems: "center", gap: "9px", width: "100%", textAlign: "left", background: "none", border: "none", borderBottom: `1px solid ${NP.bgLight}`, padding: "9px 12px", fontFamily: NP.sans, fontSize: "12px", cursor: "pointer", color: NP.text }}><span style={{ width: "20px", textAlign: "center" }}>{ic}</span>{lb}</button>
      ))}
    </div>
  );
  const txtStyle = (b) => {
    const s = b.settings || {};
    if (b.type === "heading") return { fontFamily: NP.serif, fontWeight: "700", fontSize: b.level === 3 ? "20px" : "25px", color: s.color || NP.indigo, lineHeight: "1.25" };
    if (b.type === "quote") return { fontFamily: NP.serif, fontStyle: "italic", fontSize: "17px", color: s.color || NP.muted, borderLeft: `3px solid ${NP.amber}`, paddingLeft: "14px", lineHeight: "1.6" };
    return { fontFamily: NP.serif, fontSize: s.size === "large" ? "19px" : "16px", color: s.color || NP.text, lineHeight: "1.65" };
  };

  const renderEditorBlock = (b) => {
    if (isText(b.type)) return (
      <div className="pp-txt" contentEditable suppressContentEditableWarning
        ref={(el) => { elRef.current[b.id] = el; if (el && document.activeElement !== el) { const want = htmlRef.current[b.id] !== undefined ? htmlRef.current[b.id] : b.html; if (el.innerHTML !== want) el.innerHTML = want; } }}
        onFocus={() => setSelId(b.id)}
        onInput={(e) => { htmlRef.current[b.id] = e.currentTarget.innerHTML; const t = e.currentTarget.innerText.trim(); if (b.type === "paragraph" && t === "/") setSlashFor(b.id); else if (slashFor === b.id) setSlashFor(null); }}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey && (b.type === "paragraph" || b.type === "heading")) { e.preventDefault(); setSlashFor(null); addAfter(b.id); }
          else if (e.key === "Backspace") { const t = e.currentTarget.innerText.replace(/\n/g, "").trim(); if (t === "" && blocks.length > 1) { e.preventDefault(); setSlashFor(null); removeBlock(b.id, true); } }
          else if (e.key === "Escape") setSlashFor(null);
        }}
        data-ph={b.type === "paragraph" ? "Escreva, ou digite / para inserir blocos…" : b.type === "heading" ? "Título da seção" : b.type === "quote" ? "Citação…" : "Lista…"}
        style={{ ...txtStyle(b), outline: "none", minHeight: "26px", padding: "6px 8px", border: `1px solid ${selId === b.id ? NP.ciano : "transparent"}`, borderRadius: "3px", background: selId === b.id ? "#fff" : "transparent" }}
      />
    );
    if (b.type === "image") return (
      <div onClick={() => setSelId(b.id)} style={{ border: `1px solid ${selId === b.id ? NP.ciano : "transparent"}`, borderRadius: "3px", padding: "6px" }}>
        {b.url ? <img src={b.url} alt="" style={{ width: "100%", borderRadius: "3px", display: "block" }} /> : (
          <label style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "8px", border: `1px dashed ${NP.border}`, borderRadius: "4px", padding: "28px 10px", cursor: "pointer", background: NP.bgLight, fontFamily: NP.sans, fontSize: "12px", color: NP.muted }}>
            🖼 Enviar imagem do dispositivo
            <input type="file" accept="image/*" style={{ display: "none" }} onChange={(e) => { const f = e.target.files && e.target.files[0]; if (f) uploadImg(f, (url) => setBlock(b.id, { url })); }} />
          </label>
        )}
        <input value={b.caption || ""} onChange={(e) => setBlock(b.id, { caption: e.target.value })} placeholder="Legenda (descrição ou créditos)…" style={{ width: "100%", border: "none", background: "transparent", textAlign: "center", fontFamily: NP.sans, fontSize: "11px", fontStyle: "italic", color: NP.dim, marginTop: "6px", outline: "none" }} />
      </div>
    );
    if (b.type === "divider") return <div onClick={() => setSelId(b.id)} style={{ padding: "10px 0", cursor: "pointer" }}><hr style={{ border: "none", borderTop: `1px solid ${selId === b.id ? NP.ciano : NP.border}`, margin: 0 }} /></div>;
    if (b.type === "youtube") return (
      <div onClick={() => setSelId(b.id)} style={{ border: `1px solid ${selId === b.id ? NP.ciano : "transparent"}`, borderRadius: "3px", padding: "6px" }}>
        {b.videoId ? (
          <div style={{ position: "relative", paddingTop: "56.25%", borderRadius: "4px", overflow: "hidden" }}>
            <iframe src={`https://www.youtube.com/embed/${b.videoId}`} title="Vídeo" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", border: "none" }} allowFullScreen />
          </div>
        ) : (
          <YtInput onSet={(vid) => setBlock(b.id, { videoId: vid })} />
        )}
      </div>
    );
    if (b.type === "produto") return (
      <div onClick={() => setSelId(b.id)} style={{ border: `1px solid ${selId === b.id ? NP.ciano : "transparent"}`, borderRadius: "3px", padding: "6px" }}>
        <ProductPicker value={b.productId} onPick={(p) => setBlock(b.id, { productId: p ? p.id : "", product: p || null })} />
      </div>
    );
    return null;
  };

  const aiToHtml = (s) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
  const aiStripHtml = (h) => (h || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  const aiBtnStyle = { background: NP.bgLight, border: `1px solid ${NP.border}`, borderRadius: "6px", padding: "8px 6px", fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", color: NP.text, cursor: aiBusy ? "default" : "pointer", opacity: aiBusy ? 0.6 : 1, lineHeight: "1.2" };
  const runAi = async (action) => {
    if (aiBusy) return;
    const cleanTitle = title.trim();
    if ((action === "draft" || action === "excerpt") && !cleanTitle) { setAiError("Dê um título ao post primeiro."); return; }
    let selection = "";
    if (action === "rewrite") {
      const sel = blocks.find((b) => b.id === selId);
      if (!sel || !isText(sel.type)) { setAiError("Selecione um bloco de texto para reescrever."); return; }
      selection = aiStripHtml(htmlRef.current[sel.id] !== undefined ? htmlRef.current[sel.id] : sel.html);
      if (!selection) { setAiError("O bloco selecionado está vazio."); return; }
    }
    const context = blocks.filter((b) => isText(b.type)).map((b) => aiStripHtml(htmlRef.current[b.id] !== undefined ? htmlRef.current[b.id] : b.html)).filter(Boolean).join("\n").slice(0, 4000);
    setAiBusy(true); setAiError("");
    try {
      const session = await sbAuth.getSession();
      const token = session?.access_token || SB_KEY;
      const resp = await fetch(`${SB_URL}/functions/v1/gerar-texto`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}`, "apikey": SB_KEY },
        body: JSON.stringify({ action, title: cleanTitle, category, context: context || undefined, selection: selection || undefined, instructions: aiPrompt.trim() || undefined }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || data.error) { setAiError(data.error || `Erro ${resp.status}`); setAiBusy(false); return; }
      const out = (data.text || "").trim();
      if (!out) { setAiError("A IA não retornou texto."); setAiBusy(false); return; }
      if (action === "excerpt") {
        setExcerpt(out.slice(0, 300));
      } else if (action === "rewrite") {
        const html = aiToHtml(out);
        htmlRef.current[selId] = html;
        if (elRef.current[selId]) elRef.current[selId].innerHTML = html;
        setBlock(selId, { html });
      } else {
        const paras = out.split(/\n{2,}|\n/).map((s) => s.trim()).filter(Boolean);
        const made = paras.map((p) => { const nb = newBlock("paragraph"); nb.html = aiToHtml(p); return nb; });
        setBlocks((prev) => {
          const onlyEmpty = prev.length === 1 && isText(prev[0].type) && !aiStripHtml(htmlRef.current[prev[0].id] !== undefined ? htmlRef.current[prev[0].id] : prev[0].html);
          return onlyEmpty ? made : [...prev, ...made];
        });
      }
      try { trackEvent("portal_ai_generate", { action }); } catch {}
    } catch (e) { setAiError("Erro de conexão com a IA."); }
    setAiBusy(false);
  };

  const previewPost = { title, content_blocks: commit(), cover_url: coverUrl, category, tags, excerpt, published_at: new Date().toISOString(), profiles: { username: user?.username } };
  const primaryLabel = saving ? "Salvando…" : (pubMode === "agendar" && schedule) ? "Agendar" : (post?.status === "published" ? "Atualizar" : "Publicar");

  return (
    <div style={{ maxWidth: "1080px", margin: "0 auto" }}>
      <style>{`.pp-txt:empty:before{content:attr(data-ph);color:#b8ad96;pointer-events:none;}.pp-txt ul,.pp-txt ol{margin:0;padding-left:22px;}`}</style>
      {/* Top bar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", flexWrap: "wrap", padding: "10px 14px", background: NP.indigo, borderRadius: "6px 6px 0 0" }}>
        <button onClick={onBack} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.85)", fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", cursor: "pointer" }}>← Posts</button>
        <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={() => save("draft")} disabled={saving} style={{ background: "transparent", color: "rgba(255,255,255,0.85)", border: "1px solid rgba(255,255,255,0.35)", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "8px 14px", borderRadius: "18px", cursor: "pointer" }}>{post?.status === "published" ? "Reverter p/ rascunho" : "Salvar rascunho"}</button>
          <button onClick={() => setPreview((v) => !v)} style={{ background: "transparent", color: "rgba(255,255,255,0.85)", border: "1px solid rgba(255,255,255,0.35)", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "8px 14px", borderRadius: "18px", cursor: "pointer" }}>{preview ? "✏️ Editar" : "Visualizar"}</button>
          <button onClick={() => save("publish")} disabled={saving} style={{ background: NP.ciano, color: "#fff", border: "none", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "8px 18px", borderRadius: "18px", cursor: "pointer" }}>{primaryLabel}</button>
        </div>
      </div>

      {preview ? (
        <div style={{ border: `1px solid ${NP.border}`, borderTop: "none", borderRadius: "0 0 6px 6px", padding: "24px 16px", background: "#fff" }}>
          <PortalPostView post={previewPost} onBack={() => setPreview(false)} backLabel="← Voltar a editar" />
        </div>
      ) : (
        <div style={{ display: "flex", flexWrap: "wrap", border: `1px solid ${NP.border}`, borderTop: "none", borderRadius: "0 0 6px 6px", overflow: "hidden" }}>
          {/* Canvas */}
          <div style={{ flex: 2, minWidth: "280px", background: "#f7f4ec", padding: "18px 16px 44px" }}>
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Adicionar título" style={{ width: "100%", border: "none", background: "transparent", fontFamily: NP.serif, fontSize: isMobile ? "24px" : "30px", fontWeight: "700", color: NP.indigo, outline: "none", margin: "6px 0 16px" }} />
            {blocks.map((b) => (
              <div key={b.id} style={{ position: "relative", marginBottom: "12px" }}>
                {selId === b.id && blockBar(b)}
                {renderEditorBlock(b)}
                {slashFor === b.id && slashMenu(b)}
              </div>
            ))}
            <button onClick={() => addAfter(null)} style={{ background: "none", border: `1px dashed ${NP.border}`, borderRadius: "4px", width: "100%", padding: "9px", fontFamily: NP.sans, fontSize: "12px", color: NP.muted, cursor: "pointer", marginTop: "4px" }}>+ Adicionar bloco</button>
          </div>

          {/* Sidebar */}
          <div style={{ flex: 1, minWidth: "240px", background: "#fff", borderLeft: isMobile ? "none" : `1px solid ${NP.border}`, borderTop: isMobile ? `1px solid ${NP.border}` : "none" }}>
            <div style={{ display: "flex", borderBottom: `1px solid ${NP.border}` }}>
              {[["doc", "Documento"], ["blk", "Bloco"]].map(([id, lb]) => (
                <button key={id} onClick={() => setSideTab(id)} style={{ flex: 1, background: "none", border: "none", borderBottom: sideTab === id ? `2px solid ${NP.ciano}` : "2px solid transparent", padding: "11px 0", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: sideTab === id ? NP.text : NP.dim, cursor: "pointer" }}>{lb}</button>
              ))}
            </div>

            {sideTab === "doc" ? (
              <div>
                <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px", background: "#faf7ef" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "800", color: NP.indigo, marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>✨ Gerar com IA</div>
                  <textarea value={aiPrompt} onChange={(e) => setAiPrompt(e.target.value)} rows={2} placeholder="Instruções opcionais (ângulo, tom, o que enfatizar)…" style={{ width: "100%", boxSizing: "border-box", fontFamily: NP.sans, fontSize: "12px", padding: "7px", border: `1px solid ${NP.border}`, borderRadius: "4px", outline: "none", resize: "vertical", color: NP.text, marginBottom: "8px" }} />
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                    <button onClick={() => runAi("draft")} disabled={aiBusy} style={aiBtnStyle}>📝 Rascunho do título</button>
                    <button onClick={() => runAi("continue")} disabled={aiBusy} style={aiBtnStyle}>➡️ Continuar</button>
                    <button onClick={() => runAi("rewrite")} disabled={aiBusy} style={aiBtnStyle}>🔁 Reescrever bloco</button>
                    <button onClick={() => runAi("excerpt")} disabled={aiBusy} style={aiBtnStyle}>✂️ Gerar resumo</button>
                  </div>
                  {aiBusy && <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.ciano, marginTop: "8px", fontWeight: "700" }}>Gerando…</div>}
                  {aiError && <div style={{ fontFamily: NP.sans, fontSize: "11px", color: "#a33b3b", marginTop: "8px" }}>{aiError}</div>}
                  <div style={{ fontFamily: NP.sans, fontSize: "10px", color: NP.dim, marginTop: "8px", lineHeight: "1.5" }}>Revise sempre — a IA pode cometer erros factuais. "Reescrever bloco" usa o bloco de texto selecionado.</div>
                </div>
                <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Status e visibilidade</div>
                  <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginBottom: "6px" }}>Visibilidade: <b style={{ color: NP.ciano }}>Público</b> (posts do portal são abertos a todos)</div>
                  <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginBottom: "10px", wordBreak: "break-all" }}>🔗 /post/<b style={{ color: NP.text }}>{post?.slug || slugifyPost(title) || "…"}</b></div>
                  <label style={{ display: "flex", alignItems: "center", gap: "7px", fontFamily: NP.sans, fontSize: "12px", color: NP.text, marginBottom: "6px", cursor: "pointer" }}>
                    <input type="radio" checked={pubMode === "agora"} onChange={() => setPubMode("agora")} /> Publicar imediatamente
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: "7px", fontFamily: NP.sans, fontSize: "12px", color: NP.text, cursor: "pointer" }}>
                    <input type="radio" checked={pubMode === "agendar"} onChange={() => setPubMode("agendar")} /> Agendar
                  </label>
                  {pubMode === "agendar" && <input type="datetime-local" value={schedule} onChange={(e) => setSchedule(e.target.value)} style={{ marginTop: "8px", width: "100%", fontFamily: NP.sans, fontSize: "12px", padding: "7px", border: `1px solid ${NP.border}`, borderRadius: "4px", color: NP.text }} />}
                  <label style={{ display: "flex", alignItems: "center", gap: "7px", fontFamily: NP.sans, fontSize: "12px", color: NP.text, marginTop: "12px", cursor: "pointer" }}>
                    <input type="checkbox" checked={featured} onChange={(e) => setFeatured(e.target.checked)} /> ⭐ Post em destaque (manchete do portal)
                  </label>
                </div>

                <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Categoria</div>
                  {NP_CATS.filter((c) => c.id !== "todas").map((c) => (
                    <label key={c.id} style={{ display: "flex", alignItems: "center", gap: "7px", fontFamily: NP.sans, fontSize: "12px", color: NP.text, marginBottom: "6px", cursor: "pointer" }}>
                      <input type="radio" checked={category === c.id} onChange={() => setCategory(c.id)} /> {c.label}
                    </label>
                  ))}
                </div>

                <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Tags</div>
                  <div>
                    {tags.map((t) => (
                      <span key={t} style={{ display: "inline-block", fontFamily: NP.sans, fontSize: "11px", background: NP.bgLight, border: `1px solid ${NP.border}`, borderRadius: "12px", padding: "3px 10px", margin: "0 4px 5px 0", color: NP.text }}>{t} <button onClick={() => setTags(tags.filter((x) => x !== t))} style={{ background: "none", border: "none", cursor: "pointer", color: NP.dim, fontSize: "11px", padding: 0 }}>✕</button></span>
                    ))}
                  </div>
                  <input value={tagInput} onChange={(e) => setTagInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === ",") { e.preventDefault(); addTag(); } }} onBlur={addTag} placeholder="Nova tag (Enter para adicionar)" style={{ width: "100%", fontFamily: NP.sans, fontSize: "12px", padding: "7px", border: `1px solid ${NP.border}`, borderRadius: "4px", marginTop: "4px", color: NP.text, outline: "none" }} />
                </div>

                <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Imagem destacada</div>
                  {coverUrl ? (
                    <div>
                      <img src={coverUrl} alt="" style={{ width: "100%", borderRadius: "4px", display: "block", marginBottom: "6px" }} />
                      <button onClick={() => setCoverUrl("")} style={{ background: "none", border: "none", color: "#a33b3b", fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer", padding: 0 }}>Remover</button>
                    </div>
                  ) : (
                    <label style={{ display: "block", border: `1px dashed ${NP.border}`, borderRadius: "4px", padding: "18px 10px", textAlign: "center", cursor: "pointer", background: "#faf8f2", fontFamily: NP.sans, fontSize: "11px", color: NP.muted }}>
                      Definir imagem destacada<br /><span style={{ fontSize: "10px" }}>aparece nos cards do portal e no compartilhamento</span>
                      <input type="file" accept="image/*" style={{ display: "none" }} onChange={(e) => { const f = e.target.files && e.target.files[0]; if (f) uploadImg(f, setCoverUrl); }} />
                    </label>
                  )}
                </div>

                <div style={{ padding: "12px 14px" }}>
                  <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Resumo</div>
                  <textarea value={excerpt} onChange={(e) => setExcerpt(e.target.value)} rows={3} placeholder="Resumo curto que aparece nos cards do portal…" style={{ width: "100%", fontFamily: NP.serif, fontSize: "13px", padding: "8px", border: `1px solid ${NP.border}`, borderRadius: "4px", color: NP.text, outline: "none", resize: "vertical", boxSizing: "border-box" }} />
                </div>
              </div>
            ) : (() => {
              const sel = blocks.find((x) => x.id === selId);
              if (!sel) return <div style={{ padding: "16px 14px", fontFamily: NP.sans, fontSize: "12px", color: NP.dim }}>Selecione um bloco no editor para ver as opções dele.</div>;
              const s = sel.settings || {};
              const setS = (patch) => setBlock(sel.id, { settings: { ...s, ...patch } });
              const swatches = [[NP.text, "Padrão"], ["#7a9e3f", "Oliva"], ["#c47f3a", "Âmbar"], ["#a33b3b", "Vermelho"]];
              return (
                <div>
                  <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                    <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text }}>{sel.type === "paragraph" ? "¶ Parágrafo" : sel.type === "heading" ? "🅷 Título" : sel.type === "quote" ? "❝ Citação" : sel.type === "list" ? "≡ Lista" : sel.type === "image" ? "🖼 Imagem" : sel.type === "youtube" ? "▶ Vídeo" : sel.type === "produto" ? "🛒 Produto" : "▬ Separador"}</div>
                  </div>
                  {sel.type === "heading" && (
                    <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                      <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Nível</div>
                      {[2, 3].map((lv) => <button key={lv} onClick={() => setBlock(sel.id, { level: lv })} style={{ background: sel.level === lv ? NP.ciano : NP.bgLight, color: sel.level === lv ? "#fff" : NP.text, border: "none", borderRadius: "4px", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "7px 14px", marginRight: "6px", cursor: "pointer" }}>H{lv}</button>)}
                    </div>
                  )}
                  {sel.type === "paragraph" && (
                    <div style={{ borderBottom: `1px solid ${NP.bgLight}`, padding: "12px 14px" }}>
                      <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "8px" }}>Tipografia</div>
                      {[["normal", "Normal"], ["large", "Grande"]].map(([v, lb]) => <button key={v} onClick={() => setS({ size: v === "normal" ? undefined : v })} style={{ background: (s.size || "normal") === v ? NP.ciano : NP.bgLight, color: (s.size || "normal") === v ? "#fff" : NP.text, border: "none", borderRadius: "4px", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "7px 14px", marginRight: "6px", cursor: "pointer" }}>{lb}</button>)}
                    </div>
                  )}
                  {PP_TEXT_TYPES.includes(sel.type) && (
                    <div style={{ padding: "12px 14px" }}>
                      <div style={{ fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", color: NP.text, marginBottom: "10px" }}>Cor do texto</div>
                      <div style={{ display: "flex", gap: "8px" }}>
                        {swatches.map(([c, lb]) => (
                          <button key={c} title={lb} onClick={() => setS({ color: c === NP.text ? undefined : c })} style={{ width: "24px", height: "24px", borderRadius: "50%", background: c, border: (s.color || NP.text) === c ? `2px solid ${NP.ciano}` : `1px solid ${NP.border}`, cursor: "pointer" }} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}

// Input de URL do YouTube (bloco de vídeo)
function YtInput({ onSet }) {
  const [u, setU] = useState("");
  const apply = () => { const id = ytIdFrom(u); if (id) onSet(id); else alert("URL do YouTube inválida. Cole o link completo do vídeo."); };
  return (
    <div style={{ display: "flex", gap: "6px", padding: "14px 8px", background: NP.bgLight, borderRadius: "4px" }}>
      <input value={u} onChange={(e) => setU(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") apply(); }} placeholder="Cole a URL do vídeo do YouTube…" style={{ flex: 1, fontFamily: NP.sans, fontSize: "12px", padding: "8px", border: `1px solid ${NP.border}`, borderRadius: "4px", outline: "none", color: NP.text }} />
      <button onClick={apply} style={{ background: NP.ciano, color: "#fff", border: "none", borderRadius: "4px", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "8px 14px", cursor: "pointer" }}>Adicionar</button>
    </div>
  );
}


function NewsletterAdmin({ NP, user, onBack }) {
  const [stats, setStats] = useState(null);
  const [subject, setSubject] = useState("");
  const [intro, setIntro] = useState("");
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState(null);
  useEffect(() => {
    (async () => {
      try { const rows = await sb.from("newsletter_subscribers").select("status", "&limit=10000"); const all = rows || []; setStats({ total: all.length, confirmed: all.filter((s) => s.status === "confirmed").length, pending: all.filter((s) => s.status === "pending").length }); } catch { setStats({ total: 0, confirmed: 0, pending: 0 }); }
    })();
  }, []);
  const send = async () => {
    if (sending) return;
    if (!window.confirm(`Enviar a campanha para ${stats?.confirmed || 0} inscrito(s) confirmado(s)?`)) return;
    setSending(true); setResult(null);
    try {
      const session = await sbAuth.getSession();
      const token = session?.access_token || SB_KEY;
      const r = await fetch(`${SB_URL}/functions/v1/newsletter-send`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}`, "apikey": SB_KEY },
        body: JSON.stringify({ subject: subject.trim() || undefined, intro: intro.trim() || undefined }),
      });
      const data = await r.json();
      if (r.ok && data.ok) setResult({ ok: true, text: `✅ Enviado para ${data.sent} de ${data.total} inscrito(s). ${data.failed ? data.failed + " falha(s)." : ""}` });
      else setResult({ ok: false, text: data.error || "Falha no envio." });
    } catch (e) { setResult({ ok: false, text: "Erro de conexão." }); }
    setSending(false);
  };
  return (
    <div style={{ maxWidth: "620px", margin: "0 auto" }}>
      <button onClick={onBack} style={{ background: "none", border: "none", color: NP.ciano, fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", cursor: "pointer", padding: "0 0 12px" }}>← Voltar ao portal</button>
      <h2 style={{ fontFamily: NP.serif, fontSize: "24px", fontWeight: "700", color: NP.indigo, margin: "0 0 16px" }}>📬 Newsletter</h2>
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px", flexWrap: "wrap" }}>
        {[["Confirmados", stats?.confirmed, NP.ciano], ["Pendentes", stats?.pending, NP.amber], ["Total", stats?.total, NP.muted]].map(([lb, n, c]) => (
          <div key={lb} style={{ flex: 1, minWidth: "120px", border: `1px solid ${NP.border}`, borderRadius: "8px", padding: "14px", textAlign: "center" }}>
            <div style={{ fontFamily: NP.serif, fontSize: "28px", fontWeight: "700", color: c }}>{stats === null ? "…" : (n || 0)}</div>
            <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, textTransform: "uppercase", letterSpacing: "0.5px", marginTop: "2px" }}>{lb}</div>
          </div>
        ))}
      </div>
      <div style={{ border: `1px solid ${NP.border}`, borderRadius: "8px", padding: "18px", background: "#fff" }}>
        <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", color: NP.text, marginBottom: "12px" }}>Enviar edição</div>
        <label style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, display: "block", marginBottom: "4px" }}>Assunto (opcional)</label>
        <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="As novidades da semana — Diário da Planta" style={{ width: "100%", boxSizing: "border-box", fontFamily: NP.sans, fontSize: "13px", padding: "9px", border: `1px solid ${NP.border}`, borderRadius: "4px", marginBottom: "12px", outline: "none", color: NP.text }} />
        <label style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, display: "block", marginBottom: "4px" }}>Texto de abertura (opcional)</label>
        <textarea value={intro} onChange={(e) => setIntro(e.target.value)} rows={3} placeholder="Olá! Aqui estão as principais notícias dos últimos dias." style={{ width: "100%", boxSizing: "border-box", fontFamily: NP.serif, fontSize: "13px", padding: "9px", border: `1px solid ${NP.border}`, borderRadius: "4px", marginBottom: "8px", outline: "none", resize: "vertical", color: NP.text }} />
        <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginBottom: "14px", lineHeight: "1.5" }}>A edição inclui automaticamente seus posts originais recentes + as últimas notícias do portal, com link de descadastro em cada e-mail.</div>
        <button onClick={send} disabled={sending || !stats?.confirmed} style={{ background: stats?.confirmed ? NP.ciano : NP.dim, color: "#fff", border: "none", borderRadius: "20px", fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", padding: "10px 24px", cursor: sending || !stats?.confirmed ? "default" : "pointer", opacity: sending ? 0.7 : 1 }}>{sending ? "Enviando…" : `Enviar para ${stats?.confirmed || 0} inscritos`}</button>
        {result && <div style={{ fontFamily: NP.sans, fontSize: "13px", color: result.ok ? "#3b6d11" : "#a33b3b", marginTop: "14px" }}>{result.text}</div>}
      </div>
    </div>
  );
}

function NewsletterSignup({ NP, compact = false }) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState("idle"); // idle | sending | ok | error
  const [msg, setMsg] = useState("");
  const submit = async () => {
    if (state === "sending") return;
    const e = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) { setState("error"); setMsg("Digite um e-mail válido."); return; }
    setState("sending"); setMsg("");
    try {
      const r = await fetch(`${SB_URL}/functions/v1/newsletter-subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${SB_KEY}`, "apikey": SB_KEY },
        body: JSON.stringify({ email: e }),
      });
      const data = await r.json();
      if (r.ok && data.ok) { setState("ok"); setMsg(data.message || "Inscrição recebida!"); setEmail(""); }
      else { setState("error"); setMsg(data.error || "Não foi possível inscrever."); }
    } catch { setState("error"); setMsg("Erro de conexão. Tente novamente."); }
  };
  if (state === "ok") return (
    <div style={{ fontFamily: NP.sans, fontSize: "13px", color: compact ? "rgba(255,255,255,0.9)" : NP.text, lineHeight: "1.5" }}>✅ {msg}</div>
  );
  return (
    <div>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <input type="email" value={email} onChange={(ev) => setEmail(ev.target.value)} onKeyDown={(ev) => { if (ev.key === "Enter") submit(); }} placeholder="seu@email.com" style={{ flex: 1, minWidth: "160px", fontFamily: NP.sans, fontSize: "13px", padding: "9px 12px", borderRadius: "4px", border: "none", outline: "none", color: "#3d3528" }} />
        <button onClick={submit} disabled={state === "sending"} style={{ background: NP.ciano, color: "#fff", border: "none", borderRadius: "4px", fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", padding: "9px 18px", cursor: state === "sending" ? "default" : "pointer", opacity: state === "sending" ? 0.7 : 1, whiteSpace: "nowrap" }}>{state === "sending" ? "Enviando…" : "Inscrever"}</button>
      </div>
      {state === "error" && <div style={{ fontFamily: NP.sans, fontSize: "12px", color: "#e5a0a0", marginTop: "7px" }}>{msg}</div>}
    </div>
  );
}

function PortalDiariesWidget({ onOpenDiary, NP }) {
  const [diaries, setDiaries] = useState(null);
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        // Diários públicos com capa, os mais curtidos primeiro
        const rows = await sb.from("diaries").select("id,name,strain,cover_url,likes_count,current_week,phase,profiles(username,avatar,avatar_url)", "&hidden=eq.false&cover_url=not.is.null&order=likes_count.desc&limit=4");
        if (alive) setDiaries(rows || []);
      } catch { if (alive) setDiaries([]); }
    })();
    return () => { alive = false; };
  }, []);
  if (diaries === null) return null;          // carregando: não ocupa espaço
  if (diaries.length === 0) return null;       // sem diários públicos: some
  const PHASES = ["Germinação", "Vegetativo", "Floração", "Colheita"];
  return (
    <div style={{ marginBottom: "16px" }}>
      <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", borderBottom: `2px solid ${NP.indigo}`, paddingBottom: "6px", marginBottom: "13px", color: NP.indigo }}>🌱 Cultivos em destaque</div>
      {diaries.map((d) => (
        <button key={d.id} onClick={() => onOpenDiary(d.id)} style={{ display: "flex", gap: "10px", width: "100%", textAlign: "left", background: "none", border: "none", padding: "0 0 12px", marginBottom: "12px", borderBottom: `1px solid ${NP.border}`, cursor: "pointer" }}>
          <div style={{ width: "56px", height: "56px", borderRadius: "6px", flexShrink: 0, background: d.cover_url ? `url(${d.cover_url}) center/cover no-repeat, linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` : `linear-gradient(135deg, ${NP.ciano}, ${NP.indigo})` }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: NP.serif, fontSize: "14px", fontWeight: "700", color: NP.text, lineHeight: "1.25", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{d.name}</div>
            <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginTop: "3px" }}>
              {(d.profiles?.avatar_url ? "" : (d.profiles?.avatar || "🌱") + " ")}@{d.profiles?.username || "cultivador"}
              {typeof d.likes_count === "number" && d.likes_count > 0 ? ` · ♥ ${d.likes_count}` : ""}
            </div>
            <div style={{ fontFamily: NP.sans, fontSize: "10px", color: NP.ciano, fontWeight: "700", marginTop: "2px", textTransform: "uppercase", letterSpacing: "0.3px" }}>{d.strain || PHASES[d.phase] || "Cultivo"}{typeof d.current_week === "number" && d.current_week > 0 ? ` · semana ${d.current_week}` : ""}</div>
          </div>
        </button>
      ))}
      <button onClick={() => onOpenDiary(null)} style={{ background: "none", border: "none", color: NP.ciano, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", cursor: "pointer", padding: 0 }}>Ver todos os cultivos →</button>
    </div>
  );
}

function NewsPortal({ onEnterApp, onOpenDiary, dark, onToggleDark, embedded = false, loggedUser = null, onLogout = null }) {
  const isMobile = useIsMobile();
  const [view, setView] = useState({ name: "feed" });
  const canEdit = !!(loggedUser && (loggedUser.role === "admin" || loggedUser.role === "editor"));
  const openPost = (a) => {
    setView({ name: "post", post: a });
    const key = (a.postData && (a.postData.slug || a.postData.id)) || String(a.id || "").replace("pp-", "");
    if (key) { try { history.pushState(null, "", `/post/${key}`); } catch {} }
  };
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [catFilter, setCatFilter] = useState(() => { try { const m = window.location.pathname.match(/^\/categoria\/(medicinal|politica|cultivo|geral)\/?$/); if (m) return m[1]; } catch {} return "todas"; });
  const [langFilter, setLangFilter] = useState("pt"); // padrão: notícias em português (público majoritariamente BR)
  const [hasMore, setHasMore] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);

  const NEWS_PAGE = 24;

  const buildFilter = (offset) => {
    let f = "&hidden=eq.false&order=published_at.desc";
    if (catFilter !== "todas") f += `&category=eq.${catFilter}`;
    if (langFilter !== "todas") f += `&source_lang=eq.${langFilter}`;
    f += `&limit=${NEWS_PAGE + 1}&offset=${offset}`;
    return f;
  };

  const loadNews = async (offset = 0, append = false) => {
    if (append) setLoadingMore(true); else setLoading(true);
    try {
      const rows = await sb.from("news_articles").select("*", buildFilter(offset));
      const more = (rows || []).length > NEWS_PAGE;
      const page = (rows || []).slice(0, NEWS_PAGE);
      if (append) setArticles((prev) => [...prev, ...page]);
      else {
        // Posts originais do portal entram misturados (apenas na primeira página)
        let posts = [];
        try {
          const nowIso = new Date().toISOString();
          const pr = await sb.from("portal_posts").select("*,profiles(username)", `&status=eq.published&published_at=lte.${nowIso}&order=published_at.desc&limit=50`);
          posts = (pr || []).filter((p) => (catFilter === "todas" || p.category === catFilter) && (langFilter === "todas" || langFilter === "pt"));
        } catch {}
        const mappedPosts = posts.map((p) => ({ id: "pp-" + p.id, __post: true, postData: p, title: p.title, summary: p.excerpt, url: "#", image_url: p.cover_url, source_name: "Diário da Planta", source_lang: "pt", category: p.category || "geral", published_at: p.published_at, featured: !!p.featured, pinned: !!p.pinned, pinnedAt: p.pinned_at }));
        const merged = [...mappedPosts, ...page].sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
        setArticles(merged);
      }
      setHasMore(more);
    } catch (e) { console.error("[news] load:", e); }
    if (append) setLoadingMore(false); else setLoading(false);
  };

  useEffect(() => { loadNews(0, false); /* eslint-disable-next-line */ }, [catFilter, langFilter]);

  // Fixar/desafixar reflete no estado local imediatamente
  const handlePin = (item, val) => {
    const isPortal = !!item.__post;
    const realId = isPortal ? item.postData?.id : item.id;
    const at = val ? new Date().toISOString() : null;
    setArticles((prev) => prev.map((a) => {
      const match = isPortal ? (a.__post && a.postData?.id === realId) : (!a.__post && a.id === realId);
      return match ? { ...a, pinned: val, pinnedAt: at } : a;
    }));
  };
  // Carrossel: fixadas primeiro (por data de fixação), depois destaques, depois recentes — 5 slides
  const pinTime = (a) => new Date(a.pinnedAt || a.pinned_at || 0).getTime();
  const pinnedItems = articles.filter((a) => a.pinned).sort((a, b) => pinTime(b) - pinTime(a));
  const restNonPinned = articles.filter((a) => !a.pinned);
  const featuredItems = restNonPinned.filter((a) => a.featured);
  const _seenSlide = new Set();
  const _carousel = [];
  [...pinnedItems, ...featuredItems, ...restNonPinned].forEach((a) => { if (a && !_seenSlide.has(a.id)) { _seenSlide.add(a.id); _carousel.push(a); } });
  const carouselSlides = _carousel.slice(0, 5);
  const slideIds = new Set(carouselSlides.map((a) => a.id));
  // Seções abaixo usam o resto (sem duplicar o que está no carrossel)
  const rest = articles.filter((a) => !slideIds.has(a.id));
  const colLatest = rest.slice(0, 5);
  const colArticles = rest.slice(5, 10);
  const cultivoArticles = rest.filter((a) => a.category === "cultivo").slice(0, 3);
  const medicinalArticles = rest.filter((a) => a.category === "medicinal").slice(0, 3);
  const mostRead = rest.slice(0, 5);

  const isToday = new Date().toLocaleDateString("pt-BR", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  const isTodayShort = new Date().toLocaleDateString("pt-BR", { weekday: "short", day: "2-digit", month: "2-digit" });

  const handleCat = (id) => {
    setCatFilter(id);
    if (view.name !== "feed") setView({ name: "feed" });
    try { history.pushState(null, "", id === "todas" ? "/" : `/categoria/${id}`); } catch {}
  };

  // ─── Roteamento por URL (Fase A): /post/{slug} e /categoria/{cat} ───
  const viewRef = useRef(view); useEffect(() => { viewRef.current = view; }, [view]);
  const articlesUrlRef = useRef(articles); useEffect(() => { articlesUrlRef.current = articles; }, [articles]);
  const applyPath = async (path) => {
    const mPost = path.match(/^\/post\/([^/]+)\/?$/);
    const mCat = path.match(/^\/categoria\/([a-z]+)\/?$/);
    if (mPost) {
      const param = decodeURIComponent(mPost[1]);
      const inFeed = articlesUrlRef.current.find((a) => a.__post && a.postData && (a.postData.slug === param || a.postData.id === param));
      if (inFeed) { setView({ name: "post", post: inFeed }); return; }
      try {
        const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-/.test(param);
        const rows = await sb.from("portal_posts").select("*,profiles(username)", `&${isUuid ? "id" : "slug"}=eq.${encodeURIComponent(param)}&status=eq.published&limit=1`);
        if (rows && rows[0]) { setView({ name: "post", post: { id: "pp-" + rows[0].id, __post: true, postData: rows[0], title: rows[0].title } }); return; }
      } catch {}
      setView({ name: "feed" });
    } else if (mCat && NP_CATS.some((c) => c.id === mCat[1])) {
      setView({ name: "feed" }); setCatFilter(mCat[1]);
    } else if (path === "/" || path === "") {
      setView({ name: "feed" }); setCatFilter("todas");
    }
  };
  useEffect(() => { try { const p = window.location.pathname; if (p !== "/" && p !== "") applyPath(p); } catch {} /* eslint-disable-next-line */ }, []);
  useEffect(() => {
    const onPop = () => { if (viewRef.current.name === "edit" || viewRef.current.name === "manage") return; try { applyPath(window.location.pathname); } catch {} };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
    /* eslint-disable-next-line */
  }, []);

  return (
    <div style={{ minHeight: "100vh", background: NP.white, color: NP.text, fontFamily: NP.serif, overflowX: "hidden" }}>
      {!embedded && (
        <>
          {/* ─── Top bar ─── */}
          <div style={{ background: NP.indigo, color: NP.white, fontFamily: NP.sans, fontSize: "12px", padding: "8px 20px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ color: "rgba(255,255,255,0.85)", textTransform: "capitalize" }}>{isMobile ? isTodayShort : isToday}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <button onClick={onToggleDark} title={dark ? "Modo claro" : "Modo escuro"} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.85)", cursor: "pointer", fontSize: "13px" }}>{dark ? "☀️" : "🌙"}</button>
              {loggedUser&&onLogout&&<button onClick={onLogout} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.6)", cursor: "pointer", fontFamily: NP.sans, fontSize: "12px" }}>Sair</button>}
              <button onClick={onEnterApp} style={{ background: "none", border: "none", color: NP.cianoLight, cursor: "pointer", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700" }}>{loggedUser?"🌱 Ir para o app":"Entrar / Cadastrar"}</button>
            </div>
          </div>

          {/* ─── Masthead ─── */}
          <div style={{ textAlign: "center", padding: "22px 16px 16px", background: NP.white }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: "12px" }}>
              <img src="/icon-192.png" onError={(e)=>{e.currentTarget.style.display="none";}} alt="Diário da Planta" style={{ height: "44px", width: "44px", borderRadius: "8px", objectFit: "cover", border: `2px solid ${NP.ciano}`, background: NP.white }} />
              <div style={{ textAlign: "left" }}>
                <div style={{ fontFamily: NP.serif, fontSize: isMobile ? "24px" : "32px", fontWeight: "700", color: NP.indigo, lineHeight: "1", letterSpacing: "-0.5px" }}>Diário da Planta</div>
                <div style={{ fontFamily: NP.sans, fontSize: "10px", color: NP.dim, letterSpacing: "3px", textTransform: "uppercase", marginTop: "4px" }}>Portal de Cannabis Medicinal</div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ─── Nav menu de categorias ─── */}
      <div style={{ background: NP.indigo, display: "flex", alignItems: "center", justifyContent: isMobile ? "flex-start" : "center", flexWrap: "nowrap", overflowX: "auto", WebkitOverflowScrolling: "touch", padding: "0 8px", position: embedded ? "static" : "sticky", top: 0, zIndex: 50 }}>
        {NP_CATS.map((c) => (
          <button key={c.id} onClick={() => handleCat(c.id)}
            style={{ background: catFilter === c.id ? NP.ciano : "transparent", color: NP.white, fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", padding: isMobile ? "12px 12px" : "12px 16px", textTransform: "uppercase", letterSpacing: "0.4px", border: "none", cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0, borderBottom: catFilter === c.id ? `3px solid ${NP.cianoLight}` : "3px solid transparent" }}>{c.label}</button>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", gap: "4px", padding: "6px 8px 6px 0", flexShrink: 0 }}>
          {[{ id: "todas", label: "🌐" }, { id: "pt", label: "PT" }, { id: "en", label: "EN" }].map((l) => (
            <button key={l.id} onClick={() => setLangFilter(l.id)} style={{ background: langFilter === l.id ? NP.ciano : "rgba(255,255,255,0.1)", color: NP.white, fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", padding: "5px 11px", borderRadius: "3px", border: "none", cursor: "pointer" }}>{l.label}</button>
          ))}
        </div>
      </div>

      {canEdit && view.name === "feed" && (
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "12px 16px 0", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontFamily: NP.sans, fontSize: "11px", fontWeight: "700", color: NP.dim, textTransform: "uppercase", letterSpacing: "0.5px" }}>✏️ Modo editor</span>
          <button onClick={() => setView({ name: "manage" })} style={{ background: "none", border: `1px solid ${NP.ciano}`, color: NP.ciano, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "6px 14px", borderRadius: "16px", cursor: "pointer" }}>Gerenciar posts</button>
          <button onClick={() => setView({ name: "edit", post: null })} style={{ background: NP.ciano, border: "none", color: "#fff", fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "7px 16px", borderRadius: "16px", cursor: "pointer" }}>+ Novo post</button>
          {loggedUser?.role === "admin" && <button onClick={() => setView({ name: "newsletter" })} style={{ background: "none", border: `1px solid ${NP.amber}`, color: NP.amber, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "6px 14px", borderRadius: "16px", cursor: "pointer" }}>📬 Newsletter</button>}
        </div>
      )}
      {view.name !== "feed" ? (
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "20px 16px" }}>
          {view.name === "post" ? (
            <PortalPostView post={view.post} onBack={() => { setView({ name: "feed" }); try { history.pushState(null, "", catFilter === "todas" ? "/" : `/categoria/${catFilter}`); } catch {} }} />
          ) : view.name === "manage" ? (
            <PortalPostsList onBack={() => setView({ name: "feed" })} onNew={() => setView({ name: "edit", post: null })} onEdit={(p) => setView({ name: "edit", post: p })} />
          ) : view.name === "newsletter" ? (
            <NewsletterAdmin NP={NP} user={loggedUser} onBack={() => setView({ name: "feed" })} />
          ) : (
            <PortalPostEditor post={view.post} user={loggedUser} onBack={() => setView({ name: "manage" })} onSaved={() => { setView({ name: "manage" }); loadNews(0, false); }} />
          )}
        </div>
      ) : loading ? (
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "24px 16px" }}>
          <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1.7fr 1fr", gap: "16px" }}>
            <div style={{ height: "320px", borderRadius: "3px", background: NP.bgLight }} />
            <div>{[1, 2, 3, 4].map((i) => <div key={i} style={{ display: "flex", gap: "12px", marginBottom: "14px" }}><div style={{ width: "100px", height: "72px", background: NP.bgLight, borderRadius: "3px" }} /><div style={{ flex: 1 }}><div style={{ height: "14px", background: NP.bgLight, borderRadius: "3px", marginBottom: "8px" }} /><div style={{ height: "12px", width: "60%", background: NP.bgLight, borderRadius: "3px" }} /></div></div>)}</div>
          </div>
        </div>
      ) : articles.length === 0 ? (
        <div style={{ textAlign: "center", padding: "80px 24px", color: NP.dim }}>
          <div style={{ fontSize: "56px", marginBottom: "16px" }}>📰</div>
          <p style={{ fontFamily: NP.serif, fontSize: "18px", marginBottom: "8px", color: NP.text }}>Nenhuma notícia nesta categoria ainda.</p>
          <p style={{ fontFamily: NP.sans, fontSize: "13px" }}>As notícias são atualizadas automaticamente. Volte em breve!</p>
        </div>
      ) : (
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "20px 16px" }}>
          <AdSlot slot="top" variant="banner" style={{ marginBottom: "16px" }} />

          {/* ─── Carrossel de destaques ─── */}
          <NewsCarousel items={carouselSlides} onOpen={openPost} canEdit={canEdit} onPin={handlePin} isMobile={isMobile} />

          {/* ─── Duas colunas: Últimas Atualizações + Artigos ─── */}
          {(colLatest.length > 0 || colArticles.length > 0) && (
            <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 1fr", gap: "0", borderTop: `1px solid ${NP.border}`, marginTop: "12px" }}>
              <div style={{ padding: isMobile ? "16px 0 0" : "16px 20px 0 0", borderRight: isMobile ? "none" : `1px solid ${NP.border}` }}>
                <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", color: NP.ciano, textTransform: "uppercase", letterSpacing: "0.5px", borderBottom: `2px solid ${NP.ciano}`, paddingBottom: "6px", marginBottom: "12px" }}>Últimas Atualizações</div>
                {colLatest.map((a) => <NPListItem key={a.id} article={a} compact onOpen={openPost} canEdit={canEdit} onPin={handlePin} />)}
              </div>
              <div style={{ padding: isMobile ? "8px 0 0" : "16px 0 0 20px" }}>
                <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", color: NP.indigo, textTransform: "uppercase", letterSpacing: "0.5px", borderBottom: `2px solid ${NP.indigo}`, paddingBottom: "6px", marginBottom: "12px" }}>Artigos</div>
                {colArticles.map((a) => <NPListItem key={a.id} article={a} compact onOpen={openPost} canEdit={canEdit} onPin={handlePin} />)}
              </div>
            </div>
          )}

          {/* ─── Conteúdo + Sidebar ─── */}
          <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1fr 300px", gap: "28px", marginTop: "8px" }}>
            <div>
              {cultivoArticles.length > 0 && (
                <>
                  <NPSectionHead title="Cultivo Medicinal" onMore={() => handleCat("cultivo")} />
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: "16px", padding: "14px 0 8px" }}>
                    {cultivoArticles.map((a) => <NPGridCard key={a.id} article={a} onOpen={openPost} canEdit={canEdit} onPin={handlePin} />)}
                  </div>
                </>
              )}
              {medicinalArticles.length > 0 && (
                <>
                  <NPSectionHead title="Medicinal" onMore={() => handleCat("medicinal")} />
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: "16px", padding: "14px 0 8px" }}>
                    {medicinalArticles.map((a) => <NPGridCard key={a.id} article={a} onOpen={openPost} canEdit={canEdit} onPin={handlePin} />)}
                  </div>
                </>
              )}
              {/* Espaço publicitário (in-feed) */}
              <AdSlot slot="in-feed" variant="banner" style={{ margin: "16px 0" }} />

              {rest.length > 10 && (
                <>
                  <NPSectionHead title="Mais notícias" />
                  <div style={{ padding: "14px 0 0" }}>
                    {rest.slice(10).map((a) => <NPListItem key={a.id} article={a} compact onOpen={openPost} />)}
                  </div>
                </>
              )}

              {hasMore && (
                <div style={{ textAlign: "center", marginTop: "8px" }}>
                  <button onClick={() => loadNews(articles.filter((a) => !a.__post).length, true)} disabled={loadingMore} style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", color: NP.indigo, background: "none", border: `1px solid ${NP.indigo}`, padding: "10px 32px", cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.5px" }}>{loadingMore ? "Carregando..." : "Carregar mais"}</button>
                </div>
              )}
            </div>

            {/* ─── Sidebar ─── */}
            <aside>
              <AdSlot slot="sidebar" variant="sidebar" style={{ marginBottom: "16px" }} />
              {!embedded && (
                <>
                  <div style={{ background: NP.indigo, color: NP.white, textAlign: "center", padding: "22px 14px", margin: "0 0 16px", borderRadius: "3px", borderTop: `3px solid ${NP.ciano}` }}>
                    <div style={{ fontFamily: NP.serif, fontSize: "19px", fontWeight: "700", marginBottom: "6px" }}>🌱 Registre seu cultivo</div>
                    <div style={{ fontFamily: NP.sans, fontSize: "12px", color: "rgba(255,255,255,0.8)", marginBottom: "13px" }}>Acompanhe suas plantas semana a semana</div>
                    <button onClick={onEnterApp} style={{ background: NP.ciano, color: NP.white, fontFamily: NP.sans, fontSize: "12px", fontWeight: "700", padding: "9px 22px", borderRadius: "20px", border: "none", cursor: "pointer" }}>{loggedUser?"Ir para o app 🌱":"Criar conta grátis"}</button>
                  </div>
                </>
              )}

{onOpenDiary && <PortalDiariesWidget onOpenDiary={onOpenDiary} NP={NP} />}
              <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", borderBottom: `2px solid ${NP.indigo}`, paddingBottom: "6px", marginBottom: "13px", color: NP.indigo }}>Mais Lidas</div>
              {mostRead.map((a, i) => (
                <a key={a.id} href={a.__post ? "#" : a.url} target={a.__post ? undefined : "_blank"} rel={a.__post ? undefined : "noopener noreferrer"} onClick={a.__post ? (e) => { e.preventDefault(); openPost(a); } : undefined} style={{ display: "flex", gap: "11px", marginBottom: "13px", alignItems: "flex-start", textDecoration: "none", color: "inherit" }}>
                  <span style={{ fontFamily: NP.serif, fontSize: "30px", fontWeight: "700", color: NP.amber, opacity: 0.5, lineHeight: "0.9" }}>{i + 1}</span>
                  <div>
                    <h4 style={{ fontFamily: NP.serif, fontSize: "14px", fontWeight: "700", color: NP.text, margin: 0, lineHeight: "1.25", display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{a.title}</h4>
                    <div style={{ fontFamily: NP.sans, fontSize: "11px", color: NP.dim, marginTop: "3px" }}>{npTimeAgo(a.published_at)}</div>
                  </div>
                </a>
              ))}

              <div style={{ fontFamily: NP.sans, fontSize: "13px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", borderBottom: `2px solid ${NP.indigo}`, paddingBottom: "6px", margin: "18px 0 13px", color: NP.indigo }}>Categorias</div>
              {NP_CATS.filter((c) => c.id !== "todas").map((c) => {
                const count = articles.filter((a) => a.category === c.id).length;
                return (
                  <button key={c.id} onClick={() => handleCat(c.id)} style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "center", padding: "8px 0", fontFamily: NP.sans, fontSize: "13px", background: "none", border: "none", borderBottom: `1px solid ${NP.border}`, cursor: "pointer", color: NP.text }}>
                    <span>{c.label}</span>
                    <span style={{ background: NP.indigo, color: NP.white, padding: "1px 9px", fontSize: "11px" }}>{count}</span>
                  </button>
                );
              })}
            </aside>
          </div>
        </div>
      )}

      {/* ─── Footer ─── */}
      {!embedded && (
        <footer style={{ background: NP.indigo, color: NP.white, padding: "28px 20px", fontFamily: NP.sans, marginTop: "24px" }}>
          <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
            <div style={{ display: "grid", gridTemplateColumns: isMobile ? "1fr" : "1.6fr 1.4fr 1fr", gap: "24px" }}>
              <div>
                <div style={{ fontSize: "14px", fontWeight: "700", marginBottom: "8px", letterSpacing: "0.5px" }}>SOBRE NÓS</div>
                <div style={{ fontSize: "12px", color: "rgba(255,255,255,0.7)", lineHeight: "1.6" }}>Portal de notícias sobre cannabis medicinal, ciência, legislação e cultivo. Notícias do Brasil e do mundo, mais uma comunidade de cultivadores.</div>
              </div>
              <div>
                <div style={{ fontSize: "14px", fontWeight: "700", marginBottom: "8px", letterSpacing: "0.5px" }}>📬 NEWSLETTER</div>
                <div style={{ fontSize: "12px", color: "rgba(255,255,255,0.7)", lineHeight: "1.6", marginBottom: "12px" }}>Receba as principais notícias no seu e-mail. Sem spam, cancele quando quiser.</div>
                <NewsletterSignup NP={NP} compact />
              </div>
              <div>
                <div style={{ fontSize: "14px", fontWeight: "700", marginBottom: "8px", letterSpacing: "0.5px" }}>SIGA-NOS</div>
                <div style={{ fontSize: "12px", color: "rgba(255,255,255,0.7)" }}>Facebook · Instagram · YouTube</div>
              </div>
            </div>
            <div style={{ borderTop: "1px solid rgba(255,255,255,0.15)", marginTop: "16px", paddingTop: "12px", fontSize: "11px", color: "rgba(255,255,255,0.55)", textAlign: "center", lineHeight: "1.5" }}>© Diário da Planta 2026 — As notícias são agregadas de fontes externas. Os títulos, resumos e imagens pertencem aos respectivos veículos. Clique para ler a matéria completa na fonte original.</div>
          </div>
        </footer>
      )}
    </div>
  );
}

function AuthScreen({ onLogin, onBackToPortal }) {
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
      <img src={LOGO_SRC} alt="Diário da Planta" className="dp-logo" style={{height:"64px",objectFit:"contain"}}/>
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
        {onBackToPortal&&<div style={{textAlign:"center",marginTop:"16px"}}><button style={{...linkBtn,fontSize:"13px"}} onClick={onBackToPortal}>← Voltar ao portal de notícias</button></div>}
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
                {signupPhoto?<img src={signupPhoto} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:<span style={{fontSize:"28px",opacity:0.5}}>📷</span>}
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
function ProfilePage({ user, diaries, onUpdateUser, onLogout, onBack, blockedUsers, onUnblockUser, onDeleteAccount, onNavigate, allBadges, myBadges }) {
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
      {avatarImg?<img src={avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:
        (editable?<button onClick={()=>setShowAvatars(!showAvatars)} style={{background:"none",border:"none",fontSize:fontSize+"px",cursor:"pointer",padding:0}}>{avatar}</button>:
        <span>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:user.avatar}</span>)}
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
          {allBadges&&allBadges.length>0&&<div style={{marginTop:"16px",padding:"14px",background:C.surface2,borderRadius:"12px"}}>
            <div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"600",color:C.muted,marginBottom:"10px",textTransform:"uppercase",letterSpacing:"0.5px"}}>🏆 Conquistas ({(myBadges||[]).length}/{allBadges.length})</div>
            <BadgeShelf userBadges={myBadges} allBadges={allBadges} size="md"/>
          </div>}
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
  const [shareCopied,setShareCopied]=useState(false);
  const handleShare=async(e)=>{
    e.stopPropagation();
    const url=`${window.location.origin}/?diary=${diary.id}`;
    const shareData={title:diary.name||"Diário de cultivo",text:`Confira o diário "${diary.name}" no Diário da Planta`,url};
    try{
      if(navigator.share&&navigator.canShare?.(shareData)){
        await navigator.share(shareData);
        return;
      }
    }catch{}
    // Fallback: copy to clipboard
    try{
      await navigator.clipboard.writeText(url);
      setShareCopied(true);
      setTimeout(()=>setShareCopied(false),2000);
    }catch{
      // Last-resort fallback for very old browsers
      const ta=document.createElement("textarea");
      ta.value=url;ta.style.position="fixed";ta.style.opacity="0";
      document.body.appendChild(ta);ta.select();
      try{document.execCommand("copy");setShareCopied(true);setTimeout(()=>setShareCopied(false),2000);}catch{}
      document.body.removeChild(ta);
    }
  };
  const [h,setH]=useState(false);
  return (
    <div style={{borderRadius:"14px",overflow:"hidden",border:`1px solid ${C.border}`,background:C.cardBg,transition:"all 0.3s",cursor:"pointer",transform:h?"translateY(-4px)":"none",boxShadow:h?"0 6px 24px rgba(0,0,0,0.1)":"0 1px 4px rgba(0,0,0,0.05)"}} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} onClick={onClick}>
      <div style={{height:"140px",background:COVER_GRADIENTS[(diary.cover||0)%6],display:"flex",alignItems:"center",justifyContent:"center",position:"relative",overflow:"hidden"}}>
        {diary.coverImage?<img src={diary.coverImage} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:<div dangerouslySetInnerHTML={{__html:generatePlantArt(diary.id.charCodeAt(1)*7+(diary.id.charCodeAt(0)||1),100)}} style={{opacity:0.8}}/>}
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
            <button onClick={handleShare} title={shareCopied?"Link copiado!":"Compartilhar"} style={{background:shareCopied?C.accentBg:"none",border:"none",cursor:"pointer",fontSize:"12px",padding:"2px 6px",borderRadius:"6px",color:shareCopied?C.accent:C.dim,transition:"all 0.2s"}}>{shareCopied?"✓":"🔗"}</button>
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
  const t=T[lang||"pt"];
  const [phase,setPhase]=useState(diary.phase||0); const [height,setHeight]=useState("");
  const [temp,setTemp]=useState(""); const [humidity,setHumidity]=useState("");
  const [ph,setPh]=useState(""); const [waterMl,setWaterMl]=useState("");
  const [lightHours,setLightHours]=useState(""); const [note,setNote]=useState("");
  const [media,setMedia]=useState([]);
  const [uploadProgress,setUploadProgress]=useState(null); // {current, total}
  const fileRef=useRef(null);
  const MAX_MEDIA=15;
  // Week numbering resets per phase: count existing weeks of the SAME phase that's currently selected
  const samePhaseWeeks=(diary.weeks||[]).filter(w=>w.phase===phase).length;
  const nextWeekNum=samePhaseWeeks+1;

  const handleFiles=async(e)=>{
    const files=Array.from(e.target.files||[]);
    const remaining=MAX_MEDIA-media.length;
    if(remaining<=0)return;
    const toAdd=files.slice(0,remaining);

    // Show local previews immediately
    const previews=toAdd.map(f=>({
      id:Date.now()+Math.random(),name:f.name,
      type:f.type.startsWith("video")?"video":"photo",
      data:URL.createObjectURL(f),_uploading:true,_file:f
    }));
    setMedia(prev=>[...prev,...previews].slice(0,MAX_MEDIA));
    setUploadProgress({current:0,total:toAdd.length});

    // Upload in background
    for(let i=0;i<previews.length;i++){
      const p=previews[i];const f=p._file;
      setUploadProgress({current:i+1,total:toAdd.length});
      const ext=f.name.split(".").pop()||"jpg";
      const path=`${diary.authorId||"anon"}/weeks/${diary.id}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      const finalUrl=ok?sbStorage.getUrl(path):p.data;
      setMedia(prev=>prev.map(m=>m.id===p.id?{...m,data:finalUrl,_uploading:false,_file:undefined}:m));
      URL.revokeObjectURL(p.data);
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
            <span style={{fontSize:"22px"}}>📝</span> {phase===0?t.germination:phase===3?PHASES[3]:`${t.week} ${nextWeekNum}`}
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
                  <div key={m.id} style={{position:"relative",borderRadius:"10px",overflow:"hidden",aspectRatio:"1",background:C.surface2,border:`1px solid ${m._uploading?C.accent:C.border}`}}>
                    {m.type==="photo"?(
                      <img src={m.data} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>
                    ):(
                      <div style={{width:"100%",height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:"4px"}}>
                        <span style={{fontSize:"24px"}}>🎬</span>
                        <span style={{fontSize:"9px",color:C.dim,fontFamily:F.sans,padding:"0 4px",textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"100%"}}>{m.name}</span>
                      </div>
                    )}
                    {m._uploading&&<div style={{position:"absolute",inset:0,background:"rgba(27,158,66,0.15)",display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{width:"18px",height:"18px",border:"2px solid #1B9E42",borderTop:"2px solid transparent",borderRadius:"50%",animation:"uploadSpin 0.7s linear infinite"}}/></div>}
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
              week:(phase===0||phase===3)?0:nextWeekNum,phase,height:height||null,temp:temp||null,humidity:humidity||null,
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
function DiaryDetail({ diary, onBack, onUpdate, onRemove, onHide, lang, onLike, onFav, isLiked, isFaved, onViewImage, onViewVideo, onReport, comments, onAddComment, onDeleteComment, onEditComment, blockedByOwner, onBlockUser, onUnblockUser, onReportUser, currentUserEmail, onAuthorClick }) {
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
  const commentInputRef=useRef(null);
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
  const saveWeekEdit=(idx,wd)=>{
    const weeks=[...(diary.weeks||[])];
    const oldWeek=weeks[idx]||{};
    let newWeekNum=oldWeek.week;
    // If phase changed, recalculate the week number within the new phase
    if(wd.phase!==undefined&&wd.phase!==oldWeek.phase){
      if(wd.phase===0||wd.phase===3){
        // Germinação and Colheita don't use sequential numbers
        newWeekNum=0;
      }else{
        // Count existing weeks in the target phase (excluding this one being edited)
        const samePhaseCount=weeks.filter((w,i)=>i!==idx&&w.phase===wd.phase).length;
        newWeekNum=samePhaseCount+1;
      }
    }
    weeks[idx]={...oldWeek,...wd,week:newWeekNum};
    const last=weeks[weeks.length-1];
    onUpdate({...diary,weeks,week:last.week,phase:last.phase});
    setEditingWeekIdx(null);
  };
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

    // Show local previews immediately (instant feedback)
    const previews=toAdd.map(f=>({
      id:Date.now()+Math.random(),name:f.name,
      type:f.type.startsWith("video")?"video":"photo",
      data:URL.createObjectURL(f),
      _uploading:true,_file:f
    }));
    const weeks1=[...(diary.weeks||[])];
    weeks1[weekIdx]={...weeks1[weekIdx],media:[...existing,...previews],mediaCount:existing.length+previews.length};
    onUpdate({...diary,weeks:weeks1});

    // Upload in background and replace local URLs with remote URLs
    const uploaded=[];
    for(const p of previews){
      const f=p._file;
      const ext=f.name.split(".").pop()||"jpg";
      const path=`${diary.authorId||"anon"}/weeks/${diary.id}/${Date.now()}-${Math.random().toString(36).slice(2,6)}.${ext}`;
      const ok=await sbStorage.upload(path,f);
      if(ok) uploaded.push({...p,data:sbStorage.getUrl(path),_uploading:false,_file:undefined});
      else uploaded.push({...p,_uploading:false,_file:undefined});
      URL.revokeObjectURL(p.data);
    }
    // Replace previews with uploaded versions
    const weeks2=[...(diary.weeks||[])];
    const finalMedia=[...existing,...uploaded];
    weeks2[weekIdx]={...weeks2[weekIdx],media:finalMedia,mediaCount:finalMedia.length};
    onUpdate({...diary,weeks:weeks2});
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
                <img src={diary.coverImage} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>
              </div>
            ):(
              <div dangerouslySetInnerHTML={{__html:generatePlantArt(diary.id.charCodeAt(1)*7,80)}} style={{width:"80px",opacity:0.8,margin:"0 auto"}}/>
            )}
            {/* Author avatar badge */}
            <div style={{position:"absolute",bottom:diary.coverImage?"-6px":"-8px",right:diary.coverImage?"-6px":"-20px",width:"36px",height:"36px",borderRadius:"50%",background:C.cardBg,border:"2px solid #fff",boxShadow:"0 2px 6px rgba(0,0,0,0.15)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"18px",overflow:"hidden"}}>
              {diary.avatarImg?<img src={diary.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:diary.avatar||"🌱"}
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
                          <div key={m.id} style={{position:"relative",borderRadius:"10px",overflow:"hidden",aspectRatio:"1",background:C.surface2,border:`1px solid ${m._uploading?C.accent:C.border}`,cursor:(m.type==="photo"||m.type==="video")&&m.data&&!m._uploading?"pointer":"default"}} onClick={()=>{if(m._uploading||!m.data)return;if(m.type==="photo")onViewImage?.(m.data);else if(m.type==="video")onViewVideo?.(m.data);}}>
                            {m.type==="photo"&&m.data?(
                              <img src={m.data} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>
                            ):m.type==="video"&&m.data?(
                              <div style={{width:"100%",height:"100%",position:"relative",background:"#000",display:"flex",alignItems:"center",justifyContent:"center"}}>
                                <video src={m.data} preload="metadata" muted playsInline style={{width:"100%",height:"100%",objectFit:"cover",pointerEvents:"none"}}/>
                                <div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,0,0,0.25)"}}>
                                  <div style={{width:"32px",height:"32px",borderRadius:"50%",background:"rgba(255,255,255,0.9)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",color:"#000",paddingLeft:"3px"}}>▶</div>
                                </div>
                              </div>
                            ):(
                              <div style={{width:"100%",height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:"4px"}}>
                                <span style={{fontSize:"24px"}}>{m.type==="video"?"🎬":"🖼️"}</span>
                                <span style={{fontSize:"9px",color:C.dim,fontFamily:F.sans,padding:"0 4px",textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"100%"}}>{m.name}</span>
                              </div>
                            )}
                            {m._uploading&&<div style={{position:"absolute",inset:0,background:"rgba(27,158,66,0.15)",display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{width:"20px",height:"20px",border:"2.5px solid #1B9E42",borderTop:"2.5px solid transparent",borderRadius:"50%",animation:"uploadSpin 0.7s linear infinite"}}/></div>}
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
            <div style={{display:"flex",gap:"10px",borderRadius:replyTo?"0 0 10px 10px":"10px",position:"relative"}}>
            <div style={{flex:1,position:"relative"}}>
              <input ref={commentInputRef} style={{...baseInput,borderRadius:replyTo?"0 0 24px 24px":"24px",padding:"12px 18px",width:"100%"}} value={commentText} onChange={e=>setCommentText(e.target.value)} placeholder={replyTo?`Responder ${replyTo.username}...`:"Escreva um comentário..."} onKeyDown={e=>{if(e.key==="Enter"&&commentText.trim()){onAddComment?.(diary.id,commentText.trim(),replyTo?.id);setCommentText("");setReplyTo(null);}}}/>
              <MentionAutocomplete text={commentText} setText={setCommentText} inputRef={commentInputRef}/>
            </div>
            <button onClick={()=>{if(commentText.trim()){onAddComment?.(diary.id,commentText.trim(),replyTo?.id);setCommentText("");setReplyTo(null);}}} style={{width:"44px",height:"44px",borderRadius:"50%",border:"none",background:commentText.trim()?C.accent:C.surface2,color:commentText.trim()?C.onAccent:C.dim,cursor:"pointer",fontSize:"18px",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all 0.2s"}}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
          </div></div>:<div style={{padding:"14px",borderRadius:"12px",background:C.errorBg,border:`1px solid ${C.error33}`,fontFamily:F.sans,fontSize:"13px",color:C.error,textAlign:"center",marginBottom:"20px"}}>🚫 Você foi bloqueado de comentar neste diário.</div>}

          {/* Comments list (scrollable) */}
          <div style={{maxHeight:"500px",overflowY:"auto",overscrollBehavior:"contain",WebkitOverflowScrolling:"touch",paddingRight:"4px"}}>
          {(()=>{
            const allC=comments||[];
            const allIds=new Set(allC.map(c=>c.id));
            // Root = no parent OR parent was deleted (orphan)
            const rootComments=allC.filter(c=>!c.parentId||!allIds.has(c.parentId));
            const getReplies=(parentId)=>allC.filter(r=>r.parentId===parentId&&allIds.has(parentId));
            const renderComment=(c,depth)=>(
            <div key={c.id} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"14px 16px",marginBottom:depth>0?"6px":"10px",marginLeft:depth>0?Math.min(depth,3)*24+"px":0}}>
              {c.parentId&&(()=>{const parent=allC.find(p=>p.id===c.parentId);return parent?<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginBottom:"6px"}}>↩️ respondendo a <strong>{parent.username}</strong></div>:null;})()}
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:"10px"}}>
                <div style={{display:"flex",gap:"10px",alignItems:"flex-start",flex:1,minWidth:0}}>
                  <div onClick={()=>onAuthorClick?.(c.authorEmail)} style={{width:"32px",height:"32px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"16px",border:`1px solid ${C.border}`,flexShrink:0,overflow:"hidden",cursor:"pointer"}}>{c.avatarImg?<img src={c.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:c.avatar||"🌿"}</div>
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
            // Recursive render: each comment + all its nested replies at any depth
            const renderTree=(c,depth)=>(
              <React.Fragment key={c.id}>
                {renderComment(c,depth)}
                {getReplies(c.id).map(r=>renderTree(r,depth+1))}
              </React.Fragment>
            );
            return rootComments.length>0?<>{rootComments.map(c=>renderTree(c,0))}</>:<div style={{textAlign:"center",padding:"30px",color:C.dim,fontFamily:F.sans,fontSize:"14px"}}>Nenhum comentário ainda. Seja o primeiro!</div>;
          })()}
          </div>{/* end scrollable */}
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
                {m.type==="video"?<div style={{width:"100%",height:"100%",display:"flex",alignItems:"center",justifyContent:"center"}}><span style={{fontSize:"20px"}}>🎬</span></div>:<img src={m.url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>}
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
function MessagesPage({ msgs, user, onSend, onSendMedia, onMarkRead, onMarkUnread, onDeleteConv, onDeleteMessage, onForwardMsg, onCreateGroup, onNewDM, onViewImage, onViewVideo, onBack, lang }) {
  const t=T[lang||"pt"];
  const [activeConv,setActiveConv]=useState(null);
  const [newMsg,setNewMsg]=useState("");
  const [convMenu,setConvMenu]=useState(null);
  const [showNewGroup,setShowNewGroup]=useState(false);
  const [showNewDM,setShowNewDM]=useState(false);
  const [dmUsername,setDmUsername]=useState("");
  const [dmSuggestions,setDmSuggestions]=useState([]);
  const [dmSearching,setDmSearching]=useState(false);
  const [dmFirstMsg,setDmFirstMsg]=useState("");
  // Autocomplete for recipient
  useEffect(()=>{
    if(!dmUsername||dmUsername.length<2){setDmSuggestions([]);return;}
    setDmSearching(true);
    const timer=setTimeout(async()=>{
      try{
        const rows=await sb.from("profiles").select("id,username,avatar,avatar_url",`&username=ilike.${encodeURIComponent(dmUsername)}%25&limit=6`);
        setDmSuggestions((rows||[]).filter(u=>u.id!==user?.id));
      }catch{}
      setDmSearching(false);
    },300);
    return()=>clearTimeout(timer);
  },[dmUsername]);
  const [groupName,setGroupName]=useState("");
  const [groupMembers,setGroupMembers]=useState("");
  const [groupMemberChips,setGroupMemberChips]=useState([]);
  const [groupSearch,setGroupSearch]=useState("");
  const [groupSuggestions,setGroupSuggestions]=useState([]);
  useEffect(()=>{
    if(!groupSearch||groupSearch.length<2){setGroupSuggestions([]);return;}
    const timer=setTimeout(async()=>{
      try{
        const rows=await sb.from("profiles").select("id,username,avatar,avatar_url",`&username=ilike.${groupSearch}%25&limit=6`);
        setGroupSuggestions((rows||[]).filter(u=>u.id!==user?.id&&!groupMemberChips.includes(u.username)));
      }catch{}
    },300);
    return()=>clearTimeout(timer);
  },[groupSearch,groupMemberChips]);
  const [forwardingMsg,setForwardingMsg]=useState(null);
  const [forwardTarget,setForwardTarget]=useState(null);
  const endRef=useRef(null);
  const menuRef=useRef(null);
  const mediaInputRef=useRef(null);
  const [uploadingMedia,setUploadingMedia]=useState(false);
  useEffect(()=>{endRef.current?.scrollIntoView({behavior:"smooth"});},[activeConv,msgs]);
  useEffect(()=>{const h=e=>{if(menuRef.current&&!menuRef.current.contains(e.target))setConvMenu(null);};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);

  const openConv=(id)=>{setActiveConv(id);onMarkRead?.(id);};
  const conv=activeConv?msgs.find(c=>c.id===activeConv):null;

  const timeStr=(ts)=>{const d=new Date(ts);return d.getHours().toString().padStart(2,"0")+":"+d.getMinutes().toString().padStart(2,"0");};
  const dateStr=(ts)=>{const d=new Date(ts);return d.toLocaleDateString(lang==="en"?"en":"pt-BR",{day:"numeric",month:"short"});};

  const handleSend=()=>{if(!newMsg.trim()||!activeConv)return;onSend(activeConv,newMsg.trim());setNewMsg("");};

  const handleMediaUpload=async(e)=>{
    const files=e.target.files;if(!files||!activeConv)return;
    setUploadingMedia(true);
    try{
      for(const f of Array.from(files)){
        const isVideo=f.type.startsWith("video");
        let src=f;
        if(!isVideo){try{src=await compressImage(f);}catch{src=f;}}
        const data=await new Promise((res)=>{const r=new FileReader();r.onload=ev=>res(ev.target.result);r.onerror=()=>res(null);r.readAsDataURL(src);});
        if(data)await onSendMedia?.(activeConv,{type:isVideo?"video":"image",data,name:f.name});
      }
    }finally{setUploadingMedia(false);}
    e.target.value="";
  };

  const doForward=(targetId)=>{
    if(forwardingMsg&&targetId){onForwardMsg?.(targetId,forwardingMsg.text,forwardingMsg.media);setForwardingMsg(null);setForwardTarget(null);}
  };

  const [creatingGroup,setCreatingGroup]=useState(false);
  const handleCreateGroup=()=>{
    if(creatingGroup)return;
    if(!groupName.trim())return;
    const members=groupMemberChips.length>0?groupMemberChips:groupMembers.split(",").map(m=>m.trim()).filter(Boolean);
    if(members.length===0)return;
    setCreatingGroup(true);
    onCreateGroup?.(groupName.trim(),members);
    setGroupMemberChips([]);setGroupSearch("");
    setGroupName("");setGroupMembers("");setShowNewGroup(false);
    setTimeout(()=>setCreatingGroup(false),2000);
  };

  const [dmMedia,setDmMedia]=useState(null); // {type:"image"|"video", data:base64}
  const dmMediaInputRef=useRef(null);
  const handleDmMediaUpload=(e)=>{
    const file=e.target.files?.[0];
    if(!file)return;
    const isVideo=file.type.startsWith("video/");
    const reader=new FileReader();
    reader.onload=ev=>setDmMedia({type:isVideo?"video":"image",data:ev.target.result});
    reader.readAsDataURL(file);
  };
  const handleNewDM=()=>{
    if(!dmUsername.trim()||(!dmFirstMsg.trim()&&!dmMedia))return;
    onNewDM?.(dmUsername.trim(),dmFirstMsg.trim(),dmMedia);
    setDmUsername("");setDmFirstMsg("");setDmMedia(null);setShowNewDM(false);
  };

  // Forward target picker
  if(forwardingMsg) return (
    <div style={{maxWidth:"700px",margin:"0 auto",padding:"24px"}}>
      <div style={{display:"flex",alignItems:"center",gap:"12px",marginBottom:"16px"}}>
        <button onClick={()=>setForwardingMsg(null)} style={{padding:"6px 12px",borderRadius:"16px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans}}>← Voltar</button>
        <h2 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"700",margin:0}}>Encaminhar para...</h2>
      </div>
      <div style={{padding:"12px 16px",background:C.surface2,borderRadius:"10px",marginBottom:"20px",fontFamily:F.sans,fontSize:"13px",color:C.muted,borderLeft:`3px solid ${C.accent}`}}>{forwardingMsg.media?(forwardingMsg.text?`${forwardingMsg.media.type==="video"?"🎬":"📷"} ${forwardingMsg.text}`:`${forwardingMsg.media.type==="video"?"🎬 Vídeo":"📷 Imagem"}`):`"${forwardingMsg.text}"`}</div>
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
          if(m.isSystem){
            return(<div key={m.id}>
              {showDate&&<div style={{textAlign:"center",margin:"12px 0 8px",fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{dateStr(m.time)}</div>}
              <div style={{display:"flex",justifyContent:"center",margin:"8px 0"}}>
                <div style={{maxWidth:"90%",padding:"14px 16px",borderRadius:"12px",background:C.warnBg,border:`1px solid ${C.warnBorder}`,fontFamily:F.sans,fontSize:"13px",lineHeight:"1.5",color:C.text,boxShadow:"0 1px 4px rgba(0,0,0,0.04)"}}>
                  <div style={{display:"flex",alignItems:"center",gap:"8px",marginBottom:"6px",paddingBottom:"6px",borderBottom:`1px solid ${C.warnBorder}`}}>
                    <span style={{fontSize:"16px"}}>🛡️</span>
                    <span style={{fontWeight:"700",color:C.warnText,fontSize:"12px",textTransform:"uppercase",letterSpacing:"0.5px"}}>Aviso do sistema</span>
                    {m.reportNumber&&<span style={{marginLeft:"auto",padding:"2px 8px",borderRadius:"6px",background:C.cardBg,color:C.warnText,fontSize:"11px",fontWeight:"700",border:`1px solid ${C.warnBorder}`}}>#{m.reportNumber}</span>}
                  </div>
                  <div style={{whiteSpace:"pre-wrap",color:C.text}}>{m.text}</div>
                  <div style={{fontSize:"10px",color:C.dim,marginTop:"6px",textAlign:"right"}}>{timeStr(m.time)}</div>
                </div>
              </div>
            </div>);
          }
          return (<div key={m.id}>
            {showDate&&<div style={{textAlign:"center",margin:"12px 0 8px",fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{dateStr(m.time)}</div>}
            {conv.isGroup&&!isMe&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.accent,marginBottom:"2px",marginLeft:"4px"}}>{m.from}</div>}
            <div style={{display:"flex",justifyContent:isMe?"flex-end":"flex-start",alignItems:"flex-end",gap:"6px"}}>
              <div style={{maxWidth:"75%",padding:m.media?"6px":"10px 14px",borderRadius:isMe?"16px 16px 4px 16px":"16px 16px 16px 4px",background:isMe?C.accent:C.msgBubble,color:isMe?C.onAccent:C.text,fontFamily:F.sans,fontSize:"14px",lineHeight:"1.5",position:"relative",overflow:"hidden"}}>
                {m.forwarded&&<div style={{fontSize:"11px",color:isMe?"rgba(255,255,255,0.5)":C.dim,marginBottom:"4px",fontStyle:"italic",padding:m.media?"4px 8px 0":"0"}}>↪ Encaminhada</div>}
                {m.reportNumber&&!m.isSystem&&<div style={{fontSize:"10px",color:isMe?"rgba(255,255,255,0.65)":C.warnText,marginBottom:"4px",fontWeight:"700",padding:m.media?"4px 8px 0":"0"}}>↳ ref. denúncia #{m.reportNumber}</div>}
                {m.media&&m.media.type==="image"&&<img src={m.media.data} alt="" onClick={()=>onViewImage?.(m.media.data)} style={{maxWidth:"100%",borderRadius:m.text?"10px 10px 0 0":"10px",display:"block",maxHeight:"240px",objectFit:"cover",cursor:"pointer"}} loading="lazy"/>}
                {m.media&&m.media.type==="video"&&<div onClick={()=>onViewVideo?.(m.media.data)} style={{position:"relative",cursor:"pointer",borderRadius:m.text?"10px 10px 0 0":"10px",overflow:"hidden",maxHeight:"240px",background:"#000"}}>
                  <video src={m.media.data} preload="metadata" muted playsInline style={{maxWidth:"100%",display:"block",maxHeight:"240px",pointerEvents:"none"}}/>
                  <div style={{position:"absolute",top:0,left:0,right:0,bottom:0,display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,0,0,0.25)"}}>
                    <div style={{width:"48px",height:"48px",borderRadius:"50%",background:"rgba(255,255,255,0.95)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",color:"#000"}}>▶</div>
                  </div>
                </div>}
                {m.text&&<div style={{padding:m.media?"8px 8px 0":"0"}}>{m.text}</div>}
                <div style={{fontSize:"10px",color:isMe?"rgba(255,255,255,0.55)":C.dim,marginTop:"4px",textAlign:"right",padding:m.media?"0 8px 6px":"0"}}>{timeStr(m.time)}</div>
              </div>
              <button onClick={()=>setForwardingMsg({text:m.text||"",media:m.media||null,fromConv:conv.id})} title="Encaminhar" style={{width:"24px",height:"24px",borderRadius:"50%",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",flexShrink:0,opacity:0.5,display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>e.currentTarget.style.opacity="1"} onMouseOut={e=>e.currentTarget.style.opacity="0.5"}>↪</button>
              {isMe&&<button onClick={()=>{if(window.confirm("Apagar esta mensagem?"))onDeleteMessage?.(conv.id,m.id);}} title="Apagar" style={{width:"24px",height:"24px",borderRadius:"50%",border:"none",background:"transparent",color:C.dim,cursor:"pointer",fontSize:"12px",flexShrink:0,opacity:0.5,display:"flex",alignItems:"center",justifyContent:"center"}} onMouseOver={e=>{e.currentTarget.style.opacity="1";e.currentTarget.style.color=C.error;}} onMouseOut={e=>{e.currentTarget.style.opacity="0.5";e.currentTarget.style.color=C.dim;}}>🗑</button>}
            </div>
          </div>);
        })}
        <div ref={endRef}/>
      </div>

      {uploadingMedia&&<div style={{padding:"0 20px"}}><UploadProgressBar active={true} text="Enviando mídia..."/></div>}
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
          <div style={{marginBottom:"20px"}}><label style={labelSt}>Membros</label>
            {groupMemberChips.length>0&&<div style={{display:"flex",flexWrap:"wrap",gap:"6px",marginBottom:"8px"}}>
              {groupMemberChips.map(u=><span key={u} style={{display:"inline-flex",alignItems:"center",gap:"6px",padding:"4px 10px",borderRadius:"16px",background:C.accentBg,color:C.accent,fontFamily:F.sans,fontSize:"12px",fontWeight:"600"}}>{u}<button onClick={()=>setGroupMemberChips(p=>p.filter(x=>x!==u))} style={{background:"none",border:"none",color:C.accent,cursor:"pointer",fontSize:"14px",padding:0,lineHeight:1}}>×</button></span>)}
            </div>}
            <div style={{position:"relative"}}>
              <input style={baseInput} value={groupSearch} onChange={e=>setGroupSearch(e.target.value)} placeholder="Digite um username e selecione..."/>
              {groupSuggestions.length>0&&groupSearch.length>=2&&<div style={{position:"absolute",top:"100%",left:0,right:0,marginTop:"4px",background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"10px",boxShadow:"0 4px 16px rgba(0,0,0,0.12)",overflow:"hidden",zIndex:50,maxHeight:"200px",overflowY:"auto"}}>
                {groupSuggestions.map(u=>(
                  <div key={u.id} onClick={()=>{setGroupMemberChips(p=>[...p,u.username]);setGroupSearch("");setGroupSuggestions([]);}} style={{display:"flex",alignItems:"center",gap:"10px",padding:"10px 14px",cursor:"pointer"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                    <div style={{width:"28px",height:"28px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`,flexShrink:0}}>{u.avatar_url?<img src={u.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:(u.avatar||"🌱")}</div>
                    <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{u.username}</span>
                  </div>
                ))}
              </div>}
            </div>
          </div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>setShowNewGroup(false)}>Cancelar</button><button style={{...btnPrimary,opacity:(!groupName.trim()||groupMemberChips.length===0||creatingGroup)?0.4:1}} disabled={!groupName.trim()||groupMemberChips.length===0||creatingGroup} onClick={handleCreateGroup}>{creatingGroup?"Criando...":"Criar Grupo"}</button></div>
        </div>
      </div>}

      {/* New DM Modal */}
      {showNewDM&&<div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={()=>setShowNewDM(false)}>
        <div style={{...cardBase,maxWidth:"440px"}} onClick={e=>e.stopPropagation()}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"20px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"800",margin:0}}>✉️ Nova Mensagem</h3>
            <button onClick={()=>setShowNewDM(false)} style={{width:"32px",height:"32px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"16px",display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
          </div>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Nome do Destinatário</label>
            <div style={{position:"relative"}}>
              <input style={baseInput} value={dmUsername} onChange={e=>{setDmUsername(e.target.value);}} placeholder="Digite o username..." autoFocus/>
              {dmSuggestions.length>0&&dmUsername.length>=2&&<div style={{position:"absolute",top:"100%",left:0,right:0,marginTop:"4px",background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"10px",boxShadow:"0 4px 16px rgba(0,0,0,0.12)",overflow:"hidden",zIndex:50,maxHeight:"200px",overflowY:"auto"}}>
                {dmSuggestions.map(u=>(
                  <div key={u.id} onClick={()=>{setDmUsername(u.username);setDmSuggestions([]);}} style={{display:"flex",alignItems:"center",gap:"10px",padding:"10px 14px",cursor:"pointer",borderBottom:`1px solid ${C.border}22`}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                    <div style={{width:"28px",height:"28px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`,flexShrink:0}}>{u.avatar_url?<img src={u.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:(u.avatar||"🌱")}</div>
                    <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{u.username}</span>
                  </div>
                ))}
              </div>}
              {dmSearching&&<div style={{position:"absolute",right:"12px",top:"50%",transform:"translateY(-50%)",width:"16px",height:"16px",border:"2px solid "+C.accent,borderTop:"2px solid transparent",borderRadius:"50%",animation:"uploadSpin 0.7s linear infinite"}}/>}
            </div>
          </div>
          <div style={{marginBottom:"14px"}}><label style={labelSt}>Mensagem</label><textarea style={{...baseInput,minHeight:"70px",resize:"vertical"}} value={dmFirstMsg} onChange={e=>setDmFirstMsg(e.target.value)} placeholder="Escreva sua primeira mensagem..."/></div>
          <div style={{marginBottom:"20px"}}>
            <input ref={dmMediaInputRef} type="file" accept="image/*,video/*" style={{display:"none"}} onChange={handleDmMediaUpload}/>
            {dmMedia?(
              <div style={{display:"flex",alignItems:"center",gap:"10px",padding:"10px",borderRadius:"10px",background:C.surface2,border:`1px solid ${C.border}`}}>
                {dmMedia.type==="image"?<img src={dmMedia.data} alt="" style={{width:"48px",height:"48px",objectFit:"cover",borderRadius:"8px"}}/>:<div style={{width:"48px",height:"48px",background:"#000",borderRadius:"8px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px"}}>🎬</div>}
                <span style={{fontFamily:F.sans,fontSize:"12px",color:C.muted,flex:1}}>{dmMedia.type==="image"?"Imagem":"Vídeo"} anexado</span>
                <button onClick={()=>setDmMedia(null)} style={{background:"none",border:"none",color:C.error,cursor:"pointer",fontSize:"16px"}}>✕</button>
              </div>
            ):(
              <button onClick={()=>dmMediaInputRef.current?.click()} style={{padding:"8px 14px",borderRadius:"10px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"6px"}}>📷 Anexar foto/vídeo</button>
            )}
          </div>
          <div style={{display:"flex",gap:"12px"}}><button style={{...btnSecondary,width:"auto",padding:"10px 20px"}} onClick={()=>{setShowNewDM(false);setDmMedia(null);}}>Cancelar</button><button style={{...btnPrimary,opacity:(!dmUsername.trim()||(!dmFirstMsg.trim()&&!dmMedia))?0.4:1}} disabled={!dmUsername.trim()||(!dmFirstMsg.trim()&&!dmMedia)} onClick={handleNewDM}>Enviar</button></div>
        </div>
      </div>}
    </div>
  );
}

// ─── Admin Panel ───
// ─── Admin: aba Produtos (CRUD da vitrine de afiliados) ───
const PRODUTO_BLANK = () => ({ titulo: "", descricao: "", imagem_url: "", marketplace: "mercadolivre", url_afiliado: "", categoria: "geral", tags: "", ativo: true, destaque: false, ordem: 0 });

function ProdutosAdmin() {
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(PRODUTO_BLANK());
  const [editId, setEditId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");
  const [q, setQ] = useState("");

  const load = async () => {
    setLoading(true);
    const rows = await sb.from("produtos").select("*", "&order=ordem.asc&order=created_at.desc");
    setList(rows || []); setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const edit = (p) => {
    setEditId(p.id);
    setForm({ titulo: p.titulo || "", descricao: p.descricao || "", imagem_url: p.imagem_url || "", marketplace: p.marketplace || "mercadolivre", url_afiliado: p.url_afiliado || "", categoria: p.categoria || "geral", tags: (p.tags || []).join(", "), ativo: p.ativo !== false, destaque: !!p.destaque, ordem: p.ordem || 0 });
    setMsg("");
  };
  const reset = () => { setEditId(null); setForm(PRODUTO_BLANK()); setMsg(""); };

  const save = async () => {
    if (!form.titulo.trim()) { setMsg("Informe o título."); return; }
    if (!form.url_afiliado.trim()) { setMsg("Informe o link de afiliado."); return; }
    setSaving(true); setMsg("");
    const payload = {
      titulo: form.titulo.trim(), descricao: form.descricao.trim() || null,
      imagem_url: form.imagem_url.trim() || null, marketplace: form.marketplace,
      url_afiliado: form.url_afiliado.trim(), categoria: form.categoria.trim() || "geral",
      tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
      ativo: !!form.ativo, destaque: !!form.destaque, ordem: Number(form.ordem) || 0,
    };
    try {
      if (editId) await sb.from("produtos").update(payload, `&id=eq.${editId}`);
      else await sb.from("produtos").insert(payload);
      await load(); reset();
    } catch (e) { setMsg("Erro ao salvar: " + (e.message || e)); }
    setSaving(false);
  };

  const del = async (p) => {
    if (typeof window !== "undefined" && !window.confirm(`Excluir "${p.titulo}"?`)) return;
    await sb.from("produtos").delete(`&id=eq.${p.id}`);
    if (editId === p.id) reset();
    await load();
  };
  const toggle = async (p, field) => {
    await sb.from("produtos").update({ [field]: !p[field] }, `&id=eq.${p.id}`);
    await load();
  };

  const fld = { ...baseInput, padding: "10px 12px", fontSize: "14px" };
  const lbl = { fontFamily: F.sans, fontSize: "12px", fontWeight: "600", color: C.muted, display: "block", marginBottom: "4px" };
  const filtered = list.filter((p) => !q || (p.titulo || "").toLowerCase().includes(q.toLowerCase()) || (p.categoria || "").toLowerCase().includes(q.toLowerCase()));

  return (
    <div>
      <div style={{ fontFamily: F.sans, fontSize: "15px", fontWeight: "700", marginBottom: "16px" }}>🛒 Produtos (afiliados)</div>

      <div style={{ background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: "12px", padding: "18px", marginBottom: "22px" }}>
        <div style={{ fontFamily: F.sans, fontSize: "13px", fontWeight: "700", color: C.text, marginBottom: "14px" }}>{editId ? "✏️ Editar produto" : "➕ Novo produto"}</div>
        <div style={{ display: "grid", gap: "12px" }}>
          <div><label style={lbl}>Título *</label><input style={fld} value={form.titulo} onChange={(e) => setForm({ ...form, titulo: e.target.value })} placeholder="Ex.: Kit iluminação LED 240W para cultivo indoor" /></div>
          <div><label style={lbl}>Descrição</label><textarea style={{ ...fld, minHeight: "60px", resize: "vertical" }} value={form.descricao} onChange={(e) => setForm({ ...form, descricao: e.target.value })} placeholder="Frase curta de recomendação (sem preço)" /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            <div><label style={lbl}>Marketplace</label><select style={fld} value={form.marketplace} onChange={(e) => setForm({ ...form, marketplace: e.target.value })}><option value="mercadolivre">Mercado Livre</option><option value="amazon">Amazon</option><option value="outro">Outro</option></select></div>
            <div><label style={lbl}>Categoria</label><input style={fld} value={form.categoria} onChange={(e) => setForm({ ...form, categoria: e.target.value })} placeholder="iluminacao, substrato…" /></div>
          </div>
          <div><label style={lbl}>Link de afiliado *</label><input style={fld} value={form.url_afiliado} onChange={(e) => setForm({ ...form, url_afiliado: e.target.value })} placeholder="https://…" /></div>
          <div><label style={lbl}>URL da imagem</label><input style={fld} value={form.imagem_url} onChange={(e) => setForm({ ...form, imagem_url: e.target.value })} placeholder="https://… (imagem do produto)" /></div>
          <div><label style={lbl}>Tags (separadas por vírgula)</label><input style={fld} value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="indoor, iniciante" /></div>
          <div style={{ display: "grid", gridTemplateColumns: "auto auto 1fr", gap: "16px", alignItems: "center" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: F.sans, fontSize: "13px", color: C.text, cursor: "pointer" }}><input type="checkbox" checked={form.ativo} onChange={(e) => setForm({ ...form, ativo: e.target.checked })} /> Ativo</label>
            <label style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: F.sans, fontSize: "13px", color: C.text, cursor: "pointer" }}><input type="checkbox" checked={form.destaque} onChange={(e) => setForm({ ...form, destaque: e.target.checked })} /> Destaque</label>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", justifyContent: "flex-end" }}><label style={{ fontFamily: F.sans, fontSize: "12px", color: C.muted }}>Ordem</label><input type="number" style={{ ...fld, width: "80px" }} value={form.ordem} onChange={(e) => setForm({ ...form, ordem: e.target.value })} /></div>
          </div>
          {msg && <div style={{ fontFamily: F.sans, fontSize: "12px", color: C.error }}>{msg}</div>}
          <div style={{ display: "flex", gap: "10px" }}>
            <button onClick={save} disabled={saving} style={{ ...btnPrimary, width: "auto", padding: "10px 22px", opacity: saving ? 0.6 : 1 }}>{saving ? "Salvando…" : editId ? "Salvar alterações" : "Adicionar produto"}</button>
            {editId && <button onClick={reset} style={{ padding: "10px 18px", borderRadius: "28px", border: `1px solid ${C.border}`, background: "transparent", color: C.muted, fontFamily: F.sans, fontSize: "14px", cursor: "pointer" }}>Cancelar</button>}
          </div>
        </div>
      </div>

      <div style={{ position: "relative", marginBottom: "14px" }}><input style={{ ...baseInput, paddingLeft: "36px" }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar produto…" /><span style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", fontSize: "14px", color: C.dim }}>🔍</span></div>

      {loading ? <div style={{ textAlign: "center", padding: "40px", color: C.dim, fontFamily: F.sans }}>Carregando…</div> :
        filtered.length === 0 ? <div style={{ textAlign: "center", padding: "40px", color: C.dim, fontFamily: F.sans, fontSize: "13px" }}>Nenhum produto {q ? "encontrado" : "cadastrado ainda"}.</div> :
        <div style={{ display: "grid", gap: "10px" }}>
          {filtered.map((p) => {
            const mk = MARKETPLACES[p.marketplace] || MARKETPLACES.outro;
            return (
              <div key={p.id} style={{ display: "flex", alignItems: "center", gap: "12px", background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "10px 12px", opacity: p.ativo ? 1 : 0.55 }}>
                <div style={{ width: "44px", height: "44px", borderRadius: "6px", background: C.surface2, flexShrink: 0, overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "18px" }}>{p.imagem_url ? <img src={p.imagem_url} alt="" style={{ width: "100%", height: "100%", objectFit: "contain" }} loading="lazy" /> : "🛒"}</div>
                <div style={{ flex: "1", minWidth: "0" }}>
                  <div style={{ fontFamily: F.sans, fontSize: "13px", fontWeight: "700", color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{p.destaque ? "⭐ " : ""}{p.titulo}</div>
                  <div style={{ fontFamily: F.sans, fontSize: "11px", color: C.dim }}>{mk.label} · {p.categoria || "geral"} · ordem {p.ordem || 0}</div>
                </div>
                <button onClick={() => toggle(p, "ativo")} title="Ativar/desativar" style={{ padding: "5px 10px", borderRadius: "8px", border: `1px solid ${C.border}`, background: "transparent", color: p.ativo ? "#38a169" : C.dim, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>{p.ativo ? "Ativo" : "Inativo"}</button>
                <button onClick={() => edit(p)} style={{ padding: "5px 10px", borderRadius: "8px", border: `1px solid ${C.border}`, background: "transparent", color: C.accent, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>Editar</button>
                <button onClick={() => del(p)} style={{ padding: "5px 10px", borderRadius: "8px", border: "none", background: "transparent", color: C.error, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>Excluir</button>
              </div>
            );
          })}
        </div>
      }
    </div>
  );
}

// ─── Admin: aba Fontes RSS (gerencia a tabela real news_sources) ───
const FEED_CATS = ["geral", "cultivo", "medicinal", "politica"];
const FEED_BLANK = () => ({ name: "", feed_url: "", category: "geral", lang: "pt", active: true });

function FeedsAdmin() {
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(FEED_BLANK());
  const [editId, setEditId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  const load = async () => {
    setLoading(true);
    const rows = await sb.from("news_sources").select("*", "&order=name.asc");
    setList(rows || []); setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const edit = (f) => {
    setEditId(f.id);
    setForm({ name: f.name || "", feed_url: f.feed_url || "", category: f.category || "geral", lang: f.lang || "pt", active: f.active !== false });
    setMsg("");
  };
  const reset = () => { setEditId(null); setForm(FEED_BLANK()); setMsg(""); };

  const save = async () => {
    if (!form.name.trim()) { setMsg("Informe o nome da fonte."); return; }
    const u = form.feed_url.trim();
    if (!u) { setMsg("Informe a URL do feed."); return; }
    if (!/^https?:\/\//i.test(u)) { setMsg("A URL do feed deve começar com http:// ou https://"); return; }
    setSaving(true); setMsg("");
    const payload = { name: form.name.trim(), feed_url: u, category: form.category, lang: form.lang, active: !!form.active };
    try {
      if (editId) await sb.from("news_sources").update(payload, `&id=eq.${editId}`);
      else await sb.from("news_sources").insert(payload);
      await load(); reset();
    } catch (e) {
      const m = (e.message || String(e));
      setMsg(/duplicate|unique/i.test(m) ? "Já existe uma fonte com essa URL." : "Erro ao salvar: " + m);
    }
    setSaving(false);
  };

  const del = async (f) => {
    if (typeof window !== "undefined" && !window.confirm(`Excluir a fonte "${f.name}"?\n(Os artigos já importados dela não são apagados.)`)) return;
    await sb.from("news_sources").delete(`&id=eq.${f.id}`);
    if (editId === f.id) reset();
    await load();
  };
  const toggle = async (f) => {
    await sb.from("news_sources").update({ active: !f.active }, `&id=eq.${f.id}`);
    await load();
  };

  const fld = { ...baseInput, padding: "10px 12px", fontSize: "14px" };
  const lbl = { fontFamily: F.sans, fontSize: "12px", fontWeight: "600", color: C.muted, display: "block", marginBottom: "4px" };
  const activeCount = list.filter((f) => f.active).length;

  return (
    <div>
      <div style={{ fontFamily: F.sans, fontSize: "15px", fontWeight: "700", marginBottom: "6px" }}>📡 Fontes RSS</div>
      <div style={{ fontFamily: F.sans, fontSize: "12px", color: C.dim, marginBottom: "18px", lineHeight: "1.5" }}>Fontes que alimentam o portal (tabela news_sources). O robô de ingestão (fetch-news) coleta apenas das fontes <b>ativas</b>. Alterações valem na próxima coleta.{list.length > 0 ? ` ${activeCount} de ${list.length} ativas.` : ""}</div>

      <div style={{ background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: "12px", padding: "18px", marginBottom: "22px" }}>
        <div style={{ fontFamily: F.sans, fontSize: "13px", fontWeight: "700", color: C.text, marginBottom: "14px" }}>{editId ? "✏️ Editar fonte" : "➕ Nova fonte"}</div>
        <div style={{ display: "grid", gap: "12px" }}>
          <div><label style={lbl}>Nome da fonte *</label><input style={fld} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Ex.: Sechat" /></div>
          <div><label style={lbl}>URL do feed (RSS/Atom) *</label><input style={fld} value={form.feed_url} onChange={(e) => setForm({ ...form, feed_url: e.target.value })} placeholder="https://site.com/feed/" /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            <div><label style={lbl}>Categoria padrão</label><select style={fld} value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>{FEED_CATS.map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
            <div><label style={lbl}>Idioma</label><select style={fld} value={form.lang} onChange={(e) => setForm({ ...form, lang: e.target.value })}><option value="pt">Português (pt)</option><option value="en">Inglês (en)</option></select></div>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: F.sans, fontSize: "13px", color: C.text, cursor: "pointer" }}><input type="checkbox" checked={form.active} onChange={(e) => setForm({ ...form, active: e.target.checked })} /> Ativa (o robô coleta desta fonte)</label>
          {msg && <div style={{ fontFamily: F.sans, fontSize: "12px", color: C.error }}>{msg}</div>}
          <div style={{ display: "flex", gap: "10px" }}>
            <button onClick={save} disabled={saving} style={{ ...btnPrimary, width: "auto", padding: "10px 22px", opacity: saving ? 0.6 : 1 }}>{saving ? "Salvando…" : editId ? "Salvar alterações" : "Adicionar fonte"}</button>
            {editId && <button onClick={reset} style={{ padding: "10px 18px", borderRadius: "28px", border: `1px solid ${C.border}`, background: "transparent", color: C.muted, fontFamily: F.sans, fontSize: "14px", cursor: "pointer" }}>Cancelar</button>}
          </div>
        </div>
      </div>

      {loading ? <div style={{ textAlign: "center", padding: "40px", color: C.dim, fontFamily: F.sans }}>Carregando…</div> :
        list.length === 0 ? <div style={{ textAlign: "center", padding: "40px", color: C.dim, fontFamily: F.sans, fontSize: "13px" }}>Nenhuma fonte cadastrada. Adicione a primeira acima.</div> :
        <div style={{ display: "grid", gap: "10px" }}>
          {list.map((f) => (
            <div key={f.id} style={{ display: "flex", alignItems: "center", gap: "12px", background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "12px 14px", opacity: f.active ? 1 : 0.55 }}>
              <div style={{ flex: "1", minWidth: "0" }}>
                <div style={{ fontFamily: F.sans, fontSize: "13px", fontWeight: "700", color: C.text }}>{f.name} <span style={{ fontWeight: "500", color: C.dim }}>· {f.category || "geral"} · {f.lang}</span></div>
                <div style={{ fontFamily: F.sans, fontSize: "11px", color: C.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", marginTop: "2px" }}>{f.feed_url}</div>
              </div>
              <button onClick={() => toggle(f)} title="Ativar/desativar" style={{ padding: "5px 10px", borderRadius: "8px", border: `1px solid ${C.border}`, background: "transparent", color: f.active ? "#38a169" : C.dim, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>{f.active ? "Ativa" : "Inativa"}</button>
              <button onClick={() => edit(f)} style={{ padding: "5px 10px", borderRadius: "8px", border: `1px solid ${C.border}`, background: "transparent", color: C.accent, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>Editar</button>
              <button onClick={() => del(f)} style={{ padding: "5px 10px", borderRadius: "8px", border: "none", background: "transparent", color: C.error, fontFamily: F.sans, fontSize: "11px", fontWeight: "700", cursor: "pointer" }}>Excluir</button>
            </div>
          ))}
        </div>
      }
    </div>
  );
}

function AdminPanel({ user, onBack, onNewPost }) {
  const [tab,setTab]=useState("dashboard");
  const [allUsers,setAllUsers]=useState({});
  const [allDiariesMap,setAllDiariesMap]=useState({});
  const [loading,setLoading]=useState(true);
  const [editUser,setEditUser]=useState(null);
  const [editForm,setEditForm]=useState({});
  const [confirm,setConfirm]=useState(null);
  const [warnTarget,setWarnTarget]=useState(null);
  const [warnReportNumber,setWarnReportNumber]=useState(null);
  const [reportEdits,setReportEdits]=useState({}); // {[reportId]: {notes, action}}
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
  const [portalPosts,setPortalPosts]=useState([]);

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
      const [profiles,diaries,reps,al,ac,bp,pp]=await Promise.all([
        sb.from("profiles").select("*","&order=created_at.desc"),
        sb.from("diaries").select("*,profiles(username,avatar)","&order=created_at.desc"),
        sb.from("reports").select("*,reporter:reporter_id(username),target_user:target_user_id(username,email),target_diary:target_diary_id(name,user_id)","&order=created_at.desc"),
        sb.from("audit_log").select("*,admin:admin_id(username,email)","&order=created_at.desc&limit=200"),
        sb.from("comments").select("id,text,created_at,user_id,diary_id,profiles(username,avatar,avatar_url),diaries(name)","&order=created_at.desc&limit=500"),
        sb.from("blog_posts").select("*,profiles(username)","&order=created_at.desc"),
        sb.from("portal_posts").select("id,status,featured,published_at,created_at,category","&order=created_at.desc"),
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

      setReports((reps||[]).map(r=>({id:r.id,number:r.report_number,status:r.status,reporterName:r.reporter?.username,reporterEmail:r.reporter_id,targetName:r.target_user?.username||"",targetEmail:r.target_user?.email||"",targetUserId:r.target_user_id||r.target_diary?.user_id||null,targetType:r.target_type,targetDiaryName:r.target_diary?.name||"",targetDiaryId:r.target_diary_id,targetThreadId:r.target_thread_id,targetReplyId:r.target_reply_id,reason:r.reason,adminNotes:r.admin_notes||"",actionTaken:r.action_taken||"",resolvedBy:r.resolved_by,resolvedAt:r.resolved_at?new Date(r.resolved_at).getTime():null,time:new Date(r.created_at).getTime()})));
      setAuditLog((al||[]).map(a=>({id:a.id,time:new Date(a.created_at).getTime(),admin:a.admin?.username,adminEmail:a.admin?.email,action:a.action,target:a.target,detail:a.detail})));
      setAllComments((ac||[]).map(c=>({id:c.id,text:c.text,username:c.profiles?.username,avatar:c.profiles?.avatar,avatarImg:c.profiles?.avatar_url,authorEmail:c.user_id,diaryId:c.diary_id,diaryName:c.diaries?.name,time:new Date(c.created_at).getTime()})));
      setBlogPosts((bp||[]).map(p=>({...p,authorName:p.profiles?.username})));
      setPortalPosts((pp||[]).map(p=>({...p,createdAt:new Date(p.created_at).getTime()})));
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
    // If email changed, use the admin RPC to update auth + profiles
    const originalEmail=allUsers[editUser]?.email||"";
    if(editForm.email&&editForm.email!==originalEmail){
      try{
        const ok=await sb.rpc("admin_update_user_email",{target_uid:editUser,new_email:editForm.email.trim()});
        if(ok){
          setAllUsers(p=>({...p,[editUser]:{...p[editUser],...editForm,email:editForm.email.trim()}}));
          await addAudit("Alterou email",originalEmail+" → "+editForm.email.trim(),editForm.username);
          showToast("Email e perfil atualizados.");
        }else{showToast("Erro ao atualizar email.");}
      }catch(e){reportError(e,{feature:"admin",op:"email_update"});showToast("Erro ao atualizar email: "+(e.message||""));}
    }else{
      setAllUsers(p=>({...p,[editUser]:{...p[editUser],...editForm}}));
      await addAudit("Editou usuário",allUsers[editUser]?.email,editForm.username);
      showToast("Usuário atualizado.");
    }
    setEditUser(null);
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
    if(!warnTarget||!warnMsg.trim())return;
    const cleanWarn=sanitize(warnMsg.trim(),500);
    const refNum=warnReportNumber;
    const bodyWithRef=refNum?`⚠️ Aviso da administração (ref. denúncia #${refNum}):\n\n${cleanWarn}\n\n— Você pode responder a esta mensagem para contestar.`:`⚠️ Aviso da administração:\n\n${cleanWarn}`;
    try{
      // 1) Notification
      await insertNotifications({user_id:warnTarget,type:"warning",from_username:"Administração",from_avatar:"🛡️",text:cleanWarn,report_number:refNum||null});
      // 2) DM conversation — find existing 1-on-1 with target or create new
      let convId=null;
      try{
        // Use RPC to atomically find-or-create DM conversation (avoids RLS issues)
        convId=await sb.rpc("ensure_dm_conversation",{p_target_id:warnTarget});
        if(convId){
          await sb.from("messages").insert({conversation_id:convId,sender_id:user.id,text:bodyWithRef,is_system:true,report_number:refNum||null});
        }
      }catch(e){reportError(e,{feature:"admin",op:"send_warning"});}
    }catch{}
    await addAudit(refNum?`Enviou aviso (denúncia #${refNum})`:"Enviou aviso",allUsers[warnTarget]?.email||warnTarget,cleanWarn.substring(0,60));
    setWarnTarget(null);setWarnMsg("");setWarnReportNumber(null);
    showToast(refNum?`Aviso + DM enviados (denúncia #${refNum}).`:"Aviso + DM enviados ao usuário.");
  };
  const doSendAnnouncement=async()=>{
    if(!announceMsg.trim())return;const cleanAnn=sanitize(announceMsg.trim(),500);
    const userIds=Object.keys(allUsers);
    if(userIds.length===0){showToast("Nenhum usuário carregado ainda. Abra a aba Usuários e tente novamente.");return;}
    const inserts=userIds.map(uid=>({user_id:uid,type:"announcement",from_username:"Administração",from_avatar:"📢",text:cleanAnn}));
    const {ok,count}=await insertNotifications(inserts);
    if(!ok){showToast("Erro ao enviar o anúncio. Tente novamente.");return;}
    await addAudit("Enviou anúncio global","todos ("+count+")",cleanAnn.substring(0,60));
    setAnnounceMsg("");showToast(`Anúncio enviado para ${count} usuários.`);
  };
  const doResolveReport=async(id,status,notes,action)=>{
    const cleanNotes=sanitize(notes||"",1000);
    const cleanAction=sanitize(action||"",200);
    try{await sb.from("reports").update({status,resolved_by:user.id,resolved_at:new Date().toISOString(),admin_notes:cleanNotes,action_taken:cleanAction},`id=eq.${id}`);}catch{}
    setReports(p=>p.map(r=>r.id===id?{...r,status,resolvedBy:user.username,resolvedAt:Date.now(),adminNotes:cleanNotes,actionTaken:cleanAction}:r));
    const rep=reports.find(r=>r.id===id);
    await addAudit("Resolveu denúncia → "+status,rep?.targetEmail||"",[`#${rep?.number||"?"}`,cleanAction,cleanNotes].filter(Boolean).join(" · ").substring(0,200));
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
            {tabBtn("produtos","🛒","Produtos")}
            {tabBtn("feeds","📡","Fontes RSS")}
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
        {(()=>{
          const now=Date.now();
          const dayAgo=now-86400000, weekAgo=now-604800000, monthAgo=now-2592000000;
          // Comunidade
          const totalUsers=userList.length;
          const newToday=userList.filter(u=>u.createdAt>dayAgo).length;
          const new7d=userList.filter(u=>u.createdAt>weekAgo).length;
          const new30d=userList.filter(u=>u.createdAt>monthAgo).length;
          const admins=userList.filter(u=>u.role==="admin").length;
          const banned=userList.filter(u=>u.banned).length;
          const activeDiaries=allDiariesFlat.filter(d=>!d.hidden).length;
          const hiddenDiaries=allDiariesFlat.filter(d=>d.hidden).length;
          const totalComments=allComments.length;
          const comments7d=allComments.filter(c=>c.time>weekAgo).length;
          // Portal (notícias)
          const pPub=portalPosts.filter(p=>p.status==="published"&&(!p.published_at||new Date(p.published_at).getTime()<=now)).length;
          const pSched=portalPosts.filter(p=>p.status==="published"&&p.published_at&&new Date(p.published_at).getTime()>now).length;
          const pDraft=portalPosts.filter(p=>p.status==="draft").length;
          const pFeat=portalPosts.filter(p=>p.featured).length;
          // Blog
          const bPub=blogPosts.filter(p=>p.status==="published").length;
          const bDraft=blogPosts.filter(p=>p.status==="draft").length;
          // Moderação
          const pendingReps=reports.filter(r=>r.status==="pending").length;
          const totalReps=reports.length;
          // Top cultivadores (por nº de diários)
          const byOwner={};
          allDiariesFlat.forEach(d=>{byOwner[d.ownerUserId]=(byOwner[d.ownerUserId]||0)+1;});
          const topGrowers=Object.entries(byOwner).map(([uid,count])=>({name:allUsers[uid]?.username||"—",avatar:allUsers[uid]?.avatar||"🌱",avatarImg:allUsers[uid]?.avatarImg,count})).sort((a,b)=>b.count-a.count).slice(0,5);
          // Helpers de UI
          const stat=(icon,label,value,color)=><div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"14px 18px",textAlign:"center"}}><div style={{fontSize:"24px",marginBottom:"2px"}}>{icon}</div><div style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"800",color:color||C.text}}>{value}</div><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"2px"}}>{label}</div></div>;
          const gridStyle={display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(140px,1fr))",gap:"12px"};
          const secTitle=(t)=><div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"700",color:C.muted,textTransform:"uppercase",letterSpacing:"0.5px",margin:"22px 0 10px"}}>{t}</div>;
          // Histograma diário (últimos N dias)
          const dayBuckets=(items,getTs,days=30)=>{
            const base=new Date();base.setHours(0,0,0,0);
            const start=base.getTime()-(days-1)*86400000;
            const b=new Array(days).fill(0);
            items.forEach(it=>{const ts=getTs(it);if(typeof ts==="number"&&ts>=start){const i=Math.floor((ts-start)/86400000);if(i>=0&&i<days)b[i]++;}});
            return b;
          };
          const miniBars=(title,buckets,color)=>{
            const max=Math.max(1,...buckets);const total=buckets.reduce((a,v)=>a+v,0);
            const W=560,H=90,pad=2,bw=(W-pad*2)/buckets.length;
            return <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"16px 18px"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:"10px"}}>
                <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",color:C.text}}>{title}</div>
                <div style={{fontFamily:F.sans,fontSize:"12px",color:C.dim}}>{total} no período · pico {max}/dia</div>
              </div>
              <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" style={{display:"block"}}>
                {buckets.map((v,i)=>{const h=(v/max)*(H-14);return <rect key={i} x={pad+i*bw+0.5} y={H-h} width={Math.max(1,bw-1)} height={h} rx="1" fill={color} opacity={v?1:0.18}/>;})}
              </svg>
              <div style={{display:"flex",justifyContent:"space-between",fontFamily:F.sans,fontSize:"10px",color:C.dim,marginTop:"4px"}}><span>{buckets.length}d atrás</span><span>hoje</span></div>
            </div>;
          };
          return <div>
            <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700",marginBottom:"4px"}}>📊 Visão Geral</div>

            {secTitle("Comunidade")}
            <div style={gridStyle}>
              {stat("👥","Total Usuários",totalUsers,"#3182ce")}
              {stat("🆕","Novos Hoje",newToday,"#38a169")}
              {stat("📆","Novos (7d)",new7d,"#2f855a")}
              {stat("📈","Novos (30d)",new30d,"#276749")}
              {stat("👑","Admins",admins,"#d69e2e")}
              {stat("🚫","Banidos",banned,banned?"#e53e3e":C.dim)}
              {stat("📓","Diários Ativos",activeDiaries,"#805ad5")}
              {stat("🙈","Diários Ocultos",hiddenDiaries,hiddenDiaries?"#dd6b20":C.dim)}
            </div>

            {secTitle("Conteúdo")}
            <div style={gridStyle}>
              {stat("📰","Portal Publicados",pPub,"#e53e3e")}
              {stat("⏳","Portal Agendados",pSched,pSched?"#dd6b20":C.dim)}
              {stat("📝","Portal Rascunhos",pDraft,"#718096")}
              {stat("⭐","Portal Destaques",pFeat,"#d69e2e")}
              {stat("🗞️","Blog Publicados",bPub,"#c53030")}
              {stat("📋","Blog Rascunhos",bDraft,"#718096")}
              {stat("💬","Comentários",totalComments,"#d69e2e")}
              {stat("💭","Comentários (7d)",comments7d,"#dd6b20")}
            </div>

            {secTitle("Moderação")}
            <div style={gridStyle}>
              {stat("🚨","Denúncias Pendentes",pendingReps,pendingReps?"#e53e3e":C.dim)}
              {stat("🗂️","Denúncias (total)",totalReps,C.muted)}
            </div>

            {secTitle("Tendências (últimos 30 dias)")}
            <div style={{display:"grid",gap:"12px"}}>
              {miniBars("Novos usuários por dia",dayBuckets(userList,u=>u.createdAt,30),"#38a169")}
              {miniBars("Comentários por dia",dayBuckets(allComments,c=>c.time,30),"#dd6b20")}
            </div>

            {topGrowers.length>0&&<div>
              {secTitle("Top cultivadores (por nº de diários)")}
              <div style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${C.border}`,padding:"8px 4px"}}>
                {topGrowers.map((g,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:"10px",padding:"8px 14px",borderBottom:i<topGrowers.length-1?`1px solid ${C.border}`:"none"}}>
                  <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"800",color:C.dim,width:"20px",textAlign:"center"}}>{i+1}</div>
                  <div style={{width:"30px",height:"30px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"15px",overflow:"hidden",flexShrink:0}}>{g.avatarImg?<img src={g.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:g.avatar}</div>
                  <div style={{flex:1,fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.text}}>{g.name}</div>
                  <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",color:C.accent}}>{g.count} {g.count===1?"diário":"diários"}</div>
                </div>)}
              </div>
            </div>}
          </div>;
        })()}
      </div>}

      {tab === "produtos" && <ProdutosAdmin />}
      {tab === "feeds" && <FeedsAdmin />}

      {/* USERS TAB */}
      {tab==="users"&&<div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"12px",gap:"10px",flexWrap:"wrap"}}>
          <div style={{fontFamily:F.sans,fontSize:"15px",fontWeight:"700"}}>{filteredUsers.length} usuários</div>
          <button onClick={()=>setNewUserForm({email:"",username:"",password:"",role:"user"})} style={{padding:"8px 14px",borderRadius:"10px",border:`1px solid ${C.accent}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>+ Criar</button>
        </div>
        {searchInput(searchUsers,setSearchUsers,"Buscar por nome ou email...")}
        {filteredUsers.map(u=>(
          <div key={u.email} style={{background:C.cardBg,borderRadius:"12px",border:`1px solid ${u.banned?C.error+"44":C.border}`,padding:"12px 14px",marginBottom:"8px",display:"flex",alignItems:"center",gap:"10px",flexWrap:"wrap",opacity:u.banned?0.6:1}}>
            <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"18px",border:`1px solid ${C.border}`,overflow:"hidden",flexShrink:0}}>{u.avatarImg?<img src={u.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:u.avatar}</div>
            <div style={{flex:1,minWidth:"100px"}}>
              <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",display:"flex",alignItems:"center",gap:"4px",flexWrap:"wrap"}}>{u.username} {u.role==="admin"&&<span style={{fontSize:"9px",padding:"1px 5px",borderRadius:"5px",background:C.warnBg,color:C.warnText,fontWeight:"600"}}>ADMIN</span>} {u.banned&&<span style={{fontSize:"9px",padding:"1px 5px",borderRadius:"5px",background:C.errorBg,color:C.error,fontWeight:"600"}}>BANIDO</span>}</div>
              <div style={{fontFamily:F.sans,fontSize:"10px",color:C.dim}}>{u.email}</div>
            </div>
            <div style={{display:"flex",gap:"3px",flexWrap:"wrap"}}>
              <button onClick={()=>{setEditUser(u.id);setEditForm({username:u.username,bio:u.bio||"",city:u.city||"",email:u.email||""});}} style={{padding:"4px 8px",borderRadius:"6px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>✏️</button>
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
            <div style={{width:"30px",height:"30px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",border:`1px solid ${C.border}`,flexShrink:0,overflow:"hidden"}}>{c.avatarImg?<img src={c.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:c.avatar||"🌿"}</div>
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
              <button onClick={async()=>{if(!window.confirm("Deletar post '"+p.title+"'?"))return;try{const ok=await sb.from("blog_posts").delete(`id=eq.${p.id}`);if(ok){setBlogPosts(prev=>prev.filter(x=>x.id!==p.id));addAudit("Deletou post",p.title,"");}else{console.error("Delete failed");}}catch(e){console.error("Delete error:",e);}}} style={{padding:"6px 10px",borderRadius:"8px",border:`1px solid ${C.error}33`,background:C.error+"08",color:C.error,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,flexShrink:0}}>🗑️</button>
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
                <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"700",display:"flex",alignItems:"center",gap:"6px",flexWrap:"wrap"}}>
                  {r.number&&<span style={{padding:"2px 8px",borderRadius:"5px",background:C.surface2,color:C.text,fontSize:"10px",fontWeight:"800",border:`1px solid ${C.border}`}}>#{r.number}</span>}
                  {r.status==="pending"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.warnBg,color:C.warnText,fontSize:"9px",fontWeight:"700"}}>PENDENTE</span>}
                  {r.status==="resolved"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.accentBg,color:C.accent,fontSize:"9px",fontWeight:"700"}}>RESOLVIDA</span>}
                  {r.status==="dismissed"&&<span style={{padding:"2px 6px",borderRadius:"5px",background:C.surface2,color:C.dim,fontSize:"9px",fontWeight:"700"}}>DISPENSADA</span>}
                  Denúncia de {r.reporterName}
                </div>
                <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"2px"}}>Alvo: {r.targetName||"—"} {r.targetEmail?`(${r.targetEmail})`:""} · {r.targetType==="diary"?"Diário: "+r.targetDiaryName:r.targetType==="thread"?"Tópico do fórum":r.targetType==="reply"?"Resposta do fórum":r.targetType==="comment"?"Comentário":"Perfil"} · {timeAgo(r.time)}</div>
              </div>
            </div>
            <div style={{fontFamily:F.sans,fontSize:"13px",color:C.text,padding:"10px",background:C.surface2,borderRadius:"8px",borderLeft:`3px solid #d97706`,marginBottom:"10px"}}>{r.reason}</div>
            {r.resolvedBy&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginBottom:"8px"}}>Resolvida por {r.resolvedBy} · {timeAgo(r.resolvedAt)}</div>}
            {(r.actionTaken||r.adminNotes)&&r.status!=="pending"&&<div style={{padding:"10px 12px",background:C.accentBg,borderRadius:"8px",marginBottom:"8px",border:`1px solid ${C.accent33}`}}>
              {r.actionTaken&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.accent,fontWeight:"700",marginBottom:"4px",textTransform:"uppercase",letterSpacing:"0.5px"}}>Ação tomada: {r.actionTaken}</div>}
              {r.adminNotes&&<div style={{fontFamily:F.sans,fontSize:"12px",color:C.text,whiteSpace:"pre-wrap",lineHeight:"1.4"}}>{r.adminNotes}</div>}
            </div>}
            {r.status==="pending"&&<>
              <div style={{display:"grid",gridTemplateColumns:"1fr 2fr",gap:"8px",marginBottom:"10px"}}>
                <input style={{...baseInput,padding:"8px 12px",fontSize:"12px"}} placeholder="Ação tomada (ex: warned, banned)" value={reportEdits[r.id]?.action||""} onChange={e=>setReportEdits(p=>({...p,[r.id]:{...p[r.id],action:e.target.value}}))}/>
                <input style={{...baseInput,padding:"8px 12px",fontSize:"12px"}} placeholder="Notas internas (visível só para admins)" value={reportEdits[r.id]?.notes||""} onChange={e=>setReportEdits(p=>({...p,[r.id]:{...p[r.id],notes:e.target.value}}))}/>
              </div>
              <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
                <button onClick={()=>doResolveReport(r.id,"resolved",reportEdits[r.id]?.notes,reportEdits[r.id]?.action)} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.accent44}`,background:C.accentBg,color:C.accent,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600"}}>✅ Resolvida</button>
                <button onClick={()=>doResolveReport(r.id,"dismissed",reportEdits[r.id]?.notes,reportEdits[r.id]?.action)} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>❌ Dispensar</button>
                {r.targetUserId&&<button onClick={()=>{setWarnTarget(r.targetUserId);setWarnReportNumber(r.number||null);setWarnMsg("Recebemos uma denúncia sobre seu conteúdo. Por favor, revise e adeque às diretrizes da comunidade.");setTab("warnings");}} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.warnBorder}`,background:C.warnBg,color:C.warnText,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>⚠️ Avisar</button>}
                <button onClick={()=>doDeleteReport(r.id)} style={{padding:"6px 14px",borderRadius:"8px",border:`1px solid ${C.error44}`,background:C.errorBg,color:C.error,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>🗑️</button>
              </div>
            </>}
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
              {warnReportNumber&&<span style={{fontFamily:F.sans,fontSize:"11px",color:C.warnText,fontWeight:"700",padding:"2px 6px",borderRadius:"4px",background:C.warnBg,border:`1px solid ${C.warnBorder}`}}>ref. #{warnReportNumber}</span>}
              <button onClick={()=>{setWarnTarget(null);setWarnReportNumber(null);}} style={{background:"none",border:"none",color:C.error,cursor:"pointer",fontSize:"12px",marginLeft:"auto"}}>✕</button>
            </div>}
            {warnSearch&&!warnTarget&&<div style={{maxHeight:"150px",overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:"8px",background:C.cardBg}}>
              {userList.filter(u=>(u.username+" "+u.email).toLowerCase().includes(warnSearch.toLowerCase())).slice(0,10).map(u=>(
                <div key={u.id} onClick={()=>{setWarnTarget(u.id);setWarnSearch("");}} style={{padding:"10px 14px",cursor:"pointer",display:"flex",alignItems:"center",gap:"10px",borderBottom:`1px solid ${C.border22}`,fontFamily:F.sans,fontSize:"13px"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                  <div style={{width:"28px",height:"28px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`}}>{u.avatarImg?<img src={u.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:u.avatar}</div>
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
          <div style={{marginBottom:"12px"}}><label style={labelSt}>Email (login)</label><input style={baseInput} type="email" value={editForm.email||""} onChange={e=>setEditForm(p=>({...p,email:e.target.value}))}/>{editForm.email&&editForm.email!==(allUsers[editUser]?.email||"")&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.warnText,marginTop:"4px"}}>⚠️ Alterar o email muda o login do usuário</div>}</div>
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
function PublicProfile({ targetUser, diaries, onBack, onViewDiary, lang, allBadges, onReport, currentUserId }) {
  const [profileBadges,setProfileBadges]=useState([]);
  useEffect(()=>{if(!targetUser?.id)return;(async()=>{try{const b=await sb.from("user_badges").select("*",`&user_id=eq.${targetUser.id}`);setProfileBadges(b||[]);}catch{}})();},[targetUser?.id]);
  const t=T[lang||"pt"];
  const level=getUserLevel(diaries.length);
  const totalWeeks=diaries.reduce((s,d)=>s+(d.weeks?.length||0),0);
  return (
    <div style={{maxWidth:"700px",margin:"0 auto",padding:"32px 24px"}}>
      <button onClick={onBack} style={{padding:"8px 16px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.cardBg,color:C.muted,cursor:"pointer",fontSize:"13px",fontFamily:F.sans,marginBottom:"24px"}}>← {t.back}</button>
      <div style={{background:C.surfaceLight,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"32px",textAlign:"center",marginBottom:"20px"}}>
        <div style={{width:"80px",height:"80px",borderRadius:"50%",background:C.accentBg,border:`3px solid ${C.accent}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"40px",margin:"0 auto 12px",overflow:"hidden"}}>{targetUser.avatarImg?<img src={targetUser.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:targetUser.avatar||"🌱"}</div>
        <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",margin:"0 0 4px"}}>{targetUser.username}</h2>
        <div style={{fontFamily:F.sans,fontSize:"12px",color:C.accent,fontWeight:"700",textTransform:"uppercase",letterSpacing:"1px",marginBottom:"4px"}}>{level.icon} {level.name}</div>
        {targetUser.city&&<div style={{fontFamily:F.sans,fontSize:"13px",color:C.dim}}>📍 {targetUser.city}</div>}
        {targetUser.bio&&<p style={{fontFamily:F.body,fontSize:"14px",color:C.muted,fontStyle:"italic",margin:"12px 0 0",lineHeight:"1.5"}}>"{targetUser.bio}"</p>}
        {currentUserId&&targetUser.id!==currentUserId&&<div style={{marginTop:"16px"}}>
          <button onClick={()=>onReport?.(targetUser.id,targetUser.username)} style={{padding:"8px 18px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"inline-flex",alignItems:"center",gap:"6px"}}>🚩 Denunciar usuário</button>
        </div>}
        {allBadges&&allBadges.length>0&&profileBadges.length>0&&<div style={{marginTop:"16px",padding:"14px",background:C.surface2,borderRadius:"12px"}}>
          <div style={{fontFamily:F.sans,fontSize:"12px",fontWeight:"600",color:C.muted,marginBottom:"10px",textTransform:"uppercase",letterSpacing:"0.5px"}}>🏆 Conquistas ({profileBadges.length})</div>
          <BadgeShelf userBadges={profileBadges} allBadges={allBadges.filter(b=>profileBadges.some(pb=>pb.badge_id===b.id))} size="md"/>
        </div>}
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
    }catch(e){reportError(e,{feature:"blog",op:"save_post"});}
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
          <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",overflow:"hidden",border:`1px solid ${C.border}`}}>{user?.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:user?.avatar||"🌱"}</div>
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
              {coverUrl?<div style={{position:"relative",marginBottom:"8px"}}><img src={coverUrl} alt="" style={{width:"100%",borderRadius:"8px",maxHeight:"150px",objectFit:"cover"}} loading="lazy"/><button onClick={()=>setCoverUrl(null)} style={{position:"absolute",top:"4px",right:"4px",width:"24px",height:"24px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.5)",color:"#fff",cursor:"pointer",fontSize:"12px"}}>✕</button></div>:<div onClick={()=>coverRef.current?.click()} style={{border:`2px dashed ${C.borderLight}`,borderRadius:"8px",padding:"20px",textAlign:"center",cursor:"pointer"}}><div style={{fontSize:"24px",marginBottom:"4px"}}>🖼️</div><div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>Definir imagem destacada</div></div>}
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
  const [hasMorePosts,setHasMorePosts]=useState(true);
  const [loadingMore,setLoadingMore]=useState(false);
  const BLOG_PAGE=12;
  const loadBlogPage=async(offset=0,append=false)=>{
    if(append)setLoadingMore(true);else setLoading(true);
    try{
      const rows=await sb.from("blog_posts").select("*,profiles(username,avatar,avatar_url)",
        `&status=eq.published&order=published_at.desc&limit=${BLOG_PAGE+1}&offset=${offset}`);
      const hasMore=(rows||[]).length>BLOG_PAGE;
      const page=(rows||[]).slice(0,BLOG_PAGE).map(p=>({...p,authorName:p.profiles?.username,authorAvatar:p.profiles?.avatar,authorAvatarImg:p.profiles?.avatar_url}));
      if(append)setPosts(prev=>[...prev,...page]);else setPosts(page);
      setHasMorePosts(hasMore);
    }catch{}
    if(append)setLoadingMore(false);else setLoading(false);
  };
  useEffect(()=>{loadBlogPage();},[]);

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
              <img src={previewImg} alt="" style={{width:"100%",height:"200px",objectFit:"cover"}} loading="lazy"/>
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
                <div style={{width:"24px",height:"24px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",overflow:"hidden",border:`1px solid ${C.border}`}}>{p.authorAvatarImg?<img src={p.authorAvatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:p.authorAvatar||"🌱"}</div>
                <span style={{fontFamily:F.sans,fontSize:"12px",color:C.muted}}>{p.authorName}</span>
              </div>
            </div>
          </div>
          );
        })}
      </div>}
      {hasMorePosts&&!loading&&(
        <div style={{textAlign:"center",marginTop:24,paddingBottom:8}}>
          <button onClick={()=>loadBlogPage(posts.length,true)} disabled={loadingMore}
            style={{padding:"10px 32px",borderRadius:24,border:`1px solid ${C.border}`,background:C.cardBg,color:C.text,cursor:"pointer",fontFamily:F.sans,fontSize:"14px",fontWeight:"600"}}>
            {loadingMore?"Carregando...":"Carregar mais posts"}
          </button>
        </div>
      )}
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
        <div style={{width:"36px",height:"36px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"20px",overflow:"hidden",border:`1px solid ${C.border}`}}>{post.authorAvatarImg?<img src={post.authorAvatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:post.authorAvatar||"🌱"}</div>
        <div><div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"600"}}>{post.authorName}</div></div>
      </div>
      <div ref={contentRef} style={{fontFamily:F.body,fontSize:"16px",color:C.text,lineHeight:"1.8"}} dangerouslySetInnerHTML={{__html:`<p style='margin:0 0 14px;line-height:1.8'>${renderMarkdown(post.content)}</p>`}}/>
    </div>
  );
}

// ─── Cultivadores (Growers) Page ───
function GrowersPage({user,onBack,onViewProfile,follows,onFollow,onUnfollow,onReport}){
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
              {g.avatar_url?<img src={g.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:g.avatar||"🌱"}
            </div>
            <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"4px"}}>{g.username}</div>
            <div style={{fontFamily:F.sans,fontSize:"11px",color:g.level?.color||C.accent,fontWeight:"600",marginBottom:"6px"}}>{g.level?.emoji} {g.level?.name}</div>
            <div style={{display:"flex",justifyContent:"center",gap:"12px",fontFamily:F.sans,fontSize:"11px",color:C.dim}}>
              <span>📔 {g.diaryCount}</span>
              <span>❤️ {g.totalLikes}</span>
            </div>
            {g.city&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginTop:"4px"}}>📍 {g.city}</div>}
            <div style={{display:"flex",gap:"6px",marginTop:"8px",alignItems:"center",justifyContent:"center"}}>
              {user&&g.id!==user.id&&<button onClick={e=>{e.stopPropagation();follows?.includes(g.id)?onUnfollow?.(g.id):onFollow?.(g.id);}} style={{padding:"5px 14px",borderRadius:"20px",border:follows?.includes(g.id)?`1px solid ${C.border}`:`1px solid ${C.accent}`,background:follows?.includes(g.id)?C.surface2:C.accent,color:follows?.includes(g.id)?C.muted:C.onAccent,cursor:"pointer",fontSize:"11px",fontFamily:F.sans,fontWeight:"600"}}>{follows?.includes(g.id)?"Seguindo":"+ Seguir"}</button>}
              {user&&g.id!==user.id&&<button onClick={e=>{e.stopPropagation();onReport?.(g.id,g.username);}} title="Denunciar" style={{padding:"5px 10px",borderRadius:"20px",border:`1px solid ${C.border}`,background:C.surface2,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>🚩</button>}
            </div>
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
function ForumPage({user,onBack,onReport,pendingThreadId,onThreadOpened}){
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
  const [threadLikes,setThreadLikes]=useState({});
  const [threadFavs,setThreadFavs]=useState({});
  useEffect(()=>{
    if(!user)return;
    (async()=>{
      try{
        const [lk,fv]=await Promise.all([
          sb.from("forum_thread_likes").select("thread_id",`&user_id=eq.${user.id}`),
          sb.from("forum_thread_favorites").select("thread_id",`&user_id=eq.${user.id}`),
        ]);
        const lkMap={};(lk||[]).forEach(r=>{lkMap[r.thread_id]=true;});
        const fvMap={};(fv||[]).forEach(r=>{fvMap[r.thread_id]=true;});
        setThreadLikes(lkMap);setThreadFavs(fvMap);
      }catch{}
    })();
  },[user?.id]);
  const toggleThreadLike=async(threadId,authorId)=>{
    if(!user)return;
    const liked=threadLikes[threadId];
    if(liked){
      try{await sb.from("forum_thread_likes").delete(`thread_id=eq.${threadId}&user_id=eq.${user.id}`);}catch{}
      setThreadLikes(p=>{const n={...p};delete n[threadId];return n;});
      setSelThread(p=>p&&p.id===threadId?{...p,likes_count:Math.max((p.likes_count||0)-1,0)}:p);
    }else{
      try{
        await sb.from("forum_thread_likes").insert({thread_id:threadId,user_id:user.id});
        if(authorId&&authorId!==user.id){
          await insertNotifications({user_id:authorId,type:"forum_like",from_username:user.username,from_avatar:user.avatar,text:"curtiu seu tópico",thread_id:threadId});
        }
      }catch{}
      setThreadLikes(p=>({...p,[threadId]:true}));
      setSelThread(p=>p&&p.id===threadId?{...p,likes_count:(p.likes_count||0)+1}:p);
    }
  };
  const toggleThreadFav=async(threadId)=>{
    if(!user)return;
    const faved=threadFavs[threadId];
    if(faved){
      try{await sb.from("forum_thread_favorites").delete(`thread_id=eq.${threadId}&user_id=eq.${user.id}`);}catch{}
      setThreadFavs(p=>{const n={...p};delete n[threadId];return n;});
    }else{
      try{await sb.from("forum_thread_favorites").insert({thread_id:threadId,user_id:user.id});}catch{}
      setThreadFavs(p=>({...p,[threadId]:true}));
    }
  };
  const [newTitle,setNewTitle]=useState("");
  const [newContent,setNewContent]=useState("");
  const [replyText,setReplyText]=useState("");
  const replyTextRef=useRef(null);
  const newContentRef=useRef(null);
  const [showNewThread,setShowNewThread]=useState(false);
  const [posting,setPosting]=useState(false);
  // Edit state for threads and replies
  const [editingThread,setEditingThread]=useState(null); // {id, content}
  const [editingReply,setEditingReply]=useState(null); // {id, content}
  // Attached media tracking: { newContent: [{id, url, type, name, uploading}], replyText: [...] }
  const [attachedMedia,setAttachedMedia]=useState({newContent:[],replyText:[]});

  useEffect(()=>{(async()=>{
    try{
      const cats=await sb.from("forum_categories").select("*",`&order=sort_order.asc`);
      const tops=await sb.from("forum_topics").select("*",`&order=sort_order.asc`);
      let lt=[];try{lt=await sb.from("forum_threads").select("id,title,topic_id,created_at,profiles(username)",`&order=created_at.desc&limit=20`);}catch{}
      setCategories(cats||[]);setTopics(tops||[]);setLatestThreads(lt||[]);
    }catch(e){console.error("Forum load:",e);}
    setLoading(false);
  })();},[]);

  const THREADS_PAGE=30;
  const [threadsHasMore,setThreadsHasMore]=useState(false);
  const [threadsOffset,setThreadsOffset]=useState(0);
  const loadThreads=async(tid,offset=0,append=false)=>{try{
    const r=await sb.from("forum_threads").select("*,profiles(username,avatar,avatar_url)",
      `&topic_id=eq.${tid}&order=pinned.desc,updated_at.desc&limit=${THREADS_PAGE+1}&offset=${offset}`);
    const hasMore=(r||[]).length>THREADS_PAGE;
    const page=(r||[]).slice(0,THREADS_PAGE);
    if(append)setThreads(prev=>[...prev,...page]);else setThreads(page||[]);
    setThreadsHasMore(hasMore);setThreadsOffset(offset);
  }catch{setThreads([]);setThreadsHasMore(false);}};
  const loadReplies=async(tid)=>{try{const r=await sb.from("forum_replies").select("*,profiles(username,avatar,avatar_url)",`&thread_id=eq.${tid}&order=created_at.asc&limit=200`);setReplies(r||[]);}catch{setReplies([]);}};

  // Open a thread directly when navigated from notification
  useEffect(()=>{
    if(!pendingThreadId)return;
    (async()=>{
      try{
        const rows=await sb.from("forum_threads").select("*,profiles(username,avatar,avatar_url)",`&id=eq.${pendingThreadId}&limit=1`);
        const t=rows?.[0];
        if(t){
          setSelThread(t);
          setView("thread");
          await loadReplies(t.id);
        }
      }catch(e){console.error("Open pending thread failed:",e);}
      onThreadOpened?.();
    })();
  },[pendingThreadId]);

  const catTopics=(catId)=>(topics||[]).filter(t=>t.category_id===catId);
  const fmtDate=(d)=>{try{return new Date(d).toLocaleDateString("pt-BR",{day:"numeric",month:"short"});}catch{return"";}};
  const getLatestForCat=(catId)=>{const tids=catTopics(catId).map(t=>t.id);return(latestThreads||[]).find(t=>tids.includes(t.topic_id));};

  const safeUrl=(u)=>{
    if(!u)return"#";
    const trimmed=u.trim().toLowerCase();
    if(trimmed.startsWith("javascript:")||trimmed.startsWith("data:")||trimmed.startsWith("vbscript:")||trimmed.startsWith("file:"))return"#";
    if(trimmed.startsWith("http://")||trimmed.startsWith("https://")||trimmed.startsWith("/"))return u.replace(/"/g,"&quot;");
    return"#";
  };
  const renderContent=(text)=>{
    if(!text)return{__html:""};
    try{
      // Step 1: Escape ALL HTML entities first (no raw HTML allowed from user input)
      let h=text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
      // Step 2: Apply markdown patterns with URL validation
      h=h
        .replace(/\[youtube:([a-zA-Z0-9_-]{11})\]/g,(_,id)=>`<div style="position:relative;padding-bottom:56.25%;height:0;margin:12px 0;border-radius:10px;overflow:hidden"><iframe src="https://www.youtube.com/embed/${id}?cc_load_policy=1&cc_lang_pref=pt&hl=pt&rel=0" style="position:absolute;top:0;left:0;width:100%;height:100%;border:none" allowfullscreen></iframe></div>`)
        .replace(/\[video:([^\]]+)\]/g,(_,url)=>`<div style="margin:12px 0;border-radius:10px;overflow:hidden"><video src="${safeUrl(url)}" controls playsinline style="width:100%;max-height:400px;border-radius:10px;background:#000"></video></div>`)
        .replace(/\[V&iacute;deo\]\(([^)]+)\)|\[Vídeo\]\(([^)]+)\)/g,(_,a,b)=>`<div style="margin:12px 0;border-radius:10px;overflow:hidden"><video src="${safeUrl(a||b)}" controls playsinline style="width:100%;max-height:400px;border-radius:10px;background:#000"></video></div>`)
        .replace(/!\[([^\]]*)\]\(([^)]+)\)/g,(_,alt,url)=>`<img src="${safeUrl(url)}" alt="${alt}" style="max-width:100%;border-radius:10px;margin:8px 0" loading="lazy"/>`)
        .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>")
        .replace(/\*(.+?)\*/g,"<em>$1</em>")
        .replace(/^&gt; (.+)$/gm,'<blockquote style="border-left:3px solid #1B9E42;padding:6px 14px;color:#888;margin:8px 0;background:rgba(27,158,66,0.04);border-radius:0 8px 8px 0">$1</blockquote>')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g,(_,label,url)=>`<a href="${safeUrl(url)}" target="_blank" rel="noopener noreferrer nofollow" style="color:#1B9E42">${label}</a>`)
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

  const handleMediaUpload=async(e,setter,fieldKey)=>{
    const f=e.target?.files?.[0];if(!f)return;
    const isVideo=f.type.startsWith("video");
    const localUrl=URL.createObjectURL(f);
    const tempId=Date.now()+Math.random();
    // Show thumbnail immediately with local URL
    setAttachedMedia(p=>({...p,[fieldKey]:[...(p[fieldKey]||[]),{id:tempId,url:localUrl,type:isVideo?"video":"photo",name:f.name,uploading:true}]}));
    setUploadingMedia(true);
    try{
      const path="forum/"+Date.now()+"-"+Math.random().toString(36).slice(2,5)+"."+(f.name.split(".").pop()||"jpg");
      const ok=await sbStorage.upload(path,f);
      if(ok){
        const url=sbStorage.getUrl(path);
        // Insert markdown into text
        setter(p=>p+(isVideo?"\n[video:"+url+"]\n":"\n![foto]("+url+")\n"));
        // Replace local URL with remote URL in thumbnails
        setAttachedMedia(p=>({...p,[fieldKey]:p[fieldKey].map(m=>m.id===tempId?{...m,url,uploading:false,markdown:isVideo?"[video:"+url+"]":"![foto]("+url+")"}:m)}));
        URL.revokeObjectURL(localUrl);
      }else{
        // Upload failed: remove the thumbnail
        setAttachedMedia(p=>({...p,[fieldKey]:p[fieldKey].filter(m=>m.id!==tempId)}));
        URL.revokeObjectURL(localUrl);
      }
    }catch(er){
      console.error(er);
      setAttachedMedia(p=>({...p,[fieldKey]:p[fieldKey].filter(m=>m.id!==tempId)}));
      URL.revokeObjectURL(localUrl);
    }
    setUploadingMedia(false);
    if(e.target)e.target.value="";
  };

  const removeAttachedMedia=(fieldKey,id,setter)=>{
    setAttachedMedia(p=>{
      const item=(p[fieldKey]||[]).find(m=>m.id===id);
      if(item?.markdown){
        // Remove the markdown from the textarea text
        setter(t=>t.replace("\n"+item.markdown+"\n","").replace(item.markdown,""));
      }
      return{...p,[fieldKey]:p[fieldKey].filter(m=>m.id!==id)};
    });
  };

  const renderMediaThumbs=(fieldKey,setter)=>{
    const items=attachedMedia[fieldKey]||[];
    if(items.length===0)return null;
    return(
      <div style={{display:"flex",gap:"8px",flexWrap:"wrap",marginBottom:"8px",padding:"8px",background:C.surface2,borderRadius:"8px",border:`1px solid ${C.border}`}}>
        {items.map(m=>(
          <div key={m.id} style={{position:"relative",width:"72px",height:"72px",borderRadius:"8px",overflow:"hidden",background:C.cardBg,border:`1px solid ${m.uploading?C.accent:C.border}`,flexShrink:0}}>
            {m.type==="photo"?(
              <img src={m.url} alt={m.name} style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>
            ):(
              <div style={{width:"100%",height:"100%",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",background:"#000",color:"#fff"}}>
                <span style={{fontSize:"24px"}}>🎬</span>
                <span style={{fontSize:"8px",fontFamily:F.sans,padding:"0 2px",textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"100%"}}>vídeo</span>
              </div>
            )}
            {m.uploading&&<div style={{position:"absolute",inset:0,background:"rgba(27,158,66,0.2)",display:"flex",alignItems:"center",justifyContent:"center"}}><div style={{width:"18px",height:"18px",border:"2px solid #1B9E42",borderTop:"2px solid transparent",borderRadius:"50%",animation:"uploadSpin 0.7s linear infinite"}}/></div>}
            {!m.uploading&&<button type="button" onClick={()=>removeAttachedMedia(fieldKey,m.id,setter)} title="Remover" style={{position:"absolute",top:"2px",right:"2px",width:"20px",height:"20px",borderRadius:"50%",border:"none",background:"rgba(0,0,0,0.6)",color:"#fff",cursor:"pointer",fontSize:"11px",display:"flex",alignItems:"center",justifyContent:"center",lineHeight:"1",padding:0}}>✕</button>}
          </div>
        ))}
      </div>
    );
  };

  const tbBtnSt={width:"32px",height:"32px",borderRadius:"6px",border:"1px solid "+C.border,background:C.cardBg,color:C.text,cursor:"pointer",fontSize:"13px",display:"flex",alignItems:"center",justifyContent:"center"};
  const renderToolbar=(setter,fieldKey)=>(
    <div style={{display:"flex",gap:"4px",flexWrap:"wrap",marginBottom:"8px",padding:"6px 8px",background:C.surface2,borderRadius:"8px",alignItems:"center"}}>
      <button type="button" onClick={()=>insertTag(setter,"b")} style={{...tbBtnSt,fontWeight:"800"}}>B</button>
      <button type="button" onClick={()=>insertTag(setter,"i")} style={tbBtnSt}>I</button>
      <button type="button" onClick={()=>insertTag(setter,"q")} style={tbBtnSt}>❝</button>
      <button type="button" onClick={()=>insertTag(setter,"link")} style={tbBtnSt}>🔗</button>
      <div style={{width:"1px",height:"24px",background:C.border,margin:"4px 2px"}}/>
      <label style={{...tbBtnSt,border:"1px solid "+C.accent,background:C.accentBg,color:C.accent,opacity:uploadingMedia?0.5:1,pointerEvents:uploadingMedia?"none":"auto"}}>📷<input type="file" accept="image/*,video/*" style={{display:"none"}} onChange={e=>handleMediaUpload(e,setter,fieldKey)} disabled={uploadingMedia}/></label>
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
      setAttachedMedia(p=>({...p,newContent:[]}));
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const postReply=async()=>{
    if(!replyText.trim()||!user||!selThread)return;
    setPosting(true);
    const content=replyText.substring(0,5000);
    try{
      await sb.from("forum_replies").insert({thread_id:selThread.id,author_id:user.id,content});
      // ─── Notify thread participants (author + previous repliers) ───
      try{
        const participantIds=new Set();
        if(selThread.author_id&&selThread.author_id!==user.id)participantIds.add(selThread.author_id);
        (replies||[]).forEach(r=>{if(r.author_id&&r.author_id!==user.id)participantIds.add(r.author_id);});
        // Exclude users mentioned explicitly (they get mention notif instead)
        const mentions=[...content.matchAll(/@(\w+)/g)].map(m=>m[1]);
        const threadTitle=selThread.title||"tópico";
        if(participantIds.size>0){
          const notifs=[...participantIds].map(uid=>({
            user_id:uid,
            type:"forum_reply",
            from_username:user.username,
            from_avatar:user.avatar,
            text:uid===selThread.author_id?`respondeu seu tópico "${threadTitle}"`:`respondeu em "${threadTitle}"`,
            thread_id:selThread.id,
          }));
          await insertNotifications(notifs);
        }
        // ─── Mentions ───
        if(mentions.length>0){
          const mentioned=await sb.from("profiles").select("id,username",`&username=in.(${mentions.join(",")})`);
          const mentionNotifs=(mentioned||[])
            .filter(p=>p.id!==user.id)
            .map(p=>({
              user_id:p.id,
              type:"forum_mention",
              from_username:user.username,
              from_avatar:user.avatar,
              text:`mencionou você em "${threadTitle}"`,
              thread_id:selThread.id,
            }));
          if(mentionNotifs.length>0)await insertNotifications(mentionNotifs);
        }
      }catch(e){reportError(e,{feature:"forum",op:"notify_reply"});}
      await loadReplies(selThread.id);
      setReplyText("");
      setAttachedMedia(p=>({...p,replyText:[]}));
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const saveThreadEdit=async()=>{
    if(!editingThread||!editingThread.content.trim())return;
    setPosting(true);
    try{
      const now=new Date().toISOString();
      await sb.from("forum_threads").update({content:editingThread.content.substring(0,5000),updated_at:now},`id=eq.${editingThread.id}`);
      // Update selThread in place so UI reflects immediately
      setSelThread(p=>p?{...p,content:editingThread.content,updated_at:now}:p);
      setEditingThread(null);
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const saveReplyEdit=async()=>{
    if(!editingReply||!editingReply.content.trim())return;
    setPosting(true);
    try{
      const now=new Date().toISOString();
      await sb.from("forum_replies").update({content:editingReply.content.substring(0,5000),updated_at:now},`id=eq.${editingReply.id}`);
      await loadReplies(selThread.id);
      setEditingReply(null);
    }catch(e){console.error(e);}
    setPosting(false);
  };

  const fmtDateTime=(d)=>{try{return new Date(d).toLocaleString("pt-BR",{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit"});}catch{return"";}};

  const av=(p)=><div style={{width:"32px",height:"32px",borderRadius:"50%",background:C.surface2,overflow:"hidden",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"16px",border:"1px solid "+C.border,flexShrink:0}}>{p?.avatar_url?<img src={p.avatar_url} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:(p?.avatar||"🌱")}</div>;

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
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:"10px",marginBottom:"12px",flexWrap:"wrap"}}>
          <div style={{display:"flex",alignItems:"center",gap:"10px"}}>
            {av(selThread.profiles)}
            <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{selThread.profiles?.username||"Anônimo"}</span>
            <span style={{fontFamily:F.sans,fontSize:"12px",color:C.dim}}>{fmtDate(selThread.created_at)}</span>
            {selThread.updated_at&&new Date(selThread.updated_at).getTime()-new Date(selThread.created_at).getTime()>2000&&<span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,fontStyle:"italic"}} title={fmtDateTime(selThread.updated_at)}>· editado em {fmtDateTime(selThread.updated_at)}</span>}
          </div>
          <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
            {user&&<button type="button" onClick={()=>toggleThreadLike(selThread.id,selThread.author_id)} title={threadLikes[selThread.id]?"Descurtir":"Curtir"} style={{padding:"6px 12px",borderRadius:"8px",border:`1px solid ${threadLikes[selThread.id]?"#ef4444":C.border}`,background:threadLikes[selThread.id]?"#fef2f2":C.surface2,color:threadLikes[selThread.id]?"#ef4444":C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,fontWeight:"600",display:"flex",alignItems:"center",gap:"4px"}}>{threadLikes[selThread.id]?"❤️":"🤍"} {selThread.likes_count||0}</button>}
            {user&&<button type="button" onClick={()=>toggleThreadFav(selThread.id)} title={threadFavs[selThread.id]?"Desfavoritar":"Favoritar"} style={{padding:"6px 12px",borderRadius:"8px",border:`1px solid ${threadFavs[selThread.id]?"#f59e0b":C.border}`,background:threadFavs[selThread.id]?"#fffbeb":C.surface2,color:threadFavs[selThread.id]?"#f59e0b":C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"4px"}}>{threadFavs[selThread.id]?"⭐":"☆"}</button>}
            {user&&selThread.author_id===user.id&&!editingThread&&<button type="button" onClick={()=>setEditingThread({id:selThread.id,content:selThread.content||""})} style={{padding:"6px 12px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans,display:"flex",alignItems:"center",gap:"4px"}}>✏️ Editar</button>}
            {user&&selThread.author_id!==user.id&&<button type="button" onClick={()=>onReport?.("thread",selThread.id,selThread.title)} title="Denunciar" style={{padding:"6px 12px",borderRadius:"8px",border:`1px solid ${C.border}`,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"12px",fontFamily:F.sans}}>🚩</button>}
          </div>
        </div>
        {editingThread&&editingThread.id===selThread.id?(
          <div>
            <textarea style={{...baseInput,minHeight:"140px",resize:"vertical",width:"100%",marginBottom:"10px"}} value={editingThread.content} onChange={e=>setEditingThread(p=>({...p,content:e.target.value}))}/>
            <div style={{display:"flex",gap:"8px"}}>
              <button type="button" onClick={()=>setEditingThread(null)} style={{...btnSecondary,width:"auto",padding:"8px 16px"}}>Cancelar</button>
              <button type="button" onClick={saveThreadEdit} disabled={posting||!editingThread.content.trim()} style={{...btnPrimary,width:"auto",padding:"8px 20px",opacity:(posting||!editingThread.content.trim())?0.5:1}}>{posting?"Salvando...":"Salvar"}</button>
            </div>
          </div>
        ):(
          <div style={{fontFamily:F.body,fontSize:"15px",color:C.text,lineHeight:"1.7"}} dangerouslySetInnerHTML={renderContent(selThread.content)}/>
        )}
      </div>

      <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",marginBottom:"12px"}}>💬 Respostas ({(replies||[]).length})</h3>
      {(replies||[]).map(r=>(
        <div key={r.id} style={{background:C.cardBg,borderRadius:"12px",border:"1px solid "+C.border,padding:"14px 18px",marginBottom:"8px"}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:"8px",flexWrap:"wrap",gap:"6px"}}>
            <div style={{display:"flex",alignItems:"center",gap:"8px",flexWrap:"wrap"}}>
              {av(r.profiles)}
              <span style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600"}}>{r.profiles?.username||"Anônimo"}</span>
              <span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim}}>{fmtDate(r.created_at)}</span>
              {r.updated_at&&<span style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,fontStyle:"italic"}} title={fmtDateTime(r.updated_at)}>· editado em {fmtDateTime(r.updated_at)}</span>}
            </div>
            <div style={{display:"flex",gap:"6px"}}>
              {user&&r.author_id===user.id&&!editingReply&&<button type="button" onClick={()=>setEditingReply({id:r.id,content:r.content||""})} style={{padding:"4px 10px",borderRadius:"6px",border:"1px solid "+C.border,background:C.surface2,color:C.muted,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>✏️ Editar</button>}
              <button type="button" onClick={()=>{const q=(r.content||"").substring(0,200).split("\n").map(l=>"> "+l).join("\n");setReplyText(p=>p+(p?"\n\n":"")+"> **@"+(r.profiles?.username||"")+" disse:**\n"+q+"\n\n");}} style={{padding:"4px 10px",borderRadius:"6px",border:"1px solid "+C.border,background:C.surface2,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>❝ Citar</button>
              {user&&r.author_id!==user.id&&<button type="button" onClick={()=>onReport?.("reply",r.id,`Resposta de ${r.profiles?.username||"usuário"}`)} title="Denunciar" style={{padding:"4px 10px",borderRadius:"6px",border:"1px solid "+C.border,background:C.surface2,color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>🚩</button>}
            </div>
          </div>
          {editingReply&&editingReply.id===r.id?(
            <div>
              <textarea style={{...baseInput,minHeight:"100px",resize:"vertical",width:"100%",marginBottom:"10px"}} value={editingReply.content} onChange={e=>setEditingReply(p=>({...p,content:e.target.value}))}/>
              <div style={{display:"flex",gap:"8px"}}>
                <button type="button" onClick={()=>setEditingReply(null)} style={{...btnSecondary,width:"auto",padding:"8px 16px"}}>Cancelar</button>
                <button type="button" onClick={saveReplyEdit} disabled={posting||!editingReply.content.trim()} style={{...btnPrimary,width:"auto",padding:"8px 20px",opacity:(posting||!editingReply.content.trim())?0.5:1}}>{posting?"Salvando...":"Salvar"}</button>
              </div>
            </div>
          ):(
            <div style={{fontFamily:F.body,fontSize:"14px",color:C.text,lineHeight:"1.6"}} dangerouslySetInnerHTML={renderContent(r.content)}/>
          )}
        </div>
      ))}

      <div style={{marginTop:"16px",background:C.cardBg,borderRadius:"12px",border:"1px solid "+C.border,padding:"16px"}}>
        <label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",marginBottom:"8px",display:"block"}}>Sua resposta</label>
        {renderToolbar(setReplyText,"replyText")}
        {renderMediaThumbs("replyText",setReplyText)}
        <div style={{position:"relative",marginBottom:"10px"}}>
          <textarea ref={replyTextRef} style={{...baseInput,minHeight:"100px",resize:"vertical",width:"100%"}} value={replyText} onChange={e=>setReplyText(e.target.value)} placeholder="Escreva sua resposta... **negrito** *itálico* > citação @username"/>
          <MentionAutocomplete text={replyText} setText={setReplyText} inputRef={replyTextRef}/>
        </div>
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
            {renderToolbar(setNewContent,"newContent")}
            {renderMediaThumbs("newContent",setNewContent)}
            <div style={{position:"relative"}}>
              <textarea ref={newContentRef} style={{...baseInput,minHeight:"160px",resize:"vertical",width:"100%"}} value={newContent} onChange={e=>setNewContent(e.target.value)} placeholder="Escreva sua mensagem... @username"/>
              <MentionAutocomplete text={newContent} setText={setNewContent} inputRef={newContentRef}/>
            </div>
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

function VideoViewer({ src, onClose }) {
  if(!src) return null;
  return (
    <div onClick={onClose} style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.92)",zIndex:400,display:"flex",alignItems:"center",justifyContent:"center",cursor:"zoom-out",padding:"20px"}}>
      <button onClick={onClose} style={{position:"absolute",top:"20px",right:"20px",width:"40px",height:"40px",borderRadius:"50%",border:"none",background:"rgba(255,255,255,0.15)",color:"#fff",cursor:"pointer",fontSize:"20px",display:"flex",alignItems:"center",justifyContent:"center",backdropFilter:"blur(8px)",zIndex:401}}>✕</button>
      <video src={src} controls autoPlay playsInline style={{maxWidth:"100%",maxHeight:"90vh",borderRadius:"8px",background:"#000",boxShadow:"0 8px 40px rgba(0,0,0,0.5)"}} onClick={e=>e.stopPropagation()}/>
    </div>
  );
}

// ─── Nav Bar ───
function NavBar({ user, page, setPage, setShowCreate, myDiaries, onLogout, onNavigate, lang, setLang, unreadNotifs, unreadMsgs, notifs, onMarkNotifsRead, dark, onToggleDark, onBackToPortal }) {
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
    {icon:"🌱",label:t.community,action:()=>nav("comunidade"),active:page==="comunidade"},
    {icon:"🏆",label:t.growers,action:()=>nav("cultivadores"),active:page==="cultivadores"},
    {icon:"🥇",label:t.contests,action:()=>nav("concursos"),active:page==="concursos"},
    {icon:"🐛",label:t.pests,action:()=>nav("pragas"),active:page==="pragas"},
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
            <img src={LOGO_SRC} alt="Diário da Planta" className="dp-logo" style={{height:"36px",objectFit:"contain"}}/>
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
                <div key={n.id} onClick={async()=>{
                  // Mark this notification as read
                  if(!n.read){
                    try{await sb.from("notifications").update({read:true},`id=eq.${n.id}`);}catch{}
                    setNotifs(p=>p.map(x=>x.id===n.id?{...x,read:true}:x));
                  }
                  setShowNotifs(false);
                  // Navigate based on type
                  if(n.threadId){
                    setPendingThreadId(n.threadId);
                    setPage("comunidade");
                  }
                }} style={{padding:"12px 16px",display:"flex",gap:"10px",alignItems:"flex-start",borderBottom:`1px solid ${C.border}`,background:n.read?"transparent":"rgba(27,158,66,0.03)",cursor:n.threadId?"pointer":"default"}} onMouseOver={e=>{if(n.threadId)e.currentTarget.style.background=C.surface2;}} onMouseOut={e=>{e.currentTarget.style.background=n.read?"transparent":"rgba(27,158,66,0.03)";}}>
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
            <button onClick={()=>{setShowMenu(!showMenu);setShowLangSub(false);}} style={{width:"36px",height:"36px",borderRadius:"50%",border:`2px solid ${showMenu?C.accent:C.border}`,background:showMenu?C.accentBg:C.surface2,fontSize:"18px",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",transition:"all 0.2s",overflow:"hidden",padding:0}}>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:user.avatar}</button>

            {showMenu&&<div style={{position:"absolute",top:"46px",right:0,background:C.cardBg,borderRadius:"14px",border:`1px solid ${C.border}`,padding:"8px",minWidth:"240px",boxShadow:"0 8px 30px rgba(0,0,0,0.12)",zIndex:110}}>
              {/* Profile header */}
              <div style={{padding:"12px 16px",display:"flex",alignItems:"center",gap:"12px",borderBottom:`1px solid ${C.border}`,marginBottom:"6px",paddingBottom:"14px"}}>
                <div style={{width:"44px",height:"44px",borderRadius:"50%",background:C.surface2,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"24px",border:`2px solid ${C.border}`,overflow:"hidden"}}>{user.avatarImg?<img src={user.avatarImg} alt="" style={{width:"100%",height:"100%",objectFit:"cover"}} loading="lazy"/>:user.avatar}</div>
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
                {menuItem("📰","Voltar ao Portal",()=>{if(onBackToPortal){onBackToPortal();}else{nav("home");}})}
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
// ─── Recovery Form (declared outside AppInner to avoid remounts) ───
// ─── Reusable Report Modal ───
function ReportModal({ open, targetType, targetLabel, onClose, onSubmit }) {
  const [reason,setReason]=useState("");
  const [submitting,setSubmitting]=useState(false);
  useEffect(()=>{if(!open){setReason("");setSubmitting(false);}},[open]);
  if(!open)return null;
  const typeLabels={user:"usuário",diary:"diário",thread:"tópico",reply:"resposta",comment:"comentário"};
  const typeLabel=typeLabels[targetType]||"item";
  const handle=async()=>{
    if(!reason.trim()||submitting)return;
    setSubmitting(true);
    try{await onSubmit?.(reason.trim());}finally{setSubmitting(false);onClose?.();}
  };
  return(
    <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.4)",backdropFilter:"blur(8px)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:"20px"}} onClick={onClose}>
      <div onClick={e=>e.stopPropagation()} style={{background:C.surface,borderRadius:"16px",border:`1px solid ${C.border}`,padding:"24px",width:"100%",maxWidth:"480px"}}>
        <h3 style={{fontFamily:F.sans,fontSize:"18px",fontWeight:"800",margin:"0 0 8px",display:"flex",alignItems:"center",gap:"8px"}}>🚩 Denunciar {typeLabel}</h3>
        {targetLabel&&<div style={{fontFamily:F.sans,fontSize:"13px",color:C.dim,marginBottom:"16px"}}>{targetLabel}</div>}
        <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,marginBottom:"12px",lineHeight:"1.5"}}>
          Descreva o motivo da denúncia. Nossa equipe vai revisar e tomar as medidas necessárias. Denúncias falsas podem resultar em advertência.
        </p>
        <textarea
          style={{...baseInput,minHeight:"100px",resize:"vertical",marginBottom:"16px"}}
          value={reason}
          onChange={e=>setReason(e.target.value.substring(0,500))}
          placeholder="Motivo (ex: conteúdo ofensivo, spam, assédio...)"
          autoFocus
        />
        <div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,marginBottom:"16px",textAlign:"right"}}>{reason.length}/500</div>
        <div style={{display:"flex",gap:"12px",justifyContent:"flex-end"}}>
          <button onClick={onClose} style={{...btnSecondary,width:"auto",padding:"10px 20px"}} disabled={submitting}>Cancelar</button>
          <button onClick={handle} style={{...btnPrimary,width:"auto",padding:"10px 20px",background:"#d97706",opacity:(!reason.trim()||submitting)?0.5:1}} disabled={!reason.trim()||submitting}>
            {submitting?"Enviando...":"Enviar Denúncia"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RecoveryForm({ dark, onDone }) {
  const [pw,setPw]=useState("");
  const [pw2,setPw2]=useState("");
  const [msg,setMsg]=useState("");
  const [ld,setLd]=useState(false);
  const [done,setDone]=useState(false);
  const doReset=async()=>{
    if(pw.length<8){setMsg("Senha deve ter no mínimo 8 caracteres.");return;}
    if(pw!==pw2){setMsg("As senhas não coincidem.");return;}
    setLd(true);setMsg("");
    try{
      const { error: pwError } = await supabase.auth.updateUser({ password: pw });
      if(!pwError){setDone(true);setMsg("Senha alterada com sucesso!");}
      else{
        const msg = pwError.message || "";
        // Friendly error mapping
        if(msg.includes("same_password")||/different from the old/i.test(msg)){
          setMsg("A nova senha precisa ser diferente da anterior.");
        }else if(msg.includes("weak_password")||/weak/i.test(msg)){
          setMsg("Senha muito fraca. Use letras, números e símbolos.");
        }else if(pwError.status===401||pwError.status===403){
          setMsg("O link expirou. Solicite um novo email de recuperação.");
        }else{
          setMsg(msg||"Erro ao alterar senha. Tente novamente.");
        }
      }
    }catch{setMsg("Erro de conexão.");}
    setLd(false);
  };
  if(done) return(
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"100vh",background:C.bg}}>
      <ThemeCSS dark={dark}/>
      <div style={{textAlign:"center",maxWidth:"400px",padding:"40px"}}>
        <div style={{fontSize:"48px",marginBottom:"16px"}}>✅</div>
        <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",marginBottom:"12px",color:C.text}}>Senha Alterada!</h2>
        <p style={{fontFamily:F.sans,fontSize:"14px",color:C.muted,marginBottom:"24px"}}>Sua senha foi redefinida com sucesso.</p>
        <button onClick={()=>{onDone?.();setTimeout(()=>window.location.reload(),100);}} style={{...btnPrimary,width:"auto",padding:"12px 32px"}}>Fazer Login</button>
      </div>
    </div>
  );
  return(
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"100vh",background:C.bg}}>
      <ThemeCSS dark={dark}/>
      <div style={{maxWidth:"400px",width:"100%",padding:"40px"}}>
        <div style={{textAlign:"center",marginBottom:"32px"}}>
          <div style={{fontSize:"48px",marginBottom:"12px"}}>🔑</div>
          <h2 style={{fontFamily:F.sans,fontSize:"22px",fontWeight:"700",color:C.text}}>Nova Senha</h2>
          <p style={{fontFamily:F.sans,fontSize:"13px",color:C.muted,marginTop:"4px"}}>Escolha uma nova senha para sua conta</p>
        </div>
        {msg&&<div style={{padding:"12px",borderRadius:"10px",background:"#fee2e2",color:"#991b1b",fontFamily:F.sans,fontSize:"13px",marginBottom:"16px",textAlign:"center"}}>{msg}</div>}
        <div style={{marginBottom:"14px"}}>
          <label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.text,marginBottom:"6px",display:"block"}}>Nova Senha</label>
          <input type="password" style={baseInput} value={pw} onChange={e=>setPw(e.target.value)} placeholder="Mínimo 8 caracteres" autoFocus/>
        </div>
        <div style={{marginBottom:"24px"}}>
          <label style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",color:C.text,marginBottom:"6px",display:"block"}}>Confirmar Senha</label>
          <input type="password" style={baseInput} value={pw2} onChange={e=>setPw2(e.target.value)} placeholder="Repita a nova senha" onKeyDown={e=>e.key==="Enter"&&doReset()}/>
        </div>
        <button onClick={doReset} disabled={ld} style={{...btnPrimary,opacity:ld?0.6:1}}>{ld?"Salvando...":"Redefinir Senha"}</button>
      </div>
    </div>
  );
}

function AppInner() {
  const [user,setUser]=useState(null); const [authLoading,setAuthLoading]=useState(true);
  const [page,setPage]=useState("home"); const [filter,setFilter]=useState("_ALL_");
  const [phaseFilter,setPhaseFilter]=useState("_ALL_"); const [showCreate,setShowCreate]=useState(false);
  const [myDiaries,setMyDiaries]=useState([]); const [selectedDiary,setSelectedDiary]=useState(null); const [pendingDiaryId,setPendingDiaryId]=useState(null);
  const [publicDiaries,setPublicDiaries]=useState([]);
  const [pendingThreadId,setPendingThreadId]=useState(null);
  const [favoriteThreads,setFavoriteThreads]=useState([]);
  useEffect(()=>{
    if(!user)return;
    (async()=>{
      try{
        const favs=await sb.from("forum_thread_favorites").select("thread_id",`&user_id=eq.${user.id}`);
        const ids=(favs||[]).map(f=>f.thread_id);
        if(ids.length===0){setFavoriteThreads([]);return;}
        const threads=await sb.from("forum_threads").select("id,title,content,created_at,likes_count,reply_count,profiles(username,avatar,avatar_url)",`&id=in.(${ids.join(",")})&order=created_at.desc`);
        setFavoriteThreads(threads||[]);
      }catch(e){console.error("Load fav threads:",e);}
    })();
  },[user?.id,page]);
  // Global report modal state — triggered from any page
  const [reportModal,setReportModal]=useState(null); // {targetType, targetId, targetLabel}
  const openReport=(targetType,targetId,targetLabel)=>setReportModal({targetType,targetId,targetLabel});
  const [dataLoaded,setDataLoaded]=useState(false);
  const [lang,setLang]=useState("pt");
  const [viewImage,setViewImage]=useState(null);
  const [viewVideo,setViewVideo]=useState(null);
  const [dark,setDark]=useState(()=>{try{return localStorage.getItem("dp-dark")==="1";}catch{return false;}});
  const [searchQ,setSearchQ]=useState("");
  const [debouncedSearch,setDebouncedSearch]=useState("");
  useEffect(()=>{const t=setTimeout(()=>setDebouncedSearch(searchQ),300);return()=>clearTimeout(t);},[searchQ]);
  const [showGlobalSearch,setShowGlobalSearch]=useState(false);
  const [globalResults,setGlobalResults]=useState([]);
  useEffect(()=>{
    if(!debouncedSearch||debouncedSearch.length<2){setGlobalResults([]);return;}
    let cancelled=false;
    (async()=>{
      try{
        const res=await (async()=>{const d=await sb.rpc("global_search",{q:debouncedSearch,lim:5});return {ok:d!==null,json:async()=>d};})();
        if(!res.ok)return;
        const data=await res.json();
        if(!cancelled)setGlobalResults(data||[]);
      }catch{}
    })();
    return()=>{cancelled=true;};
  },[debouncedSearch]);
  const handleGlobalSearchClick=(r)=>{
    setShowGlobalSearch(false);setSearchQ("");
    if(r.result_type==="diary"){
      const d=[...myDiaries,...publicDiaries].find(x=>x.id===r.id);
      if(d){setSelectedDiary(d);}
      else{
        // Diary not in local cache — fetch it directly
        (async()=>{try{
          const rows=await sb.from("diaries").select("*,profiles(username,avatar,avatar_url)",`&id=eq.${r.id}&hidden=eq.false&limit=1`);
          const dd=rows?.[0];
          if(dd)setSelectedDiary({id:dd.id,name:dd.name,strain:dd.strain,strains:dd.strains||[],author:dd.profiles?.username||"",authorId:dd.user_id,avatar:dd.profiles?.avatar||"🌱",avatarImg:dd.profiles?.avatar_url||null,phase:dd.phase,week:dd.current_week,env:dd.environment,light:dd.lighting,watts:dd.watts,substrate:dd.substrate,watering:dd.watering,germination:dd.germination,techniques:dd.techniques||[],numPlants:dd.num_plants,tags:dd.tags||[],likes:dd.likes_count,comments:dd.comments_count,cover:0,coverImage:dd.cover_url,hidden:false,isOwn:dd.user_id===user?.id,weeks:[]});
        }catch{}})();
      }
    }
    else if(r.result_type==="user")openPublicProfile(r.id);
    else if(r.result_type==="thread")setPage("comunidade");
  };
  const [sortBy,setSortBy]=useState("recent"); // recent | likes | comments
  const [publicProfile,setPublicProfile]=useState(null); // {user, diaries}
  const [cookieConsent,setCookieConsent]=useState(()=>{try{return localStorage.getItem("dp-cookies");}catch{return null;}});
  const [blogPost,setBlogPost]=useState(null); // viewing a post
  const [blogEditor,setBlogEditor]=useState(null); // editing/creating a post (null or post object)
  const [recoveryMode,setRecoveryMode]=useState(false); // password recovery
  const [showAuth,setShowAuth]=useState(false); // toggle: news portal (false) vs login screen (true)
  const loggingOutRef=useRef(false); // distingue logout intencional de expiração de sessão
  const [inApp,setInApp]=useState(false); // logado pode estar no portal (false) ou dentro do app (true); todo load começa no portal
  const [follows,setFollows]=useState([]); // IDs of users the current user follows
  const [allBadges,setAllBadges]=useState([]);
  const [myBadges,setMyBadges]=useState([]);
  useEffect(()=>{(async()=>{try{const b=await sb.from("badges").select("*");setAllBadges(b||[]);}catch{}})();},[]);
  useEffect(()=>{if(!user)return;(async()=>{try{const b=await sb.from("user_badges").select("*",`&user_id=eq.${user.id}`);setMyBadges(b||[]);}catch{}})();},[user]);

  const toggleDark=()=>{const next=!dark;setDark(next);try{localStorage.setItem("dp-dark",next?"1":"0");}catch{};};
  const acceptCookies=()=>{setCookieConsent("accepted");try{localStorage.setItem("dp-cookies","accepted");}catch{}};
  const rejectCookies=()=>{setCookieConsent("rejected");try{localStorage.setItem("dp-cookies","rejected");}catch{}};

  // ─── Notifications: Supabase Realtime ───
  const lastNotifRef=useRef(0);
  useEffect(()=>{
    if(!user)return;
    if("Notification" in window && Notification.permission==="default"){
      Notification.requestPermission();
    }
    const mapNotif=(x)=>({id:x.id,type:x.type,from:x.from_username,avatar:x.from_avatar,text:x.text,diary:x.diary_name,threadId:x.thread_id,time:new Date(x.created_at).getTime(),read:x.read});
    // Initial load
    const loadNotifs=async()=>{
      try{
        const n=await sb.from("notifications").select("*",`&user_id=eq.${user.id}&order=created_at.desc&limit=50`);
        const mapped=n.map(mapNotif);
        if(mapped.length>0)lastNotifRef.current=Math.max(...mapped.map(x=>x.time));
        setNotifs(mapped);
      }catch{}
    };
    loadNotifs();
    // Realtime: INSERT on notifications table filtered to this user
    const channel=supabase.channel(`notifs:${user.id}`)
      .on("postgres_changes",{event:"INSERT",schema:"public",table:"notifications",filter:`user_id=eq.${user.id}`},(payload)=>{
        const nn=mapNotif(payload.new);
        setNotifs(prev=>{
          if(prev.find(x=>x.id===nn.id))return prev;
          return [nn,...prev].slice(0,50);
        });
        if("Notification" in window&&Notification.permission==="granted"&&lastNotifRef.current>0){
          try{new Notification("Diário da Planta 🌱",{body:`${nn.from||""} ${nn.text||""}`,icon:"/icon-192.png",tag:nn.id});}catch{}
        }
        lastNotifRef.current=Math.max(lastNotifRef.current,nn.time);
      })
      .on("postgres_changes",{event:"UPDATE",schema:"public",table:"notifications",filter:`user_id=eq.${user.id}`},(payload)=>{
        const updated=mapNotif(payload.new);
        setNotifs(prev=>prev.map(x=>x.id===updated.id?updated:x));
      })
      .subscribe();
    return()=>{supabase.removeChannel(channel);};
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
        const msgRows=await sb.from("messages").select("id,text,media_url,media_type,forwarded,created_at,sender_id,is_system,report_number,profiles(username)",`&conversation_id=eq.${c.id}&order=created_at.asc`);
        // Assinar anexos privados (caminhos do bucket media-private) em lote; URLs antigas passam direto
        const signedMedia=await sbPrivate.signBatch(msgRows.map(m=>m.media_url));
        const other=members.find(m=>m.user_id!==user.id);
        convList.push({
          id:c.id,
          with:c.is_group?c.group_name:(other?.profiles?.username||"Usuário"),
          avatar:c.is_group?"👥":(other?.profiles?.avatar||"🌱"),
          isGroup:c.is_group,
          members:c.is_group?members.map(m=>m.profiles?.username).filter(Boolean):[],
          readAt:cr.read_at?new Date(cr.read_at).getTime():null,
          messages:msgRows.map(m=>({id:m.id,from:m.sender_id===user.id?user.email:(m.profiles?.username||m.sender_id),text:m.text||"",media:m.media_url?{type:m.media_type||"image",data:(signedMedia[m.media_url]||m.media_url),path:m.media_url}:null,time:new Date(m.created_at).getTime(),forwarded:m.forwarded,isSystem:!!m.is_system,reportNumber:m.report_number||null})),
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
    // Inherit report_number from the most recent message in the convo that carries one
    // (first the original system warning, then any replies referencing it)
    const conv=msgs.find(c=>c.id===convId);
    const lastRef=conv?.messages?.filter(m=>m.reportNumber).slice(-1)[0]?.reportNumber||null;
    try{
      const payload={conversation_id:convId,sender_id:user.id,text:clean};
      if(lastRef)payload.report_number=lastRef;
      await sb.from("messages").insert(payload);
      setMsgs(p=>p.map(c=>c.id===convId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:clean,time:Date.now(),reportNumber:lastRef}],readAt:Date.now()}:c));
      await sb.from("conversation_members").update({read_at:new Date().toISOString()},`conversation_id=eq.${convId}&user_id=eq.${user.id}`);
    }catch{}
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
  const deleteMessage=async(convId,msgId)=>{
    if(!user)return;
    try{await sb.from("messages").delete(`id=eq.${msgId}&sender_id=eq.${user.id}`);}catch(e){reportError(e,{feature:"messages",op:"delete_message"});}
    setMsgs(p=>p.map(c=>c.id===convId?{...c,messages:c.messages.filter(m=>m.id!==msgId)}:c));
  };
  const forwardMsg=async(targetConvId,text,media)=>{
    if(!user)return;
    const clean=sanitize(text||"",2000);
    if(!clean&&!media){return;}
    try{
      const payload={conversation_id:targetConvId,sender_id:user.id,text:clean,forwarded:true};
      if(media?.data){
        payload.media_url=media.path||media.data; // guarda o caminho (não a URL assinada que expira)
        payload.media_type=media.type||"image";
      }
      await sb.from("messages").insert(payload);
    }catch(e){reportError(e,{feature:"messages",op:"forward"});}
    setMsgs(p=>p.map(c=>c.id===targetConvId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:clean,media:media||null,time:Date.now(),forwarded:true}],readAt:Date.now()}:c));
  };
  const createGroup=async(name,members)=>{
    if(!user)return;
    const cleanName=sanitize(name,50);
    if(!cleanName)return;
    try{
      // Atomic server-side creation to avoid RLS issues with multi-row INSERT
      const convId=await sb.rpc("create_group_conversation",{
        p_group_name:cleanName,
        p_member_usernames:members,
      });
      if(!convId)return;
      setMsgs(p=>[{id:convId,with:cleanName,avatar:"👥",isGroup:true,members,messages:[{id:"m"+Date.now(),from:user.email,text:"Grupo criado! 🌱",time:Date.now()}],readAt:Date.now()},...p]);
    }catch(e){
      reportError(e,{feature:"messages",op:"createGroup"});
      alert("Erro ao criar grupo: "+(e.message||"desconhecido"));
    }
  };
  const newDM=async(username,firstMsg,media)=>{
    if(!user)return;
    const cleanMsg=sanitize(firstMsg||"",2000);
    if(!cleanMsg&&!media){alert("Mensagem vazia.");return;}
    const cleanUser=sanitize(username,30).trim();
    if(!cleanUser){alert("Username inválido.");return;}
    // Check existing conversation by username (fast path)
    const ex=msgs.find(c=>!c.isGroup&&c.with===cleanUser);
    if(ex){
      if(cleanMsg)await sendMsg(ex.id,cleanMsg);
      if(media)await sendMedia(ex.id,media);
      return;
    }
    try{
      // Resolve target profile
      const targets=await sb.from("profiles").select("id,username,avatar,avatar_url",`&username=ilike.${cleanUser}&limit=1`);
      const target=targets?.[0];
      if(!target){alert(`Usuário "${cleanUser}" não encontrado.`);return;}
      if(target.id===user.id){alert("Você não pode enviar mensagem para si mesmo.");return;}
      
      // Upload media first if provided (before the RPC, so we can pass the path)
      let mediaUrl=null,mediaType=null,mediaLocal=null;
      if(media&&media.data&&media.data.startsWith("data:")){
        const ext=media.type==="video"?"mp4":"jpg";
        const path=`${user.id}/msg-${Date.now()}.${ext}`;
        const ok=await sbPrivate.uploadBase64(path,media.data,media.type==="video"?"video/mp4":"image/jpeg");
        if(ok){mediaUrl=path;mediaType=media.type;mediaLocal=media.data;}
      }
      
      // Atomic server-side creation: conversation + members + first message(s)
      // Avoids RLS issues with INSERT multi-row on conversation_members.
      const convId=await sb.rpc("create_dm_conversation",{
        p_target_id:target.id,
        p_first_message:cleanMsg||null,
        p_media_url:mediaUrl,
        p_media_type:mediaType,
      });
      if(!convId){alert("Erro ao criar conversa. Tente novamente.");return;}
      
      // Optimistic add to state
      const optimisticMsgs=[];
      if(cleanMsg)optimisticMsgs.push({id:"m"+Date.now(),from:user.email,text:cleanMsg,time:Date.now()});
      if(mediaUrl)optimisticMsgs.push({id:"m"+(Date.now()+1),from:user.email,text:"",media:{type:mediaType,data:mediaLocal||mediaUrl,path:mediaUrl},time:Date.now()+1});
      setMsgs(p=>[{
        id:convId,
        with:target.username,
        avatar:target.avatar||"🌱",
        avatarImg:target.avatar_url||null,
        isGroup:false,
        members:[],
        messages:optimisticMsgs,
        readAt:Date.now(),
      },...p]);
    }catch(e){
      reportError(e,{feature:"messages",op:"newDM"});
      alert("Erro ao enviar mensagem: "+(e.message||"desconhecido"));
    }
  };
  const sendMedia=async(convId,media)=>{
    if(!user)return;
    // Upload para o bucket privado (anexos de DM)
    let mediaPath=null;const mediaLocal=media.data;
    if(media.data&&media.data.startsWith("data:")){
      const ext=media.type==="video"?"mp4":"jpg";
      const path=`${user.id}/msg-${Date.now()}.${ext}`;
      const ok=await sbPrivate.uploadBase64(path,media.data,media.type==="video"?"video/mp4":"image/jpeg");
      if(ok)mediaPath=path;
    }
    const dbMedia=mediaPath||media.data; // caminho novo, ou valor original (legado)
    let displayData=mediaLocal;
    if(mediaPath){try{const signed=await sbPrivate.signBatch([mediaPath]);if(signed[mediaPath])displayData=signed[mediaPath];}catch{}}
    try{await sb.from("messages").insert({conversation_id:convId,sender_id:user.id,text:"",media_url:dbMedia,media_type:media.type||"image"});}catch{}
    setMsgs(p=>p.map(c=>c.id===convId?{...c,messages:[...c.messages,{id:"m"+Date.now(),from:user.email,text:"",media:{type:media.type,data:displayData,path:dbMedia},time:Date.now()}],readAt:Date.now()}:c));
  };
  const unreadNotifs=notifs.filter(n=>!n.read).length;
  const unreadMsgs=user?msgs.reduce((s,c)=>{const last=c.messages[c.messages.length-1];return s+(last&&last.from!==user.email&&(!c.readAt||last.time>c.readAt)?1:0);},0):0;

  // ─── Session restore (Supabase) ───
  useEffect(()=>{
    // Parse ?diary=<id> from URL at mount, independent of auth flow
    try{
      const qs=new URLSearchParams(window.location.search||"");
      const did=qs.get("diary");
      if(did){
        setPendingDiaryId(did);
        // Clean URL so refresh doesn't retrigger
        const clean=window.location.pathname+window.location.hash;
        window.history.replaceState(null,"",clean);
      }
    }catch{}
  },[]);

  // ─── Session expired listener (refresh token failed) ───
  useEffect(()=>{
    const handler=()=>{
      // Se for um logout intencional, o doLogout já está limpando o estado — não mostrar alerta de expiração
      if(loggingOutRef.current)return;
      console.warn("[auth] Session expired, redirecting to login");
      // Clear all user state
      setUser(null);
      setMyDiaries([]);setPublicDiaries([]);setNotifs([]);setMsgs([]);
      setLikes({});setFavs({});setCommentsMap({});setBlockedUsers([]);
      setFollows([]);setDataLoaded(false);setSelectedDiary(null);
      setPublicProfile(null);setPage("home");
      // Show user-friendly message
      setTimeout(()=>{alert("Sua sessão expirou. Por favor, faça login novamente.");},100);
    };
    window.addEventListener("sb:session-expired",handler);
    return()=>window.removeEventListener("sb:session-expired",handler);
  },[]);

  // ─── Sentry user sync ───
  // Captures only user.id (anonymous UUID). Email, username and other PII
  // are stripped by beforeSend in main.jsx as defense in depth.
  useEffect(()=>{
    try{
      if(user?.id){
        Sentry.setUser({id:user.id});
        Sentry.setTag("user.role",user.role==="admin"?"admin":"user");
      }else{
        Sentry.setUser(null);
      }
    }catch{}
  },[user?.id,user?.role]);

  // ─── Sentry debug helpers (DevTools only) ───
  // Usage in browser console:
  //   __sentryTest()           → sends a captureMessage
  //   __sentryTestError()      → throws a real Error (tests ErrorBoundary)
  //   __sentryTestPromise()    → unhandled promise rejection
  useEffect(()=>{
    try{
      window.__sentryTest=()=>{
        const id=Sentry.captureMessage("[test] manual Sentry check from "+(user?.id||"anon"),{level:"info",tags:{feature:"debug",op:"manual_test"}});
        console.log("[sentry] test message sent, event id:",id);
        return id;
      };
      window.__sentryTestError=()=>{
        throw new Error("[test] manual Sentry error — "+new Date().toISOString());
      };
      window.__sentryTestPromise=()=>{
        Promise.reject(new Error("[test] unhandled promise rejection"));
      };
    }catch{}
  },[user?.id]);

  // Open pending diary once user is logged in and myDiaries has loaded
  useEffect(()=>{
    if(!pendingDiaryId||!user||!dataLoaded)return;
    (async()=>{
      try{
        // First check if it's one of user's own diaries
        const own=myDiaries.find(d=>d.id===pendingDiaryId);
        if(own){setSelectedDiary(own);setPendingDiaryId(null);return;}
        // Otherwise fetch the public diary from Supabase
        const rows=await sb.from("diaries").select("*,profiles(username,avatar,avatar_url)",`&id=eq.${pendingDiaryId}&hidden=eq.false&limit=1`);
        const d=rows?.[0];
        if(d){
          setSelectedDiary({
            id:d.id,name:d.name,strain:d.strain,strains:d.strains||[],
            author:d.profiles?.username,authorId:d.user_id,
            avatar:d.profiles?.avatar,avatarImg:d.profiles?.avatar_url,
            phase:d.phase,week:d.current_week,env:d.environment,light:d.lighting,
            watts:d.watts,substrate:d.substrate,watering:d.watering,
            germination:d.germination,techniques:d.techniques||[],numPlants:d.num_plants,
            tags:d.tags||[],likes:d.likes_count,comments:d.comments_count,
            cover:0,coverImage:d.cover_url,hidden:d.hidden,isOwn:false,weeks:[],
          });
        }else{
          alert("Diário não encontrado ou foi removido.");
        }
      }catch(e){console.error("Failed to open shared diary:",e);}
      setPendingDiaryId(null);
    })();
  },[pendingDiaryId,user,dataLoaded,myDiaries]);

  useEffect(()=>{(async()=>{
    // Check for password recovery token in URL hash OR query string
    const hash=window.location.hash||"";
    const search=window.location.search||"";
    const combined=(hash+"&"+search).replace(/^#|^\?/,"");
    const isRecovery=combined.includes("type=recovery");
    if(isRecovery){
      const params=new URLSearchParams(combined.replace(/^[#?]/,""));
      const accessToken=params.get("access_token");
      const refreshToken=params.get("refresh_token");
      console.log("[recovery] detected recovery link, token present:",!!accessToken);
      if(accessToken){
        // Set session from recovery link tokens
        await supabase.auth.setSession({ access_token: accessToken, refresh_token: refreshToken || "" });
        setRecoveryMode(true);
        // Clean up URL so refresh doesn't re-trigger
        window.history.replaceState(null,"",window.location.pathname);
        setAuthLoading(false);
        return;
      }else{
        console.warn("[recovery] recovery link detected but no access_token found");
      }
    }
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

  // ─── Load public diaries from all users (paginated) ───
  const [publicDiariesCursor,setPublicDiariesCursor]=useState(null);
  const [publicDiariesHasMore,setPublicDiariesHasMore]=useState(true);
  const [publicDiariesLoadingMore,setPublicDiariesLoadingMore]=useState(false);
  const PAGE_SIZE=20;
  const mapDiaryRow=(d,profiles)=>({
    id:d.id,name:d.name,strain:d.strain,strains:d.strains||[],
    author:d.profiles?.username||profiles?.username||"",authorId:d.user_id,
    avatar:d.profiles?.avatar||profiles?.avatar||"🌱",avatarImg:d.profiles?.avatar_url||profiles?.avatar_url||null,
    phase:d.phase,week:d.current_week,env:d.environment,light:d.lighting,watts:d.watts,substrate:d.substrate,
    watering:d.watering,germination:d.germination,techniques:d.techniques||[],numPlants:d.num_plants,tags:d.tags||[],
    likes:d.likes_count,comments:d.comments_count,cover:0,coverImage:d.cover_url,hidden:false,isOwn:false,
    weeks:[],
  });
  const loadPublicDiaries=useCallback(async(cursor=null,append=false)=>{
    if(!user)return;
    if(append)setPublicDiariesLoadingMore(true);
    try{
      const cursorFilter=cursor?`&created_at=lt.${encodeURIComponent(cursor)}`:"";
      const rows=await sb.from("diaries").select("*,profiles(username,avatar,avatar_url)",
        `&hidden=eq.false&user_id=neq.${user.id}&order=created_at.desc&limit=${PAGE_SIZE+1}${cursorFilter}`);
      const hasMore=(rows||[]).length>PAGE_SIZE;
      const page=(rows||[]).slice(0,PAGE_SIZE).map(d=>mapDiaryRow(d));
      if(append){setPublicDiaries(prev=>{const ids=new Set(prev.map(x=>x.id));return[...prev,...page.filter(x=>!ids.has(x.id))];});}
      else{setPublicDiaries(page);}
      setPublicDiariesHasMore(hasMore);
      if(page.length>0)setPublicDiariesCursor(page[page.length-1].id);
    }catch(e){reportError(e,{feature:"diary",op:"load_public"});}
    if(append)setPublicDiariesLoadingMore(false);
  },[user]);
  useEffect(()=>{if(!user)return;loadPublicDiaries();},[user?.id]);
  const loadMorePublicDiaries=()=>{
    if(!publicDiariesHasMore||publicDiariesLoadingMore)return;
    // fetch next page using last item's created_at as cursor
    const lastDiary=publicDiaries[publicDiaries.length-1];
    if(!lastDiary)return;
    // need created_at — re-fetch with offset instead (simpler, works with existing filters)
    if(!user)return;
    setPublicDiariesLoadingMore(true);
    (async()=>{
      try{
        const rows=await sb.from("diaries").select("*,profiles(username,avatar,avatar_url)",
          `&hidden=eq.false&user_id=neq.${user.id}&order=created_at.desc&limit=${PAGE_SIZE+1}&offset=${publicDiaries.length}`);
        const hasMore=(rows||[]).length>PAGE_SIZE;
        const page=(rows||[]).slice(0,PAGE_SIZE).map(d=>mapDiaryRow(d));
        setPublicDiaries(prev=>{const ids=new Set(prev.map(x=>x.id));return[...prev,...page.filter(x=>!ids.has(x.id))];});
        setPublicDiariesHasMore(hasMore);
      }catch(e){reportError(e,{feature:"diary",op:"load_more"});}
      setPublicDiariesLoadingMore(false);
    })();
  };

  const doLogin=u=>{setUser(u);setPage("home");setInApp(true);setShowAuth(false);try{history.replaceState(null,"","/");}catch{}trackEvent("login");};
  const doLogout=()=>{
    try{trackEvent("logout");}catch{}
    loggingOutRef.current=true; // sinaliza logout intencional (evita alerta de sessão expirada)
    // 1) Limpeza local IMEDIATA — a UI responde na hora, independente da rede
    setUser(null);setMyDiaries([]);setPublicDiaries([]);setNotifs([]);setMsgs([]);setLikes({});setFavs({});setCommentsMap({});setBlockedUsers([]);setFollows([]);setDataLoaded(false);setSelectedDiary(null);setPublicProfile(null);setShowAuth(false);setInApp(false);setPage("home");
    // 2) Remove a sessão persistida — garante que um reload não "re-loga" mesmo se o signOut travar
    try{Object.keys(localStorage).filter(k=>k.startsWith("sb-token")).forEach(k=>localStorage.removeItem(k));}catch{}
    // 3) Revogação no servidor em segundo plano, com teto de 4s (signOut do supabase-js pode travar em lock)
    Promise.race([
      supabase.auth.signOut(),
      new Promise(res=>setTimeout(res,4000)),
    ]).catch(e=>{console.warn("[logout] revogação no servidor falhou:",e);}).finally(()=>{setTimeout(()=>{loggingOutRef.current=false;},500);});
  };

  // ─── Load follows ───
  useEffect(()=>{if(!user)return;(async()=>{
    try{const rows=await sb.from("follows").select("following_id",`&follower_id=eq.${user.id}`);setFollows(rows.map(r=>r.following_id));}catch{}
  })();},[user?.id]);
  const doFollow=async(targetId)=>{
    if(!user||targetId===user.id)return;
    if(!actionRateLimit("follow",20,60000)){alert("Você está seguindo pessoas muito rápido. Aguarde um momento.");return;}
    try{await sb.from("follows").insert({follower_id:user.id,following_id:targetId});setFollows(p=>[...p,targetId]);
      await insertNotifications({user_id:targetId,type:"follow",from_username:user.username,from_avatar:user.avatar,text:`${user.username} começou a te seguir`});
      try{await sb.rpc("check_and_grant_badges",{uid:targetId});}catch{}
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
      try{await sb.rpc("check_and_grant_badges",{uid:user.id});}catch{}
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
          }catch(e){reportError(e,{feature:"diary",op:"insert_week"});}
        }
      }
      // Only delete weeks that were explicitly removed by user
      if(updated._deletedWeekIds?.length>0){
        for(const wid of updated._deletedWeekIds){
          await sb.from("weeks").delete(`id=eq.${wid}`);
        }
      }
    }catch(e){reportError(e,{feature:"diary",op:"update"});}
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
    if(!(await serverRateLimit("like",30,60))){alert("Você está curtindo muito rápido. Aguarde um momento.");return;}
    const isLiked=!!likes[id];
    const nxt={...likes};
    if(isLiked){delete nxt[id];try{await sb.from("likes").delete(`user_id=eq.${user.id}&diary_id=eq.${id}`);}catch{}}
    else{nxt[id]=true;try{await sb.from("likes").insert({user_id:user.id,diary_id:id});}catch{}}
    setLikes(nxt);
    const delta=isLiked?-1:1;
    setMyDiaries(p=>p.map(d=>d.id===id?{...d,likes:(d.likes||0)+delta}:d));
    setPublicDiaries(p=>p.map(d=>d.id===id?{...d,likes:(d.likes||0)+delta}:d));
    if(selectedDiary?.id===id)setSelectedDiary(sd=>({...sd,likes:(sd.likes||0)+delta}));
  };
  const doFav=async(id)=>{
    if(!user)return;
    if(!actionRateLimit("fav",30,60000))return;
    const nxt={...favs};
    if(nxt[id]){delete nxt[id];try{await sb.from("favorites").delete(`user_id=eq.${user.id}&diary_id=eq.${id}`);}catch{}}
    else{nxt[id]=true;try{await sb.from("favorites").insert({user_id:user.id,diary_id:id});}catch{}}
    setFavs(nxt);
  };

  // ─── Reports (Supabase) ───
  // Generic report handler: works for diary, user, thread, reply, comment
  const doReportGeneric=async({targetType,targetId,reason,targetName})=>{
    if(!user)return null;
    if(!(await serverRateLimit("report",5,300))){alert("Você já fez muitas denúncias recentemente. Aguarde alguns minutos.");return null;}
    const cleanReason=sanitize(reason,500);
    if(!cleanReason)return null;
    try{
      const payload={reporter_id:user.id,target_type:targetType,reason:cleanReason};
      if(targetType==="diary")payload.target_diary_id=targetId;
      else if(targetType==="user")payload.target_user_id=targetId;
      else if(targetType==="thread")payload.target_thread_id=targetId;
      else if(targetType==="reply")payload.target_reply_id=targetId;
      // comment type reuses target_user_id slot (commenter) — schema doesn't have comment fk
      else if(targetType==="comment")payload.target_user_id=targetId;
      const row=await sb.from("reports").insert(payload);
      const num=row?.report_number;
      alert(num?`Denúncia #${num} registrada. Nossa equipe vai revisar.`:"Denúncia registrada. Nossa equipe vai revisar.");
      return num||null;
    }catch(e){reportError(e,{feature:"report",op:"create"});alert("Erro ao registrar denúncia. Tente novamente.");return null;}
  };
  // Back-compat wrappers for existing props
  const doReport=async(diary,reason)=>doReportGeneric({targetType:"diary",targetId:diary.id,reason,targetName:diary.name});
  const doReportUser=async(targetUserId,reason,targetName)=>doReportGeneric({targetType:"user",targetId:targetUserId,reason,targetName});
  const handleReportSubmit=async(reason)=>{
    if(!reportModal)return;
    await doReportGeneric({targetType:reportModal.targetType,targetId:reportModal.targetId,reason,targetName:reportModal.targetLabel});
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
    if(!(await serverRateLimit("comment",10,60))){alert("Você está comentando muito rápido. Aguarde um momento.");return;}
    const clean=sanitize(text);
    try{
      const data={diary_id:diaryId,user_id:user.id,text:clean};
      if(parentId)data.parent_id=parentId;
      await sb.from("comments").insert(data);
      await loadComments(diaryId);
      const diary=selectedDiary||myDiaries.find(d=>d.id===diaryId);
      if(diary?.authorId&&diary.authorId!==user.id){
        await insertNotifications({user_id:diary.authorId,type:"comment",from_username:user.username,from_avatar:user.avatar,text:parentId?"respondeu um comentário":"comentou no seu diário",diary_name:diary.name});
      }
      // Notify mentioned users (@username)
      const mentions=[...clean.matchAll(/@(\w+)/g)].map(m=>m[1]);
      if(mentions.length>0){
        try{
          const mentioned=await sb.from("profiles").select("id,username",`&username=in.(${mentions.join(",")})`);
          for(const u of(mentioned||[])){
            if(u.id!==user.id) await insertNotifications({user_id:u.id,type:"comment",from_username:user.username,from_avatar:user.avatar,text:`mencionou você: ${clean.substring(0,80)}`,diary_name:diary?.name||""});
          }
        }catch{}
      }
      try{await sb.rpc("check_and_grant_badges",{uid:user.id});}catch{}
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
  const doReportUserOld_removed=()=>null;
  // Like with notification
  const doLikeWithNotif=async(id)=>{
    const wasLiked=!!likes[id];
    await doLike(id);
    if(!wasLiked){
      const diary=[...myDiaries,...publicDiaries].find(d=>d.id===id);
      if(diary?.authorId&&diary.authorId!==user?.id){
        try{await insertNotifications({user_id:diary.authorId,type:"like",from_username:user.username,from_avatar:user.avatar,text:"curtiu seu diário",diary_name:diary.name});}catch{}
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
      <img src={LOGO_SRC} alt="Diário da Planta" className="dp-logo" style={{height:"56px",objectFit:"contain",animation:"pulse 2s infinite"}}/>
      <style>{`@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.1)}}`}</style>
    </div>
  );

  if(recoveryMode){
    return <RecoveryForm dark={dark} onDone={()=>{setRecoveryMode(false);setUser(null);}}/>;
  }

  if(!user) {
    if(showAuth) return <><ThemeCSS dark={dark}/><AuthScreen onLogin={doLogin} onBackToPortal={()=>setShowAuth(false)}/></>;
    return <><ThemeCSS dark={dark}/><NewsPortal onEnterApp={()=>setShowAuth(true)} onOpenDiary={(id)=>{if(id)setPendingDiaryId(id);setShowAuth(true);}} dark={dark} onToggleDark={toggleDark}/></>;
  }

  // Logado, mas ainda no portal: todo carregamento da página começa aqui.
  // O app só abre com ação explícita ("Ir para o app").
  if(!inApp) return <><ThemeCSS dark={dark}/><NewsPortal loggedUser={user} onLogout={doLogout} onEnterApp={()=>{setInApp(true);try{history.replaceState(null,"","/");}catch{}}} onOpenDiary={(id)=>{if(id){setPendingDiaryId(id);}setInApp(true);try{history.replaceState(null,"","/");}catch{}}} dark={dark} onToggleDark={toggleDark}/></>;

  const shellStyle={minHeight:"100vh",background:C.bg,color:C.text,fontFamily:F.body,position:"relative",overflow:"hidden"};

  const renderPage=()=>{
    if(publicProfile) return <PublicProfile targetUser={publicProfile.user} diaries={publicProfile.diaries} onBack={()=>setPublicProfile(null)} onViewDiary={d=>{setPublicProfile(null);setSelectedDiary(d);}} lang={lang} allBadges={allBadges} onReport={(uid,name)=>openReport("user",uid,name)} currentUserId={user?.id}/>;
    if(page==="privacidade") return <PrivacyPolicyPage onBack={()=>setPage("home")}/>;
    if(page==="termos") return <TermsPage onBack={()=>setPage("home")}/>;
    if(blogPost) return <BlogPostView post={blogPost} onBack={()=>setBlogPost(null)} user={user} onEdit={p=>{setBlogPost(null);setBlogEditor(p);}} onViewImage={setViewImage}/>;
    // Blog do app aposentado (reativável no futuro): sem ponto de entrada na navegação.
    // Componentes BlogPage/BlogEditor e a tabela blog_posts ficam preservados.
    if(page==="cultivadores") return <GrowersPage user={user} onBack={()=>setPage("home")} follows={follows} onFollow={doFollow} onUnfollow={doUnfollow} onReport={(uid,name)=>openReport("user",uid,name)} onViewProfile={async(g)=>{try{const diaries=await sb.from("diaries").select("*",`&user_id=eq.${g.id}&hidden=eq.false&order=created_at.desc`);setPublicProfile({user:{...g,username:g.username,avatar:g.avatar,avatarImg:g.avatar_url,bio:g.bio,city:g.city,createdAt:g.created_at},diaries:diaries.map(d=>({...d,author:g.username,avatar:g.avatar,avatarImg:g.avatar_url}))});}catch{}}}/>;
    if(page==="concursos") return <ContestsPage onBack={()=>setPage("home")}/>;
    if(page==="comunidade") return <ForumPage user={user} onBack={()=>setPage("home")} onReport={openReport} pendingThreadId={pendingThreadId} onThreadOpened={()=>setPendingThreadId(null)}/>;
    if(page==="pragas") return <PestsPage onBack={()=>setPage("home")} onViewImage={setViewImage}/>;
    if(page==="perfil") return <ProfilePage user={user} diaries={myDiaries} onUpdateUser={doUpdateUser} onLogout={doLogout} onBack={()=>setPage("home")} blockedUsers={blockedUsers} onUnblockUser={doUnblockUser} onDeleteAccount={doDeleteAccount} onNavigate={doNavigate} allBadges={allBadges} myBadges={myBadges}/>;
    if(page==="mensagens") return <MessagesPage msgs={msgs} user={user} onSend={sendMsg} onSendMedia={sendMedia} onMarkRead={markMsgRead} onMarkUnread={markMsgUnread} onDeleteConv={deleteConv} onDeleteMessage={deleteMessage} onForwardMsg={forwardMsg} onCreateGroup={createGroup} onNewDM={newDM} onViewImage={setViewImage} onViewVideo={setViewVideo} onBack={()=>setPage("home")} lang={lang}/>;
    if(page==="admin"&&user.role==="admin") return <AdminPanel user={user} onBack={()=>setPage("home")} onNewPost={()=>setBlogEditor({})}/>;
    if(selectedDiary){
      const diaryComments=(commentsMap[selectedDiary.id]||[]).sort((a,b)=>b.time-a.time);
      const isOwnerViewing=selectedDiary.isOwn;
      return <DiaryDetail diary={selectedDiary} onBack={()=>setSelectedDiary(null)} onUpdate={doUpdateDiary} onRemove={doRemoveDiary} onHide={doHideDiary} lang={lang} onLike={doLikeWithNotif} onFav={doFav} isLiked={!!likes[selectedDiary.id]} isFaved={!!favs[selectedDiary.id]} onViewImage={setViewImage} onViewVideo={setViewVideo} onReport={doReport} comments={diaryComments} onAddComment={doAddComment} onDeleteComment={doDeleteComment} onEditComment={doEditComment} blockedByOwner={!isOwnerViewing&&blockedUsers.includes(user.id)} onBlockUser={doBlockUser} onUnblockUser={doUnblockUser} onReportUser={doReportUser} currentUserEmail={user.id} onAuthorClick={openPublicProfile}/>;
    }
    return null;
  };

  const pageContent=renderPage();
  if(pageContent) return (
    <div style={shellStyle}>
      <ThemeCSS dark={dark}/>
      <div style={{position:"relative",zIndex:1}}>
        <NavBar user={user} page={page} setPage={setPage} setShowCreate={setShowCreate} myDiaries={myDiaries} onLogout={doLogout} onNavigate={doNavigate} lang={lang} setLang={setLang} unreadNotifs={unreadNotifs} unreadMsgs={unreadMsgs} notifs={notifs} onMarkNotifsRead={markNotifsRead} dark={dark} onToggleDark={toggleDark} onBackToPortal={()=>setInApp(false)}/>
        {pageContent}
        <div style={{textAlign:"center",padding:"40px 24px",borderTop:`1px solid ${C.border}`,fontSize:"13px",color:C.dim,fontFamily:F.sans}}>
          <div>Diário da Planta © 2026 — {t.footer}</div>
          <div style={{display:"flex",gap:"16px",justifyContent:"center",marginTop:"8px"}}><button onClick={()=>doNavigate("privacidade")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Privacidade</button><button onClick={()=>doNavigate("termos")} style={{background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:"11px",fontFamily:F.sans}}>Termos</button></div>
        </div>
      </div>
      <ImageViewer src={viewImage} onClose={()=>setViewImage(null)}/><VideoViewer src={viewVideo} onClose={()=>setViewVideo(null)}/><ReportModal open={!!reportModal} targetType={reportModal?.targetType} targetLabel={reportModal?.targetLabel} onClose={()=>setReportModal(null)} onSubmit={handleReportSubmit}/>
      {blogEditor&&<BlogEditor post={blogEditor.id?blogEditor:null} user={user} onClose={()=>setBlogEditor(null)} onSave={()=>{setBlogEditor(null);if(page==="blog")setPage("_");setTimeout(()=>setPage("blog"),50);}}/>}
      {!cookieConsent&&<CookieBanner onAccept={acceptCookies} onReject={rejectCookies}/>}
    </div>
  );

  const allPool=[...myDiaries.filter(d=>!d.hidden),...publicDiaries];
  const allDiaries=page==="meus"?myDiaries:page==="favoritos"?allPool.filter(d=>favs[d.id]):page==="gostei"?allPool.filter(d=>likes[d.id]):page==="feed"?allPool.filter(d=>follows.includes(d.authorId)||favs[d.id]||likes[d.id]):allPool;
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
        <NavBar user={user} page={page} setPage={setPage} setShowCreate={setShowCreate} myDiaries={myDiaries} onLogout={doLogout} onNavigate={doNavigate} lang={lang} setLang={setLang} unreadNotifs={unreadNotifs} unreadMsgs={unreadMsgs} notifs={notifs} onMarkNotifsRead={markNotifsRead} dark={dark} onToggleDark={toggleDark} onBackToPortal={()=>setInApp(false)}/>
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
            {[[publicDiaries.length+myDiaries.length,t.diaries],[new Set([...publicDiaries,...myDiaries].map(d=>d.author)).size,t.growers],[new Set([...publicDiaries,...myDiaries].map(d=>d.strain)).size,t.varieties]].map(([v,l])=>(
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
            <input style={{...baseInput,paddingLeft:"36px",borderRadius:"24px",padding:"10px 16px 10px 36px"}} value={searchQ} onChange={e=>setSearchQ(e.target.value)} placeholder="Buscar diários, cultivadores, tópicos..." onFocus={()=>setShowGlobalSearch(true)} onBlur={()=>setTimeout(()=>setShowGlobalSearch(false),200)}/>
            <span style={{position:"absolute",left:"12px",top:"50%",transform:"translateY(-50%)",fontSize:"14px",color:C.dim}}>🔍</span>
            {showGlobalSearch&&debouncedSearch&&debouncedSearch.length>=2&&globalResults.length>0&&<div style={{position:"absolute",top:"100%",left:0,right:0,marginTop:"6px",background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"12px",boxShadow:"0 8px 24px rgba(0,0,0,0.12)",overflow:"hidden",zIndex:60,maxHeight:"400px",overflowY:"auto"}}>
              {globalResults.map((r,i)=>(
                <div key={r.result_type+r.id} onClick={()=>handleGlobalSearchClick(r)} style={{display:"flex",alignItems:"center",gap:"10px",padding:"10px 14px",cursor:"pointer",borderBottom:i<globalResults.length-1?`1px solid ${C.border}`:"none"}} onMouseOver={e=>e.currentTarget.style.background=C.surface2} onMouseOut={e=>e.currentTarget.style.background="transparent"}>
                  <div style={{width:"32px",height:"32px",borderRadius:"50%",background:C.accentBg,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"14px",flexShrink:0}}>{r.result_type==="diary"?"🌱":r.result_type==="user"?"👤":r.result_type==="thread"?"💬":"📰"}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontFamily:F.sans,fontSize:"13px",fontWeight:"600",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.title}</div>
                    {r.subtitle&&<div style={{fontFamily:F.sans,fontSize:"11px",color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.subtitle}</div>}
                  </div>
                  <span style={{fontFamily:F.sans,fontSize:"10px",color:C.dim,padding:"2px 8px",borderRadius:"6px",background:C.surface2,textTransform:"uppercase"}}>{r.result_type==="diary"?"diário":r.result_type==="user"?"perfil":r.result_type==="thread"?"fórum":"blog"}</span>
                </div>
              ))}
            </div>}
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
          <>
          {page==="favoritos"&&favoriteThreads.length>0&&<div style={{marginBottom:"32px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",margin:"0 0 12px",display:"flex",alignItems:"center",gap:"8px"}}>⭐ Tópicos favoritos <span style={{fontSize:"12px",color:C.dim,fontWeight:"500"}}>({favoriteThreads.length})</span></h3>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))",gap:"12px"}}>
              {favoriteThreads.map(t=>(
                <div key={t.id} onClick={()=>{setPendingThreadId(t.id);setPage("comunidade");}} style={{background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"12px",padding:"14px 16px",cursor:"pointer",transition:"all 0.15s"}} onMouseOver={e=>{e.currentTarget.style.borderColor=C.accent;e.currentTarget.style.transform="translateY(-2px)";}} onMouseOut={e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.transform="none";}}>
                  <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"6px",overflow:"hidden",textOverflow:"ellipsis",display:"-webkit-box",WebkitLineClamp:2,WebkitBoxOrient:"vertical"}}>{t.title}</div>
                  <div style={{display:"flex",alignItems:"center",gap:"8px",fontSize:"11px",color:C.dim,fontFamily:F.sans}}>
                    <span>{t.profiles?.username||"Anônimo"}</span>
                    <span>·</span>
                    <span>💬 {t.reply_count||0}</span>
                    {t.likes_count>0&&<><span>·</span><span>❤️ {t.likes_count}</span></>}
                  </div>
                </div>
              ))}
            </div>
          </div>}
          <div className="dp-grid" style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(290px, 1fr))",gap:"16px"}}>
            <VirtualList items={filtered} itemHeight={340} renderItem={d=><DiaryCard key={d.id} diary={d} onClick={()=>setSelectedDiary(d)} onLike={doLikeWithNotif} onFav={doFav} isLiked={!!likes[d.id]} isFaved={!!favs[d.id]} onViewImage={setViewImage} commentCount={(commentsMap[d.id]||[]).length||d.comments||0} onAuthorClick={openPublicProfile}/>}/>
          </div>
          {(page==="explorar"||page==="home")&&publicDiariesHasMore&&(
            <div style={{textAlign:"center",marginTop:24}}>
              <button onClick={loadMorePublicDiaries} disabled={publicDiariesLoadingMore} style={{padding:"10px 32px",borderRadius:24,border:`1px solid ${C.border}`,background:C.cardBg,color:C.text,cursor:"pointer",fontFamily:F.sans,fontSize:"14px",fontWeight:"600"}}>
                {publicDiariesLoadingMore?"Carregando...":"Carregar mais diários"}
              </button>
            </div>
          )}
          </>
        ):page==="favoritos"&&favoriteThreads.length>0?(
          <div style={{marginBottom:"32px"}}>
            <h3 style={{fontFamily:F.sans,fontSize:"16px",fontWeight:"700",margin:"0 0 12px",display:"flex",alignItems:"center",gap:"8px"}}>⭐ Tópicos favoritos <span style={{fontSize:"12px",color:C.dim,fontWeight:"500"}}>({favoriteThreads.length})</span></h3>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))",gap:"12px"}}>
              {favoriteThreads.map(t=>(
                <div key={t.id} onClick={()=>{setPendingThreadId(t.id);setPage("comunidade");}} style={{background:C.cardBg,border:`1px solid ${C.border}`,borderRadius:"12px",padding:"14px 16px",cursor:"pointer",transition:"all 0.15s"}} onMouseOver={e=>{e.currentTarget.style.borderColor=C.accent;}} onMouseOut={e=>{e.currentTarget.style.borderColor=C.border;}}>
                  <div style={{fontFamily:F.sans,fontSize:"14px",fontWeight:"700",marginBottom:"6px"}}>{t.title}</div>
                  <div style={{display:"flex",alignItems:"center",gap:"8px",fontSize:"11px",color:C.dim,fontFamily:F.sans}}>
                    <span>{t.profiles?.username||"Anônimo"}</span>
                    <span>·</span>
                    <span>💬 {t.reply_count||0}</span>
                    {t.likes_count>0&&<><span>·</span><span>❤️ {t.likes_count}</span></>}
                  </div>
                </div>
              ))}
            </div>
            <p style={{fontFamily:F.body,fontSize:"13px",color:C.dim,marginTop:"20px",textAlign:"center"}}>Nenhum diário favoritado ainda.</p>
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
      <ImageViewer src={viewImage} onClose={()=>setViewImage(null)}/><VideoViewer src={viewVideo} onClose={()=>setViewVideo(null)}/><ReportModal open={!!reportModal} targetType={reportModal?.targetType} targetLabel={reportModal?.targetLabel} onClose={()=>setReportModal(null)} onSubmit={handleReportSubmit}/>
      {blogEditor&&<BlogEditor post={blogEditor.id?blogEditor:null} user={user} onClose={()=>setBlogEditor(null)} onSave={()=>{setBlogEditor(null);if(page==="blog")setPage("_");setTimeout(()=>setPage("blog"),50);}}/>}
      {!cookieConsent&&<CookieBanner onAccept={acceptCookies} onReject={rejectCookies}/>}
    </div>
  );
}

export default function App() {
  return <ErrorBoundary><AppInner/></ErrorBoundary>;
}
