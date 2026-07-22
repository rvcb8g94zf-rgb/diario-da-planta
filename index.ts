// supabase/functions/gerar-texto/index.ts
// Edge Function do Diário da Planta: geração de texto editorial via Gemini
// para o editor de posts do portal. A chave do Gemini fica só no servidor.
//
// Deploy:
//   supabase functions deploy gerar-texto
// Secrets necessários (você já tem o GEMINI_API_KEY):
//   GEMINI_API_KEY   (obrigatório)
//   GEMINI_MODEL     (opcional; default "gemini-3.5-flash"; barato: "gemini-3.1-flash-lite")
//   SUPABASE_URL e a chave publishable/anon já são injetados pelo runtime.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const GEMINI_API_KEY = Deno.env.get("GEMINI_API_KEY") ?? "";
const GEMINI_MODEL = Deno.env.get("GEMINI_MODEL") ?? "gemini-3.5-flash";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";

// Aceita tanto a nova SUPABASE_PUBLISHABLE_KEYS (JSON) quanto a anon legada.
const SUPABASE_ANON_KEY = (() => {
  const pub = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  if (pub) {
    try {
      const o = JSON.parse(pub);
      return o.default || Object.values(o)[0] || "";
    } catch {
      return pub; // caso seja uma string simples
    }
  }
  return Deno.env.get("SUPABASE_ANON_KEY") ?? "";
})();

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

interface Payload {
  action?: string;
  title?: string;
  category?: string;
  context?: string;
  selection?: string;
  instructions?: string;
}

function buildPrompt(action: string, p: Payload): string {
  const cat = p.category ? `Categoria/editoria: ${p.category}.` : "";
  const extra = p.instructions ? `Instruções específicas do editor: ${p.instructions}.` : "";
  const ctx = p.context
    ? `\n\nTexto já presente no artigo (apenas para contexto, não repita):\n"""\n${String(p.context).slice(0, 4000)}\n"""`
    : "";
  const base = [
    "Você é um assistente editorial do Diário da Planta, um portal jornalístico brasileiro sobre cannabis (notícias, cultivo, ciência e regulação).",
    "Escreva em português do Brasil, com tom jornalístico, claro e informativo, sem sensacionalismo e sem fazer apologia.",
    "Responda em TEXTO PURO, sem markdown, sem títulos e sem listas; separe parágrafos por uma linha em branco.",
    cat,
    extra,
  ].filter(Boolean).join(" ");

  switch (action) {
    case "draft":
      return `${base}\n\nEscreva o corpo de um artigo com 3 a 6 parágrafos para a manchete: "${p.title}".${ctx}`;
    case "continue":
      return `${base}\n\nContinue o artigo abaixo com mais 2 ou 3 parágrafos coerentes, sem repetir o que já foi dito.${ctx}`;
    case "rewrite":
      return `${base}\n\nReescreva o trecho a seguir mantendo o sentido, mas melhorando clareza, fluidez e correção. Devolva apenas o trecho reescrito:\n"""\n${String(p.selection || "").slice(0, 3000)}\n"""`;
    case "excerpt":
      return `${base}\n\nEscreva uma linha-fina (resumo) de 1 a 2 frases, com no máximo ~300 caracteres, para o artigo "${p.title}".${ctx}\nResponda apenas com o resumo, sem aspas.`;
    default:
      return "";
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);
  if (!GEMINI_API_KEY) return json({ error: "GEMINI_API_KEY não configurada no servidor." }, 500);

  // --- Auth: exige usuário autenticado com papel admin ou editor ---
  const authHeader = req.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return json({ error: "Não autenticado." }, 401);

  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: uErr } = await sb.auth.getUser();
    if (uErr || !user) return json({ error: "Sessão inválida." }, 401);

    const { data: prof } = await sb.from("profiles").select("role").eq("id", user.id).single();
    const role = prof?.role || "user";
    if (role !== "admin" && role !== "editor") return json({ error: "Sem permissão." }, 403);
  } catch (_e) {
    return json({ error: "Falha na verificação de sessão." }, 401);
  }

  // --- Corpo da requisição ---
  let body: Payload;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON inválido." }, 400);
  }

  const action = String(body.action || "");
  if (!["draft", "continue", "rewrite", "excerpt"].includes(action)) {
    return json({ error: "Ação inválida." }, 400);
  }
  if ((action === "draft" || action === "excerpt") && !String(body.title || "").trim()) {
    return json({ error: "Título obrigatório para esta ação." }, 400);
  }
  if (action === "rewrite" && !String(body.selection || "").trim()) {
    return json({ error: "Nenhum texto selecionado para reescrever." }, 400);
  }

  const prompt = buildPrompt(action, body);
  const maxOutputTokens = action === "excerpt" ? 256 : 1400;

  // --- Chamada ao Gemini ---
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY,
      },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens },
        safetySettings: [
          { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_ONLY_HIGH" },
          { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_ONLY_HIGH" },
          { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_ONLY_HIGH" },
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_ONLY_HIGH" },
        ],
      }),
    });

    if (!r.ok) {
      const errTxt = await r.text();
      return json({ error: `Erro do Gemini (${r.status}).`, detail: errTxt.slice(0, 300) }, 502);
    }

    const data = await r.json();
    const cand = data?.candidates?.[0];
    const text = ((cand?.content?.parts as Array<{ text?: string }> | undefined) || [])
      .map((x) => x.text || "")
      .join("")
      .trim();

    if (!text) {
      const reason = cand?.finishReason || data?.promptFeedback?.blockReason || "sem_conteudo";
      return json({ error: `A IA não retornou texto (${reason}).` }, 502);
    }

    return json({ text, model: GEMINI_MODEL });
  } catch (e) {
    return json({ error: "Falha ao chamar a IA.", detail: String(e).slice(0, 200) }, 502);
  }
});
