// functions/oauth/logout.js
import { parseCookies, expireCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  // 2. Exigir Origin exatamente igual à PUBLIC_BASE_URL
  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origin inválida", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(request);
  const sessionCookie = cookies["__Host-session"];

  if (sessionCookie) {
    const idHash = await sha256Base64Url(sessionCookie);
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
  }

  const headers = new Headers();
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", expireCookie("__Host-session", { sameSite: "Strict" }));

  return new Response(null, { status: 302, headers });
}

// Qualquer outro método é recusado
export function onRequestGet() {
  return new Response("Method not allowed", { status: 405, headers: { "Cache-Control": "no-store" } });
}
