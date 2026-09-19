// functions/api/me.js
import { parseCookies } from "../_shared/cookies.js";
import { sha256Base64Url, nowSeconds } from "../_shared/crypto.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  const cookies = parseCookies(request);
  const sessionCookie = cookies["__Host-session"];
  if (!sessionCookie) {
    return Response.json({ error: "not_authenticated" }, { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  const idHash = await sha256Base64Url(sessionCookie);

  const row = await env.DB
    .prepare("SELECT issuer, subject, email, display_name, expires_at FROM sessions WHERE id_hash = ?")
    .bind(idHash)
    .first();

  if (!row || row.expires_at < nowSeconds()) {
    return Response.json({ error: "not_authenticated" }, { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  return Response.json(
    {
      issuer: row.issuer,
      email: row.email,
      displayName: row.display_name,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
