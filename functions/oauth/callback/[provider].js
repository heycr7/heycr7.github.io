// functions/oauth/callback/[provider].js
import { randomToken, sha256Base64Url, nowSeconds } from "../../_shared/crypto.js";
import { parseCookies, serializeCookie, expireCookie } from "../../_shared/cookies.js";
import { PROVIDERS, isValidProvider, redirectUriFor, credentialsFor } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 horas

function badRequest(message) {
  return new Response(message, { status: 400, headers: { "Cache-Control": "no-store" } });
}

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  // 1. Recusar erro do provedor ou ausência de code/state
  if (error || !code || !state) {
    return badRequest("Resposta de autorização inválida");
  }

  // 2. Exigir o cookie de transação
  const cookies = parseCookies(request);
  const rawTxId = cookies["__Host-oauth-tx"];
  if (!rawTxId) {
    return badRequest("Transação ausente");
  }

  // 3. Localizar a transação não expirada
  const idHash = await sha256Base64Url(rawTxId);
  const tx = await env.DB
    .prepare("SELECT provider, state_hash, nonce, code_verifier, expires_at FROM oauth_transactions WHERE id_hash = ?")
    .bind(idHash)
    .first();

  if (!tx || tx.provider !== provider || tx.expires_at < nowSeconds()) {
    return badRequest("Transação inválida ou expirada");
  }

  // 4. Comparar o resumo de state
  const stateHash = await sha256Base64Url(state);
  if (stateHash !== tx.state_hash) {
    return badRequest("state inválido");
  }

  // 5. Apagar a transação antes de prosseguir
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(idHash).run();

  const { clientId, clientSecret } = credentialsFor(env, provider);
  const redirectUri = redirectUriFor(env, provider);

  let identity; // { issuer, subject, email, displayName }

  if (provider === "google") {
    // 6. Trocar o código por tokens
    const tokenRes = await fetch(PROVIDERS.google.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
        code_verifier: tx.code_verifier,
      }),
    });
    if (!tokenRes.ok) return badRequest("Falha ao trocar o código com o Google");
    const tokenData = await tokenRes.json();
    if (!tokenData.id_token) return badRequest("Resposta do Google sem id_token");

    // 7. Validar o id_token (assinatura, iss, aud, exp, iat, nonce)
    let payload;
    try {
      payload = await validateGoogleIdToken(tokenData.id_token, {
        audience: clientId,
        expectedNonce: tx.nonce,
      });
    } catch (e) {
      return badRequest("id_token inválido");
    }

    identity = {
      issuer: "https://accounts.google.com",
      subject: payload.sub,
      email: payload.email || null,
      displayName: payload.name || payload.email || "Usuário Google",
    };
  } else {
    // GitHub: trocar o código por um access_token
    const tokenRes = await fetch(PROVIDERS.github.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        code_verifier: tx.code_verifier,
      }),
    });
    if (!tokenRes.ok) return badRequest("Falha ao trocar o código com o GitHub");
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
      return badRequest("Resposta do GitHub sem access_token válido");
    }

    // Consultar o perfil autenticado
    const userRes = await fetch(PROVIDERS.github.userEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "heycr7-oauth-lab",
      },
    });
   if (userRes.status !== 200) return badRequest("Falha ao consultar o perfil no GitHub");
    }
    const user = await userRes.json();
    if (typeof user.id !== "number") return badRequest("Perfil do GitHub sem id numérico");

    // Revogar a autorização concedida à OAuth App antes de criar a sessão
    const basicAuth = btoa(`${clientId}:${clientSecret}`);
    const revokeRes = await fetch(PROVIDERS.github.revokeEndpoint(clientId), {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "heycr7-oauth-lab",
      },
      body: JSON.stringify({ access_token: tokenData.access_token }),
    });
    if (revokeRes.status !== 204) return badRequest("Falha ao revogar a autorização no GitHub");

    identity = {
      issuer: "https://github.com",
      subject: String(user.id),
      email: user.email || null,
      displayName: user.name || user.login || "Usuário GitHub",
    };
  }

  // 8. Criar a sessão opaca
  const rawSessionId = randomToken();
  const sessionIdHash = await sha256Base64Url(rawSessionId);
  const now = nowSeconds();

  await env.DB
    .prepare(
      "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(sessionIdHash, identity.issuer, identity.subject, identity.email, identity.displayName, now + SESSION_TTL_SECONDS, now)
    .run();

  // 9. Limpar o cookie temporário e criar o cookie de sessão
  const sessionCookie = serializeCookie("__Host-session", rawSessionId, {
    maxAge: SESSION_TTL_SECONDS,
    sameSite: "Strict",
  });
  const clearTxCookie = expireCookie("__Host-oauth-tx", { sameSite: "Lax" });

  // 10. Redirecionar para a URL base, com os dois Set-Cookie (expira tx + cria sessão)
  const headers = new Headers();
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", clearTxCookie);
  headers.append("Set-Cookie", sessionCookie);

  return new Response(null, { status: 302, headers });
}
