// functions/oauth/login/[provider].js
import { randomToken, sha256Base64Url, pkceChallengeFromVerifier, nowSeconds } from "../../_shared/crypto.js";
import { serializeCookie } from "../../_shared/cookies.js";
import { PROVIDERS, isValidProvider, redirectUriFor, credentialsFor } from "../../_shared/providers.js";

const TX_TTL_SECONDS = 600; // 10 minutos

export async function onRequestGet(context) {
  const { params, env } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  // 1. Gerar valores aleatórios da transação
  const rawTxId = randomToken();
  const state = randomToken();
  const nonce = provider === "google" ? randomToken() : null;
  const codeVerifier = randomToken();

  // 2. Gravar os resumos no D1 (nunca os valores brutos)
  const idHash = await sha256Base64Url(rawTxId);
  const stateHash = await sha256Base64Url(state);
  const expiresAt = nowSeconds() + TX_TTL_SECONDS;

  await env.DB
    .prepare(
      "INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  // 3. Criar o cookie temporário
  const cookie = serializeCookie("__Host-oauth-tx", rawTxId, { maxAge: TX_TTL_SECONDS, sameSite: "Lax" });

  // 4. Montar o pedido de autorização
  const { clientId } = credentialsFor(env, provider);
  const redirectUri = redirectUriFor(env, provider);
  const codeChallenge = await pkceChallengeFromVerifier(codeVerifier);

  const authUrl = new URL(PROVIDERS[provider].authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", PROVIDERS.google.scope);
    authUrl.searchParams.set("nonce", nonce);
  }

  // 5. Redirecionar
  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": cookie,
      "Cache-Control": "no-store",
    },
  });
}
