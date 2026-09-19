// functions/_shared/oidc.js
// Validação manual de um id_token OIDC (JWT RS256) do Google, sem bibliotecas externas.

import { base64UrlDecode } from "./crypto.js";
import { PROVIDERS } from "./providers.js";

/** Busca o documento de descoberta OIDC e devolve o jwks_uri. */
async function getJwksUri() {
  const res = await fetch(PROVIDERS.google.discoveryUrl);
  if (!res.ok) throw new Error("Falha ao obter o documento de descoberta OIDC");
  const doc = await res.json();
  if (!doc.jwks_uri) throw new Error("Documento de descoberta sem jwks_uri");
  return doc.jwks_uri;
}

/** Busca o JWKS e devolve a JWK cujo kid corresponde ao informado. */
async function getSigningKey(kid) {
  const jwksUri = await getJwksUri();
  const res = await fetch(jwksUri);
  if (!res.ok) throw new Error("Falha ao obter o JWKS");
  const { keys } = await res.json();
  const jwk = (keys || []).find((k) => k.kid === kid);
  if (!jwk) throw new Error("Nenhuma chave JWKS corresponde ao kid do token");
  return jwk;
}

/**
 * Valida um id_token do Google: formato, assinatura RS256, iss, aud, exp, iat e nonce.
 * Devolve o payload decodificado em caso de sucesso, ou lança um erro.
 */
export async function validateGoogleIdToken(idToken, { audience, expectedNonce }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("id_token não possui três partes (JWT inválido)");
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
  if (header.alg !== "RS256") throw new Error("alg do id_token não é RS256");

  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));

  const jwk = await getSigningKey(header.kid);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(signatureB64);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);
  if (!valid) throw new Error("Assinatura do id_token inválida");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== PROVIDERS.google.issuer && payload.iss !== "accounts.google.com") {
    throw new Error("iss do id_token não corresponde ao emissor esperado");
  }
  if (payload.aud !== audience) throw new Error("aud do id_token não corresponde ao client_id");
  if (typeof payload.exp !== "number" || payload.exp < now) throw new Error("id_token expirado");
  if (typeof payload.iat !== "number" || payload.iat > now + 60) throw new Error("iat do id_token inválido");
  if (payload.nonce !== expectedNonce) throw new Error("nonce do id_token não corresponde à transação");

  return payload;
}
