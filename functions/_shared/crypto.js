// functions/_shared/crypto.js
// Utilidades de criptografia usando apenas Web Crypto (sem bibliotecas externas).

/** Codifica um ArrayBuffer/Uint8Array em Base64URL sem preenchimento (padding). */
export function base64UrlEncode(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let binary = "";
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/** Decodifica uma string Base64URL para Uint8Array. */
export function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Gera 32 bytes aleatórios codificados em Base64URL (43 caracteres). */
export function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** Calcula SHA-256 de uma string UTF-8 e devolve o resultado em Base64URL. */
export async function sha256Base64Url(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(digest);
}

/** Deriva o code_challenge (S256) a partir do code_verifier, conforme RFC 7636. */
export async function pkceChallengeFromVerifier(codeVerifier) {
  return sha256Base64Url(codeVerifier);
}

/** Timestamp Unix atual, em segundos. */
export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
