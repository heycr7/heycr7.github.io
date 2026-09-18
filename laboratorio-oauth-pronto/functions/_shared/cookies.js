// functions/_shared/cookies.js

/** Lê o cabeçalho Cookie da requisição e devolve um objeto { nome: valor }. */
export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (name) cookies[name] = value;
  });
  return cookies;
}

/** Monta uma string Set-Cookie no padrão __Host-, sempre HttpOnly e Secure. */
export function serializeCookie(name, value, { maxAge, sameSite = "Lax" } = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", `SameSite=${sameSite}`];
  if (typeof maxAge === "number") parts.push(`Max-Age=${maxAge}`);
  return parts.join("; ");
}

/** Monta o Set-Cookie que expira (remove) um cookie imediatamente. */
export function expireCookie(name, { sameSite = "Lax" } = {}) {
  return serializeCookie(name, "", { maxAge: 0, sameSite });
}
