// functions/_shared/providers.js

export const PROVIDERS = {
  google: {
    issuer: "https://accounts.google.com",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userEndpoint: "https://api.github.com/user",
    revokeEndpoint: (clientId) => `https://api.github.com/applications/${clientId}/grant`,
  },
};

/** Valida se o nome do provedor é suportado. */
export function isValidProvider(provider) {
  return provider === "google" || provider === "github";
}

/** Monta a redirect_uri exata cadastrada no provedor, a partir da PUBLIC_BASE_URL. */
export function redirectUriFor(env, provider) {
  return `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
}

/** Devolve { clientId, clientSecret } do provedor a partir das variáveis de ambiente. */
export function credentialsFor(env, provider) {
  if (provider === "google") {
    return { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET };
  }
  return { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
}
