// Managed identity tokens (user-assigned id-r360). No secret, certificate or key is stored anywhere.
// Container Apps injects IDENTITY_ENDPOINT and IDENTITY_HEADER.
export function createManagedIdentity({ clientId, env = process.env, fetcher = fetch, now = () => Date.now() }) {
  const cache = new Map();
  return async function miToken(resource) {
    const hit = cache.get(resource);
    if (hit && hit.expires - 300000 > now()) return hit.token;
    if (!env.IDENTITY_ENDPOINT || !env.IDENTITY_HEADER) throw new Error('Managed identity is not available (IDENTITY_ENDPOINT missing). r360 runs hosted only.');
    const url = new URL(env.IDENTITY_ENDPOINT);
    url.searchParams.set('resource', resource);
    url.searchParams.set('api-version', '2019-08-01');
    url.searchParams.set('client_id', clientId);
    const res = await fetcher(url, { headers: { 'X-IDENTITY-HEADER': env.IDENTITY_HEADER }, redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`Managed identity token for ${resource} failed: HTTP ${res.status}`);
    const data = await res.json();
    const expires = Number(data.expires_on) * 1000;
    if (!data.access_token || !Number.isFinite(expires)) throw new Error('Managed identity returned an unexpected token response');
    cache.set(resource, { token: data.access_token, expires });
    return data.access_token;
  };
}
export const FIC_AUDIENCE = 'api://AzureADTokenExchange';
export const VAULT_RESOURCE = 'https://vault.azure.net';
