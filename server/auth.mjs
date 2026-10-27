import { randomBytes } from 'node:crypto';
import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { FIC_AUDIENCE } from './identity.mjs';

// Entra-only sign-in to r360-web: auth code + PKCE, server-side confidential client whose client assertion is a
// managed-identity token (federated identity credential). No secret, certificate or key. Tokens stay in server memory.
export const GRAPH_READ_SCOPES = ['User.Read', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All',
  'DeviceManagementScripts.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'].map(s => `https://graph.microsoft.com/${s}`);
export const SESSION_COOKIE = '__Host-r360';
export const SESSION_TTL = 8 * 60 * 60 * 1000;
export const PENDING_TTL = 10 * 60 * 1000;

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export class SessionStore {
  constructor({ now = () => Date.now(), ttl = SESSION_TTL, max = 1000 } = {}) { this.now = now; this.ttl = ttl; this.max = max; this.map = new Map(); }
  create() {
    if (this.map.size >= this.max) this.sweep();
    const id = randomBytes(32).toString('base64url');
    const s = { id, created: this.now(), seen: this.now(), cache: new Map() };
    this.map.set(id, s);
    return s;
  }
  get(id) {
    const s = id && this.map.get(id);
    if (!s) return null;
    if (this.now() - s.created > this.ttl) { this.map.delete(id); return null; }
    s.seen = this.now();
    return s;
  }
  destroy(id) { this.map.delete(id); }
  sweep() { for (const [id, s] of this.map) if (this.now() - s.created > this.ttl) this.map.delete(id); if (this.map.size >= this.max) this.map.delete(this.map.keys().next().value); }
}

export const cookieHeader = (id, maxAgeSec) => `${SESSION_COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}`;

export function checkCallback(pending, query, now = Date.now()) {
  if (!pending) return 'No sign-in is in progress. Start again.';
  if (now - pending.created > PENDING_TTL) return 'The sign-in expired. Start again.';
  if (query.error) return 'Microsoft did not complete the sign-in.';
  if (typeof query.state !== 'string' || query.state !== pending.state) return 'The sign-in response did not match this browser session.';
  if (typeof query.code !== 'string' || query.code.length < 10) return 'The sign-in response had no authorization code.';
  return null;
}

// Claims accepted only from the ID token MSAL redeemed for r360-web in our tenant.
export function userFromClaims(claims, { tenantId, clientId }) {
  if (!claims || claims.tid !== tenantId) throw new Error('Wrong tenant');
  if (claims.aud && claims.aud !== clientId) throw new Error('Wrong audience');
  if (!/^[0-9a-f-]{36}$/i.test(claims.oid || '')) throw new Error('No object id');
  return { oid: claims.oid.toLowerCase(), upn: claims.preferred_username || '', name: claims.name || claims.preferred_username || '' };
}

export function createAuth({ config, miToken }) {
  const cca = new ConfidentialClientApplication({
    auth: { clientId: config.webClientId, authority: `https://login.microsoftonline.com/${config.tenantId}`, clientAssertion: async () => miToken(FIC_AUDIENCE) },
    system: { loggerOptions: { piiLoggingEnabled: false, logLevel: 0, loggerCallback: () => {} } },
  });
  const crypto = new CryptoProvider();
  return {
    async beginSignIn(session) {
      const { verifier, challenge } = await crypto.generatePkceCodes();
      session.pending = { state: randomBytes(24).toString('hex'), verifier, created: Date.now() };
      return cca.getAuthCodeUrl({ scopes: GRAPH_READ_SCOPES, redirectUri: config.redirectUri, codeChallenge: challenge, codeChallengeMethod: 'S256', state: session.pending.state, prompt: 'select_account' });
    },
    async completeSignIn(session, query) {
      const problem = checkCallback(session.pending, query);
      const pending = session.pending;
      session.pending = null;
      if (problem) throw Object.assign(new Error(problem), { status: 400 });
      const result = await cca.acquireTokenByCode({ code: query.code, scopes: GRAPH_READ_SCOPES, redirectUri: config.redirectUri, codeVerifier: pending.verifier, state: query.state });
      session.user = userFromClaims(result.idTokenClaims, { tenantId: config.tenantId, clientId: config.webClientId });
      session.homeAccountId = result.account.homeAccountId;
      return session.user;
    },
    async graphToken(session) {
      const account = await cca.getTokenCache().getAccountByHomeId(session.homeAccountId);
      if (!account) throw Object.assign(new Error('Session expired. Sign in again.'), { status: 401 });
      try { return (await cca.acquireTokenSilent({ account, scopes: GRAPH_READ_SCOPES })).accessToken; }
      catch { throw Object.assign(new Error('Session expired. Sign in again.'), { status: 401 }); }
    },
    async signOut(session) {
      const account = session.homeAccountId && await cca.getTokenCache().getAccountByHomeId(session.homeAccountId);
      if (account) await cca.getTokenCache().removeAccount(account);
    },
  };
}
