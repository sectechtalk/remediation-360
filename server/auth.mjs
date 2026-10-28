import { randomBytes, timingSafeEqual } from 'node:crypto';
import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { FIC_AUDIENCE } from './identity.mjs';

// Entra-only sign-in to r360-web: auth code + PKCE, server-side confidential client whose client assertion is a
// managed-identity token (federated identity credential). No secret, certificate or key. Tokens stay in server memory.
export const GRAPH_READ_SCOPES = ['User.Read', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All',
  'DeviceManagementScripts.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'].map(s => `https://graph.microsoft.com/${s}`);
export const SESSION_COOKIE = '__Host-r360';
export const SESSION_TTL = 8 * 60 * 60 * 1000;
export const PENDING_TTL = 10 * 60 * 1000;
// The write app (r360-write) is requested ONLY for Intune script writes. It never carries the read scopes.
export const WRITE_SCOPES = ['https://graph.microsoft.com/DeviceManagementScripts.ReadWrite.All'];

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
    const s = { id, created: this.now(), seen: this.now(), cache: new Map(), csrf: randomBytes(32).toString('base64url'), write: null };
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
  // True when a live session on this replica holds the write session for this person that ends at untilMs.
  hasWrite(oid, untilMs) { for (const s of this.map.values()) if (s.write && s.write.oid === oid && s.write.until === untilMs && s.write.until > this.now()) return true; return false; }
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

const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Claims accepted only from the ID token MSAL redeemed for a given app in our tenant, bound to this browser's request by nonce.
function checkNonce(claims, pending) {
  if (!pending?.nonce || !safeEq(claims?.nonce, pending.nonce)) throw Object.assign(new Error('The sign-in response did not match this browser session.'), { status: 400 });
}

// `msal` lets tests swap the network and authority metadata; production passes nothing.
export function createAuth({ config, miToken, msal = {} }) {
  const makeCca = clientId => new ConfidentialClientApplication({
    auth: { clientId, authority: msal.authority || `https://login.microsoftonline.com/${config.tenantId}`, clientAssertion: async () => miToken(FIC_AUDIENCE), ...(msal.auth || {}) },
    system: { loggerOptions: { piiLoggingEnabled: false, logLevel: 0, loggerCallback: () => {} }, ...(msal.system || {}) },
  });
  const cca = makeCca(config.webClientId);
  // Separate client app, separate token cache: the write token can never be mixed up with the read token.
  const writeCca = config.writeClientId ? makeCca(config.writeClientId) : null;
  const crypto = new CryptoProvider();
  const removeAccount = async (client, homeAccountId) => {
    const account = homeAccountId && client && await client.getTokenCache().getAccountByHomeId(homeAccountId);
    if (account) await client.getTokenCache().removeAccount(account);
  };
  const begin = async (client, session, key, { scopes, redirectUri, extra = {} }) => {
    const { verifier, challenge } = await crypto.generatePkceCodes();
    const pending = { state: randomBytes(24).toString('hex'), nonce: randomBytes(24).toString('hex'), verifier, created: Date.now() };
    session[key] = pending;
    return client.getAuthCodeUrl({ scopes, redirectUri, codeChallenge: challenge, codeChallengeMethod: 'S256', state: pending.state, nonce: pending.nonce, ...extra });
  };
  const redeem = async (client, session, key, query, { scopes, redirectUri }) => {
    const problem = checkCallback(session[key], query);
    const pending = session[key];
    session[key] = null;
    if (problem) throw Object.assign(new Error(problem), { status: 400 });
    // The nonce goes in both places msal-node reads it (request and authorization-code payload; v4 validates it inside the call).
    const result = await client.acquireTokenByCode(
      { code: query.code, scopes, redirectUri, codeVerifier: pending.verifier, state: query.state, nonce: pending.nonce },
      { code: query.code, state: query.state, nonce: pending.nonce });
    try { checkNonce(result.idTokenClaims, pending); }
    catch (e) { await removeAccount(client, result.account?.homeAccountId).catch(() => {}); throw e; }
    return result;
  };
  return {
    writeConfigured: Boolean(writeCca),
    async beginSignIn(session) {
      return begin(cca, session, 'pending', { scopes: GRAPH_READ_SCOPES, redirectUri: config.redirectUri, extra: { prompt: 'select_account' } });
    },
    async completeSignIn(session, query) {
      const result = await redeem(cca, session, 'pending', query, { scopes: GRAPH_READ_SCOPES, redirectUri: config.redirectUri });
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
    // ---- write elevation (r360-write) ----
    async beginElevate(session) {
      if (!writeCca) throw Object.assign(new Error('The write app is not configured (R360_WRITE_CLIENT_ID).'), { status: 503 });
      return begin(writeCca, session, 'writePending', { scopes: WRITE_SCOPES, redirectUri: config.writeRedirectUri, extra: { loginHint: session.user.upn || undefined } });
    },
    // Returns who the write token is for. The caller decides whether to accept it (the oid must equal the web session's).
    async completeElevate(session, query) {
      if (!writeCca) throw Object.assign(new Error('The write app is not configured.'), { status: 503 });
      const result = await redeem(writeCca, session, 'writePending', query, { scopes: WRITE_SCOPES, redirectUri: config.writeRedirectUri });
      const user = userFromClaims(result.idTokenClaims, { tenantId: config.tenantId, clientId: config.writeClientId });
      return { oid: user.oid, upn: user.upn, homeAccountId: result.account.homeAccountId, acrs: result.idTokenClaims.acrs || null, accessToken: result.accessToken };
    },
    async writeToken(homeAccountId) {
      const account = writeCca && await writeCca.getTokenCache().getAccountByHomeId(homeAccountId);
      if (!account) throw Object.assign(new Error('The write session is gone. Elevate again.'), { status: 403 });
      try { return (await writeCca.acquireTokenSilent({ account, scopes: WRITE_SCOPES })).accessToken; }
      catch { throw Object.assign(new Error('The write session is gone. Elevate again.'), { status: 403 }); }
    },
    async endWrite(homeAccountId) { await removeAccount(writeCca, homeAccountId); },
    async signOut(session) {
      await removeAccount(cca, session.homeAccountId);
      await removeAccount(writeCca, session.write?.homeAccountId);
    },
  };
}