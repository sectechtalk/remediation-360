import express from 'express';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseCookies, cookieHeader, SESSION_COOKIE, SESSION_TTL } from './auth.mjs';
import { publicSettings } from './config.mjs';
import { createWrite, csrfGuard, resolveRoles } from './write.mjs';
import { toCsv } from './audit.mjs';
import { createChanges } from './changes.mjs';
import { createIntune } from './intune.mjs';

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const CACHE_MS = 60000;

export const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://login.microsoftonline.com",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Strict-Transport-Security': 'max-age=31536000',
  'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
};

// Reads are GET. State-changing routes (sign-out, ending a write session, and the writes S3 adds) pass the CSRF guard, and
// anything that writes Intune goes through write.requireWrite(...).
export function createApp({ config, sessions, auth, data, github, audit, log = console, fetcher = fetch, now = () => Date.now() }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((req, res, next) => { res.set(SECURITY_HEADERS); next(); });

  app.get('/healthz', (req, res) => res.json({ ok: true, image: config.imageTag }));

  const sessionOf = req => sessions.get(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
  const pimGate = async s => { const token = await auth.graphToken(s); return (await data.pim(token, s.user.oid)).gate; };
  const write = createWrite({ config, auth, audit, github, pimGate, fetcher, now, log });
  const page = (res, status, title, message, href = '/', label = 'Back to r360') =>
    res.status(status).type('html').send(`<!doctype html><title>r360</title><link rel="stylesheet" href="/style.css"><main class="center"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a class="btn" href="${href}">${escapeHtml(label)}</a></main>`);

  app.get('/auth/signin', async (req, res, next) => {
    try {
      const s = sessionOf(req) || sessions.create();
      const url = await auth.beginSignIn(s);
      res.set('Set-Cookie', cookieHeader(s.id, SESSION_TTL / 1000)).redirect(302, url);
    } catch (e) { next(e); }
  });
  app.get('/auth/callback', async (req, res) => {
    const s = sessionOf(req);
    try {
      if (!s) throw Object.assign(new Error('No sign-in is in progress. Start again.'), { status: 400 });
      await auth.completeSignIn(s, req.query);
      // Sign-in events are recorded but never block reading.
      audit.record({ actorOid: s.user.oid, actorUpn: s.user.upn, action: 'session.signin', result: 'ok', target: 'web-session' })
        .then(() => write.reconcileLost(s, (oid, until) => sessions.hasWrite(oid, until)))
        .catch(e => log.error?.(`session.signin: audit failed: ${e.message}`));
      res.redirect(302, '/');
    } catch (e) {
      log.error?.(`sign-in failed: ${e.message}`);
      res.status(e.status === 400 ? 400 : 403).type('html').send(`<!doctype html><title>r360</title><link rel="stylesheet" href="/style.css"><main class="center"><h1>Sign-in failed</h1><p>${escapeHtml(e.status === 400 ? e.message : 'Microsoft Entra did not allow the sign-in. Your account must be assigned to r360 (sg-r360-operators).')}</p><a class="btn" href="/auth/signin">Sign in again</a></main>`);
    }
  });
  app.post('/auth/signout', async (req, res) => {
    const s = sessionOf(req);
    if (req.get('origin') && req.get('origin') !== config.publicUrl) return res.status(403).end();
    if (s) {
      if (s.user && s.write) await write.end(s, 'signout').catch(() => {});
      await auth.signOut(s).catch(() => {});
      sessions.destroy(s.id);
    }
    res.set('Set-Cookie', cookieHeader('', 0)).redirect(303, `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(config.publicUrl + '/')}`);
  });

  // Everything below needs a signed-in session.
  app.use((req, res, next) => {
    const s = sessionOf(req);
    if (s?.user) { req.r360 = s; return next(); }
    if (req.path.startsWith('/auth/write/')) return req.method === 'GET' ? res.redirect(302, '/auth/signin') : res.status(401).json({ error: 'Sign in required.' });
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Sign in required.' });
    if (req.path === '/' || req.path === '/index.html') return res.redirect(302, '/auth/signin');
    return next();
  });
  app.use(csrfGuard({ config }));
  // Authoring bodies carry two scripts of up to 150 KB each; everything else stays small.
  const small = express.json({ limit: '16kb', type: 'application/json' });
  const large = express.json({ limit: '1mb', type: 'application/json' });
  app.use((req, res, next) => (req.path.startsWith('/api/changes') ? large : small)(req, res, next));
  app.use(express.static(PUBLIC, { index: false, maxAge: 0 }));
  app.get(['/', '/index.html'], (req, res) => res.sendFile(path.join(PUBLIC, 'index.html')));

  // ---- write session (elevation) ----
  app.get('/auth/write/start', async (req, res) => {
    try { res.redirect(302, await write.begin(req.r360)); }
    catch (e) { log.error?.(`write start: ${e.message}`); page(res, e.status || 500, 'Write session not started', e.denied || e.status === 503 ? e.message : 'The write sign-in could not be started.'); }
  });
  app.get('/auth/write/callback', async (req, res) => {
    try { await write.complete(req.r360, req.query); res.redirect(302, '/'); }
    catch (e) { log.error?.(`write callback: ${e.message}`); page(res, e.status && e.status < 600 ? e.status : 500, 'Write session not started', e.denied || e.audit ? e.message : 'The write sign-in failed.'); }
  });
  app.post('/auth/write/end', async (req, res) => {
    try { await write.end(req.r360, 'manual'); res.json({ ok: true, write: write.status(req.r360) }); }
    catch (e) { log.error?.(`write end: ${e.message}`); res.status(500).json({ error: 'Could not end the write session.' }); }
  });

  const cached = (key, fn) => async (req, res) => {
    const s = req.r360;
    try {
      const hit = s.cache.get(key);
      if (hit && !req.query.refresh && Date.now() - hit.at < CACHE_MS) return res.json({ ...hit.value, fetchedAt: new Date(hit.at).toISOString() });
      const token = await auth.graphToken(s);
      const value = await fn(token, s);
      s.cache.set(key, { at: Date.now(), value });
      res.json({ ...value, fetchedAt: new Date().toISOString() });
    } catch (e) {
      log.error?.(`${key}: ${e.message}`);
      res.status(e.status === 401 ? 401 : 502).json({ error: e.status === 401 ? e.message : `Could not load ${key}: ${e.message}` });
    }
  };

  app.get('/api/me', async (req, res) => {
    const u = req.r360.user;
    const { roles, approversError } = await resolveRoles(github, u.oid);
    await write.live(req.r360);
    const st = write.status(req.r360);
    const blocked = !st.configured ? 'The write app is not configured.' : approversError ? 'approvers.json could not be verified.' : !roles.length ? 'You are not listed in approvers.json.' : null;
    res.json({ user: u, roles, approversError, fourEyes: config.fourEyes, pimMode: config.pimMode, csrf: req.r360.csrf,
      write: { ...st, canElevate: !blocked, blockedReason: blocked, ttlMinutes: config.elevationTtlMinutes } });
  });

  // ---- audit trail (read-only for every signed-in operator) ----
  const auditQuery = q => {
    const bad = m => Object.assign(new Error(m), { status: 400 });
    const one = v => (typeof v === 'string' ? v : undefined);
    const ms = v => { if (!v) return undefined; const t = Date.parse(v); if (!Number.isFinite(t)) throw bad('Invalid date'); return t; };
    const actions = one(q.action) ? one(q.action).split(',').map(x => x.trim()).filter(Boolean).slice(0, 40) : undefined;
    for (const a of actions || []) if (!/^[a-z0-9.]+$/.test(a)) throw bad('Invalid action filter');
    if (one(q.actor) && !/^[\w.@+'-]{1,200}$/.test(one(q.actor))) throw bad('Invalid actor filter');
    return { from: ms(one(q.from)), to: ms(one(q.to)), actions, actor: one(q.actor) || undefined, target: one(q.target)?.slice(0, 200) || undefined, limit: Number(one(q.limit)) || 500 };
  };
  const auditRows = async (req, res) => {
    try { return await audit.list(auditQuery(req.query)); }
    catch (e) {
      log.error?.(`audit list: ${e.message}`);
      res.status(e.status === 400 ? 400 : 502).json({ error: e.status === 400 ? e.message : 'The audit trail could not be read.' });
      return null;
    }
  };
  app.get('/api/audit', async (req, res) => { const r = await auditRows(req, res); if (r) res.json({ ...r, fetchedAt: new Date(now()).toISOString() }); });
  app.get('/api/audit/download', async (req, res) => {
    const r = await auditRows(req, res);
    if (!r) return;
    const stamp = new Date(now()).toISOString().replace(/[:.]/g, '-');
    if (req.query.format === 'csv') res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="r360-audit-${stamp}.csv"` }).send(toCsv(r.rows));
    else res.set({ 'Content-Disposition': `attachment; filename="r360-audit-${stamp}.json"` }).json({ exportedAt: new Date(now()).toISOString(), truncated: r.truncated, rows: r.rows });
  });
  // ---- authoring (S3): a change is a branch + pull request in the remediations repo ----
  const changes = createChanges({ config, github, audit, intune: createIntune({ fetcher }), now, log });
  const author = write.requireWrite({ roles: ['author', 'admin'] });
  const approver = write.requireWrite({ roles: ['approver'] });
  const anyChangeRole = write.requireWrite({ roles: ['author', 'approver', 'admin'] });
  const run = (fn, generic = 'GitHub could not be reached or refused the request.') => async (req, res) => {
    try { res.json(await fn(req)); }
    catch (e) {
      if (e.expose) return res.status(e.status).json({ error: e.message, ...(e.details ? { details: e.details } : {}) });
      log.error?.(`${req.method} ${req.path}: ${e.message}`);
      res.status(502).json({ error: generic });
    }
  };
  const num = req => Number(req.params.number);
  app.get('/api/changes', run(async req => ({ ...(await changes.list(req.r360.user, (await resolveRoles(github, req.r360.user.oid)).roles)), fetchedAt: new Date(now()).toISOString() })));
  app.get('/api/changes/source/:folder', author, run(req => changes.source(req.params.folder)));
  app.get('/api/changes/:number/source', author, run(req => changes.changeSource(req.r360.user, req.r360roles || [], num(req))));
  app.post('/api/changes', author, run(async req => ({ ...(await changes.propose(req.r360.user, req.body)), ...(req.res.locals.pimWarning ? { pimWarning: req.res.locals.pimWarning } : {}) })));
  app.post('/api/changes/:number/update', author, run(req => changes.update(req.r360.user, req.r360roles || [], num(req), req.body)));
  app.post('/api/changes/:number/discard', author, run(req => changes.discard(req.r360.user, req.r360roles || [], num(req))));
  app.post('/api/changes/:number/approve', approver, run(req => changes.approve(req.r360.user, req.r360roles || [], num(req), req.body)));
  app.post('/api/changes/:number/reject', approver, run(req => changes.reject(req.r360.user, req.r360roles || [], num(req), req.body)));
  app.post('/api/changes/:number/merge', approver, run(req => changes.merge(req.r360.user, req.r360roles || [], num(req), req.body)));
  // Publish writes Intune as the signed-in publisher: the delegated r360-write token of their own write session, nothing else.
  app.post('/api/changes/:number/publish', approver, run(req => changes.publish(req.r360.user, req.r360roles || [], num(req), req.body, { token: () => auth.writeToken(req.r360write.homeAccountId), readToken: () => auth.graphToken(req.r360) }), 'The publish could not be completed. Check the audit trail for what happened.'));
  // S6: promote a canary change to production. Evidence is read with the signed-in user's delegated READ token; nothing is written to Intune here.
  app.get('/api/changes/promote-evidence/:folder', run(async req => changes.promoteEvidence(req.r360.user, (await resolveRoles(github, req.r360.user.oid)).roles, req.params.folder, { readToken: () => auth.graphToken(req.r360) }), 'The canary evidence could not be read.'));
  // The group picker in the Promote dialog: a delegated read of Entra groups by display name (GroupMember.Read.All on r360-web). Approvers only.
app.get('/api/changes/promote-groups', run(async req => changes.promoteGroups(req.r360.user, (await resolveRoles(github, req.r360.user.oid)).roles, typeof req.query.q === 'string' ? req.query.q : '', { readToken: () => auth.graphToken(req.r360) }), 'The group search failed.'));
app.post('/api/changes/promote', approver, run(req => changes.promote(req.r360.user, req.r360roles || [], req.body, { readToken: () => auth.graphToken(req.r360) }), 'The promotion could not be created. Check the audit trail for what happened.'));
  app.post('/api/changes/:number/verify-signing', anyChangeRole, run(req => changes.verifySigning(req.r360.user, req.r360roles || [], num(req))));

  app.get('/api/remediations', cached('remediations', t => data.remediations(t)));
  app.get('/api/fleet', cached('fleet', t => data.fleet(t)));
  app.get('/api/certificates', cached('certificates', t => data.certificates(t)));
  app.get('/api/pim', cached('pim', (t, s) => data.pim(t, s.user.oid)));
  app.get('/api/settings', (req, res) => res.json({ settings: publicSettings(config) }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'The request is too large.' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'The request body is not valid JSON.' });
    log.error?.(err.message); res.status(500).json({ error: 'Internal error' });
  });
  return app;
}

export const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
