import express from 'express';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseCookies, cookieHeader, SESSION_COOKIE, SESSION_TTL } from './auth.mjs';
import { publicSettings } from './config.mjs';

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const CACHE_MS = 60000;

export const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://login.microsoftonline.com",
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Strict-Transport-Security': 'max-age=31536000',
  'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
};

// Phase 1 is read-only. Every /api route is GET; the only POST is sign-out.
export function createApp({ config, sessions, auth, data, github, log = console }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((req, res, next) => { res.set(SECURITY_HEADERS); next(); });

  app.get('/healthz', (req, res) => res.json({ ok: true, image: config.imageTag }));

  const sessionOf = req => sessions.get(parseCookies(req.headers.cookie)[SESSION_COOKIE]);

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
      res.redirect(302, '/');
    } catch (e) {
      log.error?.(`sign-in failed: ${e.message}`);
      res.status(e.status === 400 ? 400 : 403).type('html').send(`<!doctype html><title>r360</title><link rel="stylesheet" href="/style.css"><main class="center"><h1>Sign-in failed</h1><p>${escapeHtml(e.status === 400 ? e.message : 'Microsoft Entra did not allow the sign-in. Your account must be assigned to r360 (sg-r360-operators).')}</p><a class="btn" href="/auth/signin">Sign in again</a></main>`);
    }
  });
  app.post('/auth/signout', async (req, res) => {
    const s = sessionOf(req);
    if (req.get('origin') && req.get('origin') !== config.publicUrl) return res.status(403).end();
    if (s) { await auth.signOut(s).catch(() => {}); sessions.destroy(s.id); }
    res.set('Set-Cookie', cookieHeader('', 0)).redirect(303, `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(config.publicUrl + '/')}`);
  });

  // Everything below needs a signed-in session.
  app.use((req, res, next) => {
    const s = sessionOf(req);
    if (s?.user) { req.r360 = s; return next(); }
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Sign in required.' });
    if (req.path === '/' || req.path === '/index.html') return res.redirect(302, '/auth/signin');
    return next();
  });
  app.use(express.static(PUBLIC, { index: false, maxAge: 0 }));
  app.get(['/', '/index.html'], (req, res) => res.sendFile(path.join(PUBLIC, 'index.html')));

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
    let roles = [], approversError = null;
    try {
      const cat = await github.catalog();
      if (cat.approversError) approversError = cat.approversError;
      roles = cat.approvers?.find(a => a.entraObjectId === u.oid)?.roles || [];
    } catch (e) { approversError = e.message; }
    res.json({ user: u, roles, approversError, fourEyes: config.fourEyes, pimMode: config.pimMode });
  });
  app.get('/api/remediations', cached('remediations', t => data.remediations(t)));
  app.get('/api/fleet', cached('fleet', t => data.fleet(t)));
  app.get('/api/certificates', cached('certificates', t => data.certificates(t)));
  app.get('/api/pim', cached('pim', (t, s) => data.pim(t, s.user.oid)));
  app.get('/api/settings', (req, res) => res.json({ settings: publicSettings(config) }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => { log.error?.(err.message); res.status(500).json({ error: 'Internal error' }); });
  return app;
}

export const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
