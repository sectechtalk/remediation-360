import { timingSafeEqual } from 'node:crypto';

// Write sessions, CSRF protection and the requireWrite gate. A "write session" is a time-boxed elevation of an already
// signed-in operator: a second Entra sign-in to the r360-write app (its own consent, its own token cache), bound to the
// same person, valid for config.elevationTtlMinutes and enforced here on the server. Nothing in the browser decides it.
export const CSRF_HEADER = 'x-r360-csrf';
export const GRAPH_PROBE = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$top=1&$select=id';

const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && a.length > 0 && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Every state-changing request needs: our own Origin, the per-session token, and a JSON body type (which a plain HTML form cannot send).
export function csrfGuard({ config }) {
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const reject = why => res.status(403).json({ error: 'Request blocked.', code: why });
    if (req.get('origin') !== config.publicUrl) return reject('origin');
    if (!safeEq(req.get(CSRF_HEADER), req.r360?.csrf)) return reject('csrf');
    if (!req.is('application/json')) return reject('content-type');
    next();
  };
}

export async function resolveRoles(github, oid) {
  try {
    const cat = await github.catalog();
    if (cat.approversError) return { roles: [], approversError: cat.approversError };
    if (!cat.approvers) return { roles: [], approversError: 'approvers.json is missing' };
    return { roles: cat.approvers.find(a => a.entraObjectId === oid)?.roles || [], approversError: null };
  } catch (e) { return { roles: [], approversError: e.message }; }
}

export function createWrite({ config, auth, audit, github, pimGate, fetcher = fetch, now = () => Date.now(), log = console }) {
  const who = s => ({ actorOid: s.user.oid, actorUpn: s.user.upn });
  const note = async (event, what) => { try { await audit.record(event); } catch (e) { log.error?.(`${what}: audit failed: ${e.message}`); } };
  const status = s => {
    const w = s?.write;
    const live = Boolean(w && w.until > now());
    return { configured: auth.writeConfigured, active: live, since: live ? new Date(w.since).toISOString() : null, until: live ? new Date(w.until).toISOString() : null };
  };

  const end = async (s, reason) => {
    const w = s.write;
    if (!w) return false;
    s.write = null;
    await auth.endWrite(w.homeAccountId).catch(() => {});
    await note({ ...who(s), action: 'session.end', result: 'ok', reason, target: 'write-session', sessionUntil: new Date(w.until).toISOString(), mode: config.pimMode }, 'session.end');
    return true;
  };
  // Lazily enforces the deadline: the first request after it passes ends (and audits) the session.
  const live = async s => {
    if (!s.write) return null;
    if (s.write.until <= now()) { await end(s, 'expired'); return null; }
    return s.write;
  };

  // Sessions live in memory, so a restart or scale-to-zero ends every write session without anyone calling end(). The
  // audit trail would then show an elevation that never ends. On the person's next sign-in, close every elevation of theirs
  // that has no matching session.end and is not live on this replica. Idempotent: a closed elevation has an end row.
  const reconcileLost = async (s, isLive = () => false) => {
    const rows = (await audit.list({ from: now() - 2 * 86400000, to: now(), actor: s.user.upn, actions: ['session.elevate', 'session.end'], limit: 500 })).rows
      .filter(r => r.actorOid === s.user.oid);
    const ended = new Set(rows.filter(r => r.action === 'session.end').map(r => r.sessionUntil));
    const lost = [];
    for (const r of rows) {
      if (r.action !== 'session.elevate' || r.result !== 'ok' || !r.sessionUntil || ended.has(r.sessionUntil)) continue;
      if (isLive(s.user.oid, Date.parse(r.sessionUntil))) continue;
      ended.add(r.sessionUntil);
      await audit.record({ ...who(s), action: 'session.end', result: 'ok', reason: 'session-lost', target: 'write-session', sessionUntil: r.sessionUntil, mode: config.pimMode,
        detail: 'The app restarted or scaled to zero before the write session was ended, which drops all sessions. Recorded at the next sign-in.' });
      lost.push(r.sessionUntil);
    }
    return lost;
  };

  const denied = async (s, reason, message, status_ = 403, extra = {}) => {
    await note({ ...who(s), action: 'session.elevate.denied', result: 'denied', reason, target: 'write-session', mode: config.pimMode, ...extra }, 'session.elevate.denied');
    return Object.assign(new Error(message), { status: status_, denied: true });
  };

  const checkEligible = async s => {
    if (!auth.writeConfigured) throw await denied(s, 'write-app-not-configured', 'The write app is not configured.', 503);
    const { roles, approversError } = await resolveRoles(github, s.user.oid);
    if (approversError) throw await denied(s, 'approvers-invalid', 'The approvers list could not be verified, so write access is blocked.', 503, { detail: approversError });
    if (!roles.length) throw await denied(s, 'no-role', 'You are not listed in approvers.json, so you cannot elevate.');
    return roles;
  };

  return {
    status,
    live,
    end,
    reconcileLost,
    async begin(s) { await checkEligible(s); return auth.beginElevate(s); },
    async complete(s, query) {
      const base = who(s);
      let el;
      try { el = await auth.completeElevate(s, query); }
      catch (e) { throw await denied(s, e.status === 400 ? 'callback-invalid' : 'exchange-failed', e.status === 400 ? e.message : 'Microsoft Entra did not complete the write sign-in.', e.status === 400 ? 400 : 403, { detail: e.message }); }
      const reject = async (reason, message, extra) => { await auth.endWrite(el.homeAccountId).catch(() => {}); return denied(s, reason, message, 403, extra); };
      if (el.oid !== s.user.oid) throw await reject('oid-mismatch', 'The write sign-in was for a different account than your r360 session.', { approverOid: el.oid });
      let roles;
      try { roles = await checkEligible(s); } catch (e) { await auth.endWrite(el.homeAccountId).catch(() => {}); throw e; }
      let gate = null;
      try { gate = await pimGate(s); } catch (e) { log.error?.(`pim check failed: ${e.message}`); }
      if (config.pimMode === 'enforce' && !gate?.ok) throw await reject('pim-not-active', gate ? gate.text : 'PIM could not be verified, so write access is blocked.', { pimState: gate?.text || 'unknown' });
      // Prove the write token works against Intune with a read; the Graph request id lands in the audit row.
      let probe = 'not run', graphRequestId;
      try {
        const r = await fetcher(GRAPH_PROBE, { headers: { Authorization: `Bearer ${el.accessToken}` }, redirect: 'error', signal: AbortSignal.timeout(15000) });
        probe = `HTTP ${r.status}`;
        graphRequestId = r.headers.get('request-id') || r.headers.get('client-request-id') || undefined;
      } catch (e) { probe = `error: ${e.message}`; }
      const since = now();
      const until = since + config.elevationTtlMinutes * 60000;
      try {
        await audit.record({ ...base, action: 'session.elevate', result: 'ok', target: 'write-session', mode: config.pimMode, pimState: gate ? `${gate.ok ? 'ok' : 'not-active'}: ${gate.text}` : 'unknown',
          acrs: el.acrs, graphRequestId, sessionUntil: new Date(until).toISOString(), detail: { roles, graphProbe: probe, ttlMinutes: config.elevationTtlMinutes } });
      } catch (e) {
        await auth.endWrite(el.homeAccountId).catch(() => {});
        throw Object.assign(new Error('The audit trail is unavailable, so no write session was started.'), { status: 503, audit: true });
      }
      s.write = { homeAccountId: el.homeAccountId, oid: el.oid, since, until, acrs: el.acrs, pim: gate ? { ok: gate.ok, text: gate.text } : null };
      return status(s);
    },

    // Route gate for anything that writes. Fails closed at every step.
    requireWrite({ roles: allowed }) {
      if (!Array.isArray(allowed) || !allowed.length) throw new Error('requireWrite needs the roles that may use the route');
      return async (req, res, next) => {
        const s = req.r360;
        const stop = (code, error, why) => res.status(code).json({ error, code: why });
        try {
          if (!s?.user) return stop(401, 'Sign in required.', 'signin');
          const w = await live(s);
          if (!w) return stop(403, 'Start a write session first.', 'write-required');
          if (w.oid !== s.user.oid) { await end(s, 'oid-mismatch'); return stop(403, 'The write session belongs to a different account.', 'oid-mismatch'); }
          const { roles, approversError } = await resolveRoles(github, s.user.oid);
          if (approversError) return stop(503, 'The approvers list could not be verified, so writes are blocked.', 'approvers-invalid');
          if (!roles.some(r => allowed.includes(r))) return stop(403, 'Your role does not allow this action.', 'role');
          let gate = null;
          try { gate = await pimGate(s); } catch (e) { log.error?.(`pim check failed: ${e.message}`); }
          if (config.pimMode === 'enforce' && !gate?.ok) return stop(403, gate ? gate.text : 'PIM could not be verified.', 'pim');
          // Informational only, and only when PIM was actually evaluated (a failed lookup is logged, not shown as a warning).
          if (gate && !gate.ok) res.locals.pimWarning = `PIM (informational, not enforced): ${gate.text}`;
          req.r360write = w;
          req.r360roles = roles;
          next();
        } catch (e) { log.error?.(`requireWrite: ${e.message}`); stop(503, 'Write access could not be verified.', 'error'); }
      };
    },
  };
}
