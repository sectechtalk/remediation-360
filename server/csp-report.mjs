// Trusted Types in report-only mode (Modern Web Guidance: security 2.2 and 3.3, trusted-types).
// The browser reports every place a page script hands a plain string to an HTML or script sink (innerHTML,
// insertAdjacentHTML, ...), without blocking anything. Reports go to POST /csp-report, which keeps a short,
// de-duplicated list and logs each new one once. When the list stops growing, the policy can be enforced.
import express from 'express';

export const REPORT_PATH = '/csp-report';
// report-uri, not report-to: Chrome delivers report-uri reports at once to a same-origin path, while report-to needs an
// absolute Reporting-Endpoints URL and batches. Every browser that enforces Trusted Types still honours report-uri.
export const REPORT_ONLY_POLICY = `require-trusted-types-for 'script'; report-uri ${REPORT_PATH}`;
const MAX_KEYS = 200;

// One report body (legacy application/csp-report or Reporting API application/reports+json) to short records.
// Only the page path, script file, line and sink are kept: never query strings or the sample text, which can hold data.
export function parseReports(body) {
  const items = Array.isArray(body) ? body.map(r => r?.body).filter(Boolean) : body?.['csp-report'] ? [body['csp-report']] : [];
  return items.map(r => {
    const path = u => { try { return new URL(u).pathname; } catch { return ''; } };
    const sample = String(r.sample ?? r['script-sample'] ?? '');
    return {
      directive: String(r.effectiveDirective ?? r['effective-directive'] ?? r['violated-directive'] ?? ''),
      page: path(r.documentURL ?? r['document-uri']),
      file: path(r.sourceFile ?? r['source-file']),
      line: Number(r.lineNumber ?? r['line-number']) || 0,
      sink: sample.split('|')[0].trim().slice(0, 60),
    };
  }).filter(r => /trusted-types/.test(r.directive));
}

export function createCspReports({ log = line => console.log(line) } = {}) {
  const seen = new Map();
  const add = r => {
    const key = `${r.file}:${r.line}:${r.sink}`;
    const hit = seen.get(key);
    if (hit) { hit.count++; return; }
    if (seen.size >= MAX_KEYS) return;
    seen.set(key, { ...r, count: 1 });
    log(`[trusted-types report-only] ${r.sink || 'sink'} at ${r.file || '?'}:${r.line} (page ${r.page || '?'})`);
  };
  const router = express.Router();
  router.post(REPORT_PATH, express.json({ type: ['application/csp-report', 'application/reports+json', 'application/json'], limit: '16kb' }), (req, res) => {
    for (const r of parseReports(req.body)) add(r);
    res.status(204).end();
  });
  return { router, list: () => [...seen.values()] };
}
