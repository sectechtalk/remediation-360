#!/usr/bin/env node
// Builds the Chaos Monkey detect.ps1 scripts. Each test body lives in chaos/tests/<ID>.ps1 and names the helper regions
// it needs on its first line ("# uses: Ad, Smb"); the shared helpers live in chaos/lib.ps1. Intune runs one
// self-contained file, so this copies the Base region, the named regions (and the regions they need) and the body into
// one script per test:
//   chaos/dist/<ID>.detect.ps1   the exact file r360 proposes (PSScriptAnalyzer checks these in CI)
//   public/chaos-scripts.js      the same scripts for the New remediation form
// Run `node tools/build-chaos.mjs` after editing chaos/, and commit the output. `--check` only reports whether the
// output is up to date (tests/chaos.test.mjs runs it).
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { CHAOS_TESTS } from '../public/chaos-list.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TIER = { probe: 'Active probe', local: 'Configuration check: this machine', ad: 'Configuration check: AD objects' };
// Regions a region calls into. Order of output follows chaos/lib.ps1.
// A Windows checkout can turn LF into CRLF; the build reads and compares LF only, so the output is the same everywhere.
const lf = text => text.replace(/\r\n/g, '\n');
const NEEDS = { Sysvol: ['Ad'], Ca: ['Ad'], Sync: ['Ad'], Pki: ['Ad', 'Ca'], NtlmShare: ['Reg'] };

export function readRegions(libText) {
  const regions = new Map();
  const re = /^#region (\w+)\n([\s\S]*?)^#endregion\n/gm;
  for (const m of libText.matchAll(re)) regions.set(m[1], `#region ${m[1]}\n${m[2]}#endregion\n`);
  return regions;
}

export function buildScript(test, body, regions) {
  const [id, tier, group, name, proves] = test;
  const first = body.split('\n', 1)[0];
  const m = /^# uses:(.*)$/.exec(first);
  if (!m) throw new Error(`chaos/tests/${id}.ps1: the first line must be "# uses: <regions>"`);
  const want = new Set(['Base']);
  const add = r => {
    if (!regions.has(r)) throw new Error(`chaos/tests/${id}.ps1: unknown region "${r}"`);
    if (want.has(r)) return;
    want.add(r);
    for (const n of NEEDS[r] || []) add(n);
  };
  for (const r of m[1].split(',').map(s => s.trim()).filter(Boolean)) add(r);
  const rest = body.slice(first.length + 1).replace(/\s+$/, '');
  const indented = rest.split('\n').map(l => (l ? `    ${l}` : l)).join('\n');
  return [
    `# STT - Chaos - ${id} ${name}`,
    `# ${TIER[tier]} (${group}). Proves: ${proves}`,
    '# Chaos Monkey test from HeatMap 360. It only reads and asks: it never changes this machine or any other.',
    '# Exit 0 = PASS (proved hardened). Exit 1 = FAIL or COULD NOT TEST. The first line of output is the verdict.',
    `# Built from chaos/tests/${id}.ps1 and chaos/lib.ps1 in r360 by tools/build-chaos.mjs.`,
    '',
    ...[...regions.keys()].filter(r => want.has(r)).map(r => regions.get(r)),
    `$script:ChaosId = '${id}'`,
    'try {',
    indented,
    '} catch {',
    "    Write-Verdict -Verdict 'COULD NOT TEST' -Summary \"the test stopped: $($_.Exception.Message)\"",
    '}',
    '',
  ].join('\n');
}

export function buildAll() {
  const regions = readRegions(lf(readFileSync(join(ROOT, 'chaos/lib.ps1'), 'utf8')));
  const out = {};
  for (const t of CHAOS_TESTS) {
    const f = join(ROOT, 'chaos/tests', `${t[0]}.ps1`);
    if (!existsSync(f)) throw new Error(`missing chaos/tests/${t[0]}.ps1`);
    out[t[0]] = buildScript(t, lf(readFileSync(f, 'utf8')), regions);
  }
  const extra = readdirSync(join(ROOT, 'chaos/tests')).map(f => f.replace(/\.ps1$/, '')).filter(id => !out[id]);
  if (extra.length) throw new Error(`chaos/tests has scripts for unknown ids: ${extra.join(', ')}`);
  const js = '// Built by tools/build-chaos.mjs from chaos/tests/*.ps1 and chaos/lib.ps1. Do not edit by hand.\n'
    + `export const CHAOS_DETECT = ${JSON.stringify(out, null, 1)};\n`;
  return { scripts: out, js };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { scripts, js } = buildAll();
  const check = process.argv.includes('--check');
  const stale = [];
  const put = (rel, text) => {
    const f = join(ROOT, rel);
    if ((existsSync(f) ? lf(readFileSync(f, 'utf8')) : null) === text) return;
    if (check) stale.push(rel); else { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); }
  };
  for (const [id, s] of Object.entries(scripts)) put(`chaos/dist/${id}.detect.ps1`, s);
  put('public/chaos-scripts.js', js);
  if (check && stale.length) { console.error(`Out of date, run node tools/build-chaos.mjs: ${stale.join(', ')}`); process.exit(1); }
  console.log(check ? 'Chaos Monkey scripts are up to date.' : `Built ${Object.keys(scripts).length} Chaos Monkey scripts.`);
}
