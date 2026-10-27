import { buildCatalog, fleetRows } from './catalog.mjs';
import { profileCertCheck, certDeviceRows } from './certs.mjs';
import { summarizePim } from './pim.mjs';

const HS = '/beta/deviceManagement/deviceHealthScripts';

// Bounded parallelism so one page load does not fan out into hundreds of concurrent Graph calls.
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

export function createData({ graph, github, config }) {
  async function listScripts(token) {
    return graph.all(token, `${HS}?$select=id,displayName,description,publisher,version,runAsAccount,runAs32Bit,enforceSignatureCheck,lastModifiedDateTime`);
  }
  return {
    async remediations(token) {
      const [repo, scripts] = await Promise.all([github.catalog(), listScripts(token)]);
      const full = await mapLimit(scripts, 4, s => graph.get(token, `${HS}/${s.id}`));
      const summaries = new Map();
      await mapLimit(scripts, 4, async s => { try { summaries.set(s.id, await graph.get(token, `${HS}/${s.id}/runSummary`)); } catch { /* no runs yet */ } });
      return { repoSha: repo.sha, repoDate: repo.date, repoMessage: repo.message, rows: buildCatalog({ repoItems: repo.items, intuneScripts: full, summaries, repoSha: repo.sha.slice(0, 8) }) };
    },
    async fleet(token) {
      const scripts = await listScripts(token);
      const per = await mapLimit(scripts, 4, async s => fleetRows(s.displayName, s.id,
        await graph.all(token, `${HS}/${s.id}/deviceRunStates?$expand=managedDevice($select=deviceName,userPrincipalName,osVersion)`)));
      return { rows: per.flat() };
    },
    async certificates(token) {
      const all = await graph.all(token, '/beta/deviceManagement/deviceConfigurations?$select=id,displayName,lastModifiedDateTime');
      const profiles = [];
      for (const [label, name] of [['Trusted Root', config.rootProfile], ['Trusted Publisher', config.publisherProfile]]) {
        const hits = all.filter(p => p.displayName === name);
        if (!hits.length) { profiles.push({ label, name, id: null, ...profileCertCheck(null, config.codesignThumbprint), assignments: [], overview: null, devices: [] }); continue; }
        const p = await graph.get(token, `/beta/deviceManagement/deviceConfigurations/${hits[0].id}`);
        const [assign, statuses, overview] = await Promise.all([
          graph.all(token, `/beta/deviceManagement/deviceConfigurations/${p.id}/assignments`),
          graph.all(token, `/beta/deviceManagement/deviceConfigurations/${p.id}/deviceStatuses`),
          graph.get(token, `/beta/deviceManagement/deviceConfigurations/${p.id}/deviceStatusOverview`).catch(() => null),
        ]);
        const groups = await mapLimit(assign, 4, async a => {
          const gid = a.target?.groupId;
          if (!gid) return a.target?.['@odata.type']?.replace('#microsoft.graph.', '') || 'unknown';
          try { return (await graph.get(token, `/v1.0/groups/${gid}?$select=displayName`)).displayName; } catch { return gid; }
        });
        profiles.push({ label, name, id: p.id, duplicates: hits.length - 1, lastModified: p.lastModifiedDateTime, ...profileCertCheck(p, config.codesignThumbprint), assignments: groups,
          overview: overview && { success: overview.successCount ?? overview.compliantDeviceCount ?? null, error: overview.errorCount ?? overview.errorDeviceCount ?? null, pending: overview.pendingCount ?? null, failed: overview.failedCount ?? null },
          devices: certDeviceRows(label, statuses) });
      }
      return { thumbprint: config.codesignThumbprint, canaryDevice: config.canaryDevice,
        profiles: profiles.map(({ devices, ...rest }) => rest), devices: profiles.flatMap(p => p.devices) };
    },
    async pim(token, oid) {
      const f = encodeURIComponent(`principalId eq '${oid}'`);
      const [active, eligible, definitions] = await Promise.all([
        graph.all(token, `/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=${f}`),
        graph.all(token, `/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=${f}`).catch(() => []),
        graph.all(token, '/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId'),
      ]);
      return summarizePim({ active, eligible, definitions });
    },
  };
}
