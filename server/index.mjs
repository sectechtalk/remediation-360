import { loadConfig } from './config.mjs';
import { createManagedIdentity, FIC_AUDIENCE } from './identity.mjs';
import { createAuth, SessionStore } from './auth.mjs';
import { createGraph } from './graph.mjs';
import { createGitHubApp } from './github.mjs';
import { createData } from './data.mjs';
import { createApp } from './app.mjs';
import { createAudit } from './audit.mjs';
import { createLlm } from './llm.mjs';
import { servicenowSettings, createServiceNowSearch, createQueryStore, keyVaultSecret, loadPreconfigured } from './servicenow.mjs';

const config = loadConfig();
const miToken = createManagedIdentity({ clientId: config.miClientId });
const github = createGitHubApp({ config, miToken });
const audit = createAudit({ config, miToken });
// ServiceNow search: settings from the environment; the password from a secret reference or, locally, from Key Vault.
const snSettings = servicenowSettings();
let preconfigured = [];
try { preconfigured = loadPreconfigured(); } catch (e) { console.error(e.message); }
const servicenow = deps => createServiceNowSearch({ ...deps, settings: snSettings, preconfigured,
  store: snSettings.configured ? createQueryStore({ account: config.auditAccount, table: snSettings.queryTable, miToken }) : null,
  password: snSettings.passwordSecret ? keyVaultSecret({ vaultUri: config.vaultUri, name: snSettings.passwordSecret, miToken }) : undefined });
// Summary provider key: the app secret (Azure) wins; otherwise, locally, the Key Vault secret named by R360_LLM_API_KEY_SECRET.
const llm = createLlm({ config, apiKey: !config.llm.apiKey && config.llm.apiKeySecret ? keyVaultSecret({ vaultUri: config.vaultUri, name: config.llm.apiKeySecret, miToken }) : null });
const app = createApp({ config, sessions: new SessionStore(), auth: createAuth({ config, miToken }), data: createData({ graph: createGraph(), github, config }), github, audit, servicenow, llm });

app.listen(config.port, config.host, () => console.log(`r360 ${config.imageTag} listening on ${config.port}`));

// Startup self-check (logged, never fatal): proves the managed identity, the federated credential audience, the
// Key Vault sign path and the GitHub App installation without any user data.
(async () => {
  const step = async (name, fn) => { try { console.log(`selfcheck ${name}: PASS ${await fn()}`); } catch (e) { console.log(`selfcheck ${name}: FAIL ${e.message}`); } };
  await step('mi-fic-token', async () => (await miToken(FIC_AUDIENCE)) ? 'token issued' : 'empty');
  await step('audit-store', async () => { const r = await audit.list({ limit: 1 }); return `table ${config.auditTable} readable on ${config.auditAccount}, write app ${config.writeClientId ? 'configured' : 'NOT configured'}, ${r.rows.length ? 'has events' : 'empty'}`; });
  if (config.changeMailbox) await step('llm-key', () => llm.checkKey());
  await step('github-app', async () => { const c = await github.catalog(); return `main ${c.sha.slice(0, 8)}, ${c.items.length} remediation(s), approvers ${c.approvers ? c.approvers.length : 'INVALID'}`; });
})();
