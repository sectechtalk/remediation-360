import { loadConfig } from './config.mjs';
import { createManagedIdentity, FIC_AUDIENCE } from './identity.mjs';
import { createAuth, SessionStore } from './auth.mjs';
import { createGraph } from './graph.mjs';
import { createGitHubApp } from './github.mjs';
import { createData } from './data.mjs';
import { createApp } from './app.mjs';

const config = loadConfig();
const miToken = createManagedIdentity({ clientId: config.miClientId });
const github = createGitHubApp({ config, miToken });
const app = createApp({ config, sessions: new SessionStore(), auth: createAuth({ config, miToken }), data: createData({ graph: createGraph(), github, config }), github });

app.listen(config.port, config.host, () => console.log(`r360 ${config.imageTag} listening on ${config.port}`));

// Startup self-check (logged, never fatal): proves the managed identity, the federated credential audience, the
// Key Vault sign path and the GitHub App installation without any user data.
(async () => {
  const step = async (name, fn) => { try { console.log(`selfcheck ${name}: PASS ${await fn()}`); } catch (e) { console.log(`selfcheck ${name}: FAIL ${e.message}`); } };
  await step('mi-fic-token', async () => (await miToken(FIC_AUDIENCE)) ? 'token issued' : 'empty');
  await step('github-app', async () => { const c = await github.catalog(); return `main ${c.sha.slice(0, 8)}, ${c.items.length} remediation(s), approvers ${c.approvers ? c.approvers.length : 'INVALID'}`; });
})();
