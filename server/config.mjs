import { parseDeployTargets, decodeDeployTargets } from './deploy-targets.mjs';

// Configuration from environment variables only. Hosted r360 fails closed: there is no demo mode and no fallback data.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const REQUIRED = ['ENTRA_TENANT_ID', 'R360_WEB_CLIENT_ID', 'AZURE_CLIENT_ID', 'R360_PUBLIC_URL', 'R360_KEY_VAULT_URI',
  'R360_GITHUB_APP_ID', 'R360_GITHUB_INSTALLATION_ID', 'R360_CODESIGN_THUMBPRINT', 'R360_AUDIT_STORAGE_ACCOUNT'];

// Fills derivable values: the Key Vault name set in Phase 0 (R360_KEY_VAULT) and the Container Apps default FQDN
// (CONTAINER_APP_NAME + CONTAINER_APP_ENV_DNS_SUFFIX are injected by the platform).
export function withDefaults(env) {
  const e = { ...env };
  if (!e.R360_KEY_VAULT_URI && /^[a-z0-9-]{3,24}$/i.test(e.R360_KEY_VAULT || '')) e.R360_KEY_VAULT_URI = `https://${e.R360_KEY_VAULT}.vault.azure.net`;
  if (!e.R360_PUBLIC_URL && e.CONTAINER_APP_NAME && e.CONTAINER_APP_ENV_DNS_SUFFIX) e.R360_PUBLIC_URL = `https://${e.CONTAINER_APP_NAME}.${e.CONTAINER_APP_ENV_DNS_SUFFIX}`;
  return e;
}

export function loadConfig(rawEnv = process.env) {
  const env = withDefaults(rawEnv);
  const missing = REQUIRED.filter(k => !String(env[k] || '').trim());
  if (missing.length) throw new Error(`r360 cannot start; missing settings: ${missing.join(', ')}`);
  for (const k of ['ENTRA_TENANT_ID', 'R360_WEB_CLIENT_ID', 'AZURE_CLIENT_ID']) if (!GUID.test(env[k])) throw new Error(`${k} must be a GUID`);
  const publicUrl = new URL(env.R360_PUBLIC_URL);
  // https everywhere except local hosting on this PC: http://localhost:<port> only (browsers treat localhost as a secure
  // context, so the Secure __Host- session cookie still works, and Entra accepts http://localhost redirect URIs).
  const localHttp = publicUrl.protocol === 'http:' && publicUrl.hostname === 'localhost';
  if (publicUrl.protocol !== 'https:' && !localHttp) throw new Error('R360_PUBLIC_URL must be https (or http://localhost:<port> for local hosting)');
  const vault = new URL(env.R360_KEY_VAULT_URI);
  if (vault.protocol !== 'https:' || !/^[a-z0-9-]{3,24}\.vault\.azure\.net$/i.test(vault.hostname)) throw new Error('R360_KEY_VAULT_URI must be https://<name>.vault.azure.net');
  if (env.R360_WRITE_CLIENT_ID && !GUID.test(env.R360_WRITE_CLIENT_ID)) throw new Error('R360_WRITE_CLIENT_ID must be a GUID');
  if (!/^[a-z0-9]{3,24}$/.test(env.R360_AUDIT_STORAGE_ACCOUNT)) throw new Error('R360_AUDIT_STORAGE_ACCOUNT must be a storage account name (3-24 lowercase letters and digits)');
  const auditTable = env.R360_AUDIT_TABLE || 'r360audit';
  const auditContainer = env.R360_AUDIT_EXPORT_CONTAINER || 'r360audit-export';
  if (!/^[A-Za-z][A-Za-z0-9]{2,62}$/.test(auditTable)) throw new Error('R360_AUDIT_TABLE is not a valid table name');
  if (!/^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}$/.test(auditContainer)) throw new Error('R360_AUDIT_EXPORT_CONTAINER is not a valid container name');
  const ttl = Number(env.R360_ELEVATION_TTL_MINUTES || 480);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 480) throw new Error('R360_ELEVATION_TTL_MINUTES must be a whole number from 1 to 480');
  const thumb = String(env.R360_CODESIGN_THUMBPRINT).replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (thumb.length !== 40) throw new Error('R360_CODESIGN_THUMBPRINT must be a SHA-1 thumbprint (40 hex)');
  if (env.R360_CANARY_GROUP_ID && !GUID.test(env.R360_CANARY_GROUP_ID)) throw new Error('R360_CANARY_GROUP_ID must be a GUID');
  if (env.R360_PROD_GROUP_ID && !GUID.test(env.R360_PROD_GROUP_ID)) throw new Error('R360_PROD_GROUP_ID must be a GUID');
  if (env.R360_PROD_GROUP_ID && env.R360_CANARY_GROUP_ID && env.R360_PROD_GROUP_ID.toLowerCase() === env.R360_CANARY_GROUP_ID.toLowerCase()) throw new Error('R360_PROD_GROUP_ID must differ from R360_CANARY_GROUP_ID');
  const soakDays = Number(env.R360_CANARY_SOAK_DAYS ?? 7);
  if (!Number.isInteger(soakDays) || soakDays < 0 || soakDays > 90) throw new Error('R360_CANARY_SOAK_DAYS must be a whole number from 0 to 90');
  const maxOpen = Number(env.R360_MAX_OPEN_CHANGES || 5);
  if (!Number.isInteger(maxOpen) || maxOpen < 1 || maxOpen > 50) throw new Error('R360_MAX_OPEN_CHANGES must be a whole number from 1 to 50');
  const repo = env.R360_REMEDIATIONS_REPO || 'your-org/remediations';
  const deployText = decodeDeployTargets(env.R360_DEPLOY_TARGETS);
  const deployTargets = deployText ? parseDeployTargets(deployText, { owner: repo.split('/')[0] }) : [];
  const cr = changeRequestSettings(env, repo);
  const oneOf = (v, allowed, dflt) => { const x = String(v || dflt).toLowerCase(); if (!allowed.includes(x)) throw new Error(`invalid value ${v}; expected ${allowed.join('|')}`); return x; };
  return Object.freeze({
    tenantId: env.ENTRA_TENANT_ID,
    webClientId: env.R360_WEB_CLIENT_ID,
    miClientId: env.AZURE_CLIENT_ID,
    publicUrl: publicUrl.origin,
    redirectUri: `${publicUrl.origin}/auth/callback`,
    writeClientId: env.R360_WRITE_CLIENT_ID || '',
    writeRedirectUri: `${publicUrl.origin}/auth/write/callback`,
    auditAccount: env.R360_AUDIT_STORAGE_ACCOUNT,
    auditTable,
    auditContainer,
    vaultUri: `https://${vault.hostname}`,
    githubKeyName: env.R360_GITHUB_KEY_NAME || 'github-app-r360',
    githubAppId: String(env.R360_GITHUB_APP_ID),
    githubInstallationId: String(env.R360_GITHUB_INSTALLATION_ID),
    repo,
    deployTargets: Object.freeze(deployTargets),
    branch: env.R360_REMEDIATIONS_BRANCH || 'main',
    codesignThumbprint: thumb,
    rootProfile: env.R360_ROOT_PROFILE || 'r360 - Code Signing - Trusted Root',
    publisherProfile: env.R360_PUB_PROFILE || 'r360 - Code Signing - Trusted Publisher',
    canaryDevice: env.R360_CANARY_DEVICE || 'DEVICE01',
    canaryGroupId: (env.R360_CANARY_GROUP_ID || '').toLowerCase(),
    prodGroupId: (env.R360_PROD_GROUP_ID || '').toLowerCase(),
    canarySoakDays: soakDays,
    maxOpenChanges: maxOpen,
    fourEyes: oneOf(env.R360_FOUR_EYES, ['testing', 'enforced'], 'testing'),
    pimMode: oneOf(env.R360_PIM_MODE, ['warn', 'enforce'], 'warn'),
    elevationTtlMinutes: ttl,
    emergencyWindowMinutes: Number(env.R360_EMERGENCY_WINDOW_MINUTES || 240),
    emergencyMaxDevices: Number(env.R360_EMERGENCY_MAX_DEVICES || 1),
    // Offboard requests (Disable user everywhere, Remove from one app): off = the requester runs it; on = a second person must.
    offboardFourEyes: oneOf(env.R360_OFFBOARD_FOUR_EYES, ['off', 'on'], 'off'),
    port: Number(env.PORT || 8080),
    host: env.HOST || '0.0.0.0',
    imageTag: env.R360_IMAGE_TAG || 'dev',
    ...cr,
  });
}

// Change requests (email-tracked changes). Off unless R360_CHANGE_MAILBOX is set. The tracker is GitHub issues on
// R360_CHANGE_REPO (same owner as the remediations repo, so the same GitHub App installation). The summary provider is
// pluggable; its API key comes from a Container Apps secret that is a Key Vault reference, never from the repo.
export const LLM_PROVIDERS = ['anthropic', 'openai', 'azure-openai'];
const DEFAULT_MODEL = { anthropic: 'claude-opus-5-5', openai: 'gpt-5', 'azure-openai': '' };
export function changeRequestSettings(env, remediationsRepo = 'your-org/remediations') {
  const mailbox = String(env.R360_CHANGE_MAILBOX || '').trim().toLowerCase();
  if (mailbox && !/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(mailbox)) throw new Error('R360_CHANGE_MAILBOX must be an email address');
  const owner = remediationsRepo.split('/')[0];
  const changeRepo = String(env.R360_CHANGE_REPO || `${owner}/r360`).trim();
  if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(changeRepo) || changeRepo.split('/')[0].toLowerCase() !== owner.toLowerCase()) throw new Error(`R360_CHANGE_REPO must be ${owner}/<repo>`);
  const provider = String(env.R360_LLM_PROVIDER || 'anthropic').toLowerCase();
  if (!LLM_PROVIDERS.includes(provider)) throw new Error(`R360_LLM_PROVIDER must be one of ${LLM_PROVIDERS.join('|')}`);
  const model = String(env.R360_LLM_MODEL || DEFAULT_MODEL[provider]).trim();
  if (model && !/^[A-Za-z0-9._:-]{1,100}$/.test(model)) throw new Error('R360_LLM_MODEL is not a valid model name');
  const endpoint = String(env.R360_LLM_ENDPOINT || '').trim();
  if (endpoint && !/^https:\/\/[a-z0-9-]+\.(openai\.azure\.com|cognitiveservices\.azure\.com|services\.ai\.azure\.com)\/?$/i.test(endpoint)) throw new Error('R360_LLM_ENDPOINT must be an https Azure OpenAI endpoint');
  if (provider === 'azure-openai' && mailbox && (!endpoint || !model)) throw new Error('azure-openai needs R360_LLM_ENDPOINT and R360_LLM_MODEL (the deployment name)');
  // Local hosting has no Container Apps secret references: the key is read from this Key Vault secret with the managed identity.
  const apiKeySecret = String(env.R360_LLM_API_KEY_SECRET || '').trim();
  if (apiKeySecret && !/^[A-Za-z0-9-]{1,127}$/.test(apiKeySecret)) throw new Error('R360_LLM_API_KEY_SECRET is not a valid Key Vault secret name');
  return {
    changeMailbox: mailbox,
    changeRepo,
    llm: Object.freeze({ provider, model, endpoint: endpoint.replace(/\/$/, ''), apiKey: String(env.R360_LLM_API_KEY || ''), apiKeySecret }),
  };
}

// Read-only view for the Settings page. Ids only, never tokens.
export function publicSettings(c) {
  return {
    tenantId: c.tenantId, webClientId: c.webClientId, managedIdentityClientId: c.miClientId, publicUrl: c.publicUrl,
    keyVault: c.vaultUri, githubAppId: c.githubAppId, githubInstallationId: c.githubInstallationId, githubKey: c.githubKeyName,
    repo: `${c.repo}@${c.branch}`, codesignThumbprint: c.codesignThumbprint, rootProfile: c.rootProfile, publisherProfile: c.publisherProfile,
    writeClientId: c.writeClientId || null, auditStorage: c.auditAccount, auditTable: c.auditTable, auditExportContainer: c.auditContainer,
    canaryDevice: c.canaryDevice, canaryGroupId: c.canaryGroupId || null, prodGroupId: c.prodGroupId || null, canarySoakDays: c.canarySoakDays, maxOpenChanges: c.maxOpenChanges, fourEyes: c.fourEyes, pimMode: c.pimMode, elevationTtlMinutes: c.elevationTtlMinutes,
    emergencyWindowMinutes: c.emergencyWindowMinutes, emergencyMaxDevices: c.emergencyMaxDevices, offboardFourEyes: c.offboardFourEyes, imageTag: c.imageTag,
    changeMailbox: c.changeMailbox || 'off', changeRepo: c.changeRepo, llmProvider: c.llm.provider, llmModel: c.llm.model || 'not set', llmApiKey: c.llm.apiKey ? 'set (Key Vault reference)' : c.llm.apiKeySecret ? `read from Key Vault secret ${c.llm.apiKeySecret}` : 'NOT set',
    deployTargets: c.deployTargets.length ? c.deployTargets.map(t => `${t.id} (${t.repo} ${t.workflow}, environment ${t.environment})`).join('; ') : 'none', deployFourEyes: 'off',
  };
}
