// Configuration from environment variables only. Hosted r360 fails closed: there is no demo mode and no fallback data.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const REQUIRED = ['ENTRA_TENANT_ID', 'R360_WEB_CLIENT_ID', 'AZURE_CLIENT_ID', 'R360_PUBLIC_URL', 'R360_KEY_VAULT_URI',
  'R360_GITHUB_APP_ID', 'R360_GITHUB_INSTALLATION_ID', 'R360_CODESIGN_THUMBPRINT'];

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
  if (publicUrl.protocol !== 'https:') throw new Error('R360_PUBLIC_URL must be https');
  const vault = new URL(env.R360_KEY_VAULT_URI);
  if (vault.protocol !== 'https:' || !/^[a-z0-9-]{3,24}\.vault\.azure\.net$/i.test(vault.hostname)) throw new Error('R360_KEY_VAULT_URI must be https://<name>.vault.azure.net');
  const thumb = String(env.R360_CODESIGN_THUMBPRINT).replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (thumb.length !== 40) throw new Error('R360_CODESIGN_THUMBPRINT must be a SHA-1 thumbprint (40 hex)');
  const oneOf = (v, allowed, dflt) => { const x = String(v || dflt).toLowerCase(); if (!allowed.includes(x)) throw new Error(`invalid value ${v}; expected ${allowed.join('|')}`); return x; };
  return Object.freeze({
    tenantId: env.ENTRA_TENANT_ID,
    webClientId: env.R360_WEB_CLIENT_ID,
    miClientId: env.AZURE_CLIENT_ID,
    publicUrl: publicUrl.origin,
    redirectUri: `${publicUrl.origin}/auth/callback`,
    vaultUri: `https://${vault.hostname}`,
    githubKeyName: env.R360_GITHUB_KEY_NAME || 'github-app-r360',
    githubAppId: String(env.R360_GITHUB_APP_ID),
    githubInstallationId: String(env.R360_GITHUB_INSTALLATION_ID),
    repo: env.R360_REMEDIATIONS_REPO || 'your-org/remediations',
    branch: env.R360_REMEDIATIONS_BRANCH || 'main',
    codesignThumbprint: thumb,
    rootProfile: env.R360_ROOT_PROFILE || 'r360 - Code Signing - Trusted Root',
    publisherProfile: env.R360_PUB_PROFILE || 'r360 - Code Signing - Trusted Publisher',
    canaryDevice: env.R360_CANARY_DEVICE || 'DEVICE01',
    fourEyes: oneOf(env.R360_FOUR_EYES, ['testing', 'enforced'], 'testing'),
    pimMode: oneOf(env.R360_PIM_MODE, ['warn', 'enforce'], 'warn'),
    elevationTtlMinutes: Number(env.R360_ELEVATION_TTL_MINUTES || 480),
    emergencyWindowMinutes: Number(env.R360_EMERGENCY_WINDOW_MINUTES || 240),
    emergencyMaxDevices: Number(env.R360_EMERGENCY_MAX_DEVICES || 1),
    port: Number(env.PORT || 8080),
    host: env.HOST || '0.0.0.0',
    imageTag: env.R360_IMAGE_TAG || 'dev',
  });
}

// Read-only view for the Settings page. Ids only, never tokens.
export function publicSettings(c) {
  return {
    tenantId: c.tenantId, webClientId: c.webClientId, managedIdentityClientId: c.miClientId, publicUrl: c.publicUrl,
    keyVault: c.vaultUri, githubAppId: c.githubAppId, githubInstallationId: c.githubInstallationId, githubKey: c.githubKeyName,
    repo: `${c.repo}@${c.branch}`, codesignThumbprint: c.codesignThumbprint, rootProfile: c.rootProfile, publisherProfile: c.publisherProfile,
    canaryDevice: c.canaryDevice, fourEyes: c.fourEyes, pimMode: c.pimMode, elevationTtlMinutes: c.elevationTtlMinutes,
    emergencyWindowMinutes: c.emergencyWindowMinutes, emergencyMaxDevices: c.emergencyMaxDevices, imageTag: c.imageTag,
  };
}
