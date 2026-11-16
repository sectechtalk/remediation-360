export const ENV = { ENTRA_TENANT_ID: 'b4000000-0000-4000-8000-0000000000c1', R360_WEB_CLIENT_ID: '29400000-0000-4000-8000-0000000000c5', AZURE_CLIENT_ID: '11111111-2222-4333-8444-555555555555',
  R360_PUBLIC_URL: 'https://app-r360.example.westus3.azurecontainerapps.io', R360_KEY_VAULT_URI: 'https://kv-r360-abc123.vault.azure.net/', R360_GITHUB_APP_ID: '1234567',
  R360_GITHUB_INSTALLATION_ID: '12345678', R360_CODESIGN_THUMBPRINT: 'DCFE9BD52139FB88200D26B420D25E5C41C00780',
  R360_WRITE_CLIENT_ID: '29400000-0000-4000-8000-0000000000c6', R360_AUDIT_STORAGE_ACCOUNT: 'str360test01' };

// The two Intune code-signing profiles behind a fake Graph fetcher. Both carry the fixture thumbprint in a TrustedPublisher
// OMA-URI (the Trusted Root profile is a certificate blob in real life; its SHA-1 cannot be made to equal a fixed thumbprint).
// handle() answers /beta/deviceManagement/deviceConfigurations[...] and returns undefined for anything else.
export function signingProfiles({ thumbprint = ENV.R360_CODESIGN_THUMBPRINT, canary, names = ['r360 - Code Signing - Trusted Root', 'r360 - Code Signing - Trusted Publisher'] } = {}) {
  const sp = { profiles: new Map(), assigns: new Map(), posts: [] };
  names.forEach((displayName, i) => {
    const id = `cfg-${i + 1}`;
    sp.profiles.set(id, { id, displayName, '@odata.type': '#microsoft.graph.windows10CustomConfiguration',
      omaSettings: [{ omaUri: `./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/${thumbprint}/EncodedCertificate` }] });
    sp.assigns.set(id, canary ? [{ id: 'a0', target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: canary } }] : []);
  });
  sp.handle = (method, pathname, body, json, rid) => {
    const m = /^\/beta\/deviceManagement\/deviceConfigurations(?:\/([^/]+)(\/assignments|\/assign)?)?$/.exec(pathname);
    if (!m) return undefined;
    const [, id, sub] = m;
    if (!id && method === 'GET') return json(200, { value: [...sp.profiles.values()].map(({ id: i, displayName }) => ({ id: i, displayName })) }, rid);
    if (!sp.profiles.has(id)) return json(404, { error: { code: 'NotFound', message: 'gone' } }, rid);
    if (!sub && method === 'GET') return json(200, sp.profiles.get(id), rid);
    if (sub === '/assignments' && method === 'GET') return json(200, { value: sp.assigns.get(id) }, rid);
    if (sub === '/assign' && method === 'POST') { sp.posts.push({ id, body }); sp.assigns.set(id, body.assignments.map((a, i) => ({ id: `a${i}`, ...a }))); return json(200, {}, rid); }
    return json(405, { error: { code: 'MethodNotAllowed', message: 'x' } }, rid);
  };
  // Group ids (lowercase) and 'allDevices' each profile is assigned to now.
  sp.targets = id => sp.assigns.get(id).map(a => a.target.groupId ? a.target.groupId.toLowerCase() : a.target['@odata.type'].replace('#microsoft.graph.', '').replace('AssignmentTarget', ''));
  return sp;
}
