// Delegated Microsoft Graph reads as the signed-in user. Pages through @odata.nextLink and waits on 429/503 using
// Retry-After automatically (bounded), so no caller ever needs a manual retry.
export const GRAPH = 'https://graph.microsoft.com';

export function createGraph({ fetcher = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), maxRetries = 4 } = {}) {
  async function request(token, url) {
    for (let attempt = 0; ; attempt++) {
      const res = await fetcher(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ConsistencyLevel: 'eventual' }, signal: AbortSignal.timeout(30000) });
      if ((res.status === 429 || res.status === 503 || res.status === 504) && attempt < maxRetries) {
        const ra = Number(res.headers.get('retry-after'));
        await sleep(Math.min(Number.isFinite(ra) && ra > 0 ? ra * 1000 : 2 ** attempt * 1000, 30000));
        continue;
      }
      if (!res.ok) {
        let detail = '';
        try { const j = await res.json(); detail = j?.error?.code ? ` ${j.error.code}` : ''; } catch { /* no body */ }
        const err = new Error(`Graph ${res.status}${detail} for ${new URL(url).pathname}`);
        err.status = res.status;
        throw err;
      }
      return res.json();
    }
  }
  const abs = path => path.startsWith('https://') ? path : `${GRAPH}${path}`;
  return {
    get: (token, path) => request(token, abs(path)),
    async all(token, path, limit = 5000) {
      const out = [];
      let next = abs(path);
      while (next && out.length < limit) {
        if (!next.startsWith(`${GRAPH}/`)) throw new Error('Unexpected nextLink host');
        const page = await request(token, next);
        out.push(...(page.value || []));
        next = page['@odata.nextLink'] || null;
      }
      return out;
    },
  };
}
