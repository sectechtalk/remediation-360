// Reads the shared change mailbox with the signed-in operator's delegated token (Mail.Read.Shared). The operator must have
// Full Access to the mailbox in Exchange Online; nothing here uses an application permission. Mail is read, never moved,
// flagged or deleted, so the mailbox stays the source of truth.
export const GRAPH = 'https://graph.microsoft.com';
export const NUMBER_PREFIX = 'R360-CHG-';
const NUMBER_RE = /\bR360-CHG-0*(\d{1,9})(?!\d)/gi;
export const MAX_SCAN = 1000;
export const MAX_BODY = 20000;

export const changeNumber = n => `${NUMBER_PREFIX}${Number(n)}`;

// Every change number in a piece of text (subject or body). R360-CHG-12 never matches R360-CHG-123.
export function numbersIn(text) {
  const out = new Set();
  for (const m of String(text || '').matchAll(NUMBER_RE)) out.add(Number(m[1]));
  return out;
}

// Plain text for the summary: drop quoted reply history after the usual separators so each email adds only what is new.
export function newPart(body) {
  const text = String(body || '').replace(/\r\n/g, '\n');
  const cut = text.search(/\n(?:-{2,}\s*Original Message\s*-{2,}|_{8,}|From: .+\n(?:Sent|Date): |On .{6,120} wrote:\n)/i);
  return (cut > 0 ? text.slice(0, cut) : text).trim().slice(0, MAX_BODY);
}

export function createMailbox({ config, fetcher = fetch, sleep = ms => new Promise(r => setTimeout(r, ms)) }) {
  const box = encodeURIComponent(config.changeMailbox);
  async function request(token, url) {
    for (let attempt = 0; ; attempt++) {
      const res = await fetcher(url, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', Prefer: 'outlook.body-content-type="text"' },
        redirect: 'error', signal: AbortSignal.timeout(30000),
      });
      if ((res.status === 429 || res.status === 503 || res.status === 504) && attempt < 4) {
        const ra = Number(res.headers.get('retry-after'));
        await sleep(Math.min(Number.isFinite(ra) && ra > 0 ? ra * 1000 : 2 ** attempt * 1000, 30000));
        continue;
      }
      if (!res.ok) {
        let code = '';
        try { code = (await res.json())?.error?.code || ''; } catch { /* no body */ }
        const denied = res.status === 403 || res.status === 404 || code === 'ErrorAccessDenied' || code === 'MailboxNotEnabledForRESTAPI';
        throw Object.assign(new Error(denied
          ? `Your account cannot read ${config.changeMailbox}. It needs Full Access to that shared mailbox (run tools/Set-R360ChangeRequests.ps1 -Apply).`
          : `Reading ${config.changeMailbox} failed: Graph ${res.status} ${code}`.trim()), { status: denied ? 403 : 502, expose: denied });
      }
      return res.json();
    }
  }

  // Messages received at or after `sinceIso`, newest first, at most MAX_SCAN. Drafts are skipped.
  async function messagesSince(token, sinceIso) {
    const q = new URLSearchParams({
      $filter: `receivedDateTime ge ${new Date(sinceIso).toISOString()} and isDraft eq false`,
      $orderby: 'receivedDateTime desc',
      $select: 'id,internetMessageId,subject,from,receivedDateTime,body,hasAttachments,conversationId',
      $top: '100',
    });
    let next = `${GRAPH}/v1.0/users/${box}/messages?${q}`;
    const out = [];
    while (next && out.length < MAX_SCAN) {
      if (!next.startsWith(`${GRAPH}/`)) throw new Error('Unexpected nextLink host');
      const page = await request(token, next);
      for (const m of page.value || []) out.push(toMail(m));
      next = page['@odata.nextLink'] || null;
    }
    return { messages: out, truncated: Boolean(next) };
  }
  return { messagesSince };
}

export function toMail(m) {
  const body = String(m.body?.content || '');
  return {
    id: String(m.internetMessageId || m.id || ''),
    subject: String(m.subject || '(no subject)').slice(0, 300),
    fromName: String(m.from?.emailAddress?.name || '').slice(0, 200),
    fromAddress: String(m.from?.emailAddress?.address || '').toLowerCase().slice(0, 200),
    receivedAt: m.receivedDateTime || null,
    hasAttachments: Boolean(m.hasAttachments),
    body,
    numbers: numbersIn(`${m.subject || ''}\n${body}`),
  };
}
