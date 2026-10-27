// Pure logic: PIM status for the signed-in user (design 3.2: r360 only reads and links; activation happens in Entra).
export const ROLE_TEMPLATES = {
  globalAdmin: '62e90394-69f5-4237-9190-012177145e10',
  intuneAdmin: '3a2c62db-5318-420d-8d74-23affee5d9d5',
};
export const PIM_ACTIVATE_URL = 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles';

export function summarizePim({ active = [], eligible = [], definitions = [], now = Date.now() }) {
  const defs = new Map(definitions.map(d => [d.id, d]));
  const name = id => defs.get(id)?.displayName || id;
  const tmpl = id => defs.get(id)?.templateId || id;
  const rows = [
    ...active.map(a => ({ role: name(a.roleDefinitionId), templateId: tmpl(a.roleDefinitionId), state: a.assignmentType === 'Activated' ? 'Active (PIM)' : 'Permanent',
      start: a.startDateTime || null, end: a.endDateTime || null, scope: a.directoryScopeId || '/' })),
    ...eligible.map(e => ({ role: name(e.roleDefinitionId), templateId: tmpl(e.roleDefinitionId), state: 'Eligible', start: e.startDateTime || null, end: e.endDateTime || null, scope: e.directoryScopeId || '/' })),
  ].filter(r => !r.end || Date.parse(r.end) > now).sort((a, b) => a.role.localeCompare(b.role) || a.state.localeCompare(b.state));
  const live = rows.filter(r => r.state !== 'Eligible');
  const ga = live.some(r => r.templateId === ROLE_TEMPLATES.globalAdmin);
  const intune = live.find(r => r.templateId === ROLE_TEMPLATES.intuneAdmin);
  const intuneEligible = rows.some(r => r.state === 'Eligible' && r.templateId === ROLE_TEMPLATES.intuneAdmin);
  let gate;
  if (ga) gate = { ok: true, text: 'Global Administrator is active (bypasses PIM; make it eligible in hardening).' };
  else if (intune) gate = { ok: true, text: `Intune Administrator is ${intune.state.toLowerCase()}${intune.end ? ` until ${intune.end}` : ''}.` };
  else gate = { ok: false, text: intuneEligible ? 'Intune Administrator is eligible but not active. Activate it in PIM before Intune writes.' : 'No Intune Administrator assignment. Writes will be blocked once PIM is enforced.' };
  return { rows, gate, activateUrl: PIM_ACTIVATE_URL };
}
