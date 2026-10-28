import test from 'node:test';
import assert from 'node:assert/strict';
import { fourEyes, samePerson, MODES, STEPS } from '../server/foureyes.mjs';

const A = '94540000-0000-4000-8000-0000000000c3';
const U = '0d000000-0000-4000-8000-0000000000c4';

test('four-eyes matrix: mode x same/different person x step', () => {
  const rows = [
    // mode, step, author, actor, approval, allowed, selfApproved
    ['testing', 'approve', A, A, null, true, true],
    ['testing', 'approve', A, U, null, true, false],
    ['enforced', 'approve', A, A, null, false, false],
    ['enforced', 'approve', A, U, null, true, false],
    ['testing', 'merge', A, A, { approverOid: A }, true, true],
    ['testing', 'merge', A, A, { approverOid: U }, true, false],
    ['testing', 'merge', A, U, { approverOid: A }, true, true],
    ['enforced', 'merge', A, A, { approverOid: U }, true, false],
    ['enforced', 'merge', A, U, { approverOid: U }, true, false],
    ['enforced', 'merge', A, U, { approverOid: A }, false, false],
    ['enforced', 'merge', A, A, { approverOid: A }, false, false],
    ['testing', 'publish', A, A, null, true, true],
    ['testing', 'publish', A, U, null, true, false],
    ['enforced', 'publish', A, A, null, false, false],
    ['enforced', 'publish', A, U, null, true, false],
  ];
  for (const [mode, step, authorOid, actorOid, approval, allowed, selfApproved] of rows) {
    const r = fourEyes({ mode, step, authorOid, actorOid, approval });
    assert.equal(r.allowed, allowed, `${mode} ${step} author=${authorOid.slice(0, 4)} actor=${actorOid.slice(0, 4)} approval=${JSON.stringify(approval)}`);
    assert.equal(r.selfApproved, selfApproved, `${mode} ${step} selfApproved`);
    if (!allowed) assert.ok(r.reason && r.message, 'a denial says why');
  }
});

test('four-eyes: merge needs an approval, whatever the mode', () => {
  for (const mode of MODES) {
    assert.equal(fourEyes({ mode, step: 'merge', authorOid: A, actorOid: U }).reason, 'not-approved');
    assert.equal(fourEyes({ mode, step: 'merge', authorOid: A, actorOid: U, approval: {} }).allowed, false);
  }
});

test('four-eyes: an unknown mode, step or missing id is denied, never allowed by default', () => {
  assert.equal(fourEyes({ mode: 'off', step: 'approve', authorOid: A, actorOid: U }).reason, 'unknown-mode');
  assert.equal(fourEyes({ mode: undefined, step: 'approve', authorOid: A, actorOid: U }).allowed, false);
  assert.equal(fourEyes({ mode: 'testing', step: 'deploy', authorOid: A, actorOid: U }).reason, 'unknown-step');
  for (const step of STEPS) {
    for (const [authorOid, actorOid] of [['', U], [A, ''], [null, U], [A, undefined], ['  ', U]]) {
      assert.equal(fourEyes({ mode: 'testing', step, authorOid, actorOid, approval: { approverOid: U } }).reason, 'unknown-person', `${step} ${authorOid}/${actorOid}`);
    }
  }
});

test('samePerson compares object ids case-insensitively and never matches empty values', () => {
  assert.equal(samePerson(A, A.toUpperCase()), true);
  assert.equal(samePerson(A, U), false);
  assert.equal(samePerson('', ''), false);
  assert.equal(samePerson(null, undefined), false);
});
