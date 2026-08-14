import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeTitle,
  registrableHost,
  findDuplicateGroups,
  findReusedPasswords,
} from '../duplicates.js';

test('normalizeTitle: lowercases, trims and collapses spaces', () => {
  assert.equal(normalizeTitle('  GitHub   Corp  '), 'github corp');
});

test('registrableHost: strips www and survives bad urls', () => {
  assert.equal(registrableHost('https://www.github.com/login'), 'github.com');
  assert.equal(registrableHost('github.com'), 'github.com');
  assert.equal(registrableHost('not a url at all :::'), '');
});

function it(id, title, username, url, extra = {}) {
  return { id, vaultId: 'v1', vaultName: 'V', data: { type: 'login', title, username, url, ...extra } };
}

test('findDuplicateGroups: same title+user+host groups despite case/www/spacing', () => {
  const groups = findDuplicateGroups([
    it('a', 'GitHub', 'bob', 'https://www.github.com'),
    it('b', '  github ', 'bob', 'https://github.com/login'),
    it('c', 'GitHub', 'alice', 'https://github.com'),
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].map(x => x.id).sort(), ['a', 'b']);
});

test('findDuplicateGroups: missing url/username still group when equal', () => {
  const groups = findDuplicateGroups([
    it('a', 'Router', '', undefined),
    it('b', 'router', '', undefined),
  ]);
  assert.equal(groups.length, 1);
});

test('findDuplicateGroups: non-login types are ignored', () => {
  const note = { id: 'n', vaultId: 'v1', vaultName: 'V', data: { type: 'note', title: 'X' } };
  const groups = findDuplicateGroups([note, { ...note, id: 'n2' }]);
  assert.equal(groups.length, 0);
});

test('findReusedPasswords: groups by password, ignores empties', () => {
  const items = [
    it('a', 'A', 'u1', '', { password: 'shared' }),
    it('b', 'B', 'u2', '', { password: 'shared' }),
    it('c', 'C', 'u3', '', { password: 'unique' }),
    it('d', 'D', 'u4', '', { password: '' }),
  ];
  const reused = findReusedPasswords(items);
  assert.equal(reused.size, 1);
  assert.deepEqual([...reused.get('shared')].map(x => x.id).sort(), ['a', 'b']);
});
