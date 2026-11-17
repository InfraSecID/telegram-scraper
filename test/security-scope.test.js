import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildScopeRegex,
  isHostAllowed,
  isParameterizedUrl,
  normalizeTarget,
  parseAllowedDomains,
  SecurityError,
} from '../src/security/scope.js';

test('parseAllowedDomains menormalkan domain, wildcard, URL, dan IP', () => {
  const scope = parseAllowedDomains(
    'example.com, *.contoh.id, https://api.test.local, 203.0.113.7, EXAMPLE.COM',
  );
  assert.deepEqual(scope, [
    'example.com',
    '*.contoh.id',
    'api.test.local',
    '203.0.113.7',
  ]);
  assert.deepEqual(parseAllowedDomains(''), []);
});

test('parseAllowedDomains menolak entri tidak valid', () => {
  assert.throws(() => parseAllowedDomains('bukan_domain!'), SecurityError);
  assert.throws(() => parseAllowedDomains('https://'), SecurityError);
});

test('isHostAllowed membatasi apex, subdomain, wildcard, dan IP', () => {
  const scope = parseAllowedDomains('example.com,*.contoh.id,203.0.113.7');
  assert.equal(isHostAllowed('example.com', scope), true);
  assert.equal(isHostAllowed('api.example.com', scope), true);
  assert.equal(isHostAllowed('attacker-example.com', scope), false);
  assert.equal(isHostAllowed('contoh.id', scope), false);
  assert.equal(isHostAllowed('app.contoh.id', scope), true);
  assert.equal(isHostAllowed('203.0.113.7', scope), true);
  assert.equal(isHostAllowed('203.0.113.8', scope), false);
  assert.equal(isHostAllowed('example.com.evil.test', scope), false);
});

test('normalizeTarget menambah https dan membuang fragment', () => {
  const scope = parseAllowedDomains('example.com');
  const target = normalizeTarget('example.com/path?x=1#section', scope);
  assert.equal(target.url, 'https://example.com/path?x=1');
  assert.equal(target.host, 'example.com');
  assert.equal(target.origin, 'https://example.com');
  assert.equal(target.hasQuery, true);
  assert.equal(target.queryParamCount, 1);
});

test('normalizeTarget menolak target di luar scope dan protocol berbahaya', () => {
  const scope = parseAllowedDomains('example.com');
  assert.throws(
    () => normalizeTarget('https://evil.test/', scope),
    (error) => error instanceof SecurityError && error.code === 'target_out_of_scope' && error.status === 403,
  );
  assert.throws(
    () => normalizeTarget('file:///etc/passwd', scope),
    (error) => error instanceof SecurityError && error.code === 'invalid_target',
  );
  assert.throws(
    () => normalizeTarget('https://user:pass@example.com/', scope),
    (error) => error instanceof SecurityError && error.code === 'invalid_target',
  );
});

test('buildScopeRegex hanya cocok dengan host dalam scope', () => {
  const regex = new RegExp(buildScopeRegex(parseAllowedDomains('example.com')));
  assert.equal(regex.test('https://example.com/path'), true);
  assert.equal(regex.test('https://api.example.com/path'), true);
  assert.equal(regex.test('https://example.com.evil.test/path'), false);
  assert.equal(regex.test('https://evil.test/?next=example.com'), false);
  assert.equal(buildScopeRegex([]), null);
});

test('isParameterizedUrl mendeteksi query string', () => {
  assert.equal(isParameterizedUrl('https://example.com/?id=1'), true);
  assert.equal(isParameterizedUrl('https://example.com/path'), false);
  assert.equal(isParameterizedUrl('bukan-url'), false);
});
