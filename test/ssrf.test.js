import test from 'node:test';
import assert from 'node:assert/strict';
import { assertPublicUrl, isPublicIp, SsrfError } from '../src/util/ssrf.js';

test('isPublicIp membedakan IP publik dan internal', () => {
  assert.equal(isPublicIp('8.8.8.8'), true);
  assert.equal(isPublicIp('1.1.1.1'), true);
  assert.equal(isPublicIp('127.0.0.1'), false);
  assert.equal(isPublicIp('10.0.0.5'), false);
  assert.equal(isPublicIp('172.16.0.1'), false);
  assert.equal(isPublicIp('192.168.1.10'), false);
  assert.equal(isPublicIp('169.254.169.254'), false);
  assert.equal(isPublicIp('100.64.0.1'), false);
  assert.equal(isPublicIp('0.0.0.0'), false);
  assert.equal(isPublicIp('::1'), false);
  assert.equal(isPublicIp('fd00::1'), false);
  assert.equal(isPublicIp('2001:4860:4860::8888'), true);
  assert.equal(isPublicIp('bukan-ip'), false);
});

test('assertPublicUrl menolak protocol dan hostname internal', async () => {
  await assert.rejects(() => assertPublicUrl('file:///etc/passwd'), SsrfError);
  await assert.rejects(() => assertPublicUrl('gopher://example.com/'), SsrfError);
  await assert.rejects(() => assertPublicUrl('http://localhost:3000/'), SsrfError);
  await assert.rejects(() => assertPublicUrl('http://metadata.google.internal/'), SsrfError);
  await assert.rejects(() => assertPublicUrl('http://127.0.0.1/'), SsrfError);
  await assert.rejects(() => assertPublicUrl('http://[::1]/'), SsrfError);
  await assert.rejects(() => assertPublicUrl('http://user:pass@example.com/'), SsrfError);
});
