import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSources } from '../src/sources.js';

test('semua config contoh valid', () => {
  const { sources, errors } = loadSources('config/sources');
  assert.deepEqual(errors, []);
  assert.ok(sources.has('books-demo'));
  assert.ok(sources.has('quotes-demo'));
  assert.equal(sources.get('books-demo').request.maxPages, 3);
});
