import test from 'node:test';
import assert from 'node:assert/strict';
import { applyTransforms, parseNumber } from '../src/scrape/transforms.js';

test('parseNumber mendukung format Indonesia & internasional', () => {
  assert.equal(parseNumber('£51.77'), 51.77);
  assert.equal(parseNumber('Rp 1.234.567'), 1234567);
  assert.equal(parseNumber('1,234.56'), 1234.56);
  assert.equal(parseNumber('1.234,56'), 1234.56);
  assert.equal(parseNumber('1,5'), 1.5);
  assert.equal(parseNumber('12.500'), 12500);
  assert.equal(parseNumber('-2.500,75'), -2500.75);
  assert.equal(parseNumber('gratis'), null);
  assert.equal(parseNumber(null), null);
});

test('applyTransforms berantai dan mendukung args', () => {
  assert.equal(applyTransforms('  Rp 1.234,56 ', ['trim', { name: 'number' }], {}), 1234.56);
  assert.equal(applyTransforms('Halo Dunia', ['lowercase'], {}), 'halo dunia');
  assert.equal(applyTransforms('teks', ['uppercase', { name: 'prefix', value: 'X-' }], {}), 'X-TEKS');
  assert.equal(
    applyTransforms('/buku/1', ['absoluteUrl'], { baseUrl: 'https://contoh.com/daftar' }),
    'https://contoh.com/buku/1',
  );
  assert.equal(
    applyTransforms('judul - 2024', [
      { name: 'regex', pattern: '- (\\d{4})$', group: 1 },
      'int',
    ], {}),
    2024,
  );
});

test('transform default menyelamatkan nilai kosong', () => {
  assert.equal(applyTransforms(null, [{ name: 'default', value: '-' }], {}), '-');
  assert.equal(applyTransforms('', ['trim', { name: 'default', value: 'N/A' }], {}), 'N/A');
  assert.equal(applyTransforms(null, ['trim'], {}), null);
});

test('transform replace dan date', () => {
  assert.equal(
    applyTransforms('harga 100 rb', [{ name: 'replace', pattern: '\\s*rb', replacement: '.000' }], {}),
    'harga 100.000',
  );
  assert.equal(applyTransforms('2024-01-02', ['date'], {}), '2024-01-02T00:00:00.000Z');
  assert.equal(applyTransforms('bukan tanggal', ['date'], {}), null);
});
