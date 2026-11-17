import test from 'node:test';
import assert from 'node:assert/strict';
import { itemsToCsv } from '../src/util/csv.js';

test('itemsToCsv menulis header union, quoting, dan BOM', () => {
  const csv = itemsToCsv([
    { title: 'Buku, "Spesial"', price: 12000 },
    { title: 'Baris\nBaru', stock: true },
  ]);

  assert.ok(csv.startsWith('\uFEFF'));
  const lines = csv.replace(/^\uFEFF/, '').trimEnd().split('\r\n');
  assert.equal(lines[0], 'title,price,stock');
  assert.equal(lines[1], '"Buku, ""Spesial""",12000,');
  assert.ok(lines[2].startsWith('"Baris\nBaru",,true'));
});

test('itemsToCsv menangani array kosong dan formula injection', () => {
  assert.equal(itemsToCsv([]), '\uFEFF');
  const csv = itemsToCsv([{ name: '=HYPERLINK("x")' }]);
  assert.ok(csv.includes('\'=HYPERLINK'));
});
