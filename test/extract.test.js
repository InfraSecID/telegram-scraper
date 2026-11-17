import test from 'node:test';
import assert from 'node:assert/strict';
import { load } from 'cheerio';
import { createWarnings, extractDocument, extractItem } from '../src/scrape/extract.js';

const html = `
  <div class="item" data-sku="SKU-1">
    <h2><a href="/buku/a">Buku A</a></h2>
    <span class="price">Rp 12.500</span>
    <span class="tag">baru</span>
    <span class="tag">promo</span>
    <p class="attrs" data-id="7">Deskripsi</p>
  </div>
`;

test('extractItem mengambil text, attr, multiple, const, dan transform', () => {
  const $ = load(html);
  const warnings = createWarnings();
  const item = extractItem($, $('.item').get(0), {
    title: { selector: 'h2 a' },
    link: {
      selector: 'h2 a',
      attr: 'href',
      transforms: ['absoluteUrl'],
    },
    price: { selector: '.price', transforms: [{ name: 'number' }] },
    tags: { selector: '.tag', multiple: true },
    dataId: { selector: '.attrs', attr: 'data-id', transforms: ['int'] },
    source: { const: 'demo' },
    missing: { selector: '.tidak-ada' },
  }, { baseUrl: 'https://contoh.com/daftar', warnings });

  assert.equal(item.title, 'Buku A');
  assert.equal(item.link, 'https://contoh.com/buku/a');
  assert.equal(item.price, 12500);
  assert.deepEqual(item.tags, ['baru', 'promo']);
  assert.equal(item.dataId, 7);
  assert.equal(item.source, 'demo');
  assert.equal(item.missing, null);
  assert.ok(warnings.list().some((warning) => warning.includes('missing')));
});

test('extractDocument memakai selector level dokumen', () => {
  const $ = load('<main><h1>Judul Detail</h1><div class="harga">9.999</div></main>');
  const data = extractDocument($, {
    title: { selector: 'h1' },
    price: { selector: '.harga', transforms: [{ name: 'number' }] },
  }, { warnings: createWarnings() });

  assert.deepEqual(data, { title: 'Judul Detail', price: 9999 });
});
