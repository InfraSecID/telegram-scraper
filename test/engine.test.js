import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { scrapeSource } from '../src/scrape/engine.js';

function renderPage(items, nextHref) {
  const cards = items
    .map(
      (item) => `
    <article class="item">
      <h2><a href="${item.href}">${item.title}</a></h2>
      <span class="price">${item.price}</span>
    </article>`,
    )
    .join('');
  const next = nextHref ? `<a class="next" href="${nextHref}">Next</a>` : '';
  return `<!doctype html><html><body>${cards}${next}</body></html>`;
}

async function withServer(routes, callback) {
  const server = http.createServer((req, res) => {
    const route = routes.get(req.url);
    if (!route) {
      res.statusCode = 404;
      res.setHeader('content-type', 'text/plain');
      res.end('not found');
      return;
    }
    res.setHeader('content-type', route.contentType ?? 'text/html; charset=utf-8');
    res.end(route.body);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    return await callback(baseUrl);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

function baseSource(overrides = {}) {
  return {
    id: 'test',
    name: 'Test',
    enabled: true,
    maxItems: 20,
    list: { selector: 'article.item', limit: 20 },
    fields: {
      title: { selector: 'h2 a' },
      link: { selector: 'h2 a', attr: 'href', transforms: ['absoluteUrl'] },
      price: { selector: '.price', transforms: [{ name: 'number' }] },
    },
    ...overrides,
  };
}

test('pagination nextSelector, dedupe, dan limit', async () => {
  const routes = new Map([
    [
      '/page/1',
      {
        body: renderPage(
          [
            { href: '/b/1', title: 'Buku 1', price: 'Rp 10.000' },
            { href: '/b/2', title: 'Buku 2', price: 'Rp 20.000' },
          ],
          '/page/2',
        ),
      },
    ],
    [
      '/page/2',
      {
        body: renderPage([
          { href: '/b/2', title: 'Buku 2', price: 'Rp 20.000' },
          { href: '/b/3', title: 'Buku 3', price: 'Rp 30.000' },
        ]),
      },
    ],
  ]);

  await withServer(routes, async (baseUrl) => {
    const source = baseSource({
      request: {
        url: `${baseUrl}/page/1`,
        nextSelector: 'a.next',
        maxPages: 3,
        delayMs: 0,
        timeoutMs: 5000,
        headers: {},
      },
    });

    const result = await scrapeSource(source, {
      respectRobots: false,
      userAgent: 'test',
      maxItems: 20,
    });

    assert.equal(result.items.length, 3);
    assert.equal(result.meta.pagesFetched, 2);
    assert.equal(result.meta.duplicatesSkipped, 1);
    assert.deepEqual(
      result.items.map((item) => item.title),
      ['Buku 1', 'Buku 2', 'Buku 3'],
    );
    assert.equal(result.items[0].price, 10000);
    assert.equal(result.items[0].link, `${baseUrl}/b/1`);
  });
});

test('limit menghentikan scraping lebih awal', async () => {
  const routes = new Map([
    [
      '/page/1',
      {
        body: renderPage(
          [
            { href: '/b/1', title: 'Buku 1', price: '1' },
            { href: '/b/2', title: 'Buku 2', price: '2' },
          ],
          '/page/2',
        ),
      },
    ],
  ]);

  await withServer(routes, async (baseUrl) => {
    const source = baseSource({
      request: {
        url: `${baseUrl}/page/1`,
        nextSelector: 'a.next',
        maxPages: 3,
        delayMs: 0,
        headers: {},
      },
    });

    const result = await scrapeSource(source, {
      limit: 1,
      respectRobots: false,
      userAgent: 'test',
      maxItems: 20,
    });

    assert.equal(result.items.length, 1);
    assert.equal(result.meta.pagesFetched, 1);
  });
});

test('pagination placeholder {page}', async () => {
  const routes = new Map([
    [
      '/tpl-1.html',
      { body: renderPage([{ href: '/b/1', title: 'Satu', price: '1' }]) },
    ],
    [
      '/tpl-2.html',
      { body: renderPage([{ href: '/b/2', title: 'Dua', price: '2' }]) },
    ],
  ]);

  await withServer(routes, async (baseUrl) => {
    const source = baseSource({
      request: {
        url: `${baseUrl}/tpl-{page}.html`,
        startPage: 1,
        maxPages: 2,
        delayMs: 0,
        headers: {},
      },
    });

    const result = await scrapeSource(source, {
      respectRobots: false,
      userAgent: 'test',
      maxItems: 20,
    });

    assert.equal(result.meta.pagesFetched, 2);
    assert.deepEqual(
      result.items.map((item) => item.title),
      ['Satu', 'Dua'],
    );
  });
});

test('enrichment halaman detail', async () => {
  const routes = new Map([
    [
      '/list',
      {
        body: renderPage([{ href: '/detail/1', title: 'Produk', price: '5000' }]),
      },
    ],
    [
      '/detail/1',
      {
        body: '<html><body><h1>Produk</h1><span class="sku">SKU-9</span><div class="desc">Deskripsi lengkap</div></body></html>',
      },
    ],
  ]);

  await withServer(routes, async (baseUrl) => {
    const source = baseSource({
      request: { url: `${baseUrl}/list`, maxPages: 1, delayMs: 0, headers: {} },
      detail: {
        enabled: true,
        linkField: 'link',
        maxItems: 2,
        fields: {
          sku: { selector: '.sku' },
          description: { selector: '.desc' },
        },
      },
    });

    const result = await scrapeSource(source, {
      respectRobots: false,
      userAgent: 'test',
      maxItems: 20,
    });

    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].sku, 'SKU-9');
    assert.equal(result.items[0].description, 'Deskripsi lengkap');
    assert.equal(result.meta.detailEnriched, 1);
  });
});

test('robots.txt disallow dihormati secara default', async () => {
  const routes = new Map([
    [
      '/robots.txt',
      {
        contentType: 'text/plain',
        body: 'User-agent: *\nDisallow: /private\n',
      },
    ],
    [
      '/private/data',
      { body: renderPage([{ href: '/b/1', title: 'Rahasia', price: '1' }]) },
    ],
  ]);

  await withServer(routes, async (baseUrl) => {
    const source = baseSource({
      request: {
        url: `${baseUrl}/private/data`,
        maxPages: 1,
        delayMs: 0,
        headers: {},
      },
    });

    await assert.rejects(
      () => scrapeSource(source, { userAgent: 'test', maxItems: 20 }),
      /robots\.txt melarang/,
    );
  });
});
