import { load } from 'cheerio';
import { fetchHtml } from './fetch.js';
import { createWarnings, extractDocument, extractItem } from './extract.js';
import { ScrapeError } from './errors.js';

const silentLogger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

function clamp(value, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return min;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function applyPage(url, page) {
  return url.replaceAll('{page}', String(page));
}

function hasValue(value) {
  return !(
    value === null ||
    value === undefined ||
    value === '' ||
    (Array.isArray(value) && value.length === 0)
  );
}

/**
 * Jalankan scraping berdasarkan definisi source (dari YAML atau ad-hoc API).
 *
 * @param {object} source source tervalidasi
 * @param {object} [options]
 * @param {number} [options.limit] override jumlah item
 * @param {number} [options.maxPages] override jumlah halaman
 * @param {number} [options.delayMs] override jeda per origin
 * @param {AbortSignal} [options.signal]
 * @param {boolean} [options.respectRobots]
 * @param {string} [options.userAgent]
 * @param {number} [options.maxItems] batas global item
 * @param {object} [options.logger]
 * @returns {Promise<{items: object[], meta: object}>}
 */
export async function scrapeSource(source, options = {}) {
  const logger = options.logger ?? silentLogger;
  const startedAt = Date.now();
  const warnings = createWarnings();
  const request = source.request;
  const startPage = request.startPage ?? 1;

  const maxPages = clamp(options.maxPages ?? request.maxPages ?? 1, 1, 50);
  const sourceMaxItems = source.maxItems ?? 500;
  const globalMaxItems = options.maxItems ?? Number.POSITIVE_INFINITY;
  const maxItems = Math.max(1, Math.min(sourceMaxItems, globalMaxItems));
  const limit = clamp(options.limit ?? source.list.limit ?? 100, 1, maxItems);
  const delayMs = clamp(options.delayMs ?? request.delayMs ?? 1000, 0, 60_000);
  const timeoutMs = clamp(request.timeoutMs ?? 15_000, 1000, 60_000);
  const respectRobots = options.respectRobots ?? request.respectRobots ?? true;
  const userAgent = options.userAgent ?? 'TelegramScraperBot/1.0';
  const ssrfGuard = source.adhoc === true;
  const signal = options.signal;

  const items = [];
  const itemPageUrls = [];
  const seen = new Set();
  let pagesFetched = 0;
  let duplicatesSkipped = 0;
  let detailEnriched = 0;

  let nextUrl = request.url.includes('{page}')
    ? applyPage(request.url, startPage)
    : request.url;

  for (let pageIndex = 0; pageIndex < maxPages; pageIndex += 1) {
    if (items.length >= limit || !nextUrl) break;
    if (signal?.aborted) throw new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' });

    const pageUrl = nextUrl;
    let page;

    try {
      page = await fetchHtml(pageUrl, {
        headers: request.headers ?? {},
        timeoutMs,
        delayMs,
        respectRobots,
        userAgent,
        ssrfGuard,
        signal,
        allowNotFound: pageIndex > 0,
      });
    } catch (error) {
      if (pageIndex > 0 && error instanceof ScrapeError && error.status === 404) {
        warnings.add(`Halaman ${pageIndex + 1} mengembalikan 404, pagination dihentikan`);
        break;
      }
      throw error;
    }

    if (page.status === 404) {
      warnings.add(`Halaman ${pageIndex + 1} mengembalikan 404, pagination dihentikan`);
      break;
    }

    pagesFetched += 1;
    const $ = load(page.html);
    const nodes = $(source.list.selector).toArray();

    if (nodes.length === 0) {
      warnings.add(
        `Selector list "${source.list.selector}" tidak menemukan item di ${pageUrl}`,
      );
      break;
    }

    logger.debug(
      { page: pageIndex + 1, nodes: nodes.length, url: pageUrl },
      'halaman diproses',
    );

    for (const node of nodes) {
      if (items.length >= limit) break;

      const item = extractItem($, node, source.fields, { baseUrl: pageUrl, warnings });
      if (!Object.values(item).some(hasValue)) continue;

      const rawKey = source.dedupeKey ? item[source.dedupeKey] : JSON.stringify(item);
      if (rawKey !== null && rawKey !== undefined && rawKey !== '') {
        const key = String(rawKey);
        if (seen.has(key)) {
          duplicatesSkipped += 1;
          continue;
        }
        seen.add(key);
      }

      items.push(item);
      itemPageUrls.push(pageUrl);
    }

    // URL halaman berikutnya: template {page} diprioritaskan, lalu nextSelector.
    if (request.url.includes('{page}')) {
      nextUrl = applyPage(request.url, startPage + pageIndex + 1);
    } else if (request.nextSelector) {
      const href = $(request.nextSelector).first().attr('href');
      if (!href || href.startsWith('#')) {
        nextUrl = null;
      } else {
        try {
          const resolved = new URL(href, pageUrl).toString();
          nextUrl = resolved === pageUrl ? null : resolved;
        } catch {
          nextUrl = null;
        }
      }
    } else {
      nextUrl = null;
    }
  }

  if (source.detail?.enabled && source.detail.fields && Object.keys(source.detail.fields).length) {
    const linkField = source.detail.linkField ?? 'link';
    const detailMax = clamp(source.detail.maxItems ?? 25, 1, 100);
    const detailCount = Math.min(items.length, detailMax);

    for (let index = 0; index < detailCount; index += 1) {
      if (signal?.aborted) throw new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' });

      const rawLink = items[index]?.[linkField];
      if (!rawLink) continue;

      let detailUrl;
      try {
        detailUrl = new URL(String(rawLink), itemPageUrls[index]).toString();
      } catch {
        warnings.add(`Link detail tidak valid pada item #${index + 1}`);
        continue;
      }

      try {
        const detailPage = await fetchHtml(detailUrl, {
          headers: request.headers ?? {},
          timeoutMs,
          delayMs,
          respectRobots,
          userAgent,
          ssrfGuard,
          signal,
          allowNotFound: true,
        });
        if (detailPage.status === 404) {
          warnings.add(`Halaman detail 404: ${detailUrl}`);
          continue;
        }

        const $detail = load(detailPage.html);
        const detailData = extractDocument($detail, source.detail.fields, {
          baseUrl: detailUrl,
          warnings,
        });

        for (const [key, value] of Object.entries(detailData)) {
          if (hasValue(value)) items[index][key] = value;
        }
        detailEnriched += 1;
      } catch (error) {
        if (error instanceof ScrapeError && error.code === 'ABORTED') throw error;
        warnings.add(`Gagal mengambil detail ${detailUrl}: ${error.message}`);
      }
    }
  }

  if (items.length === 0) {
    warnings.add('Tidak ada item yang berhasil diekstrak. Cek selector, URL, dan akses situs.');
  }

  const finishedAt = Date.now();
  return {
    items,
    meta: {
      sourceId: source.id,
      sourceName: source.name,
      pagesFetched,
      itemsCount: items.length,
      duplicatesSkipped,
      detailEnriched,
      limit,
      maxPages,
      durationMs: finishedAt - startedAt,
      startedAt: new Date(startedAt).toISOString(),
      finishedAt: new Date(finishedAt).toISOString(),
      warnings: warnings.list(),
    },
  };
}
