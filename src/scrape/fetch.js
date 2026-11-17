import { Agent, fetch } from 'undici';
import robotsParser from 'robots-parser';
import { ScrapeError } from './errors.js';
import { assertPublicUrl, guardedLookup } from '../util/ssrf.js';

const ROBOTS_TTL_MS = 60 * 60 * 1000;
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 5 * 1024 * 1024;

// Agent khusus request ad-hoc: DNS lookup saat connect ikut divalidasi (anti DNS rebinding).
const guardedAgent = new Agent({
  connect: { lookup: guardedLookup(), timeout: 10_000 },
  headersTimeout: 30_000,
  bodyTimeout: 30_000,
});

const lastRequestAt = new Map();
const robotsCache = new Map();
const originChains = new Map();

function assertNotAborted(signal) {
  if (signal?.aborted) {
    throw new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' });
  }
}

function sleep(ms, signal) {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' }));
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      cleanup();
      reject(new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' }));
    };
    function cleanup() {
      signal?.removeEventListener('abort', onAbort);
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Batasi request per origin dengan antrean agar dua job yang berjalan bersamaan
 * tidak menembak origin yang sama secara bersamaan.
 */
async function waitForSlot(origin, delayMs, signal) {
  const previous = originChains.get(origin) ?? Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  const chained = previous.then(() => current);
  originChains.set(origin, chained);

  await previous.catch(() => {});

  try {
    const wait = (lastRequestAt.get(origin) ?? 0) + delayMs - Date.now();
    if (wait > 0) await sleep(wait, signal);
    lastRequestAt.set(origin, Date.now());
  } finally {
    release();
    if (originChains.get(origin) === chained) {
      // Biarkan chain selesai lalu bersihkan agar map tidak tumbuh tanpa batas.
      chained.finally(() => {
        if (originChains.get(origin) === chained) originChains.delete(origin);
      });
    }
  }
}

async function getRobots(origin, { userAgent, ssrfGuard, signal }) {
  const cached = robotsCache.get(origin);
  if (cached && Date.now() - cached.at < ROBOTS_TTL_MS) return cached.parser;

  let parser = null;
  try {
    const timeout = AbortSignal.timeout(5000);
    const robotsSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const response = await fetch(`${origin}/robots.txt`, {
      headers: { 'user-agent': userAgent, accept: 'text/plain,*/*;q=0.8' },
      signal: robotsSignal,
      dispatcher: ssrfGuard ? guardedAgent : undefined,
    });
    if (response.ok) {
      const buffer = await readLimited(response, 500_000);
      parser = robotsParser(
        `${origin}/robots.txt`,
        decodeBody(buffer, response.headers.get('content-type') ?? 'text/plain'),
      );
    } else {
      await response.body?.cancel().catch(() => {});
    }
  } catch {
    // robots.txt tidak tersedia / gagal diambil: izinkan, tapi tetap catat cache.
    parser = null;
  }

  robotsCache.set(origin, { at: Date.now(), parser });
  return parser;
}

function isTextualContent(contentType) {
  if (!contentType) return true;
  const type = contentType.split(';')[0].trim().toLowerCase();
  return (
    type.startsWith('text/') ||
    type === 'application/xhtml+xml' ||
    type === 'application/xml'
  );
}

function decodeBody(buffer, contentType) {
  const match = /charset\s*=\s*["']?([^;"'\s]+)/i.exec(contentType ?? '');
  const charset = match?.[1]?.toLowerCase() ?? 'utf-8';
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    return buffer.toString('utf8');
  }
}

async function readLimited(response, maxBytes) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new ScrapeError(`Body melebihi batas ${maxBytes} byte`, {
          code: 'BODY_TOO_LARGE',
        });
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // ignore
    }
  }
  return Buffer.concat(chunks);
}

/**
 * Ambil satu halaman HTML.
 *
 * @param {string} url
 * @param {object} options
 * @param {Record<string,string>} [options.headers]
 * @param {number} [options.timeoutMs]
 * @param {AbortSignal} [options.signal]
 * @param {number} [options.delayMs] jeda minimum per origin
 * @param {boolean} [options.respectRobots]
 * @param {string} [options.userAgent]
 * @param {boolean} [options.ssrfGuard] aktifkan validasi alamat privat (untuk URL ad-hoc)
 * @param {number} [options.maxBytes]
 * @param {boolean} [options.allowNotFound] kembalikan status 404 tanpa throw
 * @returns {Promise<{url:string,status:number,html:string,contentType:string}>}
 */
export async function fetchHtml(url, options = {}) {
  const {
    headers = {},
    timeoutMs = 15_000,
    signal,
    delayMs = 1000,
    respectRobots = true,
    userAgent = 'TelegramScraperBot/1.0',
    ssrfGuard = false,
    maxBytes = MAX_BODY_BYTES,
    allowNotFound = false,
  } = options;

  let currentUrl = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    assertNotAborted(signal);
    if (ssrfGuard) await assertPublicUrl(currentUrl);

    const origin = new URL(currentUrl).origin;

    let robots = null;
    if (respectRobots) {
      robots = await getRobots(origin, { userAgent, ssrfGuard, signal });
      const allowed = robots?.isAllowed(currentUrl, userAgent);
      if (allowed === false) {
        throw new ScrapeError(`robots.txt melarang pengambilan ${currentUrl}`, {
          code: 'ROBOTS_DISALLOWED',
        });
      }
    }

    const crawlDelaySeconds = robots?.getCrawlDelay?.(userAgent);
    const effectiveDelay = Math.max(delayMs, Math.round((crawlDelaySeconds ?? 0) * 1000));
    await waitForSlot(origin, effectiveDelay, signal);
    assertNotAborted(signal);

    const requestHeaders = new Headers({
      'user-agent': userAgent,
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    });
    for (const [key, value] of Object.entries(headers)) {
      requestHeaders.set(key, value);
    }

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

    let response;
    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        headers: requestHeaders,
        redirect: 'manual',
        signal: combinedSignal,
        dispatcher: ssrfGuard ? guardedAgent : undefined,
      });
    } catch (error) {
      if (signal?.aborted) {
        throw new ScrapeError('Scrape dibatalkan', { code: 'ABORTED' });
      }
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        throw new ScrapeError(`Timeout ${timeoutMs}ms saat mengambil ${currentUrl}`, {
          code: 'TIMEOUT',
        });
      }
      throw new ScrapeError(`Gagal mengambil ${currentUrl}: ${error.message}`, {
        code: 'FETCH_FAILED',
      });
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel().catch(() => {});
      if (!location) {
        throw new ScrapeError(`Redirect tanpa header Location dari ${currentUrl}`, {
          status: response.status,
        });
      }
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    if (response.status === 404 && allowNotFound) {
      await response.body?.cancel().catch(() => {});
      return { url: currentUrl, status: 404, html: '', contentType: '' };
    }

    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new ScrapeError(
        `HTTP ${response.status} ${response.statusText || ''} dari ${currentUrl}`.trim(),
        { status: response.status, code: 'HTTP_ERROR' },
      );
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (!isTextualContent(contentType)) {
      await response.body?.cancel().catch(() => {});
      throw new ScrapeError(
        `Content-Type tidak didukung (${contentType || 'kosong'}) dari ${currentUrl}`,
        { code: 'UNSUPPORTED_CONTENT_TYPE' },
      );
    }

    const buffer = await readLimited(response, maxBytes);
    return {
      url: currentUrl,
      status: response.status,
      html: decodeBody(buffer, contentType),
      contentType,
    };
  }

  throw new ScrapeError(`Terlalu banyak redirect (maks ${MAX_REDIRECTS}) dari ${url}`, {
    code: 'TOO_MANY_REDIRECTS',
  });
}
