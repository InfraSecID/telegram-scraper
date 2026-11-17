import { EventEmitter } from 'node:events';
import { scrapeSource } from './scrape/engine.js';
import { shortId } from './util/ids.js';

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createJobRunner({ db, logger, config }) {
  const emitter = new EventEmitter();
  const queue = [];
  const controllers = new Set();
  let active = 0;
  let pumping = false;
  let shuttingDown = false;

  function buildStoredResult(result) {
    const cap = config.maxResultBytes;
    const makeJson = (items) => {
      const truncated = items.length < result.items.length;
      const meta = {
        ...result.meta,
        itemsCount: items.length,
        ...(truncated
          ? {
              truncated: true,
              warnings: [
                ...result.meta.warnings,
                `Hasil dipotong karena melebihi batas MAX_RESULT_BYTES (${cap} byte)`,
              ],
            }
          : {}),
      };
      return JSON.stringify({ items, meta });
    };

    let json = makeJson(result.items);
    if (Buffer.byteLength(json) <= cap) {
      return { json, itemsCount: result.items.length };
    }

    let items = result.items;
    while (items.length > 1) {
      items = items.slice(0, Math.max(1, Math.floor(items.length / 2)));
      json = makeJson(items);
      if (Buffer.byteLength(json) <= cap) {
        return { json, itemsCount: items.length };
      }
    }

    if (Buffer.byteLength(json) > cap) {
      throw new Error(`Hasil melebihi MAX_RESULT_BYTES (${cap} byte) bahkan setelah dipotong`);
    }
    return { json, itemsCount: items.length };
  }

  async function runTask({ jobId, source, params }) {
    const controller = new AbortController();
    controllers.add(controller);

    const timeout = setTimeout(
      () => controller.abort(new Error('timeout')),
      config.jobTimeoutMs,
    );
    timeout.unref?.();

    db.markRunning(jobId, new Date().toISOString());
    let job = null;

    try {
      const result = await scrapeSource(source, {
        limit: params.limit,
        maxPages: params.maxPages,
        delayMs: params.delayMs,
        signal: controller.signal,
        respectRobots: source.request.respectRobots ?? config.respectRobots,
        userAgent: config.defaultUserAgent,
        maxItems: config.maxItems,
        logger,
      });

      const stored = buildStoredResult(result);
      db.saveResults(jobId, stored.json);
      db.markSucceeded(jobId, new Date().toISOString(), stored.itemsCount);
      job = db.getJob(jobId);

      logger.info(
        {
          jobId,
          sourceId: source.id,
          items: stored.itemsCount,
          durationMs: result.meta.durationMs,
        },
        'job selesai',
      );
    } catch (error) {
      const message =
        controller.signal.aborted && !shuttingDown
          ? `Timeout: job melebihi ${config.jobTimeoutMs}ms`
          : error.message || 'Terjadi error tidak diketahui';
      db.markFailed(jobId, new Date().toISOString(), message);
      job = db.getJob(jobId);
      logger.warn({ jobId, sourceId: source.id, err: message }, 'job gagal');
    } finally {
      clearTimeout(timeout);
      controllers.delete(controller);
    }

    if (job) emitter.emit('finished', job);
    return job;
  }

  function pump() {
    if (pumping) return;
    pumping = true;
    try {
      while (!shuttingDown && active < config.jobConcurrency && queue.length > 0) {
        const task = queue.shift();
        active += 1;
        runTask(task)
          .catch((error) => logger.error({ err: error, jobId: task.jobId }, 'job runner error'))
          .finally(() => {
            active -= 1;
            setImmediate(pump);
          });
      }
    } finally {
      pumping = false;
    }
  }

  function createJob({ source, params = {}, chatId = null, origin = 'api' }) {
    if (shuttingDown) throw new Error('Server sedang shutdown');

    if (queue.length + active >= config.maxQueue) {
      const error = new Error(
        `Antrian job penuh (${config.maxQueue}). Tunggu beberapa job selesai lalu coba lagi.`,
      );
      error.status = 429;
      error.code = 'queue_full';
      throw error;
    }

    let id = shortId();
    while (db.getJob(id)) id = shortId();

    const job = {
      id,
      sourceId: source.id,
      sourceName: source.name,
      status: 'queued',
      params,
      origin,
      chatId,
      createdAt: new Date().toISOString(),
    };

    db.insertJob(job);
    queue.push({ jobId: id, source, params });
    setImmediate(pump);
    return db.getJob(id);
  }

  async function shutdown(graceMs = 10_000) {
    shuttingDown = true;

    for (const task of queue.splice(0)) {
      db.markFailed(
        task.jobId,
        new Date().toISOString(),
        'Server shutdown sebelum job dijalankan',
      );
    }

    const deadline = Date.now() + graceMs;
    while (active > 0 && Date.now() < deadline) {
      await delay(100);
    }

    for (const controller of controllers) {
      controller.abort(new Error('shutdown'));
    }

    const abortDeadline = Date.now() + 2000;
    while (active > 0 && Date.now() < abortDeadline) {
      await delay(50);
    }
  }

  return {
    createJob,
    shutdown,
    stats: db.stats,
    on: (event, listener) => emitter.on(event, listener),
    off: (event, listener) => emitter.off(event, listener),
  };
}
