import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import YAML from 'yaml';
import {
  AdhocSchema,
  adhocToSource,
  loadSources,
  toSourceSummary,
} from './sources.js';
import { assertPublicUrl, SsrfError } from './util/ssrf.js';
import { itemsToCsv } from './util/csv.js';
import { SecurityError } from './security/scope.js';

const ScrapeBody = z
  .object({
    sourceId: z.string().min(1).max(100),
    limit: z.number().int().min(1).max(1000).optional(),
    maxPages: z.number().int().min(1).max(50).optional(),
    delayMs: z.number().int().min(0).max(60_000).optional(),
  })
  .strict();

const JobsQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  status: z.enum(['queued', 'running', 'succeeded', 'failed']).optional(),
});

const SecurityScanBody = z
  .object({
    target: z.string().min(3).max(2048),
    profile: z.enum(['quick', 'standard', 'deep']).default('standard'),
    confirmAuthorization: z.literal(true),
  })
  .strict();

const SecurityScansQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  status: z
    .enum(['queued', 'running', 'succeeded', 'failed', 'cancelled'])
    .optional(),
});

const SecuritySendBody = z
  .object({
    to: z.string().email().optional(),
    confirmSend: z.literal(true),
  })
  .strict();

const SecurityReportQuery = z.object({
  format: z.enum(['md', 'markdown', 'json']).default('md'),
});

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

function httpError(status, message, code) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function pickDefined(object) {
  return Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));
}

function safeEqual(first, second) {
  const a = createHash('sha256').update(first).digest();
  const b = createHash('sha256').update(second).digest();
  return timingSafeEqual(a, b);
}

export function createApi({ config, db, runner, logger, webhook = null, security = null }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use(helmet());
  app.use(express.json({ limit: '512kb' }));

  let openapiDoc = null;
  try {
    const docPath = fileURLToPath(new URL('../docs/openapi.yaml', import.meta.url));
    openapiDoc = YAML.parse(readFileSync(docPath, 'utf8'));
  } catch (error) {
    logger.warn({ err: error }, 'docs/openapi.yaml tidak bisa dimuat');
  }

  app.get('/healthz', (req, res) => {
    res.json({
      ok: true,
      uptimeSec: Math.round(process.uptime()),
      jobs: db.stats(),
      security: db.securityStats(),
    });
  });

  app.get('/api/openapi.json', (req, res) => {
    if (!openapiDoc) return res.status(503).json({ error: 'openapi_unavailable' });
    return res.json(openapiDoc);
  });

  // Webhook Telegram (tanpa API key, diamankan dengan secret token dari Telegram).
  if (webhook) {
    app.post(webhook.path, (req, res) => {
      if (webhook.secret && req.get('x-telegram-bot-api-secret-token') !== webhook.secret) {
        return res.status(403).json({ error: 'forbidden' });
      }
      res.status(200).end();
      Promise.resolve(webhook.handleUpdate(req.body)).catch((error) => {
        logger.error({ err: error }, 'update telegram gagal diproses');
      });
      return undefined;
    });
  }

  const api = express.Router();

  api.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      handler: (req, res) => {
        res.status(429).json({
          error: 'rate_limited',
          message: 'Terlalu banyak request. Coba lagi sebentar.',
        });
      },
    }),
  );

  api.use((req, res, next) => {
    if (!config.apiKey) {
      return res.status(503).json({
        error: 'api_key_not_configured',
        message: 'Isi API_KEY di .env untuk mengaktifkan REST API.',
      });
    }
    const bearer = req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1];
    const provided = req.get('x-api-key') || bearer || '';
    if (!provided || !safeEqual(provided, config.apiKey)) {
      return res.status(401).json({
        error: 'unauthorized',
        message: 'API key tidak valid. Kirim header x-api-key atau Authorization: Bearer <key>.',
      });
    }
    return next();
  });

  api.get('/sources', (req, res) => {
    const { sources, errors } = loadSources(config.sourcesDir);
    const list = [...sources.values()].sort((a, b) => a.name.localeCompare(b.name, 'id'));
    res.json({ sources: list.map(toSourceSummary), errors });
  });

  api.get('/sources/:id', (req, res) => {
    const { sources } = loadSources(config.sourcesDir);
    const source = sources.get(req.params.id);
    if (!source) throw httpError(404, `Sumber "${req.params.id}" tidak ditemukan`, 'source_not_found');
    res.json({ source });
  });

  api.post(
    '/scrape',
    asyncHandler(async (req, res) => {
      const body = ScrapeBody.parse(req.body ?? {});
      const { sources } = loadSources(config.sourcesDir);
      const source = sources.get(body.sourceId);
      if (!source) {
        throw httpError(404, `Sumber "${body.sourceId}" tidak ditemukan`, 'source_not_found');
      }
      if (!source.enabled) {
        throw httpError(400, `Sumber "${body.sourceId}" sedang nonaktif`, 'source_disabled');
      }

      const job = runner.createJob({
        source,
        params: pickDefined({
          limit: body.limit,
          maxPages: body.maxPages,
          delayMs: body.delayMs,
        }),
        origin: 'api',
      });
      res.status(202).json({ job });
    }),
  );

  api.post(
    '/scrape/adhoc',
    asyncHandler(async (req, res) => {
      if (!config.allowAdhoc) {
        throw httpError(
          403,
          'Endpoint scrape ad-hoc dinonaktifkan. Set ALLOW_ADHOC=true untuk mengaktifkan.',
          'adhoc_disabled',
        );
      }
      const body = AdhocSchema.parse(req.body ?? {});
      await assertPublicUrl(body.url);

      const source = adhocToSource(body);
      const job = runner.createJob({
        source,
        params: pickDefined({
          limit: body.limit,
          maxPages: body.maxPages,
          delayMs: body.delayMs,
        }),
        origin: 'api',
      });
      res.status(202).json({ job });
    }),
  );

  api.get('/jobs', (req, res) => {
    const query = JobsQuery.parse(req.query ?? {});
    res.json({ jobs: db.listJobs(query) });
  });

  api.get('/jobs/:id', (req, res) => {
    const job = db.getJob(req.params.id);
    if (!job) throw httpError(404, 'Job tidak ditemukan', 'job_not_found');
    res.json({ job });
  });

  api.get('/jobs/:id/results', (req, res) => {
    const job = db.getJob(req.params.id);
    if (!job) throw httpError(404, 'Job tidak ditemukan', 'job_not_found');
    if (job.status !== 'succeeded') {
      return res.status(409).json({
        error: 'results_not_ready',
        message: `Job berstatus "${job.status}". Hasil tersedia setelah job sukses.`,
        status: job.status,
      });
    }

    const stored = db.getResults(job.id);
    if (!stored) throw httpError(409, 'Hasil tidak ditemukan', 'results_not_ready');

    let payload;
    try {
      payload = JSON.parse(stored.json);
    } catch {
      throw httpError(500, 'Hasil tersimpan rusak', 'corrupt_results');
    }

    const items = payload.items ?? [];
    const format = req.query.format === 'csv' ? 'csv' : 'json';

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${job.sourceId}-${job.id}.csv"`,
      );
      return res.send(itemsToCsv(items));
    }

    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${job.sourceId}-${job.id}.json"`,
    );
    return res.json({ job, items, meta: payload.meta });
  });

  // ===== Security / bug bounty =====

  api.use('/security', (req, res, next) => {
    if (!security) {
      return res.status(503).json({
        error: 'security_unavailable',
        message: 'Modul security tidak aktif pada instance ini.',
      });
    }
    return next();
  });

  api.get(
    '/security/status',
    asyncHandler(async (req, res) => {
      const refreshTools = ['1', 'true', 'yes'].includes(
        String(req.query.refresh ?? '').toLowerCase(),
      );
      res.json(await security.status({ refreshTools }));
    }),
  );

  api.get(
    '/security/tools',
    asyncHandler(async (req, res) => {
      const refreshTools = ['1', 'true', 'yes'].includes(
        String(req.query.refresh ?? '').toLowerCase(),
      );
      const status = await security.status({ refreshTools });
      res.json({ tools: status.tools, summary: status.toolSummary });
    }),
  );

  api.get('/security/scope', (req, res) => {
    res.json({
      scope: {
        enabled: config.security.enabled,
        allowedDomains: config.security.allowedDomains,
        authorizationRequired: true,
      },
    });
  });

  api.post(
    '/security/scans',
    asyncHandler(async (req, res) => {
      const body = SecurityScanBody.parse(req.body ?? {});
      const scan = await security.enqueue({
        target: body.target,
        profile: body.profile,
        origin: 'api',
        authorizedBy: 'api',
      });
      res.status(202).json({ scan });
    }),
  );

  api.get('/security/scans', (req, res) => {
    const query = SecurityScansQuery.parse(req.query ?? {});
    res.json({ scans: security.listScans(query) });
  });

  api.get('/security/scans/:id', (req, res) => {
    const detail = security.getScanDetail(req.params.id);
    if (!detail) throw httpError(404, 'Scan tidak ditemukan', 'scan_not_found');
    res.json(detail);
  });

  api.get(
    '/security/scans/:id/report',
    asyncHandler(async (req, res) => {
      const query = SecurityReportQuery.parse(req.query ?? {});
      const detail = security.getScanDetail(req.params.id);
      if (!detail) throw httpError(404, 'Scan tidak ditemukan', 'scan_not_found');

      const reports = await security.prepareReports(req.params.id);
      const format = query.format === 'json' ? 'json' : 'markdown';
      const report = reports[format];
      const extension = format === 'json' ? 'json' : 'md';
      const safeHost = String(detail.scan.host).replace(/[^a-z0-9.-]+/gi, '-');
      res.setHeader(
        'Content-Type',
        format === 'json' ? 'application/json; charset=utf-8' : 'text/markdown; charset=utf-8',
      );
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="security-${safeHost}-${detail.scan.id}.${extension}"`,
      );
      return res.send(report.content);
    }),
  );

  api.post(
    '/security/scans/:id/report/send',
    asyncHandler(async (req, res) => {
      const body = SecuritySendBody.parse(req.body ?? {});
      const delivery = await security.sendReport(req.params.id, { to: body.to });
      res.json({ delivery });
    }),
  );

  api.post(
    '/security/scans/:id/cancel',
    asyncHandler(async (req, res) => {
      res.json(security.cancel(req.params.id));
    }),
  );

  app.use('/api', api);

  app.use((req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);

    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'validation_error',
        issues: error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }
    if (error instanceof SsrfError) {
      return res.status(400).json({ error: 'ssrf_blocked', message: error.message });
    }
    if (error instanceof SecurityError) {
      return res.status(error.status ?? 400).json({
        error: error.code,
        message: error.message,
        ...(error.details !== undefined ? { details: error.details } : {}),
      });
    }
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'invalid_json' });
    }
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ error: 'payload_too_large' });
    }
    if (error.status >= 400 && error.status < 500) {
      return res.status(error.status).json({
        error: error.code || 'request_error',
        message: error.message,
      });
    }

    logger.error({ err: error, path: req.originalUrl }, 'api error');
    return res.status(500).json({ error: 'internal_error' });
  });

  return app;
}
