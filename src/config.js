import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { parseAllowedDomains } from './security/scope.js';

// Muat .env untuk pemakaian lokal (di Docker, env masuk lewat env_file).
if (existsSync('.env')) {
  try {
    process.loadEnvFile('.env');
  } catch {
    // biarkan; env tetap bisa datang dari shell / container
  }
}

const boolEnv = (defaultValue) =>
  z.preprocess((value) => {
    if (value === undefined || value === null || value === '') return defaultValue;
    if (typeof value === 'boolean') return value;
    return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
  }, z.boolean());

const optionalText = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
  });

const EnvSchema = z.object({
  NODE_ENV: z.string().default('development'),

  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default('0.0.0.0'),
  API_KEY: optionalText,
  DATA_DIR: z.string().default('./data'),
  CONFIG_DIR: z.string().default('./config/sources'),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
    .default('info'),
  TRUST_PROXY: boolEnv(false),
  TIMEZONE: z.string().default('Asia/Jakarta'),

  TELEGRAM_BOT_TOKEN: optionalText,
  TELEGRAM_ALLOWED_USER_IDS: z.string().default(''),
  BOT_MODE: z.enum(['auto', 'polling', 'webhook']).default('auto'),
  PUBLIC_URL: z
    .string()
    .optional()
    .transform((value) => value?.trim().replace(/\/+$/, '') || undefined),
  WEBHOOK_PATH: z.string().default('/telegram/webhook'),
  WEBHOOK_SECRET: optionalText,

  DEFAULT_USER_AGENT: z
    .string()
    .default('TelegramScraperBot/1.0 (+https://example.com/kontak)'),
  RESPECT_ROBOTS: boolEnv(true),
  ALLOW_ADHOC: boolEnv(true),
  JOB_CONCURRENCY: z.coerce.number().int().min(1).max(10).default(2),
  JOB_TIMEOUT_MS: z.coerce.number().int().min(5000).max(900000).default(120000),
  MAX_QUEUE: z.coerce.number().int().min(1).max(1000).default(50),
  MAX_RESULT_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .max(50 * 1024 * 1024)
    .default(10 * 1024 * 1024),
  MAX_ITEMS: z.coerce.number().int().min(1).max(5000).default(500),

  // ===== Security / Bug Bounty scanner =====
  SECURITY_ENABLED: boolEnv(true),
  SECURITY_ALLOWED_DOMAINS: z.string().default(''),
  SECURITY_RATE_LIMIT: z.coerce.number().int().min(1).max(150).default(20),
  SECURITY_MAX_ACTIVE_SCANS: z.coerce.number().int().min(1).max(3).default(1),
  SECURITY_MAX_QUEUE: z.coerce.number().int().min(1).max(50).default(10),
  SECURITY_COOLDOWN_SECONDS: z.coerce.number().int().min(0).max(86400).default(60),
  SECURITY_SCAN_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(60_000)
    .max(3_600_000)
    .default(900_000),
  SECURITY_TOOL_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(5_000)
    .max(1_800_000)
    .default(120_000),
  SECURITY_NUCLEI_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(10_000)
    .max(3_600_000)
    .default(600_000),
  SECURITY_SQLMAP_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(10_000)
    .max(1_800_000)
    .default(180_000),
  SECURITY_MAX_FINDINGS: z.coerce.number().int().min(1).max(2000).default(200),
  SECURITY_MAX_PARAM_URLS: z.coerce.number().int().min(1).max(500).default(50),
  SECURITY_DALFOX_MAX_URLS: z.coerce.number().int().min(1).max(100).default(10),
  SECURITY_SQLMAP_MAX_URLS: z.coerce.number().int().min(1).max(50).default(5),
  SECURITY_SUBFINDER_LIMIT: z.coerce.number().int().min(1).max(500).default(50),
  SECURITY_NUCLEI_SEVERITY: z
    .string()
    .default('critical,high,medium,low,info'),
  SECURITY_NUCLEI_EXCLUDE_TAGS: z
    .string()
    .default('dos,fuzz,intrusive,brute-force,credential-stuffing'),
  SECURITY_NUCLEI_TEMPLATES: optionalText,
  SECURITY_USER_AGENT: optionalText,

  SECURITY_NUCLEI_BIN: z.string().default('nuclei'),
  SECURITY_HTTPX_BIN: z.string().default('httpx'),
  SECURITY_KATANA_BIN: z.string().default('katana'),
  SECURITY_SUBFINDER_BIN: z.string().default('subfinder'),
  SECURITY_DALFOX_BIN: z.string().default('dalfox'),
  SECURITY_SQLMAP_BIN: z.string().default('sqlmap'),
  SECURITY_PARAMSPIDER_BIN: z.string().default('paramspider'),

  // Pengiriman laporan ke target NONAKTIF secara default (mencegah spam).
  SECURITY_REPORT_SEND: boolEnv(false),
  SECURITY_REPORT_TO: optionalText,
  SMTP_HOST: optionalText,
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_SECURE: boolEnv(false),
  SMTP_USER: optionalText,
  SMTP_PASS: optionalText,
  SMTP_FROM: optionalText,
});

export function loadConfig(env = process.env) {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join('.') || 'ENV'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Konfigurasi environment tidak valid:\n${details}`);
  }
  const e = parsed.data;

  if (e.API_KEY && e.API_KEY.length < 16) {
    throw new Error('API_KEY terlalu pendek. Gunakan minimal 16 karakter (disarankan 64 hex).');
  }

  const allowedTelegramIds = e.TELEGRAM_ALLOWED_USER_IDS.split(/[\s,]+/)
    .map((id) => id.trim())
    .filter(Boolean);
  const badIds = allowedTelegramIds.filter((id) => !/^\d+$/.test(id));
  if (badIds.length) {
    throw new Error(`TELEGRAM_ALLOWED_USER_IDS berisi ID tidak valid: ${badIds.join(', ')}`);
  }

  let botMode = e.BOT_MODE;
  if (botMode === 'auto') botMode = e.PUBLIC_URL ? 'webhook' : 'polling';

  if (botMode === 'webhook') {
    if (!e.TELEGRAM_BOT_TOKEN) {
      throw new Error('BOT_MODE=webhook membutuhkan TELEGRAM_BOT_TOKEN.');
    }
    if (!e.PUBLIC_URL) {
      throw new Error('BOT_MODE=webhook membutuhkan PUBLIC_URL (contoh: https://scraper.domainmu.com).');
    }
    if (!/^https:\/\//i.test(e.PUBLIC_URL)) {
      throw new Error('PUBLIC_URL harus memakai https:// karena Telegram mewajibkan webhook HTTPS.');
    }
  }

  const webhookPath = e.WEBHOOK_PATH.startsWith('/') ? e.WEBHOOK_PATH : `/${e.WEBHOOK_PATH}`;
  const webhookSecret = e.WEBHOOK_SECRET || randomBytes(24).toString('hex');
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(webhookSecret)) {
    throw new Error('WEBHOOK_SECRET hanya boleh berisi A-Z, a-z, 0-9, _ dan - (maks 256 karakter).');
  }

  try {
    new Intl.DateTimeFormat('id-ID', { timeZone: e.TIMEZONE });
  } catch {
    throw new Error(`TIMEZONE tidak valid: ${e.TIMEZONE}`);
  }

  let securityAllowedDomains = [];
  try {
    securityAllowedDomains = parseAllowedDomains(e.SECURITY_ALLOWED_DOMAINS);
  } catch (error) {
    throw new Error(
      `SECURITY_ALLOWED_DOMAINS tidak valid: ${error.message}. ` +
        'Contoh: example.com,*.example.com,203.0.113.10',
    );
  }

  const severityValues = e.SECURITY_NUCLEI_SEVERITY.split(/[\s,]+/)
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  const invalidSeverities = severityValues.filter((value) => !validSeverities.includes(value));
  if (invalidSeverities.length) {
    throw new Error(
      `SECURITY_NUCLEI_SEVERITY berisi nilai tidak valid: ${invalidSeverities.join(', ')}. ` +
        `Pilihan: ${validSeverities.join(', ')}`,
    );
  }
  if (severityValues.length === 0) severityValues.push('critical', 'high');

  if (e.SECURITY_REPORT_SEND) {
    if (!e.SMTP_HOST) {
      throw new Error('SECURITY_REPORT_SEND=true membutuhkan SMTP_HOST.');
    }
    if (!e.SMTP_FROM) {
      throw new Error('SECURITY_REPORT_SEND=true membutuhkan SMTP_FROM (alamat pengirim).');
    }
  }

  const dataDir = path.resolve(process.cwd(), e.DATA_DIR);
  const securityBins = {
    nuclei: e.SECURITY_NUCLEI_BIN,
    httpx: e.SECURITY_HTTPX_BIN,
    katana: e.SECURITY_KATANA_BIN,
    subfinder: e.SECURITY_SUBFINDER_BIN,
    dalfox: e.SECURITY_DALFOX_BIN,
    sqlmap: e.SECURITY_SQLMAP_BIN,
    paramspider: e.SECURITY_PARAMSPIDER_BIN,
  };

  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    host: e.HOST,
    apiKey: e.API_KEY,
    dataDir,
    sourcesDir: path.resolve(process.cwd(), e.CONFIG_DIR),
    logLevel: e.LOG_LEVEL,
    trustProxy: e.TRUST_PROXY,
    timezone: e.TIMEZONE,

    telegramBotToken: e.TELEGRAM_BOT_TOKEN,
    allowedTelegramIds,
    botMode,
    publicUrl: e.PUBLIC_URL,
    webhookPath,
    webhookSecret,

    defaultUserAgent: e.DEFAULT_USER_AGENT,
    respectRobots: e.RESPECT_ROBOTS,
    allowAdhoc: e.ALLOW_ADHOC,
    jobConcurrency: e.JOB_CONCURRENCY,
    jobTimeoutMs: e.JOB_TIMEOUT_MS,
    maxQueue: e.MAX_QUEUE,
    maxResultBytes: e.MAX_RESULT_BYTES,
    maxItems: e.MAX_ITEMS,

    security: {
      enabled: e.SECURITY_ENABLED,
      allowedDomains: securityAllowedDomains,
      rateLimit: e.SECURITY_RATE_LIMIT,
      maxActiveScans: e.SECURITY_MAX_ACTIVE_SCANS,
      maxQueue: e.SECURITY_MAX_QUEUE,
      cooldownMs: e.SECURITY_COOLDOWN_SECONDS * 1000,
      scanTimeoutMs: e.SECURITY_SCAN_TIMEOUT_MS,
      toolTimeoutMs: e.SECURITY_TOOL_TIMEOUT_MS,
      nucleiTimeoutMs: e.SECURITY_NUCLEI_TIMEOUT_MS,
      sqlmapTimeoutMs: e.SECURITY_SQLMAP_TIMEOUT_MS,
      maxFindings: e.SECURITY_MAX_FINDINGS,
      maxParamUrls: e.SECURITY_MAX_PARAM_URLS,
      dalfoxMaxUrls: e.SECURITY_DALFOX_MAX_URLS,
      sqlmapMaxUrls: e.SECURITY_SQLMAP_MAX_URLS,
      subfinderLimit: e.SECURITY_SUBFINDER_LIMIT,
      nucleiSeverity: severityValues.join(','),
      nucleiExcludeTags: e.SECURITY_NUCLEI_EXCLUDE_TAGS,
      nucleiTemplates: e.SECURITY_NUCLEI_TEMPLATES ?? null,
      userAgent: e.SECURITY_USER_AGENT || e.DEFAULT_USER_AGENT,
      bins: securityBins,
      reportsDir: path.join(dataDir, 'security', 'reports'),
      reportSendEnabled: e.SECURITY_REPORT_SEND,
      reportTo: e.SECURITY_REPORT_TO ?? null,
      smtp: {
        host: e.SMTP_HOST ?? null,
        port: e.SMTP_PORT,
        secure: e.SMTP_SECURE,
        user: e.SMTP_USER ?? null,
        pass: e.SMTP_PASS ?? null,
        from: e.SMTP_FROM ?? null,
      },
    },
  };
}
