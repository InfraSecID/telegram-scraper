import http from 'node:http';
import process from 'node:process';
import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { openDb } from './db.js';
import { createJobRunner } from './jobs.js';
import { createApi } from './api.js';
import { createBotRuntime } from './bot.js';
import { loadSources } from './sources.js';
import { createSecurityRuntime } from './security/runtime.js';

async function main() {
  const config = loadConfig();
  const logger = createLogger(config.logLevel);

  logger.info(
    { node: process.version, env: config.nodeEnv, port: config.port },
    'starting telegram-scraper',
  );

  const db = openDb(config.dataDir);
  const recovered = db.recoverStaleJobs();
  if (recovered > 0) {
    logger.warn({ count: recovered }, 'job lama yang tertinggal ditandai gagal');
  }
  const recoveredScans = db.recoverStaleScans();
  if (recoveredScans > 0) {
    logger.warn({ count: recoveredScans }, 'scan security lama yang tertinggal ditandai gagal');
  }

  const runner = createJobRunner({ db, logger, config });
  const security = createSecurityRuntime({ config, logger, db });
  const botRuntime = createBotRuntime({ config, runner, db, logger, security });

  const app = createApi({
    config,
    db,
    runner,
    logger,
    security,
    webhook: botRuntime?.webhookConfig() ?? null,
  });

  const server = http.createServer(app);
  server.requestTimeout = 60_000;
  server.headersTimeout = 20_000;
  server.keepAliveTimeout = 5_000;

  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(config.port, config.host, () => {
      server.off('error', onError);
      resolve();
    });
  });

  const { sources, errors } = loadSources(config.sourcesDir);
  logger.info(
    {
      port: config.port,
      host: config.host,
      botMode: botRuntime ? config.botMode : 'disabled',
      allowedUsers: config.allowedTelegramIds.length,
      sources: sources.size,
      configErrors: errors.length,
      securityEnabled: config.security.enabled,
      securityScope: config.security.allowedDomains.length,
    },
    'API siap',
  );
  for (const item of errors) {
    logger.warn({ file: item.file, error: item.error }, 'config sumber bermasalah');
  }

  if (!config.apiKey) {
    logger.warn('API_KEY belum diisi — endpoint /api akan menolak semua request (503)');
  }
  if (config.apiKey && config.apiKey === 'ganti-dengan-hasil-openssl-rand-hex-32') {
    logger.warn('API_KEY masih placeholder — segera ganti dengan nilai acak yang kuat');
  }
  if (botRuntime && config.allowedTelegramIds.length === 0) {
    logger.warn(
      'TELEGRAM_ALLOWED_USER_IDS kosong — bot akan menolak semua user sampai ID diisi',
    );
  }
  if (!botRuntime) {
    logger.warn('TELEGRAM_BOT_TOKEN tidak diisi — bot Telegram tidak dijalankan');
  }
  if (config.security.enabled && config.security.allowedDomains.length === 0) {
    logger.warn(
      'SECURITY_ALLOWED_DOMAINS kosong — fitur scan menolak semua target sampai scope diisi',
    );
  }
  if (config.security.reportSendEnabled) {
    logger.warn(
      'SECURITY_REPORT_SEND=true — pengiriman laporan email aktif. Pastikan hanya dipakai untuk target yang berwenang.',
    );
  }

  if (botRuntime) {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        await botRuntime.start();
        break;
      } catch (error) {
        logger.error(
          { err: error, attempt, maxAttempts },
          'gagal memulai bot Telegram',
        );
        if (attempt === maxAttempts) {
          logger.error(
            'bot Telegram tidak aktif — REST API tetap berjalan. Cek token/konfigurasi lalu restart container.',
          );
        } else {
          await new Promise((resolve) => setTimeout(resolve, 3000));
        }
      }
    }
  }

  let shuttingDown = false;

  async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'shutdown dimulai');

    const forceTimer = setTimeout(() => {
      logger.error('shutdown melewati batas waktu, keluar paksa');
      process.exit(1);
    }, 30_000);
    forceTimer.unref();

    await new Promise((resolve) => server.close(resolve));
    if (botRuntime) await botRuntime.stop();
    await runner.shutdown(10_000);
    await security.shutdown(10_000);
    db.close();
    clearTimeout(forceTimer);

    logger.info('shutdown selesai');
    process.exit(0);
  }

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('unhandledRejection', (error) => {
    logger.error({ err: error }, 'unhandledRejection');
  });
  process.on('uncaughtException', (error) => {
    logger.error({ err: error }, 'uncaughtException');
    void shutdown('uncaughtException');
  });
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exit(1);
});
