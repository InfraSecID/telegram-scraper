import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';

test('loadConfig memakai default yang aman', () => {
  const config = loadConfig({ API_KEY: 'a'.repeat(32), PORT: '4000' });
  assert.equal(config.port, 4000);
  assert.equal(config.botMode, 'polling');
  assert.equal(config.webhookPath, '/telegram/webhook');
  assert.equal(config.respectRobots, true);
  assert.equal(config.allowAdhoc, true);
  assert.equal(config.maxQueue, 50);
});

test('loadConfig memvalidasi API key dan allowlist', () => {
  assert.throws(() => loadConfig({ API_KEY: 'pendek' }), /API_KEY terlalu pendek/);
  assert.throws(
    () => loadConfig({ TELEGRAM_ALLOWED_USER_IDS: '123, bukan-angka' }),
    /ID tidak valid/,
  );
});

test('mode webhook mewajibkan token, PUBLIC_URL https, dan secret valid', () => {
  assert.throws(
    () => loadConfig({ TELEGRAM_BOT_TOKEN: '123:abc', BOT_MODE: 'webhook' }),
    /PUBLIC_URL/,
  );
  assert.throws(
    () =>
      loadConfig({
        TELEGRAM_BOT_TOKEN: '123:abc',
        BOT_MODE: 'webhook',
        PUBLIC_URL: 'http://contoh.com',
      }),
    /https/,
  );

  const config = loadConfig({
    TELEGRAM_BOT_TOKEN: '123:abc',
    BOT_MODE: 'webhook',
    PUBLIC_URL: 'https://contoh.com/',
  });
  assert.equal(config.publicUrl, 'https://contoh.com');
  assert.equal(config.botMode, 'webhook');
  assert.match(config.webhookSecret, /^[a-f0-9]{48}$/);
});

test('PUBLIC_URL otomatis memilih webhook pada BOT_MODE=auto', () => {
  const config = loadConfig({
    TELEGRAM_BOT_TOKEN: '123:abc',
    PUBLIC_URL: 'https://contoh.com',
  });
  assert.equal(config.botMode, 'webhook');
});

test('konfigurasi security memakai default aman', () => {
  const config = loadConfig({});
  assert.equal(config.security.enabled, true);
  assert.deepEqual(config.security.allowedDomains, []);
  assert.equal(config.security.reportSendEnabled, false);
  assert.equal(config.security.rateLimit, 20);
  assert.equal(config.security.maxActiveScans, 1);
  assert.equal(config.security.bins.httpx, 'httpx');
  assert.equal(config.security.nucleiSeverity, 'critical,high,medium,low,info');
});

test('konfigurasi security mem-parse scope dan severity', () => {
  const config = loadConfig({
    SECURITY_ALLOWED_DOMAINS: 'example.com,*.contoh.id',
    SECURITY_NUCLEI_SEVERITY: 'HIGH, critical',
    SECURITY_NUCLEI_BIN: '/usr/local/bin/nuclei',
  });
  assert.deepEqual(config.security.allowedDomains, ['example.com', '*.contoh.id']);
  assert.equal(config.security.nucleiSeverity, 'high,critical');
  assert.equal(config.security.bins.nuclei, '/usr/local/bin/nuclei');
});

test('konfigurasi security menolak scope dan severity tidak valid', () => {
  assert.throws(
    () => loadConfig({ SECURITY_ALLOWED_DOMAINS: 'bukan_domain!' }),
    /SECURITY_ALLOWED_DOMAINS tidak valid/,
  );
  assert.throws(
    () => loadConfig({ SECURITY_NUCLEI_SEVERITY: 'urgent' }),
    /SECURITY_NUCLEI_SEVERITY/,
  );
});

test('SECURITY_REPORT_SEND mewajibkan SMTP_HOST dan SMTP_FROM', () => {
  assert.throws(
    () => loadConfig({ SECURITY_REPORT_SEND: 'true' }),
    /SMTP_HOST/,
  );
  assert.throws(
    () =>
      loadConfig({
        SECURITY_REPORT_SEND: 'true',
        SMTP_HOST: 'smtp.example.com',
      }),
    /SMTP_FROM/,
  );

  const config = loadConfig({
    SECURITY_REPORT_SEND: 'true',
    SMTP_HOST: 'smtp.example.com',
    SMTP_PORT: '465',
    SMTP_SECURE: 'true',
    SMTP_USER: 'user',
    SMTP_PASS: 'pass',
    SMTP_FROM: 'security@example.com',
    SECURITY_REPORT_TO: 'security@example.com',
  });
  assert.equal(config.security.reportSendEnabled, true);
  assert.equal(config.security.smtp.port, 465);
  assert.equal(config.security.smtp.secure, true);
  assert.equal(config.security.reportTo, 'security@example.com');
});
