import test from 'node:test';
import assert from 'node:assert/strict';
import { createBotRuntime } from '../src/bot.js';

const baseConfig = {
  telegramBotToken: '123456:token-untuk-test',
  allowedTelegramIds: ['123456789'],
  sourcesDir: 'config/sources',
  botMode: 'polling',
  publicUrl: undefined,
  webhookPath: '/telegram/webhook',
  webhookSecret: 'secret-test',
  timezone: 'Asia/Jakarta',
};

const db = {
  listJobs: () => [],
  getJob: () => null,
  getResults: () => null,
};

const runner = {
  on() {},
  off() {},
  createJob() {
    throw new Error('tidak dipanggil pada test ini');
  },
};

const logger = { warn() {}, error() {}, info() {} };

test('createBotRuntime hanya mengaktifkan route webhook pada mode webhook', () => {
  const polling = createBotRuntime({ config: baseConfig, runner, db, logger });
  assert.ok(polling);
  assert.equal(polling.webhookConfig(), null);

  const webhook = createBotRuntime({
    config: { ...baseConfig, botMode: 'webhook', publicUrl: 'https://contoh.com' },
    runner,
    db,
    logger,
  });
  const config = webhook.webhookConfig();
  assert.equal(config.path, '/telegram/webhook');
  assert.equal(config.secret, 'secret-test');
  assert.equal(typeof config.handleUpdate, 'function');
});
