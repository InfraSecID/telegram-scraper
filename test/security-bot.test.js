import test from 'node:test';
import assert from 'node:assert/strict';
import { registerSecurityBot } from '../src/security/bot.js';
import { parseAllowedDomains } from '../src/security/scope.js';

function setupBot(scan) {
  const commands = new Map();
  const actions = [];
  const enqueued = [];
  const bot = {
    command: (name, handler) => commands.set(name, handler),
    action: (trigger, handler) => actions.push({ trigger, handler }),
  };
  const security = {
    getScan: () => scan,
    enqueue: async (input) => {
      enqueued.push(input);
      return { id: 'bbccdd', target: input.target, profile: input.profile };
    },
    on() {},
    off() {},
  };
  const config = {
    security: {
      enabled: true,
      allowedDomains: parseAllowedDomains('example.com'),
      reportSendEnabled: false,
    },
    timezone: 'Asia/Jakarta',
  };
  registerSecurityBot({ bot, security, db: {}, config, logger: { warn() {} } });
  return { commands, actions, enqueued };
}

function context(text) {
  return {
    message: { text },
    chat: { id: 123 },
    from: { id: 456, username: 'tester' },
    replies: [],
    reply(message) {
      this.replies.push(message);
      return Promise.resolve();
    },
    replyWithHTML(message, markup) {
      this.replies.push(message);
      this.markup = markup;
      return Promise.resolve();
    },
    answerCbQuery: async () => {},
  };
}

test('retry hanya menerima scan gagal karena timeout dan meminta konfirmasi baru', async () => {
  const { commands, actions, enqueued } = setupBot({
    id: 'a1b2c3',
    target: 'https://example.com/path',
    host: 'example.com',
    profile: 'quick',
    status: 'failed',
    error: 'Scan melewati batas waktu 900 detik.',
  });
  const ctx = context('/retry a1b2c3');

  await commands.get('retry')(ctx);

  assert.match(ctx.replies[0], /Konfirmasi Pengulangan Scan/);
  assert.match(ctx.replies[0], /scope dan cooldown/);
  assert.equal(enqueued.length, 0);

  const callbackData = JSON.stringify(ctx.markup);
  const token = callbackData.match(/bb:confirm:([a-f0-9]{8})/)?.[1];
  assert.ok(token);
  const confirm = actions.find(({ trigger }) => String(trigger).includes('bb:confirm'));
  const callbackCtx = context('');
  callbackCtx.match = [`bb:confirm:${token}`, token];

  await confirm.handler(callbackCtx);

  assert.equal(enqueued.length, 1);
  assert.equal(enqueued[0].target, 'https://example.com/path');
  assert.equal(enqueued[0].profile, 'quick');
  assert.equal(enqueued[0].origin, 'telegram');
  assert.match(callbackCtx.replies[0], /Mengulang scan/);
});

test('retry menolak scan sukses dan scan gagal non-timeout', async () => {
  for (const scan of [
    { id: 'a1b2c3', status: 'succeeded', error: null },
    { id: 'a1b2c3', status: 'failed', error: 'Target tidak dapat dihubungi.' },
  ]) {
    const { commands, enqueued } = setupBot(scan);
    const ctx = context('/retry a1b2c3');

    await commands.get('retry')(ctx);

    assert.match(ctx.replies[0], /Hanya scan yang gagal karena batas waktu total/);
    assert.equal(enqueued.length, 0);
  }
});

test('toolbox memberi rujukan manual tanpa menjalankan tool eksternal', async () => {
  const { commands } = setupBot(null);
  const ctx = context('/toolbox');

  await commands.get('toolbox')(ctx);

  assert.match(ctx.replies[0], /Postman/);
  assert.match(ctx.replies[0], /MITRE CWE/);
  assert.match(ctx.replies[0], /tidak mengirim target, token, atau file/);
});
