import { Telegraf, Markup, Input } from 'telegraf';
import { loadSources } from './sources.js';
import { itemsToCsv } from './util/csv.js';
import { registerSecurityBot, SECURITY_COMMANDS } from './security/bot.js';

const STATUS_LABEL = {
  queued: '⏳ menunggu',
  running: '🏃 berjalan',
  succeeded: '✅ sukses',
  failed: '❌ gagal',
};

const STATUS_EMOJI = {
  queued: '⏳',
  running: '🏃',
  succeeded: '✅',
  failed: '❌',
};

const HELP_TEXT = `<b>🤖 Telegram Scraper — Bantuan</b>

<b>Menu</b>
/menu — semua menu
/help — bantuan ini

<b>Scraper</b>
/sources — daftar sumber + tombol scrape
/scrape &lt;id&gt; [limit] [halaman] — mulai job
/jobs — 10 job terakhir
/job &lt;id&gt; — detail satu job
/results &lt;id&gt; [json|csv] — unduh hasil
/id — lihat ID Telegram kamu

<b>🛡 Bug Bounty / Security</b>
/bugbounty — menu bug bounty
/scan &lt;url&gt; [quick|standard|deep] — scan target (butuh konfirmasi otorisasi)
/retry &lt;scan-id&gt; — ulangi scan yang gagal karena timeout (konfirmasi ulang)
/scans — 10 scan terakhir
/scaninfo &lt;id&gt; — detail scan + temuan
/tools — status nuclei, httpx, dalfox, sqlmap, dll
/toolbox — rujukan alat bantu keamanan non-eksekusi
/scope — domain yang diizinkan
/report &lt;id&gt; [md|json] — unduh laporan
/sendreport &lt;id&gt; [email] — kirim laporan ke target

<b>Contoh</b>
<code>/scrape books-demo 20 2</code>
<code>/results a1b2c3d4e5 csv</code>
<code>/scan https://example.com standard</code>
<code>/report 9f3a1c md</code>

<b>Keamanan</b>
Scan hanya berjalan pada <code>SECURITY_ALLOWED_DOMAINS</code> dan setelah kamu mengonfirmasi punya izin tertulis. Laporan dibuat otomatis; pengiriman email ke target nonaktif secara default.

<b>Sumber</b>
Daftar sumber dibaca dari folder <code>config/sources</code> (file YAML). Tambah/ubah file di sana, tidak perlu restart.`;

const COMMANDS = [
  { command: 'start', description: 'Menu utama' },
  { command: 'menu', description: 'Semua menu' },
  { command: 'help', description: 'Bantuan' },
  { command: 'sources', description: 'Daftar sumber & tombol scrape' },
  { command: 'scrape', description: 'Scrape: /scrape <id> [limit] [halaman]' },
  { command: 'jobs', description: '10 job terakhir' },
  { command: 'job', description: 'Detail job: /job <id>' },
  { command: 'results', description: 'Ambil file: /results <id> [json|csv]' },
  ...SECURITY_COMMANDS,
  { command: 'id', description: 'Lihat ID Telegram kamu' },
];

const MAIN_MENU_TEXT = `<b>🤖 Telegram Scraper</b>

Pilih menu di bawah. Semua fitur juga bisa dipanggil lewat perintah — lihat /help.

<b>Scraper</b>
/sources — daftar sumber
/scrape &lt;id&gt; — mulai job
/jobs — job terakhir

<b>Bug Bounty</b>
/bugbounty — menu security scanner
/scan &lt;url&gt; — scan XSS, SQLi, CVE, dll
/report &lt;id&gt; — unduh laporan otomatis`;


function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function clip(value, max) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function parseOptionalInt(raw, min, max) {
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) return null;
  return value;
}

function mainKeyboard() {
  return Markup.inlineKeyboard([
    [
      Markup.button.callback('📚 Sumber', 'sources'),
      Markup.button.callback('🕒 Job', 'jobs'),
    ],
    [Markup.button.callback('🛡 Bug Bounty', 'bb:menu')],
    [Markup.button.callback('❓ Bantuan', 'help')],
  ]);
}

function jobKeyboard(job) {
  const rows = [];
  if (job.status === 'succeeded') {
    rows.push([
      Markup.button.callback('📄 JSON', `file:${job.id}:json`),
      Markup.button.callback('📊 CSV', `file:${job.id}:csv`),
    ]);
  }
  rows.push([
    Markup.button.callback('🔄 Ulangi', `scrape:${job.sourceId}`),
    Markup.button.callback('🏠 Menu', 'menu'),
  ]);
  return Markup.inlineKeyboard(rows);
}

export function createBotRuntime({ config, runner, db, logger, security }) {
  if (!config.telegramBotToken) return null;

  const bot = new Telegraf(config.telegramBotToken, { handlerTimeout: 30_000 });
  const allowedIds = new Set(config.allowedTelegramIds);
  const commandHits = new Map();
  let securityBot = null;

  const formatTime = (value) => {
    if (!value) return '-';
    try {
      return new Date(value).toLocaleString('id-ID', {
        timeZone: config.timezone,
        dateStyle: 'short',
        timeStyle: 'medium',
      });
    } catch {
      return value;
    }
  };

  bot.catch((error, ctx) => {
    logger.error({ err: error, updateType: ctx?.updateType }, 'error di handler bot');
  });

  // Allowlist user Telegram.
  bot.use(async (ctx, next) => {
    const userId = ctx.from?.id;

    if (allowedIds.size === 0) {
      if (ctx.chat?.type === 'private' && ctx.message) {
        const userId = ctx.from?.id ?? 'tidak diketahui';
        await ctx
          .reply(
            `Bot belum aktif.\nID Telegram kamu: ${userId}\n` +
              'Minta admin menambahkan ID ini ke TELEGRAM_ALLOWED_USER_IDS lalu restart bot.',
          )
          .catch(() => {});
      }
      return undefined;
    }

    if (!userId || !allowedIds.has(String(userId))) {
      if (ctx.callbackQuery) {
        await ctx.answerCbQuery('Tidak diizinkan').catch(() => {});
      } else if (ctx.chat?.type === 'private') {
        await ctx
          .reply(
            `Tidak diizinkan.\nID Telegram kamu: ${userId ?? 'tidak diketahui'}\n` +
              'Minta admin menambahkannya ke TELEGRAM_ALLOWED_USER_IDS.',
          )
          .catch(() => {});
      }
      return undefined;
    }

    return next();
  });

  // Throttle per user: maksimal 20 aksi per menit.
  bot.use(async (ctx, next) => {
    if (!ctx.message && !ctx.callbackQuery) return next();
    const userId = String(ctx.from.id);
    const now = Date.now();
    const hits = (commandHits.get(userId) ?? []).filter((time) => now - time < 60_000);
    if (hits.length >= 20) {
      if (ctx.callbackQuery) {
        await ctx.answerCbQuery('Terlalu banyak aksi. Coba lagi nanti.').catch(() => {});
      } else {
        await ctx.reply('Terlalu banyak perintah dalam 1 menit. Coba lagi nanti.').catch(() => {});
      }
      return undefined;
    }
    hits.push(now);
    commandHits.set(userId, hits);
    return next();
  });

  async function sendSources(ctx) {
    const { sources, errors } = loadSources(config.sourcesDir);
    const list = [...sources.values()]
      .filter((source) => source.enabled)
      .sort((a, b) => a.name.localeCompare(b.name, 'id'));

    let text = '<b>📚 Sumber aktif</b>\n\n';
    if (list.length === 0) {
      text +=
        'Belum ada sumber aktif.\nTambahkan file YAML di <code>config/sources</code> lalu kirim /sources lagi.';
    } else {
      text += list
        .map((source) => {
          const description = source.description
            ? `\n  <i>${escapeHtml(clip(source.description, 90))}</i>`
            : '';
          return `• <b>${escapeHtml(source.id)}</b> — ${escapeHtml(source.name)}${description}`;
        })
        .join('\n');
      text += `\n\nTekan tombol untuk scrape dengan setelan default, atau:\n<code>/scrape ${escapeHtml(
        list[0].id,
      )} 20 2</code>`;
    }

    const buttons = list
      .slice(0, 20)
      .map((source) => [
        Markup.button.callback(`▶️ ${clip(source.name, 45)}`, `scrape:${source.id}`),
      ]);

    await ctx.replyWithHTML(
      text,
      buttons.length ? Markup.inlineKeyboard(buttons) : undefined,
    );

    if (errors.length) {
      const errorText = errors
        .map((item) => `${item.file}: ${item.error}`)
        .join('\n')
        .slice(0, 1500);
      await ctx.reply(`⚠️ Config bermasalah:\n${errorText}`).catch(() => {});
    }
  }

  async function sendJobs(ctx) {
    const jobs = db.listJobs({ limit: 10 });
    if (jobs.length === 0) {
      return ctx.reply('Belum ada job. Lihat /sources untuk memulai.');
    }

    const lines = jobs.map((job) => {
      const count = job.itemsCount !== null ? ` — ${job.itemsCount} item` : '';
      return `${STATUS_EMOJI[job.status] ?? '•'} <code>${job.id}</code> ${escapeHtml(
        job.sourceName,
      )}${count}\n   ${formatTime(job.createdAt)}`;
    });

    const buttons = jobs
      .slice(0, 5)
      .map((job) => [
        Markup.button.callback(
          `${STATUS_EMOJI[job.status] ?? '•'} ${job.id}`,
          `job:${job.id}`,
        ),
      ]);

    return ctx.replyWithHTML(
      `<b>🕒 10 job terakhir</b>\n\n${lines.join('\n')}`,
      buttons.length ? Markup.inlineKeyboard(buttons) : undefined,
    );
  }

  function jobDetailText(job) {
    let extra = '';

    if (job.status === 'succeeded') {
      const stored = db.getResults(job.id);
      if (stored) {
        try {
          const payload = JSON.parse(stored.json);
          const meta = payload.meta ?? {};
          extra += `\nItem: <b>${payload.items?.length ?? job.itemsCount ?? 0}</b>`;
          extra += `\nHalaman: ${meta.pagesFetched ?? '-'}`;
          extra += `\nDurasi: ${
            meta.durationMs !== undefined && meta.durationMs !== null
              ? `${(meta.durationMs / 1000).toFixed(1)}s`
              : '-'
          }`;
          extra += `\nDuplikat dilewati: ${meta.duplicatesSkipped ?? 0}`;
          if (meta.detailEnriched) extra += `\nHalaman detail: ${meta.detailEnriched}`;
          if (meta.warnings?.length) {
            extra += `\n\n⚠️ <b>Peringatan (${meta.warnings.length})</b>\n${meta.warnings
              .slice(0, 5)
              .map((warning) => `• ${escapeHtml(clip(warning, 180))}`)
              .join('\n')}`;
          }
        } catch {
          extra += '\n<i>Metadata tidak bisa dibaca.</i>';
        }
      }
    }

    if (job.error) extra += `\n\n❌ ${escapeHtml(clip(job.error, 600))}`;

    return (
      `<b>Job ${job.id}</b>\n` +
      `Status: ${STATUS_LABEL[job.status] ?? job.status}\n` +
      `Sumber: <b>${escapeHtml(job.sourceName)}</b> (<code>${escapeHtml(job.sourceId)}</code>)\n` +
      `Dibuat: ${formatTime(job.createdAt)}\n` +
      `Selesai: ${formatTime(job.finishedAt)}${extra}`
    );
  }

  async function sendJobDetail(ctx, jobId) {
    const job = db.getJob(jobId);
    if (!job) return ctx.reply(`Job "${jobId}" tidak ditemukan.`);
    return ctx.replyWithHTML(jobDetailText(job), jobKeyboard(job));
  }

  async function sendJobFile(ctx, jobId, format) {
    const job = db.getJob(jobId);
    if (!job) return ctx.reply(`Job "${jobId}" tidak ditemukan.`);
    if (job.status !== 'succeeded') {
      return ctx.reply(`Job masih berstatus "${job.status}". File tersedia setelah sukses.`);
    }

    const stored = db.getResults(job.id);
    if (!stored) return ctx.reply('Hasil job tidak ditemukan.');

    let payload;
    try {
      payload = JSON.parse(stored.json);
    } catch {
      return ctx.reply('Hasil job rusak dan tidak bisa dibaca.');
    }

    const items = Array.isArray(payload.items) ? payload.items : [];
    let buffer;
    let filename;
    let caption;

    if (format === 'csv') {
      buffer = Buffer.from(itemsToCsv(items), 'utf8');
      filename = `${job.sourceId}-${job.id}.csv`;
      caption = `📊 ${items.length} item (CSV) — job ${job.id}`;
    } else {
      buffer = Buffer.from(
        JSON.stringify(
          {
            job: {
              id: job.id,
              sourceId: job.sourceId,
              sourceName: job.sourceName,
              status: job.status,
              createdAt: job.createdAt,
              finishedAt: job.finishedAt,
            },
            items,
            meta: payload.meta,
          },
          null,
          2,
        ),
        'utf8',
      );
      filename = `${job.sourceId}-${job.id}.json`;
      caption = `📄 ${items.length} item (JSON) — job ${job.id}`;
    }

    return ctx.replyWithDocument(Input.fromBuffer(buffer, filename), { caption });
  }

  async function createJobFromChat(ctx, source, params = {}) {
    try {
      const job = runner.createJob({
        source,
        params,
        chatId: ctx.chat?.id ? String(ctx.chat.id) : null,
        origin: 'telegram',
      });
      await ctx.replyWithHTML(
        `🕒 <b>Job masuk antrian</b>\nSumber: <b>${escapeHtml(source.name)}</b>\nJob: <code>${
          job.id
        }</code>\n\nNotifikasi akan dikirim setelah job selesai.`,
        Markup.inlineKeyboard([
          [Markup.button.callback('Lihat status', `job:${job.id}`)],
        ]),
      );
    } catch (error) {
      await ctx.reply(`Gagal membuat job: ${error.message}`).catch(() => {});
    }
  }

  const notify = async (job) => {
    if (!job.chatId) return;
    try {
      if (job.status === 'succeeded') {
        let extra = '';
        const stored = db.getResults(job.id);
        if (stored) {
          try {
            const payload = JSON.parse(stored.json);
            const meta = payload.meta ?? {};
            extra = `\nItem: <b>${payload.items?.length ?? job.itemsCount ?? 0}</b> | Halaman: ${
              meta.pagesFetched ?? '-'
            } | ${
              meta.durationMs !== undefined
                ? `${(meta.durationMs / 1000).toFixed(1)}s`
                : '-'
            }`;
            if (meta.warnings?.length) {
              extra += `\n⚠️ ${meta.warnings.length} peringatan — lihat detail job.`;
            }
          } catch {
            // abaikan
          }
        }
        await bot.telegram.sendMessage(
          job.chatId,
          `✅ <b>Scrape selesai</b>\nSumber: <b>${escapeHtml(job.sourceName)}</b>\nJob: <code>${
            job.id
          }</code>${extra}`,
          { parse_mode: 'HTML', ...jobKeyboard(job) },
        );
      } else if (job.status === 'failed') {
        await bot.telegram.sendMessage(
          job.chatId,
          `❌ <b>Scrape gagal</b>\nSumber: <b>${escapeHtml(
            job.sourceName,
          )}</b>\nJob: <code>${job.id}</code>\n\n${escapeHtml(
            clip(job.error || 'Error tidak diketahui', 500),
          )}`,
          { parse_mode: 'HTML', ...jobKeyboard(job) },
        );
      }
    } catch (error) {
      logger.warn({ err: error, jobId: job.id }, 'gagal mengirim notifikasi Telegram');
    }
  };

  runner.on('finished', notify);

  bot.start((ctx) => ctx.replyWithHTML(MAIN_MENU_TEXT, mainKeyboard()));
  bot.command('menu', (ctx) => ctx.replyWithHTML(MAIN_MENU_TEXT, mainKeyboard()));
  bot.command('help', (ctx) => ctx.replyWithHTML(HELP_TEXT, mainKeyboard()));
  bot.command('sources', sendSources);
  bot.command('jobs', sendJobs);

  bot.command('scrape', async (ctx) => {
    const parts = (ctx.message?.text ?? '').trim().split(/\s+/).slice(1);
    if (parts.length === 0) {
      return ctx.replyWithHTML(
        'Format: <code>/scrape &lt;id-sumber&gt; [limit] [halaman]</code>\n' +
          'Contoh: <code>/scrape books-demo 20 2</code>\nLihat /sources.',
      );
    }

    const [sourceId, limitRaw, pagesRaw] = parts;
    const limit = parseOptionalInt(limitRaw, 1, 1000);
    const maxPages = parseOptionalInt(pagesRaw, 1, 50);

    if (limit === null) return ctx.reply('Limit harus bilangan bulat 1-1000.');
    if (maxPages === null) return ctx.reply('Jumlah halaman harus bilangan bulat 1-50.');

    const { sources } = loadSources(config.sourcesDir);
    const source = sources.get(sourceId);
    if (!source) return ctx.reply(`Sumber "${sourceId}" tidak ditemukan. Lihat /sources.`);
    if (!source.enabled) return ctx.reply(`Sumber "${sourceId}" sedang nonaktif.`);

    return createJobFromChat(ctx, source, { limit, maxPages });
  });

  bot.command('job', async (ctx) => {
    const jobId = (ctx.message?.text ?? '').trim().split(/\s+/)[1];
    if (!jobId) return ctx.reply('Format: /job <id>');
    return sendJobDetail(ctx, jobId);
  });

  bot.command('results', async (ctx) => {
    const parts = (ctx.message?.text ?? '').trim().split(/\s+/).slice(1);
    if (parts.length === 0) {
      return ctx.replyWithHTML(
        'Format: <code>/results &lt;id-job&gt; [json|csv]</code>\nContoh: <code>/results a1b2c3d4e5 csv</code>',
      );
    }
    const format = parts[1] === 'csv' ? 'csv' : 'json';
    return sendJobFile(ctx, parts[0], format);
  });

  bot.command('id', (ctx) =>
    ctx.reply(`User ID: ${ctx.from.id}\nChat ID: ${ctx.chat.id}`),
  );

  bot.action('menu', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return ctx.replyWithHTML(MAIN_MENU_TEXT, mainKeyboard());
  });

  bot.action('sources', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendSources(ctx);
  });

  bot.action('jobs', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendJobs(ctx);
  });

  bot.action('help', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return ctx.replyWithHTML(HELP_TEXT, mainKeyboard());
  });

  bot.action(/^scrape:(.+)$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    const sourceId = ctx.match[1];
    const { sources } = loadSources(config.sourcesDir);
    const source = sources.get(sourceId);
    if (!source) return ctx.reply(`Sumber "${sourceId}" tidak ditemukan. Lihat /sources.`);
    if (!source.enabled) return ctx.reply(`Sumber "${sourceId}" sedang nonaktif.`);
    return createJobFromChat(ctx, source);
  });

  bot.action(/^job:([a-f0-9]{4,40})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendJobDetail(ctx, ctx.match[1]);
  });

  bot.action(/^file:([a-f0-9]{4,40}):(json|csv)$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendJobFile(ctx, ctx.match[1], ctx.match[2]);
  });

  if (security) {
    securityBot = registerSecurityBot({ bot, security, db, config, logger });
  }

  async function start() {
    bot.botInfo = await bot.telegram.getMe();
    await bot.telegram
      .setMyCommands(COMMANDS)
      .catch((error) => logger.warn({ err: error }, 'gagal setMyCommands'));

    if (config.botMode === 'webhook') {
      const url = `${config.publicUrl}${config.webhookPath}`;
      await bot.telegram.setWebhook(url, {
        secret_token: config.webhookSecret,
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: true,
      });
      logger.info({ url }, 'bot memakai webhook Telegram');
    } else {
      await bot.telegram.deleteWebhook({ drop_pending_updates: false }).catch(() => {});
      await bot.launch({ dropPendingUpdates: true });
      logger.info('bot berjalan dengan long polling');
    }
  }

  async function stop() {
    runner.off('finished', notify);
    securityBot?.stop();
    try {
      bot.stop('shutdown');
    } catch (error) {
      logger.warn({ err: error }, 'gagal menghentikan bot');
    }
  }

  function webhookConfig() {
    if (config.botMode !== 'webhook') return null;
    return {
      path: config.webhookPath,
      secret: config.webhookSecret,
      handleUpdate: (update) => bot.handleUpdate(update),
    };
  }

  return { start, stop, notify, webhookConfig };
}
