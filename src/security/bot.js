import { Input, Markup } from 'telegraf';
import { isValidEmail } from './report.js';
import { normalizeTarget, SecurityError } from './scope.js';

const PENDING_TTL_MS = 10 * 60 * 1000;

const SEVERITY_EMOJI = {
  critical: '🟥',
  high: '🟧',
  medium: '🟨',
  low: '🟦',
  info: '⬜',
};

const STATUS_EMOJI = {
  queued: '⏳',
  running: '🏃',
  succeeded: '✅',
  failed: '❌',
  cancelled: '⚪',
};

export const SECURITY_COMMANDS = [
  { command: 'bugbounty', description: 'Menu bug bounty & security scanner' },
  { command: 'scan', description: 'Scan target: /scan <url> [quick|standard|deep]' },
  { command: 'retry', description: 'Ulangi scan timeout: /retry <scan-id>' },
  { command: 'scans', description: '10 scan security terakhir' },
  { command: 'scaninfo', description: 'Detail scan: /scaninfo <id>' },
  { command: 'tools', description: 'Status tool security' },
  { command: 'toolbox', description: 'Rujukan alat bantu keamanan non-eksekusi' },
  { command: 'scope', description: 'Scope domain yang diizinkan' },
  { command: 'report', description: 'Unduh laporan: /report <id> [md|json]' },
  { command: 'sendreport', description: 'Kirim laporan: /sendreport <id> [email]' },
];

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

function formatDate(value, timezone) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString('id-ID', {
      timeZone: timezone,
      dateStyle: 'short',
      timeStyle: 'medium',
    });
  } catch {
    return value;
  }
}

function severityLine(summary = {}) {
  return [
    `${SEVERITY_EMOJI.critical} ${summary.critical ?? 0} kritis`,
    `${SEVERITY_EMOJI.high} ${summary.high ?? 0} tinggi`,
    `${SEVERITY_EMOJI.medium} ${summary.medium ?? 0} sedang`,
    `${SEVERITY_EMOJI.low} ${summary.low ?? 0} rendah`,
    `${SEVERITY_EMOJI.info} ${summary.info ?? 0} info`,
  ].join(' | ');
}

export function registerSecurityBot({ bot, security, db, config, logger }) {
  const pendingScans = new Map();
  const pendingSends = new Map();

  function cleanupPending() {
    const now = Date.now();
    for (const [token, value] of pendingScans) {
      if (now - value.createdAt > PENDING_TTL_MS) pendingScans.delete(token);
    }
    for (const [token, value] of pendingSends) {
      if (now - value.createdAt > PENDING_TTL_MS) pendingSends.delete(token);
    }
  }

  function requireSecurity(ctx) {
    if (!config.security.enabled) {
      void ctx.reply(
        'Fitur security scanner dinonaktifkan. Set SECURITY_ENABLED=true lalu restart layanan.',
      );
      return false;
    }
    return true;
  }

  async function sendBugBountyMenu(ctx) {
    let status = null;
    try {
      status = await security.status();
    } catch (error) {
      logger.warn({ err: error }, 'gagal membaca status security');
    }
    const scope = status?.scope?.allowedDomains ?? [];
    const toolSummary = status?.toolSummary;
    const text =
      '<b>🛡 Menu Bug Bounty</b>\n\n' +
      'Scan XSS, SQL injection, CVE, miskonfigurasi, dan temuan umum lainnya. ' +
      'Laporan dibuat <b>otomatis</b> setelah scan selesai.\n\n' +
      `<b>Scope:</b> ${
        scope.length ? scope.map((item) => `<code>${escapeHtml(item)}</code>`).join(', ') : '<i>belum diatur</i>'
      }\n` +
      `<b>Tool:</b> ${toolSummary ? `${toolSummary.available.length}/${toolSummary.total} tersedia` : '-'}\n` +
      `<b>Antrean:</b> ${status?.active ?? 0} berjalan, ${status?.queued ?? 0} menunggu\n` +
      `<b>Kirim email laporan:</b> ${status?.reportSendEnabled ? 'aktif' : 'nonaktif (default aman)'}\n\n` +
      '<b>Perintah</b>\n' +
      '/scan &lt;url&gt; [quick|standard|deep] — mulai scan (butuh konfirmasi)\n' +
      '/retry &lt;scan-id&gt; — ulangi scan yang gagal karena timeout (konfirmasi ulang)\n' +
      '/scans — daftar scan terakhir\n' +
      '/scaninfo &lt;id&gt; — detail scan\n' +
      '/report &lt;id&gt; [md|json] — unduh laporan\n' +
      '/sendreport &lt;id&gt; [email] — kirim laporan ke target\n' +
      '/tools — status tool\n' +
      '/toolbox — rujukan alat bantu keamanan\n' +
      '/scope — scope domain';

    return ctx.replyWithHTML(
      text,
      Markup.inlineKeyboard([
        [Markup.button.callback('🚀 Scan baru', 'bb:new')],
        [
          Markup.button.callback('📋 Daftar scan', 'bb:scans'),
          Markup.button.callback('🧰 Tools', 'bb:tools'),
        ],
        [Markup.button.callback('📚 Rujukan', 'bb:toolbox')],
        [
          Markup.button.callback('🎯 Scope', 'bb:scope'),
          Markup.button.callback('🏠 Menu utama', 'menu'),
        ],
      ]),
    );
  }

  async function sendTools(ctx) {
    let status;
    try {
      status = await security.status({ refreshTools: true });
    } catch (error) {
      return ctx.reply(`Gagal membaca status tool: ${error.message}`);
    }

    const lines = status.tools.map((tool) => {
      const icon = tool.available ? '✅' : '❌';
      const version = tool.version ? ` v${tool.version}` : '';
      let detail = '';
      if (!tool.available && tool.error) detail = `\n   <i>${escapeHtml(clip(tool.error, 180))}</i>`;
      if (tool.name === 'nuclei' && tool.templates) {
        detail += tool.templates.available
          ? `\n   Template: <code>${escapeHtml(tool.templates.path)}</code>`
          : `\n   <i>${escapeHtml(clip(tool.templates.error ?? 'template tidak ditemukan', 160))}</i>`;
      }
      return `${icon} <b>${escapeHtml(tool.label)}</b>${version}${detail}`;
    });

    return ctx.replyWithHTML(
      `<b>🧰 Status Tool Security</b>\n\n${lines.join('\n')}\n\n` +
        'Override path binary lewat env <code>SECURITY_*_BIN</code> jika tool tidak terdeteksi. ' +
        'Contoh: <code>SECURITY_HTTPX_BIN=/usr/local/bin/httpx</code>.',
      Markup.inlineKeyboard([[Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]]),
    );
  }

  async function sendScope(ctx) {
    const allowed = config.security.allowedDomains;
    const text =
      '<b>🎯 Scope Pemindaian</b>\n\n' +
      (allowed.length
        ? allowed.map((item) => `• <code>${escapeHtml(item)}</code>`).join('\n')
        : '<i>Belum ada domain diizinkan.</i>') +
      '\n\n' +
      'Scan hanya berjalan pada domain di atas. Atur lewat <code>SECURITY_ALLOWED_DOMAINS</code> ' +
      '(contoh: <code>example.com,*.example.com</code>).\n\n' +
      '⚠️ Hanya tambahkan domain yang kamu punya <b>izin tertulis</b> untuk diuji ' +
      '(program bug bounty atau kontrak pentest).';
    return ctx.replyWithHTML(
      text,
      Markup.inlineKeyboard([[Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]]),
    );
  }

  async function sendToolbox(ctx) {
    return ctx.replyWithHTML(
      '<b>📚 Rujukan Keamanan</b>\n\n' +
        'Rujukan berikut dibuka secara manual; bot tidak mengirim target, token, atau file ke layanan ini.\n\n' +
        '• <a href="https://www.postman.com/">Postman</a> / ' +
        '<a href="https://hoppscotch.io/">Hoppscotch</a> — klien untuk menguji API milikmu.\n' +
        '• <a href="https://gchq.github.io/CyberChef/">CyberChef</a> — transformasi dan decoding data.\n' +
        '• <a href="https://jwt.io/">JWT.io</a> — inspeksi JWT; jangan tempel token produksi atau rahasia.\n' +
        '• <a href="https://nvd.nist.gov/">NVD / CVE</a> dan ' +
        '<a href="https://cwe.mitre.org/">MITRE CWE</a> — referensi kerentanan dan kelemahan.\n' +
        '• <a href="https://www.virustotal.com/">VirusTotal</a> — reputasi domain publik; jangan unggah artefak privat.\n' +
        '• <a href="https://github.com/gitleaks/gitleaks">Gitleaks</a> / ' +
        '<a href="https://github.com/trufflesecurity/trufflehog">TruffleHog</a> — pemeriksaan secret pada repositori yang kamu miliki.\n\n' +
        'Alat pihak ketiga tersebut tidak dijalankan oleh bot. Jangan memasukkan kredensial, token, data pribadi, ' +
        'atau artefak rahasia ke layanan publik.',
      Markup.inlineKeyboard([[Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]]),
    );
  }

  function scanKeyboard(scan) {
    const rows = [];
    const fileRow = [Markup.button.callback('📄 Laporan MD', `bb:file:${scan.id}:md`)];
    if (config.security.reportSendEnabled) {
      fileRow.push(Markup.button.callback('📧 Kirim ke target', `bb:send:${scan.id}`));
    }
    rows.push(fileRow);
    if (scan.status === 'queued' || scan.status === 'running') {
      rows.push([Markup.button.callback('🛑 Batalkan scan', `bb:stop:${scan.id}`)]);
    }
    rows.push([
      Markup.button.callback('📋 Daftar scan', 'bb:scans'),
      Markup.button.callback('🏠 Menu', 'bb:menu'),
    ]);
    return Markup.inlineKeyboard(rows);
  }

  function scanDetailText(detail) {
    const { scan, findings, reports, deliveries } = detail;
    const lines = [];
    lines.push(`<b>🛡 Scan ${escapeHtml(scan.id)}</b>`);
    lines.push(`Status: ${STATUS_EMOJI[scan.status] ?? '•'} ${escapeHtml(scan.status)}`);
    lines.push(`Target: <code>${escapeHtml(scan.target)}</code>`);
    lines.push(`Profil: ${escapeHtml(scan.profile)}`);
    lines.push(`Dibuat: ${formatDate(scan.createdAt, config.timezone)}`);
    lines.push(`Selesai: ${formatDate(scan.finishedAt, config.timezone)}`);
    if (scan.durationMs) lines.push(`Durasi: ${(scan.durationMs / 1000).toFixed(1)} detik`);
    if (scan.status === 'succeeded') {
      lines.push(`Temuan: <b>${scan.findingsCount}</b> — ${severityLine(scan.summary)}`);
      lines.push(`Laporan: ${reports.length ? reports.map((item) => item.format).join(', ') : 'belum tersedia'}`);
      if (deliveries.length) {
        const last = deliveries[0];
        lines.push(
          `Email terakhir: ${escapeHtml(last.toEmail)} — ${last.status === 'sent' ? '✅ terkirim' : '❌ gagal'}`,
        );
      }
    }
    if (scan.error) lines.push(`\n❌ ${escapeHtml(clip(scan.error, 500))}`);
    if (scan.warnings?.length) {
      lines.push(`\n⚠️ <b>Peringatan (${scan.warnings.length})</b>`);
      lines.push(
        scan.warnings
          .slice(0, 3)
          .map((warning) => `• ${escapeHtml(clip(warning, 180))}`)
          .join('\n'),
      );
    }
    if (findings?.length) {
      lines.push('\n<b>5 temuan teratas</b>');
      lines.push(
        findings
          .slice(0, 5)
          .map(
            (finding, index) =>
              `${index + 1}. ${SEVERITY_EMOJI[finding.severity] ?? '•'} ${escapeHtml(
                clip(finding.title, 120),
              )}${finding.parameter ? ` (<code>${escapeHtml(finding.parameter)}</code>)` : ''}`,
          )
          .join('\n'),
      );
    }
    return lines.join('\n');
  }

  async function sendScanDetail(ctx, id) {
    const detail = security.getScanDetail(id);
    if (!detail) return ctx.reply(`Scan "${id}" tidak ditemukan.`);
    return ctx.replyWithHTML(scanDetailText(detail), scanKeyboard(detail.scan));
  }

  async function sendScanList(ctx) {
    const scans = security.listScans({ limit: 10 });
    if (scans.length === 0) {
      return ctx.replyWithHTML(
        'Belum ada scan. Mulai dengan:\n<code>/scan https://example.com quick</code>',
        Markup.inlineKeyboard([[Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]]),
      );
    }
    const lines = scans.map((scan) => {
      const counts =
        scan.status === 'succeeded'
          ? ` — ${scan.findingsCount} temuan`
          : scan.error
            ? ` — ${clip(scan.error, 80)}`
            : '';
      return `${STATUS_EMOJI[scan.status] ?? '•'} <code>${scan.id}</code> ${escapeHtml(
        scan.host,
      )}${counts}\n   ${scan.profile} • ${formatDate(scan.createdAt, config.timezone)}`;
    });
    const buttons = scans
      .slice(0, 8)
      .map((scan) => [
        Markup.button.callback(
          `${STATUS_EMOJI[scan.status] ?? '•'} ${scan.id} ${clip(scan.host, 30)}`,
          `bb:scan:${scan.id}`,
        ),
      ]);
    buttons.push([Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]);
    return ctx.replyWithHTML(
      `<b>📋 10 scan terakhir</b>\n\n${lines.join('\n')}`,
      Markup.inlineKeyboard(buttons),
    );
  }

  function reportFilename(scan, format) {
    const host = String(scan.host ?? 'target').replace(/[^a-z0-9.-]+/gi, '-');
    return `security-${host}-${scan.id}.${format === 'json' ? 'json' : 'md'}`;
  }

  async function sendReportFile(ctx, id, format = 'md') {
    const detail = security.getScanDetail(id);
    if (!detail) return ctx.reply(`Scan "${id}" tidak ditemukan.`);
    if (detail.scan.status !== 'succeeded') {
      return ctx.reply(`Laporan belum tersedia (status scan: ${detail.scan.status}).`);
    }
    let reports;
    try {
      reports = await security.prepareReports(id);
    } catch (error) {
      return ctx.reply(`Gagal menyiapkan laporan: ${error.message}`);
    }
    const normalizedFormat = format === 'json' ? 'json' : 'markdown';
    const report = reports[normalizedFormat];
    const content = report.content;
    return ctx.replyWithDocument(
      Input.fromBuffer(
        Buffer.from(content, 'utf8'),
        reportFilename(detail.scan, normalizedFormat === 'json' ? 'json' : 'md'),
      ),
      {
        caption: `📄 Laporan ${normalizedFormat.toUpperCase()} — scan ${id} (${detail.scan.host})`,
      },
    );
  }

  async function askSendConfirmation(ctx, scanId, to) {
    if (!config.security.reportSendEnabled) {
      return ctx.replyWithHTML(
        '📧 Pengiriman email laporan <b>dinonaktifkan</b> (default aman).\n\n' +
          'Laporan tetap dibuat otomatis dan bisa diunduh lewat /report. ' +
          'Untuk mengaktifkan pengiriman, set <code>SECURITY_REPORT_SEND=true</code>, ' +
          'lengkapi <code>SMTP_HOST</code>, <code>SMTP_FROM</code> (dan kredensial SMTP bila perlu), ' +
          'lalu restart layanan.',
      );
    }
    const detail = security.getScanDetail(scanId);
    if (!detail) return ctx.reply(`Scan "${scanId}" tidak ditemukan.`);
    if (detail.scan.status !== 'succeeded') {
      return ctx.reply(`Laporan belum bisa dikirim (status scan: ${detail.scan.status}).`);
    }

    cleanupPending();
    const token = Math.random().toString(16).slice(2, 10);
    pendingSends.set(token, { scanId, to: to ?? null, createdAt: Date.now() });

    return ctx.replyWithHTML(
      '<b>📧 Konfirmasi Kirim Laporan</b>\n\n' +
        `Target: <code>${escapeHtml(detail.scan.target)}</code>\n` +
        `Tujuan: ${to ? `<code>${escapeHtml(to)}</code>` : '<i>kontak security.txt / SECURITY_REPORT_TO</i>'}\n` +
        `Temuan: <b>${detail.scan.findingsCount}</b> — ${severityLine(detail.scan.summary)}\n\n` +
        'Laporan berisi detail teknis kerentanan dan bukti. Pastikan alamat tujuan adalah kontak ' +
        'resmi tim keamanan/pemilik target.\n\n' +
        '<b>Kirim sekarang?</b>',
      Markup.inlineKeyboard([
        [
          Markup.button.callback('✅ Ya, kirim', `bb:sendyes:${token}`),
          Markup.button.callback('❌ Batal', 'bb:scans'),
        ],
      ]),
    );
  }

  async function handleScanCommand(ctx, parts) {
    if (!requireSecurity(ctx)) return undefined;
    if (parts.length === 0) {
      return ctx.replyWithHTML(
        '<b>🚀 Scan baru</b>\n\n' +
          'Format: <code>/scan &lt;url&gt; [quick|standard|deep]</code>\n\n' +
          '<b>Profil</b>\n' +
          '• <code>quick</code> — header + nuclei high/critical (cepat)\n' +
          '• <code>standard</code> — nuclei + XSS + SQLi (default)\n' +
          '• <code>deep</code> — standard + recon subdomain\n\n' +
          'Contoh:\n<code>/scan https://example.com standard</code>\n\n' +
          '⚠️ Scan membutuhkan konfirmasi otorisasi dan hanya berjalan pada scope yang diizinkan.',
        Markup.inlineKeyboard([[Markup.button.callback('🎯 Lihat scope', 'bb:scope')]]),
      );
    }

    const target = parts[0];
    const profile = (parts[1] ?? 'standard').toLowerCase();
    if (!['quick', 'standard', 'deep'].includes(profile)) {
      return ctx.reply('Profil harus salah satu dari: quick, standard, deep.');
    }

    let normalized;
    try {
      normalized = normalizeTarget(target, config.security.allowedDomains);
    } catch (error) {
      if (error instanceof SecurityError) return ctx.reply(error.message);
      throw error;
    }

    cleanupPending();
    const token = Math.random().toString(16).slice(2, 10);
    pendingScans.set(token, {
      target: normalized.url,
      profile,
      createdAt: Date.now(),
      chatId: ctx.chat?.id ?? null,
      userId: ctx.from?.id ?? null,
    });

    return ctx.replyWithHTML(
      '<b>🔐 Konfirmasi Otorisasi</b>\n\n' +
        `Target: <code>${escapeHtml(normalized.url)}</code>\n` +
        `Profil: <b>${escapeHtml(profile)}</b>\n\n` +
        'Dengan menekan tombol di bawah, kamu menyatakan bahwa:\n' +
        '• Kamu memiliki <b>izin tertulis</b> untuk menguji target ini (program bug bounty / kontrak).\n' +
        '• Target berada dalam scope yang diizinkan.\n' +
        '• Kamu memahami bahwa pemindaian mengirim request aktif ke target.\n\n' +
        'Pemindaian bersifat deteksi, bukan eksploitasi data.',
      Markup.inlineKeyboard([
        [
          Markup.button.callback('✅ Saya berwenang, mulai scan', `bb:confirm:${token}`),
          Markup.button.callback('❌ Batal', `bb:abort:${token}`),
        ],
      ]),
    );
  }

  async function handleRetryCommand(ctx, id) {
    if (!requireSecurity(ctx)) return undefined;
    if (!/^[a-f0-9]{4,40}$/i.test(id ?? '')) {
      return ctx.reply('Format: /retry <scan-id>');
    }

    const previous = security.getScan(id);
    if (!previous) return ctx.reply(`Scan "${id}" tidak ditemukan.`);
    if (previous.status !== 'failed' || !/timeout|batas waktu/i.test(previous.error ?? '')) {
      return ctx.reply('Hanya scan yang gagal karena batas waktu total yang bisa diulang dengan /retry.');
    }

    let normalized;
    try {
      normalized = normalizeTarget(previous.target, config.security.allowedDomains);
    } catch (error) {
      if (error instanceof SecurityError) return ctx.reply(error.message);
      throw error;
    }

    cleanupPending();
    const token = Math.random().toString(16).slice(2, 10);
    pendingScans.set(token, {
      target: normalized.url,
      profile: previous.profile,
      retryOf: previous.id,
      createdAt: Date.now(),
      chatId: ctx.chat?.id ?? null,
      userId: ctx.from?.id ?? null,
    });

    return ctx.replyWithHTML(
      '<b>🔁 Konfirmasi Pengulangan Scan</b>\n\n' +
        `Scan sebelumnya: <code>${escapeHtml(previous.id)}</code>\n` +
        `Target: <code>${escapeHtml(normalized.url)}</code>\n` +
        `Profil: <b>${escapeHtml(previous.profile)}</b>\n\n` +
        'Pengulangan membuat scan baru, tetap mematuhi scope dan cooldown, dan tidak berjalan otomatis. ' +
        'Dengan menyetujui, kamu menyatakan kembali bahwa kamu memiliki izin tertulis untuk menguji target ini.',
      Markup.inlineKeyboard([
        [
          Markup.button.callback('✅ Saya berwenang, ulangi', `bb:confirm:${token}`),
          Markup.button.callback('❌ Batal', `bb:abort:${token}`),
        ],
      ]),
    );
  }

  // ===== Commands =====

  bot.command('bugbounty', async (ctx) => sendBugBountyMenu(ctx));

  bot.command('scan', async (ctx) => {
    const parts = (ctx.message?.text ?? '').trim().split(/\s+/).slice(1);
    return handleScanCommand(ctx, parts);
  });

  bot.command('scans', async (ctx) => sendScanList(ctx));
  bot.command('retry', async (ctx) => {
    const id = (ctx.message?.text ?? '').trim().split(/\s+/)[1];
    return handleRetryCommand(ctx, id);
  });

  bot.command('scaninfo', async (ctx) => {
    const id = (ctx.message?.text ?? '').trim().split(/\s+/)[1];
    if (!id) return ctx.reply('Format: /scaninfo <id>');
    return sendScanDetail(ctx, id);
  });

  bot.command('tools', async (ctx) => sendTools(ctx));
  bot.command('toolbox', async (ctx) => sendToolbox(ctx));
  bot.command('scope', async (ctx) => sendScope(ctx));

  bot.command('report', async (ctx) => {
    const parts = (ctx.message?.text ?? '').trim().split(/\s+/).slice(1);
    if (!parts[0]) return ctx.reply('Format: /report <id> [md|json]');
    return sendReportFile(ctx, parts[0], parts[1]);
  });

  bot.command('sendreport', async (ctx) => {
    const parts = (ctx.message?.text ?? '').trim().split(/\s+/).slice(1);
    if (!parts[0]) return ctx.reply('Format: /sendreport <id> [email]');
    if (!requireSecurity(ctx)) return undefined;
    if (parts[1] && !isValidEmail(parts[1])) {
      return ctx.reply('Alamat email tidak valid.');
    }
    return askSendConfirmation(ctx, parts[0], parts[1]);
  });

  // ===== Callback actions =====

  bot.action('bb:menu', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendBugBountyMenu(ctx);
  });

  bot.action('bb:new', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return ctx.replyWithHTML(
      '🚀 <b>Scan baru</b>\n\n' +
        'Kirim perintah:\n<code>/scan https://example.com standard</code>\n\n' +
        'Profil: <code>quick</code>, <code>standard</code>, atau <code>deep</code>.',
      Markup.inlineKeyboard([[Markup.button.callback('⬅️ Menu Bug Bounty', 'bb:menu')]]),
    );
  });

  bot.action('bb:scans', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendScanList(ctx);
  });

  bot.action('bb:tools', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendTools(ctx);
  });

  bot.action('bb:toolbox', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendToolbox(ctx);
  });

  bot.action('bb:scope', async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendScope(ctx);
  });

  bot.action(/^bb:confirm:([a-f0-9]{8})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    cleanupPending();
    const token = ctx.match[1];
    const pending = pendingScans.get(token);
    if (!pending) {
      return ctx.reply('Konfirmasi kedaluwarsa. Jalankan /scan lagi.');
    }
    pendingScans.delete(token);

    try {
      const scan = await security.enqueue({
        target: pending.target,
        profile: pending.profile,
        origin: 'telegram',
        chatId: pending.chatId,
        authorizedBy: ctx.from?.username ? `telegram:@${ctx.from.username}` : 'telegram',
      });
      return ctx.replyWithHTML(
        '🚀 <b>Scan masuk antrean</b>\n' +
          `Target: <code>${escapeHtml(scan.target)}</code>\n` +
          `Profil: <b>${escapeHtml(scan.profile)}</b>\n` +
          `ID: <code>${scan.id}</code>\n\n` +
          `${pending.retryOf ? `Mengulang scan <code>${escapeHtml(pending.retryOf)}</code> sebagai scan baru.\n` : ''}` +
          'Notifikasi akan dikirim setelah scan selesai. Laporan dibuat otomatis.',
        Markup.inlineKeyboard([
          [Markup.button.callback('Lihat detail', `bb:scan:${scan.id}`)],
          [
            Markup.button.callback('📋 Daftar scan', 'bb:scans'),
            Markup.button.callback('🏠 Menu', 'bb:menu'),
          ],
        ]),
      );
    } catch (error) {
      return ctx.reply(`Gagal memulai scan: ${error.message}`);
    }
  });

  bot.action(/^bb:abort:([a-f0-9]{8})$/, async (ctx) => {
    await ctx.answerCbQuery('Dibatalkan').catch(() => {});
    pendingScans.delete(ctx.match[1]);
    return ctx.reply('Scan dibatalkan.');
  });

  bot.action(/^bb:scan:([a-f0-9]{4,40})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendScanDetail(ctx, ctx.match[1]);
  });

  bot.action(/^bb:retry:([a-f0-9]{4,40})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return handleRetryCommand(ctx, ctx.match[1]);
  });

  bot.action(/^bb:file:([a-f0-9]{4,40}):(md|json)$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    return sendReportFile(ctx, ctx.match[1], ctx.match[2]);
  });

  bot.action(/^bb:stop:([a-f0-9]{4,40})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    try {
      const result = security.cancel(ctx.match[1]);
      return ctx.reply(
        result.status === 'cancelling'
          ? '🛑 Permintaan pembatalan dikirim. Scan akan berhenti sebentar lagi.'
          : '⚪ Scan dibatalkan.',
      );
    } catch (error) {
      return ctx.reply(`Gagal membatalkan scan: ${error.message}`);
    }
  });

  bot.action(/^bb:send:([a-f0-9]{4,40})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    const detail = security.getScanDetail(ctx.match[1]);
    if (!detail) return ctx.reply('Scan tidak ditemukan.');
    return askSendConfirmation(ctx, detail.scan.id, null);
  });

  bot.action(/^bb:sendyes:([a-f0-9]{8})$/, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    cleanupPending();
    const pending = pendingSends.get(ctx.match[1]);
    if (!pending) return ctx.reply('Konfirmasi kedaluwarsa. Jalankan /sendreport lagi.');
    pendingSends.delete(ctx.match[1]);

    await ctx.reply('📧 Mengirim laporan...').catch(() => {});
    try {
      const result = await security.sendReport(pending.scanId, { to: pending.to });
      return ctx.replyWithHTML(
        '✅ <b>Laporan terkirim</b>\n' +
          `Ke: <code>${escapeHtml(result.to)}</code>\n` +
          `Subject: ${escapeHtml(result.subject)}\n` +
          `Message-ID: <code>${escapeHtml(result.messageId ?? '-')}</code>\n\n` +
          'Simpan bukti pengiriman ini. Jangan menghubungi target secara berulang.',
      );
    } catch (error) {
      return ctx.reply(`❌ Gagal mengirim laporan: ${error.message}`);
    }
  });

  // ===== Notifikasi scan selesai =====

  const onFinished = async ({ scan, findings, reports, contacts }) => {
    if (!scan?.chatId) return;
    try {
      const reportNote = reports
        ? '\n📄 <b>Laporan otomatis sudah dibuat.</b>'
        : '\n⚠️ Laporan otomatis gagal dibuat — buka detail scan.';
      const contactNote =
        contacts?.length > 0
          ? `\n📬 Kontak security.txt: ${contacts.map((item) => `<code>${escapeHtml(item)}</code>`).join(', ')}`
          : '';
      const topFindings = (findings ?? [])
        .slice(0, 5)
        .map(
          (finding, index) =>
            `${index + 1}. ${SEVERITY_EMOJI[finding.severity] ?? '•'} ${escapeHtml(
              clip(finding.title, 110),
            )}`,
        )
        .join('\n');

      await bot.telegram.sendMessage(
        scan.chatId,
        `✅ <b>Scan security selesai</b>\n` +
          `Target: <code>${escapeHtml(scan.target)}</code>\n` +
          `ID: <code>${scan.id}</code>\n` +
          `Temuan: <b>${scan.findingsCount}</b> — ${severityLine(scan.summary)}\n` +
          `${topFindings ? `\n${topFindings}\n` : ''}` +
          reportNote +
          contactNote,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [
              Markup.button.callback('🔎 Detail', `bb:scan:${scan.id}`),
              Markup.button.callback('📄 Laporan MD', `bb:file:${scan.id}:md`),
            ],
            ...(config.security.reportSendEnabled
              ? [[Markup.button.callback('📧 Kirim ke target', `bb:send:${scan.id}`)]]
              : []),
            [Markup.button.callback('🏠 Menu Bug Bounty', 'bb:menu')],
          ]),
        },
      );
    } catch (error) {
      logger.warn({ err: error, scanId: scan.id }, 'gagal mengirim notifikasi scan');
    }
  };

  const onFailed = async ({ scan, error }) => {
    if (!scan?.chatId) return;
    try {
      const timedOut = /timeout|batas waktu/i.test(error ?? scan.error ?? '');
      await bot.telegram.sendMessage(
        scan.chatId,
        `❌ <b>Scan security gagal</b>\n` +
          `Target: <code>${escapeHtml(scan.target)}</code>\n` +
          `ID: <code>${scan.id}</code>\n\n` +
          `${escapeHtml(clip(error ?? scan.error ?? 'Error tidak diketahui', 500))}`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [Markup.button.callback('🔎 Detail', `bb:scan:${scan.id}`)],
            ...(timedOut
              ? [[Markup.button.callback('🔁 Ulangi (konfirmasi)', `bb:retry:${scan.id}`)]]
              : []),
          ]),
        },
      );
    } catch (err) {
      logger.warn({ err, scanId: scan.id }, 'gagal mengirim notifikasi scan gagal');
    }
  };

  const onCancelled = async (scan) => {
    if (!scan?.chatId) return;
    try {
      await bot.telegram.sendMessage(
        scan.chatId,
        `⚪ Scan <code>${scan.id}</code> untuk <code>${escapeHtml(scan.target)}</code> dibatalkan.`,
        { parse_mode: 'HTML' },
      );
    } catch (error) {
      logger.warn({ err: error, scanId: scan.id }, 'gagal mengirim notifikasi scan batal');
    }
  };

  security.on('finished', onFinished);
  security.on('failed', onFailed);
  security.on('cancelled', onCancelled);

  return {
    sendBugBountyMenu,
    stop: () => {
      security.off('finished', onFinished);
      security.off('failed', onFailed);
      security.off('cancelled', onCancelled);
    },
  };
}
