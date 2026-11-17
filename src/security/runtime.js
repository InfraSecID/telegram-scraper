import { EventEmitter } from 'node:events';
import { shortId } from '../util/ids.js';
import { discoverSecurityContacts, ensureReports, sendReportEmail } from './report.js';
import { scanTarget, SCAN_PROFILES } from './scanner.js';
import { normalizeTarget, scopeInfo, SecurityError } from './scope.js';
import { createToolRegistry, toolStatusSummary } from './tools.js';

const TERMINAL_STATUSES = new Set(['succeeded', 'failed', 'cancelled']);

function nowIso() {
  return new Date().toISOString();
}

export function createSecurityRuntime({ config, logger, db }) {
  const security = config.security;
  const emitter = new EventEmitter();
  const queue = [];
  const active = new Map();
  const cooldowns = new Map();
  const tools = createToolRegistry(config);
  let pumping = false;
  let shuttingDown = false;

  function assertEnabled() {
    if (!security.enabled) {
      throw new SecurityError(
        'Fitur security scanner dinonaktifkan. Set SECURITY_ENABLED=true untuk mengaktifkan.',
        { status: 403, code: 'security_disabled' },
      );
    }
  }

  function assertScopeConfigured() {
    if (security.allowedDomains.length === 0) {
      throw new SecurityError(
        'Scope belum diatur. Isi SECURITY_ALLOWED_DOMAINS dengan domain yang kamu miliki izin tertulis ' +
          'untuk diuji (contoh: example.com,*.example.com).',
        { status: 403, code: 'scope_empty' },
      );
    }
  }

  function assertProfile(profile) {
    if (!SCAN_PROFILES.includes(profile)) {
      throw new SecurityError(
        `Profil tidak dikenal: ${profile}. Pilihan: ${SCAN_PROFILES.join(', ')}.`,
        { status: 400, code: 'invalid_profile' },
      );
    }
  }

  function activeForHost(host) {
    for (const item of active.values()) {
      if (item.host === host) return item;
    }
    return null;
  }

  function queuedForHost(host) {
    return queue.some((item) => item.scan.host === host);
  }

  function checkCooldown(host) {
    if (security.cooldownMs <= 0) return;
    const last = cooldowns.get(host) ?? 0;
    const elapsed = Date.now() - last;
    if (elapsed < security.cooldownMs) {
      const retryAfterSec = Math.ceil((security.cooldownMs - elapsed) / 1000);
      throw new SecurityError(
        `Host ${host} baru saja dipindai. Tunggu ${retryAfterSec} detik sebelum memindai lagi ` +
          'agar tidak membebani target.',
        { status: 429, code: 'scan_cooldown', details: { retryAfterSec } },
      );
    }
  }

  async function enqueue({
    target,
    profile = 'standard',
    origin = 'api',
    chatId = null,
    authorizedBy = null,
  } = {}) {
    assertEnabled();
    assertScopeConfigured();
    assertProfile(profile);
    if (shuttingDown) {
      throw new SecurityError('Server sedang shutdown; scan baru tidak dapat diantrikan.', {
        status: 503,
        code: 'security_shutting_down',
      });
    }

    const normalized = normalizeTarget(target, security.allowedDomains);
    if (activeForHost(normalized.host) || queuedForHost(normalized.host)) {
      throw new SecurityError(
        `Sudah ada scan yang berjalan atau mengantre untuk ${normalized.host}. Tunggu hingga selesai.`,
        { status: 409, code: 'scan_in_progress' },
      );
    }
    checkCooldown(normalized.host);

    if (queue.length + active.size >= security.maxQueue + security.maxActiveScans) {
      throw new SecurityError(
        `Antrean scan penuh (${queue.length + active.size} menunggu/berjalan). Coba lagi nanti.`,
        { status: 429, code: 'scan_queue_full' },
      );
    }

    const scan = {
      id: shortId(6),
      target: normalized.url,
      host: normalized.host,
      profile,
      status: 'queued',
      origin,
      chatId: chatId ? String(chatId) : null,
      authorizedBy: authorizedBy ? String(authorizedBy).slice(0, 120) : null,
      createdAt: nowIso(),
    };

    db.insertScan(scan);
    queue.push({ scan, target: normalized });
    emitter.emit('queued', scan);
    pump();
    return db.getScan(scan.id);
  }

  function pump() {
    if (pumping || shuttingDown) return;
    pumping = true;
    queueMicrotask(() => {
      try {
        while (!shuttingDown && active.size < security.maxActiveScans && queue.length > 0) {
          const item = queue.shift();
          void runScan(item);
        }
      } finally {
        pumping = false;
      }
    });
  }

  async function runScan({ scan }) {
    const current = db.getScan(scan.id);
    if (!current || current.status !== 'queued') return;

    const controller = new AbortController();
    const startedAt = Date.now();
    const deadline = startedAt + security.scanTimeoutMs;
    const context = {
      scanId: scan.id,
      host: scan.host,
      controller,
      cancelled: false,
      timedOut: false,
      startedAt,
    };

    const timer = setTimeout(() => {
      context.timedOut = true;
      controller.abort();
    }, security.scanTimeoutMs);
    timer.unref?.();

    active.set(scan.id, context);
    cooldowns.set(scan.host, startedAt);
    db.markScanRunning(scan.id, nowIso());
    emitter.emit('started', db.getScan(scan.id));

    try {
      // Deteksi ulang saat scan dimulai: cache negatif dari startup (mis. binary lambat
      // merespons ketika mesin sibuk) tidak boleh membuat tool penting dilewati.
      const toolStatuses = await tools.detect(true);
      const result = await scanTarget({
        scan: {
          ...scan,
          target: current.target,
          host: current.host,
          profile: current.profile,
        },
        config,
        toolStatuses,
        signal: controller.signal,
        deadline,
        logger,
        onProgress: (event) => emitter.emit('progress', { scanId: scan.id, ...event }),
      });

      if (controller.signal.aborted) {
        throw new SecurityError('Scan dibatalkan.', { status: 408, code: 'scan_aborted' });
      }

      db.saveFindings(scan.id, result.findings);
      db.markScanSucceeded(scan.id, {
        summary: result.summary,
        recon: result.recon,
        warnings: result.warnings,
        toolRuns: result.toolRuns,
        durationMs: result.durationMs,
        finishedAt: nowIso(),
      });

      const finishedScan = db.getScan(scan.id);
      let contacts = { contacts: [], sources: [], errors: [] };
      try {
        contacts = await discoverSecurityContacts({
          targetUrl: finishedScan.target,
          allowedDomains: security.allowedDomains,
          userAgent: security.userAgent,
          timeoutMs: 8000,
        });
      } catch (error) {
        logger.debug({ err: error, scanId: scan.id }, 'security.txt tidak bisa dibaca');
      }

      let reports = null;
      try {
        reports = await ensureReports({
          config,
          db,
          scan: finishedScan,
          contacts: contacts.contacts,
          force: false,
        });
      } catch (error) {
        logger.warn({ err: error, scanId: scan.id }, 'gagal membuat laporan otomatis');
      }

      emitter.emit('finished', {
        scan: db.getScan(scan.id),
        findings: result.findings,
        reports,
        contacts: contacts.contacts,
      });
    } catch (error) {
      if (TERMINAL_STATUSES.has(db.getScan(scan.id)?.status)) {
        // Scan sudah selesai; jangan menimpa status.
      } else if (context.cancelled) {
        db.markScanCancelled(scan.id, nowIso());
        emitter.emit('cancelled', db.getScan(scan.id));
      } else if (context.timedOut) {
        const message = `Scan melewati batas waktu ${(security.scanTimeoutMs / 1000).toFixed(0)} detik.`;
        db.markScanFailed(scan.id, nowIso(), message);
        emitter.emit('failed', { scan: db.getScan(scan.id), error: message });
      } else {
        const message = error?.message || String(error);
        db.markScanFailed(scan.id, nowIso(), message);
        emitter.emit('failed', { scan: db.getScan(scan.id), error: message });
        logger.warn({ err: error, scanId: scan.id }, 'scan security gagal');
      }
    } finally {
      clearTimeout(timer);
      active.delete(scan.id);
      cooldowns.set(scan.host, Date.now());
      pump();
    }
  }

  function cancel(id) {
    const queuedIndex = queue.findIndex((item) => item.scan.id === id);
    if (queuedIndex >= 0) {
      const [item] = queue.splice(queuedIndex, 1);
      db.markScanCancelled(item.scan.id, nowIso());
      const scan = db.getScan(item.scan.id);
      emitter.emit('cancelled', scan);
      return { cancelled: true, status: 'cancelled', scan };
    }

    const context = active.get(id);
    if (context) {
      context.cancelled = true;
      context.controller.abort();
      return { cancelled: true, status: 'cancelling' };
    }

    const scan = db.getScan(id);
    if (!scan) {
      throw new SecurityError('Scan tidak ditemukan.', { status: 404, code: 'scan_not_found' });
    }
    throw new SecurityError(
      `Scan sudah berstatus "${scan.status}" dan tidak bisa dibatalkan.`,
      { status: 409, code: 'scan_not_cancellable' },
    );
  }

  async function status({ refreshTools = false } = {}) {
    const toolStatuses = await tools.detect(Boolean(refreshTools));
    return {
      enabled: security.enabled,
      scope: scopeInfo(security.allowedDomains, security.enabled),
      profiles: SCAN_PROFILES,
      reportSendEnabled: security.reportSendEnabled,
      smtpConfigured: Boolean(security.smtp.host && security.smtp.from),
      rateLimit: security.rateLimit,
      cooldownSeconds: Math.round(security.cooldownMs / 1000),
      active: active.size,
      queued: queue.length,
      tools: toolStatuses,
      toolSummary: toolStatusSummary(toolStatuses),
      reportsDir: security.reportsDir,
    };
  }

  function getScan(id) {
    return db.getScan(id);
  }

  function getScanDetail(id) {
    return db.getScanDetail(id);
  }

  function listScans(options) {
    return db.listScans(options);
  }

  async function prepareReports(id, { force = false } = {}) {
    const scan = db.getScan(id);
    if (!scan) {
      throw new SecurityError('Scan tidak ditemukan.', { status: 404, code: 'scan_not_found' });
    }
    if (scan.status !== 'succeeded') {
      throw new SecurityError(
        `Laporan belum tersedia karena scan berstatus "${scan.status}".`,
        { status: 409, code: 'report_not_ready' },
      );
    }
    let contacts = [];
    try {
      const discovered = await discoverSecurityContacts({
        targetUrl: scan.target,
        allowedDomains: security.allowedDomains,
        userAgent: security.userAgent,
        timeoutMs: 8000,
      });
      contacts = discovered.contacts;
    } catch {
      contacts = [];
    }
    return ensureReports({ config, db, scan, contacts, force });
  }

  async function sendReport(id, { to } = {}) {
    const scan = db.getScan(id);
    if (!scan) {
      throw new SecurityError('Scan tidak ditemukan.', { status: 404, code: 'scan_not_found' });
    }
    if (scan.status !== 'succeeded') {
      throw new SecurityError(
        `Laporan belum bisa dikirim karena scan berstatus "${scan.status}".`,
        { status: 409, code: 'report_not_ready' },
      );
    }
    const contacts = await discoverSecurityContacts({
      targetUrl: scan.target,
      allowedDomains: security.allowedDomains,
      userAgent: security.userAgent,
      timeoutMs: 8000,
    }).catch(() => ({ contacts: [] }));
    return sendReportEmail({
      config,
      db,
      scan,
      to: to ?? security.reportTo ?? contacts.contacts[0] ?? null,
      contacts: contacts.contacts,
    });
  }

  async function waitForIdle(timeoutMs = 10_000) {
    if (active.size === 0) return true;
    const startedAt = Date.now();
    while (active.size > 0 && Date.now() - startedAt < timeoutMs) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return active.size === 0;
  }

  async function shutdown(timeoutMs = 10_000) {
    if (shuttingDown) return;
    shuttingDown = true;
    for (const item of queue.splice(0)) {
      db.markScanCancelled(item.scan.id, nowIso());
    }
    for (const context of active.values()) {
      context.cancelled = true;
      context.controller.abort();
    }
    await waitForIdle(timeoutMs);
  }

  return {
    enqueue,
    cancel,
    status,
    getScan,
    getScanDetail,
    listScans,
    prepareReports,
    sendReport,
    shutdown,
    waitForIdle,
    on: (...args) => {
      emitter.on(...args);
      return () => emitter.off(...args);
    },
    off: (...args) => emitter.off(...args),
    tools,
  };
}
