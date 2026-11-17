import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  buildJsonReport,
  buildMarkdownReport,
  ensureReports,
  discoverSecurityContacts,
  isValidEmail,
  sendReportEmail,
  writeReports,
} from '../src/security/report.js';

const tempDirs = [];

async function makeConfig() {
  const reportsDir = await mkdtemp(path.join(tmpdir(), 'security-reports-'));
  tempDirs.push(reportsDir);
  return {
    timezone: 'Asia/Jakarta',
    security: {
      reportsDir,
      reportSendEnabled: false,
      reportTo: null,
      smtp: { host: null, from: null },
    },
  };
}

after(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

const scan = {
  id: 'a1b2c3',
  target: 'https://example.com/search?q=1',
  host: 'example.com',
  profile: 'standard',
  status: 'succeeded',
  chatId: '987654321',
  authorizedBy: 'telegram:@secretuser',
  createdAt: '2026-11-17T10:00:00.000Z',
  startedAt: '2026-11-17T10:00:01.000Z',
  finishedAt: '2026-11-17T10:01:00.000Z',
  durationMs: 59_000,
  summary: { critical: 0, high: 1, medium: 1, low: 0, info: 0, total: 2 },
  recon: {
    statusCode: 200,
    title: 'Halaman Contoh',
    tech: ['Nginx', 'PHP'],
    parameterUrls: ['https://example.com/search?q=1'],
    subdomains: ['api.example.com'],
  },
  warnings: ['sqlmap timeout pada https://example.com/search?q=1'],
  toolRuns: [
    { name: 'headers', ok: true, durationMs: 120 },
    { name: 'nuclei', ok: true, durationMs: 5000 },
  ],
};

const findings = [
  {
    id: 'f1',
    category: 'XSS',
    type: 'xss',
    severity: 'high',
    title: 'Reflected XSS pada parameter q',
    tool: 'dalfox',
    url: 'https://example.com/search?q=1',
    parameter: 'q',
    evidence: 'Payload: <script>alert(1)</script>\nReflected di body.',
    cwe: 'CWE-79',
    cve: null,
    remediation: 'Encode output sesuai konteks HTML.',
    reference: 'https://owasp.org/www-community/attacks/xss/',
  },
  {
    id: 'f2',
    category: 'Kerentanan Web',
    type: 'misconfiguration',
    severity: 'medium',
    title: 'Content-Security-Policy tidak ada',
    tool: 'headers',
    url: 'https://example.com/',
    parameter: null,
    evidence: 'Response tidak mengirim header CSP. (HTTP 200)',
    cwe: null,
    cve: null,
    remediation: 'Terapkan CSP.',
    reference: 'https://owasp.org/www-project-secure-headers/',
  },
];

test('buildMarkdownReport memuat temuan dan tidak membocorkan data internal', () => {
  const markdown = buildMarkdownReport({
    scan,
    findings,
    contacts: ['security@example.com'],
    generatedAt: '2026-11-17T10:02:00.000Z',
  });

  assert.match(markdown, /Laporan Kerentanan Keamanan — example\.com/);
  assert.match(markdown, /Reflected XSS pada parameter q/);
  assert.match(markdown, /Tinggi/);
  assert.match(markdown, /CWE-79/);
  assert.match(markdown, /Encode output sesuai konteks HTML/);
  assert.match(markdown, /security@example\.com/);
  assert.match(markdown, /sqlmap timeout/);
  assert.doesNotMatch(markdown, /987654321/);
  assert.doesNotMatch(markdown, /secretuser/);
  assert.doesNotMatch(markdown, /chatId/);
  assert.match(markdown, /Tidak ada data pengguna, nilai cookie, atau kredensial/);
});

test('buildMarkdownReport menangani scan tanpa temuan', () => {
  const markdown = buildMarkdownReport({ scan, findings: [] });
  assert.match(markdown, /Tidak ada temuan yang dapat dikonfirmasi otomatis/);
  assert.match(markdown, /\| \*\*Total\*\* \| \*\*0\*\* \|/);
});

test('buildJsonReport menyusun data terstruktur tanpa metadata internal', () => {
  const report = buildJsonReport({ scan, findings });
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.scan.id, 'a1b2c3');
  assert.equal(report.summary.total, 2);
  assert.equal(report.summary.high, 1);
  assert.equal(report.findings.length, 2);
  assert.equal(report.disclosure.detectionOnly, true);
  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /987654321/);
  assert.doesNotMatch(serialized, /secretuser/);
});

test('writeReports menulis Markdown dan JSON ke disk', async () => {
  const config = await makeConfig();
  const reports = await writeReports({ config, scan, findings });

  const markdown = await readFile(reports.markdown.path, 'utf8');
  const json = JSON.parse(await readFile(reports.json.path, 'utf8'));
  assert.match(markdown, /Reflected XSS/);
  assert.equal(json.scan.id, scan.id);
  assert.ok(reports.markdown.bytes > 0);
  assert.ok(reports.json.bytes > 0);
});

test('ensureReports memakai cache DB lalu membuat ulang saat file hilang', async () => {
  const config = await makeConfig();
  const store = new Map();
  const db = {
    getFindings: () => findings,
    getReport: (id, format) => store.get(format) ?? null,
    saveReport: (id, report) => store.set(report.format, report),
  };

  const first = await ensureReports({ config, db, scan });
  assert.match(first.markdown.content, /Reflected XSS/);
  assert.equal(store.size, 2);

  await rm(path.join(config.security.reportsDir, scan.id), {
    recursive: true,
    force: true,
  });

  const second = await ensureReports({ config, db, scan });
  assert.match(second.json.content, /a1b2c3/);
  const persisted = JSON.parse(await readFile(second.json.path, 'utf8'));
  assert.equal(persisted.summary.high, 1);
});

test('sendReportEmail menolak pengiriman saat fitur nonaktif', async () => {
  const config = {
    timezone: 'Asia/Jakarta',
    security: {
      reportsDir: '/tmp/tidak-dipakai',
      reportSendEnabled: false,
      smtp: { host: 'smtp.example.com', from: 'security@example.com' },
    },
  };
  await assert.rejects(
    () => sendReportEmail({ config, db: null, scan, to: 'security@example.com' }),
    (error) => error.code === 'report_send_disabled' && error.status === 403,
  );
});

test('isValidEmail memvalidasi alamat email sederhana', () => {
  assert.equal(isValidEmail('security@example.com'), true);
  assert.equal(isValidEmail('bukan-email'), false);
  assert.equal(isValidEmail('a@b'), false);
  assert.equal(isValidEmail(''), false);
});

test('discoverSecurityContacts membatasi pembacaan body security.txt', async () => {
  const originalFetch = globalThis.fetch;
  let cancelled = false;
  let fetchCount = 0;
  globalThis.fetch = async () => {
    fetchCount += 1;
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(
            new TextEncoder().encode(
              `Contact: mailto:security@example.com\n${'x'.repeat(100_000)}`,
            ),
          );
        },
        cancel() {
          cancelled = true;
        },
      }),
      { status: 200 },
    );
  };

  try {
    const result = await discoverSecurityContacts({
      targetUrl: 'https://example.com/',
      allowedDomains: ['example.com'],
      timeoutMs: 1000,
    });

    assert.deepEqual(result.contacts, ['security@example.com']);
    assert.equal(fetchCount, 2);
    assert.equal(cancelled, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
