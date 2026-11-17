import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { shortId } from '../util/ids.js';
import { SecurityError } from './scope.js';

const SEVERITY_LABEL = {
  critical: 'Kritis',
  high: 'Tinggi',
  medium: 'Sedang',
  low: 'Rendah',
  info: 'Informasi',
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const TYPE_LABEL = {
  xss: 'Cross-Site Scripting (XSS)',
  dom_xss: 'DOM-based XSS',
  sqli: 'SQL Injection',
  ssrf: 'Server-Side Request Forgery (SSRF)',
  lfi: 'Local/Remote File Inclusion',
  rce: 'Remote Code Execution',
  cve: 'Kerentanan CVE',
  exposure: 'Kebocoran Informasi',
  default_login: 'Kredensial Default',
  misconfiguration: 'Miskonfigurasi',
  nuclei: 'Temuan Pemindaian',
};

const PROFILE_LABEL = {
  quick: 'Cepat (header + nuclei high/critical)',
  standard: 'Standar (nuclei + XSS + SQLi)',
  deep: 'Mendalam (+ recon subdomain)',
};

const REPORT_GENERATOR = 'Telegram Security Scanner (telegram-scraper)';
const REPORT_VERSION = 1;

function formatDate(value, timezone = 'Asia/Jakarta') {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString('id-ID', {
      timeZone: timezone,
      dateStyle: 'long',
      timeStyle: 'medium',
    });
  } catch {
    return String(value);
  }
}

function clip(value, max = 4000) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function codeBlock(value, max = 3000) {
  const text = clip(value ?? '', max).replace(/```/g, '`​``');
  return `\`\`\`\n${text}\n\`\`\``;
}

function inlineCode(value) {
  return `\`${String(value ?? '').replace(/`/g, "'")}\``;
}

function cweUrl(cwe) {
  const numbers = String(cwe ?? '').match(/\d+/g) ?? [];
  if (numbers.length === 0) return null;
  return `https://cwe.mitre.org/data/definitions/${numbers[0]}.html`;
}

function severityLabel(value) {
  return SEVERITY_LABEL[value] ?? value ?? 'Informasi';
}

function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const finding of findings) {
    const severity = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : 'info';
    summary[severity] += 1;
    summary.total += 1;
  }
  return summary;
}

function groupFindings(findings) {
  const groups = [];
  for (const severity of SEVERITY_ORDER) {
    const items = findings.filter((finding) => finding.severity === severity);
    if (items.length) groups.push({ severity, items });
  }
  return groups;
}

function remediationPriority(findings) {
  return [...findings]
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .slice(0, 5);
}

function findingMethod(finding) {
  const target = finding.url || 'URL target';
  const parameter = finding.parameter ? ` pada parameter ${inlineCode(finding.parameter)}` : '';
  switch (finding.type) {
    case 'xss':
    case 'dom_xss':
      return [
        `Akses ${inlineCode(target)}${parameter}.`,
        'Kirim nilai yang mengandung karakter HTML/JavaScript sesuai konteks input.',
        'Perhatikan apakah payload tercermin dan dieksekusi oleh browser tanpa encoding yang benar.',
      ].join('\n');
    case 'sqli':
      return [
        `Akses ${inlineCode(target)}${parameter}.`,
        'Ubah nilai parameter dengan karakter kutip tunggal dan operator SQL sederhana.',
        'Bandingkan respons/error/waktu respons dengan permintaan normal untuk memastikan injeksi.',
      ].join('\n');
    case 'ssrf':
      return [
        `Akses ${inlineCode(target)}${parameter}.`,
        'Isi parameter dengan URL internal/controlled host yang berada di luar jangkauan publik.',
        'Amati apakah server melakukan request ke URL tersebut.',
      ].join('\n');
    case 'lfi':
      return [
        `Akses ${inlineCode(target)}${parameter}.`,
        'Ganti nilai parameter dengan path file lokal yang umum (mis. /etc/passwd) menggunakan variasi traversal.',
        'Periksa apakah isi file muncul pada respons.',
      ].join('\n');
    case 'misconfiguration':
    case 'exposure':
      return [
        `Akses ${inlineCode(target)}.`,
        'Periksa header/response yang dilaporkan pada bagian bukti.',
        'Bandingkan dengan konfigurasi aman yang direkomendasikan.',
      ].join('\n');
    default:
      return [
        `Akses ${inlineCode(target)}${parameter}.`,
        'Ikuti bukti request/response pada bagian Bukti.',
        'Verifikasi temuan secara manual sebelum melakukan perubahan.',
      ].join('\n');
  }
}

function findingReferences(finding) {
  const references = [];
  if (finding.reference) references.push(String(finding.reference));
  const cwe = cweUrl(finding.cwe);
  if (cwe && !references.includes(cwe)) references.push(cwe);
  if (finding.cve) {
    const cves = String(finding.cve).match(/CVE-\d{4}-\d{4,}/gi) ?? [];
    for (const cve of cves.slice(0, 3)) {
      references.push(`https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`);
    }
  }
  return [...new Set(references)].slice(0, 6);
}

export function buildMarkdownReport({
  scan,
  findings = [],
  recon = scan.recon ?? {},
  warnings = scan.warnings ?? [],
  toolRuns = scan.toolRuns ?? [],
  contacts = [],
  timezone = 'Asia/Jakarta',
  generatedAt = new Date().toISOString(),
}) {
  const summary = summarize(findings);
  const lines = [];
  const host = scan.host || new URL(scan.target).hostname;
  const title = `Laporan Kerentanan Keamanan — ${host}`;

  lines.push(`# ${title}`);
  lines.push('');
  lines.push(
    'Laporan ini dibuat secara otomatis dari pemindaian keamanan yang terotorisasi. ' +
      'Tujuannya membantu pemilik/operator situs memahami dan memperbaiki masalah keamanan yang ditemukan. ' +
      'Tidak ada data pengguna, nilai cookie, atau kredensial yang disertakan dalam laporan ini.',
  );
  lines.push('');

  lines.push('## 1. Informasi Pemindaian');
  lines.push('');
  lines.push('| Item | Nilai |');
  lines.push('| --- | --- |');
  lines.push(`| Target | ${inlineCode(scan.target)} |`);
  lines.push(`| Host | ${inlineCode(host)} |`);
  lines.push(`| ID Pemindaian | ${inlineCode(scan.id)} |`);
  lines.push(`| Profil | ${PROFILE_LABEL[scan.profile] ?? scan.profile} |`);
  lines.push(`| Waktu Mulai | ${formatDate(scan.createdAt || scan.startedAt, timezone)} |`);
  lines.push(
    `| Waktu Selesai | ${formatDate(scan.finishedAt || generatedAt, timezone)} |`,
  );
  lines.push(
    `| Durasi | ${scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)} detik` : '-'} |`,
  );
  lines.push(`| Status HTTP | ${recon.statusCode ?? '-'} |`);
  lines.push(`| Judul Halaman | ${recon.title ? clip(recon.title, 160) : '-'} |`);
  lines.push('');

  lines.push('## 2. Ringkasan Temuan');
  lines.push('');
  lines.push('| Tingkat | Jumlah |');
  lines.push('| --- | ---: |');
  for (const severity of SEVERITY_ORDER) {
    lines.push(`| ${severityLabel(severity)} | ${summary[severity]} |`);
  }
  lines.push(`| **Total** | **${summary.total}** |`);
  lines.push('');

  if (summary.total === 0) {
    lines.push(
      'Tidak ada temuan yang dapat dikonfirmasi otomatis pada pemindaian ini. ' +
        'Hasil ini bukan jaminan bahwa aplikasi bebas dari kerentanan; pengujian manual dan ' +
        'pemindaian lanjutan tetap disarankan.',
    );
    lines.push('');
  }

  lines.push('## 3. Dasar Otorisasi & Ruang Lingkup');
  lines.push('');
  lines.push(
    `Pemindaian dilakukan hanya terhadap ${inlineCode(host)} yang telah dicantumkan dalam scope ` +
      'program bug bounty / izin tertulis pemilik target. Pemindaian dibatasi pada host dan subdomain ' +
      'yang diizinkan; redirect ke host di luar scope tidak diikuti.',
  );
  lines.push('');
  lines.push(
    'Pemindaian bersifat **deteksi**, bukan eksploitasi. sqlmap dijalankan dengan `--level=1 --risk=1` ' +
      'tanpa dump data, OS shell, atau pengambilan file. Template nuclei yang bersifat intrusive, DoS, ' +
      'brute-force, dan fuzzing dikecualikan. Tidak ada data pengguna yang diambil atau disimpan.',
  );
  lines.push('');

  lines.push('## 4. Metodologi');
  lines.push('');
  lines.push(
    'Pemindaian menggunakan kombinasi pemeriksaan bawaan dan tool open-source berikut: ' +
      'httpx (fingerprinting), nuclei (CVE/miskonfigurasi berbasis template), katana & paramspider ' +
      '(penemuan URL berparameter), dalfox (XSS), sqlmap (SQL injection), dan subfinder (recon pasif).',
  );
  lines.push('');
  if (recon.tech?.length) {
    lines.push(`Teknologi terdeteksi: ${recon.tech.map((item) => inlineCode(item)).join(', ')}`);
    lines.push('');
  }
  if (toolRuns.length) {
    lines.push('| Fase | Status | Durasi |');
    lines.push('| --- | --- | ---: |');
    for (const run of toolRuns) {
      lines.push(
        `| ${run.name} | ${run.ok ? 'selesai' : 'gagal/dilewati'} | ${
          run.durationMs ? `${(run.durationMs / 1000).toFixed(1)}s` : '-'
        } |`,
      );
    }
    lines.push('');
  }

  lines.push('## 5. Temuan');
  lines.push('');
  if (findings.length === 0) {
    lines.push('_Tidak ada temuan pada pemindaian ini._');
    lines.push('');
  }

  let index = 0;
  for (const group of groupFindings(findings)) {
    lines.push(`### ${severityLabel(group.severity)} (${group.items.length})`);
    lines.push('');
    for (const finding of group.items) {
      index += 1;
      lines.push(`#### ${index}. ${finding.title}`);
      lines.push('');
      lines.push(`- **Tingkat:** ${severityLabel(finding.severity)}`);
      lines.push(`- **Kategori:** ${TYPE_LABEL[finding.type] ?? finding.category ?? 'Kerentanan Web'}`);
      lines.push(`- **Tool:** ${finding.tool ?? '-'}`);
      if (finding.url) lines.push(`- **URL:** ${inlineCode(finding.url)}`);
      if (finding.parameter) lines.push(`- **Parameter:** ${inlineCode(finding.parameter)}`);
      if (finding.cwe) lines.push(`- **CWE:** ${finding.cwe}`);
      if (finding.cve) lines.push(`- **CVE:** ${finding.cve}`);
      lines.push('');
      if (finding.evidence) {
        lines.push('**Bukti**');
        lines.push('');
        lines.push(codeBlock(finding.evidence, 3500));
        lines.push('');
      }
      lines.push('**Langkah Reproduksi**');
      lines.push('');
      lines.push(findingMethod(finding));
      lines.push('');
      if (finding.remediation) {
        lines.push('**Rekomendasi Perbaikan**');
        lines.push('');
        lines.push(finding.remediation);
        lines.push('');
      }
      const references = findingReferences(finding);
      if (references.length) {
        lines.push('**Referensi**');
        lines.push('');
        for (const reference of references) lines.push(`- ${reference}`);
        lines.push('');
      }
    }
  }

  const priority = remediationPriority(findings);
  if (priority.length) {
    lines.push('## 6. Prioritas Perbaikan');
    lines.push('');
    priority.forEach((finding, position) => {
      lines.push(
        `${position + 1}. **${severityLabel(finding.severity)}** — ${finding.title}` +
          (finding.parameter ? ` (parameter ${inlineCode(finding.parameter)})` : ''),
      );
    });
    lines.push('');
    lines.push(
      'Disarankan memperbaiki temuan dengan tingkat Kritis dan Tinggi terlebih dahulu, lalu melakukan ' +
        'verifikasi ulang setelah perbaikan diterapkan.',
    );
    lines.push('');
  }

  if (warnings.length) {
    lines.push('## 7. Catatan & Keterbatasan');
    lines.push('');
    for (const warning of warnings) lines.push(`- ${clip(warning, 600)}`);
    lines.push('');
    lines.push(
      'Keterbatasan di atas dapat mengurangi cakupan pemindaian. Temuan yang tidak muncul bukan berarti ' +
        'tidak ada; verifikasi manual tetap diperlukan.',
    );
    lines.push('');
  }

  if (recon.parameterUrls?.length) {
    lines.push('## 8. Lampiran URL Berparameter');
    lines.push('');
    for (const url of recon.parameterUrls.slice(0, 30)) {
      lines.push(`- ${inlineCode(url)}`);
    }
    if (recon.parameterUrls.length > 30) {
      lines.push(`- … dan ${recon.parameterUrls.length - 30} URL lainnya`);
    }
    lines.push('');
  }

  if (recon.subdomains?.length) {
    lines.push('## 9. Lampiran Subdomain (Recon Pasif)');
    lines.push('');
    for (const subdomain of recon.subdomains.slice(0, 50)) {
      lines.push(`- ${inlineCode(subdomain)}`);
    }
    lines.push('');
  }

  lines.push('## Kontak & Disclosure');
  lines.push('');
  if (contacts.length) {
    lines.push('Kontak keamanan yang ditemukan pada `security.txt` target:');
    lines.push('');
    for (const contact of contacts) lines.push(`- ${contact}`);
  } else {
    lines.push(
      'Kontak keamanan target tidak ditemukan melalui `security.txt`. Laporan ini dapat dikirim ke ' +
        'alamat resmi program bug bounty atau tim keamanan pemilik situs.',
    );
  }
  lines.push('');
  lines.push(
    'Mohon jangan membagikan detail teknis laporan ini secara publik sebelum perbaikan diterapkan. ' +
      'Peneliti bersedia membantu verifikasi ulang setelah perbaikan.',
  );
  lines.push('');
  lines.push('---');
  lines.push(
    `Dibuat oleh ${REPORT_GENERATOR} pada ${formatDate(generatedAt, timezone)}. ` +
      'Laporan ini tidak memuat ID Telegram, nilai cookie, token sesi, atau kredensial.',
  );
  lines.push('');

  return lines.join('\n');
}

export function buildJsonReport({
  scan,
  findings = [],
  recon = scan.recon ?? {},
  warnings = scan.warnings ?? [],
  toolRuns = scan.toolRuns ?? [],
  contacts = [],
  generatedAt = new Date().toISOString(),
}) {
  return {
    schemaVersion: REPORT_VERSION,
    generator: REPORT_GENERATOR,
    generatedAt,
    scan: {
      id: scan.id,
      target: scan.target,
      host: scan.host,
      profile: scan.profile,
      createdAt: scan.createdAt,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt ?? null,
      durationMs: scan.durationMs ?? null,
    },
    summary: summarize(findings),
    recon,
    findings: findings.map((finding) => ({
      id: finding.id,
      category: finding.category,
      type: finding.type,
      severity: finding.severity,
      title: finding.title,
      tool: finding.tool,
      url: finding.url,
      parameter: finding.parameter,
      evidence: finding.evidence,
      cwe: finding.cwe,
      cve: finding.cve,
      remediation: finding.remediation,
      reference: finding.reference,
    })),
    warnings,
    toolRuns,
    contacts,
    disclosure: {
      detectionOnly: true,
      scopeEnforced: true,
      authorizationRequired: true,
      excludedData: ['cookie values', 'session tokens', 'credentials', 'Telegram user IDs'],
    },
  };
}

function reportPaths(config, scanId) {
  const directory = path.join(config.security.reportsDir, scanId);
  return {
    directory,
    markdown: path.join(directory, 'report.md'),
    json: path.join(directory, 'report.json'),
  };
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Tulis laporan Markdown + JSON ke disk. Reports selalu dibuat otomatis setelah scan selesai.
 */
export async function writeReports({
  config,
  scan,
  findings,
  contacts = [],
  force = true,
  generatedAt = new Date().toISOString(),
}) {
  const paths = reportPaths(config, scan.id);
  const markdown = buildMarkdownReport({
    scan,
    findings,
    recon: scan.recon,
    warnings: scan.warnings,
    toolRuns: scan.toolRuns,
    contacts,
    timezone: config.timezone,
    generatedAt,
  });
  const jsonObject = buildJsonReport({
    scan,
    findings,
    recon: scan.recon,
    warnings: scan.warnings,
    toolRuns: scan.toolRuns,
    contacts,
    generatedAt,
  });
  const json = JSON.stringify(jsonObject, null, 2);

  if (force || !(await fileExists(paths.markdown)) || !(await fileExists(paths.json))) {
    await mkdir(paths.directory, { recursive: true });
    await writeFile(paths.markdown, markdown, 'utf8');
    await writeFile(paths.json, json, 'utf8');
  }

  return {
    markdown: {
      format: 'markdown',
      path: paths.markdown,
      bytes: Buffer.byteLength(markdown, 'utf8'),
      content: markdown,
    },
    json: {
      format: 'json',
      path: paths.json,
      bytes: Buffer.byteLength(json, 'utf8'),
      content: json,
    },
  };
}

/**
 * Pastikan laporan tersedia. Dipakai bot/API untuk scan lama atau setelah restart.
 */
export async function ensureReports({ config, db, scan, contacts = [], force = false }) {
  const existingMarkdown = db.getReport(scan.id, 'markdown');
  const existingJson = db.getReport(scan.id, 'json');
  if (
    !force &&
    existingMarkdown &&
    existingJson &&
    (await fileExists(existingMarkdown.path)) &&
    (await fileExists(existingJson.path))
  ) {
    return {
      markdown: {
        format: 'markdown',
        path: existingMarkdown.path,
        bytes: existingMarkdown.bytes,
        content: await readFile(existingMarkdown.path, 'utf8'),
      },
      json: {
        format: 'json',
        path: existingJson.path,
        bytes: existingJson.bytes,
        content: await readFile(existingJson.path, 'utf8'),
      },
    };
  }

  const findings = db.getFindings(scan.id);
  const reports = await writeReports({ config, scan, findings, contacts, force: true });
  db.saveReport(scan.id, reports.markdown);
  db.saveReport(scan.id, reports.json);
  return reports;
}

async function readTextLimited(response, maxBytes) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const remaining = maxBytes - total;
      const chunk = value.subarray(0, remaining);
      chunks.push(Buffer.from(chunk));
      total += chunk.byteLength;
      if (chunk.byteLength < value.byteLength) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Cari kontak pada /.well-known/security.txt dan /security.txt target.
 * Redirect tidak diikuti agar host di luar scope tidak tersentuh.
 */
export async function discoverSecurityContacts({
  targetUrl,
  allowedDomains,
  userAgent,
  signal,
  timeoutMs = 8000,
}) {
  const origin = new URL(targetUrl).origin;
  const candidates = [`${origin}/.well-known/security.txt`, `${origin}/security.txt`];
  const contacts = [];
  const sources = [];
  const errors = [];

  for (const url of candidates) {
    if (signal?.aborted) break;
    try {
      const response = await fetch(url, {
        redirect: 'manual',
        signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
          : AbortSignal.timeout(timeoutMs),
        headers: { 'user-agent': userAgent || 'SecurityScanner/1.0', accept: 'text/plain' },
      });
      if (response.status !== 200) continue;
      const text = await readTextLimited(response, 64 * 1024);
      sources.push(url);
      for (const line of text.split(/\r?\n/)) {
        const match = line.match(/^\s*contact\s*:\s*(.+)$/i);
        if (!match) continue;
        let value = match[1].trim();
        if (/^mailto:/i.test(value)) value = value.slice(7);
        value = value.split('?')[0].trim();
        if (
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value) &&
          !contacts.includes(value.toLowerCase())
        ) {
          contacts.push(value.toLowerCase());
        }
        if (contacts.length >= 5) break;
      }
      if (contacts.length >= 5) break;
    } catch (error) {
      errors.push(`${url}: ${error.message}`);
    }
  }

  return { contacts, sources, errors };
}

export function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(value ?? '').trim());
}

function markdownToEmailText(markdown) {
  return (
    markdown
      .replace(/^#{1,6}\s*/gm, '')
      .replace(/`{3}[^\n]*\n([\s\S]*?)`{3}/g, '$1')
      .replace(/`([^`]+)`/g, '$1')
      .replace(/\*\*([^*]+)\*\*/g, '$1')
      .replace(/^\s*---\s*$/gm, '')
      .trimEnd() +
    '\n\nLampiran: report.md (Markdown) dan report.json (data terstruktur).\n'
  );
}

/**
 * Kirim laporan melalui SMTP. Nonaktif kecuali SECURITY_REPORT_SEND=true.
 * Fungsi ini tidak pernah dipanggil otomatis; harus ada konfirmasi eksplisit dari pengguna.
 */
export async function sendReportEmail({ config, db, scan, to, contacts = [] }) {
  const security = config.security;
  if (!security.reportSendEnabled) {
    throw new SecurityError(
      'Pengiriman laporan ke target dinonaktifkan. Set SECURITY_REPORT_SEND=true dan konfigurasi SMTP ' +
        'hanya jika kamu memiliki izin untuk menghubungi target melalui email.',
      { status: 403, code: 'report_send_disabled' },
    );
  }
  if (!security.smtp.host || !security.smtp.from) {
    throw new SecurityError('SMTP_HOST dan SMTP_FROM belum dikonfigurasi.', {
      status: 400,
      code: 'smtp_not_configured',
    });
  }

  const recipient = String(to ?? security.reportTo ?? '').trim();
  if (!recipient) {
    throw new SecurityError(
      'Alamat email tujuan belum ditentukan. Gunakan /sendreport <id> <email> atau isi SECURITY_REPORT_TO.',
      { status: 400, code: 'recipient_required' },
    );
  }
  if (!isValidEmail(recipient)) {
    throw new SecurityError(`Alamat email tidak valid: ${recipient}`, {
      status: 400,
      code: 'invalid_recipient',
    });
  }

  const reports = await ensureReports({ config, db, scan, contacts, force: false });
  const markdown = reports.markdown.content;
  const summary = scan.summary ?? {};
  const subject = `Laporan Kerentanan Keamanan — ${scan.host} (scan ${scan.id})`;

  let nodemailer;
  try {
    nodemailer = (await import('nodemailer')).default;
  } catch {
    throw new SecurityError(
      'nodemailer belum terpasang. Jalankan npm install lalu restart layanan.',
      { status: 500, code: 'mailer_unavailable' },
    );
  }

  const transport = nodemailer.createTransport({
    host: security.smtp.host,
    port: security.smtp.port,
    secure: security.smtp.secure,
    auth: security.smtp.user
      ? { user: security.smtp.user, pass: security.smtp.pass ?? '' }
      : undefined,
  });

  const attachments = [
    {
      filename: `security-report-${scan.id}.md`,
      content: markdown,
      contentType: 'text/markdown; charset=utf-8',
    },
    {
      filename: `security-report-${scan.id}.json`,
      content: reports.json.content,
      contentType: 'application/json; charset=utf-8',
    },
  ];

  let info;
  try {
    info = await transport.sendMail({
      from: security.smtp.from,
      to: recipient,
      subject,
      text:
        `Halo,\n\n` +
        `Kami ingin menyampaikan laporan kerentanan keamanan untuk ${scan.host}.\n` +
        `Ringkasan: ${summary.total ?? 0} temuan ` +
        `(kritis ${summary.critical ?? 0}, tinggi ${summary.high ?? 0}, ` +
        `sedang ${summary.medium ?? 0}, rendah ${summary.low ?? 0}, info ${summary.info ?? 0}).\n\n` +
        `Laporan lengkap tersedia pada lampiran. Jika Anda bukan pihak yang berwenang, ` +
        `mohon abaikan email ini.\n\n` +
        markdownToEmailText(markdown),
      attachments,
    });
  } catch (error) {
    if (db) {
      db.recordDelivery({
        id: shortId(6),
        scanId: scan.id,
        format: 'markdown',
        toEmail: recipient,
        status: 'failed',
        error: error.message,
        createdAt: new Date().toISOString(),
      });
    }
    throw new SecurityError(`Gagal mengirim email: ${error.message}`, {
      status: 502,
      code: 'smtp_send_failed',
    });
  } finally {
    transport.close?.();
  }

  if (db) {
    db.recordDelivery({
      id: shortId(6),
      scanId: scan.id,
      format: 'markdown',
      toEmail: recipient,
      status: 'sent',
      messageId: info.messageId ?? null,
      createdAt: new Date().toISOString(),
    });
  }

  return {
    messageId: info.messageId ?? null,
    accepted: info.accepted ?? [],
    rejected: info.rejected ?? [],
    to: recipient,
    subject,
    attachmentBytes: reports.markdown.bytes + reports.json.bytes,
  };
}
