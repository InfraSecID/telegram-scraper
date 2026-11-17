import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { analyzeHeaders, probeTarget } from './probe.js';
import {
  buildScopeRegex,
  isHostAllowed,
  isParameterizedUrl,
  SecurityError,
} from './scope.js';
import { runProcess } from './tools.js';
import { shortId } from '../util/ids.js';

export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

const DEFAULT_EXCLUDE_TAGS = [
  'dos',
  'fuzz',
  'intrusive',
  'brute-force',
  'credential-stuffing',
].join(',');

const PROFILE_SETTINGS = {
  quick: {
    nucleiSeverity: 'high,critical',
    paramDiscovery: false,
    dalfox: false,
    sqlmap: false,
    subfinder: false,
  },
  standard: {
    nucleiSeverity: null,
    paramDiscovery: true,
    dalfox: true,
    sqlmap: true,
    subfinder: false,
  },
  deep: {
    nucleiSeverity: 'low,medium,high,critical',
    paramDiscovery: true,
    dalfox: true,
    sqlmap: true,
    subfinder: true,
  },
};

export const SCAN_PROFILES = Object.keys(PROFILE_SETTINGS);

function normalizeSeverity(value) {
  const severity = String(value ?? '').toLowerCase();
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  if (severity === 'medium' || severity === 'moderate') return 'medium';
  if (severity === 'low') return 'low';
  return 'info';
}

function stripAnsi(value) {
  return String(value ?? '').replace(/\u001b\[[0-9;]*m/g, '');
}

function trimText(value, max = 4000) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function unique(values) {
  const seen = new Set();
  const output = [];
  for (const value of values) {
    if (!value || seen.has(value)) continue;
    seen.add(value);
    output.push(value);
  }
  return output;
}

export function parseHttpxJsonl(stdout) {
  for (const line of stripAnsi(stdout).split('\n')) {
    const text = line.trim();
    if (!text.startsWith('{')) continue;
    try {
      const data = JSON.parse(text);
      if (!data || typeof data !== 'object') continue;
      return {
        statusCode: data.status_code ?? null,
        title: data.title ?? null,
        tech: Array.isArray(data.tech) ? data.tech.filter(Boolean) : [],
        server: data.webserver ?? data.web_server ?? null,
        finalUrl: data.final_url ?? data.url ?? null,
        contentType: data.content_type ?? null,
        location: data.location ?? null,
      };
    } catch {
      // baris bukan JSON valid
    }
  }
  return null;
}

export function extractParameterUrls(text, { allowedDomains = [], limit = 100 } = {}) {
  const urls = [];
  const candidates = stripAnsi(text).match(/https?:\/\/[^\s"'<>]+/g) ?? [];
  for (const candidate of candidates) {
    let url;
    try {
      url = new URL(candidate.replace(/[),.;]+$/, ''));
    } catch {
      continue;
    }
    if (!['http:', 'https:'].includes(url.protocol)) continue;
    if (!isHostAllowed(url.hostname, allowedDomains)) continue;
    if (url.searchParams.size === 0) continue;
    url.hash = '';
    urls.push(url.toString());
    if (urls.length >= limit) break;
  }
  return unique(urls);
}

export function parseNucleiJsonl(stdout, { target, maxFindings = 200 } = {}) {
  const findings = [];
  for (const line of stripAnsi(stdout).split('\n')) {
    const text = line.trim();
    if (!text.startsWith('{')) continue;
    let entry;
    try {
      entry = JSON.parse(text);
    } catch {
      continue;
    }
    if (!entry || typeof entry !== 'object') continue;

    const info = entry.info ?? {};
    const tags = Array.isArray(info.tags)
      ? info.tags
      : String(info.tags ?? '')
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean);
    const classification = info.classification ?? {};
    const cwe = Array.isArray(classification['cwe-id'])
      ? classification['cwe-id'].join(', ')
      : classification['cwe-id'] ?? null;
    const cve = Array.isArray(classification['cve-id'])
      ? classification['cve-id'].join(', ')
      : classification['cve-id'] ?? null;

    let type = 'nuclei';
    if (tags.some((tag) => /xss/i.test(tag))) type = 'xss';
    else if (tags.some((tag) => /sqli|sql-injection/i.test(tag))) type = 'sqli';
    else if (tags.some((tag) => /ssrf/i.test(tag))) type = 'ssrf';
    else if (tags.some((tag) => /lfi|rfi|file-inclusion/i.test(tag))) type = 'lfi';
    else if (tags.some((tag) => /rce|command-injection/i.test(tag))) type = 'rce';
    else if (tags.some((tag) => /default-login/i.test(tag))) type = 'default_login';
    else if (tags.some((tag) => /exposure|disclosure/i.test(tag))) type = 'exposure';
    else if (tags.some((tag) => /misconfig|config/i.test(tag))) type = 'misconfiguration';
    else if (tags.some((tag) => /cve/i.test(tag)) || cve) type = 'cve';

    const extracted = Array.isArray(entry['extracted-results'])
      ? entry['extracted-results']
      : [];
    const evidenceParts = [
      info.description,
      entry['matcher-name'] ? `Matcher: ${entry['matcher-name']}` : null,
      extracted.length ? `Extracted: ${extracted.slice(0, 5).join(' | ')}` : null,
      entry['curl-command'] ? `Curl: ${trimText(entry['curl-command'], 1200)}` : null,
    ].filter(Boolean);

    findings.push({
      tool: 'nuclei',
      type,
      severity: normalizeSeverity(info.severity),
      title: String(info.name || entry['template-id'] || 'Temuan nuclei').slice(0, 300),
      url: entry['matched-at'] || entry.host || target || null,
      parameter: null,
      evidence: trimText(evidenceParts.join('\n')),
      cwe,
      cve,
      remediation:
        info.remediation ||
        'Perbarui komponen/konfigurasi yang terdeteksi dan terapkan mitigasi sesuai template nuclei.',
      reference: Array.isArray(info.reference)
        ? info.reference.slice(0, 3).join(' ')
        : info.reference ?? null,
      raw: trimText(
        JSON.stringify({
          'template-id': entry['template-id'],
          'matcher-name': entry['matcher-name'],
          severity: info.severity,
          tags,
          extracted,
        }),
        6000,
      ),
    });

    if (findings.length >= maxFindings) break;
  }

  return findings;
}

export function parseDalfoxJson(text, { target } = {}) {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return [];
  }

  const entries = Array.isArray(payload?.findings) ? payload.findings : [];
  const findings = [];

  for (const item of entries) {
    const tier = String(item.type ?? '').toUpperCase();
    const injectType = String(item.inject_type ?? '');
    const detection = String(item.detection_method ?? '');
    // Hanya type "A" (AST) / inDOM yang benar-benar DOM XSS.
    // "dom-verification" pada dalfox v3 adalah verifikasi browser untuk XSS reflected.
    const isDom = tier === 'A' || /DOM/i.test(injectType) || /^ast/i.test(detection);
    const type = isDom ? 'dom_xss' : 'xss';
    const severity = isDom
      ? normalizeSeverity(item.severity === 'High' ? 'medium' : item.severity)
      : normalizeSeverity(item.severity);

    const title = isDom
      ? 'DOM-based XSS (perlu verifikasi)'
      : tier === 'V'
        ? 'Reflected XSS (terverifikasi)'
        : 'XSS (perlu verifikasi manual)';

    const evidenceParts = [
      item.message_str,
      item.evidence,
      item.payload ? `Payload: ${item.payload}` : null,
      item.location ? `Location: ${item.location}` : null,
      item.confidence ? `Confidence: ${item.confidence}` : null,
    ].filter(Boolean);

    findings.push({
      tool: 'dalfox',
      type,
      severity,
      title,
      url: item.data || target || null,
      parameter: item.param ?? null,
      evidence: trimText(unique(evidenceParts).join('\n')),
      cwe: item.cwe || 'CWE-79',
      cve: null,
      remediation:
        'Encode output sesuai konteks (HTML/attribute/JS/URL), gunakan sanitizer yang tepat, terapkan CSP, dan hindari sink DOM berbahaya.',
      reference: 'https://owasp.org/www-community/attacks/xss/',
      raw: trimText(
        JSON.stringify({
          type: item.type,
          inject_type: item.inject_type,
          detection_method: item.detection_method,
          confidence: item.confidence,
          param: item.param,
          location: item.location,
          payload: item.payload,
        }),
        6000,
      ),
    });
  }

  return findings;
}

export function parseSqlmapOutput(stdout, { target } = {}) {
  const text = stripAnsi(stdout);
  const parameters = [];
  const parameterRegex = /Parameter:\s*([^\s(]+)\s*\(([^)]+)\)/g;
  let match;
  while ((match = parameterRegex.exec(text)) !== null) {
    parameters.push({ name: match[1], location: match[2] });
  }

  const types = unique(
    [...text.matchAll(/Type:\s*(.+)/g)].map((item) => item[1].trim()).filter(Boolean),
  );
  const payloads = unique(
    [...text.matchAll(/Payload:\s*(.+)/g)].map((item) => item[1].trim()).filter(Boolean),
  );
  const dbms = text.match(/back-end DBMS:\s*(.+)/i)?.[1]?.trim() ?? null;
  const vulnerable =
    /is vulnerable/i.test(text) || (parameters.length > 0 && types.length > 0);

  if (!vulnerable) return [];

  const evidenceParts = [
    parameters.length
      ? `Parameter: ${parameters.map((p) => `${p.name} (${p.location})`).join(', ')}`
      : null,
    types.length ? `Type: ${types.join('; ')}` : null,
    payloads.length ? `Payload: ${payloads.slice(0, 3).join(' | ')}` : null,
    dbms ? `Back-end DBMS: ${dbms}` : null,
    'Mode deteksi: --level=1 --risk=1 (tanpa dump data).',
  ].filter(Boolean);

  if (parameters.length === 0) {
    return [
      {
        tool: 'sqlmap',
        type: 'sqli',
        severity: 'high',
        title: 'SQL Injection terdeteksi',
        url: target ?? null,
        parameter: null,
        evidence: trimText(evidenceParts.join('\n')),
        cwe: 'CWE-89',
        cve: null,
        remediation:
          'Gunakan prepared statement/parameterized query, validasi tipe input, batasi hak akses DB, dan jangan menyusun query dengan konkatenasi string.',
        reference: 'https://owasp.org/www-community/attacks/SQL_Injection',
        raw: trimText(text, 6000),
      },
    ];
  }

  return parameters.map((parameter) => ({
    tool: 'sqlmap',
    type: 'sqli',
    severity: 'high',
    title: `SQL Injection pada parameter "${parameter.name}"`,
    url: target ?? null,
    parameter: parameter.name,
    evidence: trimText(
      `${evidenceParts.join('\n')}\nLocation: ${parameter.location}`,
      5000,
    ),
    cwe: 'CWE-89',
    cve: null,
    remediation:
      'Gunakan prepared statement/parameterized query, validasi tipe input, batasi hak akses DB, dan jangan menyusun query dengan konkatenasi string.',
    reference: 'https://owasp.org/www-community/attacks/SQL_Injection',
    raw: trimText(
      JSON.stringify({
        parameter,
        types,
        payloads: payloads.slice(0, 5),
        dbms,
      }),
      6000,
    ),
  }));
}

export function parseSubfinderOutput(stdout, { allowedDomains = [], limit = 50 } = {}) {
  const hosts = [];
  for (const line of stripAnsi(stdout).split('\n')) {
    const host = line.trim().toLowerCase().replace(/\.$/, '');
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)) continue;
    if (!isHostAllowed(host, allowedDomains)) continue;
    hosts.push(host);
    if (hosts.length >= limit) break;
  }
  return unique(hosts);
}

function findingKey(finding) {
  return [
    finding.tool,
    finding.type,
    finding.severity,
    finding.title,
    finding.url,
    finding.parameter,
  ]
    .map((value) => String(value ?? '').toLowerCase())
    .join('|');
}

export function dedupeFindings(findings, maxFindings = 200) {
  const seen = new Set();
  const output = [];
  for (const finding of findings) {
    const key = findingKey(finding);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(finding);
    if (output.length >= maxFindings) break;
  }
  return output.sort(
    (a, b) =>
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
      String(a.title).localeCompare(String(b.title), 'id'),
  );
}

export function summarizeFindings(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] ?? 0) + 1;
    summary.total += 1;
  }
  return summary;
}

function category(type) {
  switch (type) {
    case 'xss':
    case 'dom_xss':
      return 'XSS';
    case 'sqli':
      return 'SQL Injection';
    case 'ssrf':
      return 'SSRF';
    case 'lfi':
      return 'File Inclusion';
    case 'rce':
      return 'RCE';
    case 'cve':
      return 'CVE';
    case 'exposure':
      return 'Information Disclosure';
    case 'default_login':
      return 'Default Login';
    default:
      return 'Kerentanan Web';
  }
}

function sortGenericFindings(findings, maxFindings = 200) {
  return dedupeFindings(findings, maxFindings).map((finding) => ({
    id: shortId(),
    category: category(finding.type),
    ...finding,
  }));
}

function profileConfig(profile, config) {
  const base = PROFILE_SETTINGS[profile];
  return {
    ...base,
    nucleiSeverity: base.nucleiSeverity ?? config.security.nucleiSeverity,
  };
}

async function writeIfNeeded(filePath, content) {
  if (!filePath || content === undefined || content === null) return;
  try {
    await writeFile(filePath, content, 'utf8');
  } catch {
    // penyimpanan bukti tidak boleh menggagalkan scan
  }
}

export async function scanTarget({
  scan,
  config,
  toolStatuses,
  signal,
  deadline,
  onProgress = () => {},
  logger,
}) {
  const startedAt = Date.now();
  const settings = profileConfig(scan.profile, config);
  const bin = config.security.bins;
  const rateLimit = config.security.rateLimit;
  const userAgent = config.security.userAgent;
  const workDir = path.join(config.dataDir, 'security', scan.id);
  const maxFindings = config.security.maxFindings;
  const findings = [];
  const warnings = [];
  const toolRuns = [];
  const recon = {
    target: scan.target,
    host: scan.host,
    profile: scan.profile,
    statusCode: null,
    title: null,
    server: null,
    tech: [],
    finalUrl: null,
    redirectBlocked: false,
    parameterUrls: [],
    parameterUrlCount: 0,
    subdomains: [],
    securityTxt: [],
  };

  const statusByName = Object.fromEntries(
    (toolStatuses ?? []).map((tool) => [tool.name, tool]),
  );

  await mkdir(workDir, { recursive: true });

  const ensureActive = () => {
    if (signal?.aborted) {
      throw new SecurityError('Scan dibatalkan atau melewati batas waktu.', {
        status: 408,
        code: 'scan_aborted',
      });
    }
    if (deadline && Date.now() >= deadline) {
      throw new SecurityError('Scan melewati batas waktu.', {
        status: 408,
        code: 'scan_timeout',
      });
    }
  };

  async function phase(name, fn) {
    ensureActive();
    const phaseStarted = Date.now();
    onProgress({ phase: name, message: `Mulai ${name}` });
    try {
      const value = await fn();
      toolRuns.push({
        name,
        ok: true,
        durationMs: Date.now() - phaseStarted,
      });
      return value;
    } catch (error) {
      ensureActive();
      const message = error?.message || String(error);
      warnings.push(`${name}: ${message}`);
      toolRuns.push({
        name,
        ok: false,
        durationMs: Date.now() - phaseStarted,
        error: trimText(message, 500),
      });
      logger?.warn({ scanId: scan.id, phase: name, err: message }, 'fase security gagal');
      return null;
    }
  }

  async function exec(name, args, { timeoutMs, cwd = workDir, maxOutputBytes } = {}) {
    ensureActive();
    const remaining = deadline
      ? Math.max(1000, deadline - Date.now())
      : Number.POSITIVE_INFINITY;
    const result = await runProcess({
      command: bin[name],
      args,
      cwd,
      signal,
      timeoutMs: Math.min(timeoutMs ?? config.security.toolTimeoutMs, remaining),
      maxOutputBytes,
      env: { NO_COLOR: '1' },
    });
    if (result.aborted) ensureActive();
    return result;
  }

  // 1. Probe HTTP + pemeriksaan header/cookie bawaan.
  let probe = null;
  probe = await phase('headers', async () => {
    const result = await probeTarget(scan.target, {
      allowedDomains: config.security.allowedDomains,
      userAgent,
      signal,
    });
    recon.statusCode = result.status;
    recon.title = result.title;
    recon.server = result.headers.server ?? null;
    recon.finalUrl = result.finalUrl;
    recon.redirectBlocked = result.redirectBlocked;
    if (result.redirectChain?.length > 1) {
      recon.redirectChain = result.redirectChain.slice(0, 8);
    }
    findings.push(...analyzeHeaders(result));
    return result;
  });

  if (probe?.redirectBlocked) {
    warnings.push(
      'Redirect ke host di luar scope tidak diikuti. Pemindaian hanya dilakukan pada scope yang diizinkan.',
    );
  }

  if (!probe) {
    throw new SecurityError(
      'Tidak dapat terhubung ke target. Periksa URL, DNS, dan konektivitas jaringan. ' +
        'Laporan tidak dibuat agar tidak menghasilkan kesimpulan "aman" yang keliru.',
      { status: 502, code: 'target_unreachable' },
    );
  }

  // 2. httpx untuk fingerprint tambahan.
  await phase('httpx', async () => {
    if (!statusByName.httpx?.available) {
      throw new Error('httpx (ProjectDiscovery) tidak tersedia');
    }
    const args = [
      '-u',
      scan.target,
      '-silent',
      '-json',
      '-sc',
      '-title',
      '-td',
      '-server',
      '-location',
      '-timeout',
      '8',
      '-retries',
      '1',
      '-rl',
      String(rateLimit),
      '-nc',
      '-duc',
      '-H',
      `User-Agent: ${userAgent}`,
    ];
    const result = await exec('httpx', args, { timeoutMs: 60_000 });
    await writeIfNeeded(path.join(workDir, 'httpx.jsonl'), result.stdout);
    if (result.spawnError) throw new Error(`httpx gagal dijalankan: ${result.spawnError.message}`);
    if (result.timedOut) throw new Error('httpx timeout');
    const data = parseHttpxJsonl(result.stdout);
    if (!data) throw new Error('httpx tidak mengembalikan data');
    recon.statusCode ??= data.statusCode;
    recon.title ??= data.title;
    recon.server ??= data.server;
    recon.finalUrl ??= data.finalUrl;
    recon.tech = unique([...recon.tech, ...(data.tech ?? [])]);
    if (data.contentType) recon.contentType = data.contentType;
    if (data.location) recon.location = data.location;
  });

  // 3. Penemuan URL berparameter.
  const paramspiderUrls = [];
  const katanaUrls = [];
  if (settings.paramDiscovery) {
    await phase('paramspider', async () => {
      if (!statusByName.paramspider?.available) {
        throw new Error('paramspider tidak tersedia');
      }
      const domain = scan.host.replace(/^www\./i, '');
      const result = await exec('paramspider', ['-d', domain, '-s'], {
        timeoutMs: 90_000,
      });
      await writeIfNeeded(path.join(workDir, 'paramspider.txt'), result.stdout);
      if (result.spawnError) {
        throw new Error(`paramspider gagal dijalankan: ${result.spawnError.message}`);
      }
      if (result.timedOut) throw new Error('paramspider timeout');
      paramspiderUrls.push(
        ...extractParameterUrls(result.stdout, {
          allowedDomains: config.security.allowedDomains,
          limit: config.security.maxParamUrls,
        }),
      );
    });

    await phase('katana', async () => {
      if (!statusByName.katana?.available) {
        throw new Error('katana tidak tersedia');
      }
      const args = [
        '-u',
        scan.target,
        '-silent',
        '-d',
        '2',
        '-f',
        'qurl',
        '-rl',
        String(rateLimit),
        '-timeout',
        '8',
        '-nc',
        '-fs',
        'rdn',
      ];
      const result = await exec('katana', args, { timeoutMs: 90_000 });
      await writeIfNeeded(path.join(workDir, 'katana.txt'), result.stdout);
      if (result.spawnError) throw new Error(`katana gagal dijalankan: ${result.spawnError.message}`);
      if (result.timedOut) throw new Error('katana timeout');
      katanaUrls.push(
        ...extractParameterUrls(result.stdout, {
          allowedDomains: config.security.allowedDomains,
          limit: config.security.maxParamUrls,
        }),
      );
    });
  }

  // URL live hasil crawl diprioritaskan di atas URL arsip dari paramspider.
  const parameterUrls = [];
  if (isParameterizedUrl(scan.target)) parameterUrls.push(scan.target);
  parameterUrls.push(...katanaUrls, ...paramspiderUrls);
  recon.parameterUrls = unique(parameterUrls).slice(0, config.security.maxParamUrls);
  recon.parameterUrlCount = recon.parameterUrls.length;
  await writeIfNeeded(
    path.join(workDir, 'parameter-urls.txt'),
    recon.parameterUrls.join('\n'),
  );

  if (recon.parameterUrls.length === 0) {
    warnings.push(
      'Tidak ada URL berparameter yang ditemukan. Dalfox dan sqlmap dilewati; XSS/SQLi pada form dinamis mungkin tidak tercakup.',
    );
  }

  // 4. nuclei.
  await phase('nuclei', async () => {
    const status = statusByName.nuclei;
    if (!status?.available) throw new Error('nuclei tidak tersedia');
    if (status.templates && status.templates.available === false) {
      throw new Error(
        status.templates.error ||
          'Template nuclei belum tersedia. Jalankan nuclei -update-templates.',
      );
    }
    const args = [
      '-u',
      scan.target,
      '-jsonl',
      '-silent',
      '-nc',
      '-severity',
      settings.nucleiSeverity,
      '-rate-limit',
      String(rateLimit),
      '-timeout',
      '8',
      '-retries',
      '1',
      '-exclude-tags',
      config.security.nucleiExcludeTags || DEFAULT_EXCLUDE_TAGS,
      '-no-interactsh',
      '-disable-update-check',
      '-H',
      `User-Agent: ${userAgent}`,
    ];
    if (status.templates?.path) args.push('-t', status.templates.path);
    const result = await exec('nuclei', args, {
      timeoutMs: config.security.nucleiTimeoutMs,
      maxOutputBytes: 32 * 1024 * 1024,
    });
    await writeIfNeeded(path.join(workDir, 'nuclei.jsonl'), result.stdout);
    if (result.spawnError) throw new Error(`nuclei gagal dijalankan: ${result.spawnError.message}`);
    if (result.timedOut) throw new Error('nuclei timeout');
    const parsed = parseNucleiJsonl(result.stdout, {
      target: scan.target,
      maxFindings,
    });
    findings.push(...parsed);
  });

  // 5. dalfox untuk XSS pada URL berparameter.
  if (settings.dalfox && recon.parameterUrls.length > 0) {
    await phase('dalfox', async () => {
      if (!statusByName.dalfox?.available) throw new Error('dalfox tidak tersedia');
      const urls = recon.parameterUrls.slice(0, config.security.dalfoxMaxUrls);
      const urlFile = path.join(workDir, 'dalfox-urls.txt');
      const outputFile = path.join(workDir, 'dalfox.json');
      await writeFile(urlFile, urls.join('\n'), 'utf8');
      const args = [
        'scan',
        urlFile,
        '-i',
        'file',
        '-f',
        'json',
        '-o',
        outputFile,
        '-S',
        '--no-color',
        '--timeout',
        '8',
        '--scan-timeout',
        String(scan.profile === 'deep' ? 90 : 45),
        '--rate-limit',
        String(rateLimit),
        '--workers',
        '5',
        '--only-poc',
        'v,r,a',
        '--limit',
        '50',
        '--follow-redirects',
        '--user-agent',
        userAgent,
      ];
      const scopeRegex = buildScopeRegex(config.security.allowedDomains);
      if (scopeRegex) args.push('--include-url', scopeRegex);
      const result = await exec('dalfox', args, { timeoutMs: 180_000 });
      if (result.spawnError) {
        throw new Error(`dalfox gagal dijalankan: ${result.spawnError.message}`);
      }
      if (result.timedOut) throw new Error('dalfox timeout');
      let json = '';
      try {
        json = await readFile(outputFile, 'utf8');
      } catch {
        json = result.stdout;
      }
      await writeIfNeeded(path.join(workDir, 'dalfox.stdout.txt'), result.stdout);
      if (!json.trim()) {
        if (result.code === 2) throw new Error('dalfox melaporkan error');
        return;
      }
      findings.push(...parseDalfoxJson(json, { target: scan.target }));
    });
  }

  // 6. sqlmap untuk SQLi pada URL berparameter (deteksi saja).
  if (settings.sqlmap && recon.parameterUrls.length > 0) {
    await phase('sqlmap', async () => {
      if (!statusByName.sqlmap?.available) throw new Error('sqlmap tidak tersedia');
      const urls = recon.parameterUrls.slice(0, config.security.sqlmapMaxUrls);
      await mkdir(path.join(workDir, 'sqlmap'), { recursive: true });
      for (let index = 0; index < urls.length; index += 1) {
        ensureActive();
        const url = urls[index];
        const args = [
          '-u',
          url,
          '--batch',
          '--smart',
          '--level=1',
          '--risk=1',
          '--threads=1',
          '--timeout=10',
          '--retries=0',
          '--disable-coloring',
          '--flush-session',
          '--output-dir',
          path.join(workDir, 'sqlmap'),
          '--user-agent',
          userAgent,
        ];
        const result = await exec('sqlmap', args, {
          timeoutMs: config.security.sqlmapTimeoutMs,
          maxOutputBytes: 32 * 1024 * 1024,
        });
        await writeIfNeeded(
          path.join(workDir, `sqlmap-${index + 1}.txt`),
          result.stdout,
        );
        if (result.spawnError) {
          throw new Error(`sqlmap gagal dijalankan: ${result.spawnError.message}`);
        }
        if (result.timedOut) {
          warnings.push(`sqlmap timeout pada ${url}`);
          continue;
        }
        const parsed = parseSqlmapOutput(result.stdout, { target: url });
        findings.push(...parsed);
      }
    });
  }

  // 7. subfinder (deep): recon pasif, tidak otomatis memindai subdomain.
  if (settings.subfinder) {
    await phase('subfinder', async () => {
      if (!statusByName.subfinder?.available) throw new Error('subfinder tidak tersedia');
      const domain = scan.host.replace(/^www\./i, '');
      const result = await exec(
        'subfinder',
        ['-d', domain, '-silent', '-nc', '-timeout', '20'],
        { timeoutMs: 60_000 },
      );
      await writeIfNeeded(path.join(workDir, 'subfinder.txt'), result.stdout);
      if (result.spawnError) {
        throw new Error(`subfinder gagal dijalankan: ${result.spawnError.message}`);
      }
      if (result.timedOut) throw new Error('subfinder timeout');
      recon.subdomains = parseSubfinderOutput(result.stdout, {
        allowedDomains: config.security.allowedDomains,
        limit: config.security.subfinderLimit,
      });
    });
  }

  // 8. Pastikan target masih merespons. Jika target down/rate-limit setelah pemindaian,
  // hasil "tanpa temuan" tidak boleh disajikan seolah-olah aplikasi aman.
  if (!signal?.aborted) {
    try {
      const finalCheck = await probeTarget(scan.target, {
        allowedDomains: config.security.allowedDomains,
        userAgent,
        signal,
        timeoutMs: 10_000,
        maxRedirects: 3,
      });
      if (!finalCheck.status) {
        warnings.push(
          'Target tidak memberikan respons valid setelah pemindaian. Hasil mungkin tidak lengkap; ' +
            'verifikasi manual dan pengulangan scan disarankan.',
        );
      } else {
        recon.finalStatusCode = finalCheck.status;
      }
    } catch {
      warnings.push(
        'Tidak dapat menghubungi target setelah pemindaian (koneksi gagal/timeout). ' +
          'Kemungkinan target down atau memblokir scanner; hasil mungkin tidak lengkap.',
      );
    }
  }

  const finalFindings = sortGenericFindings(findings, maxFindings);
  const summary = summarizeFindings(finalFindings);

  if (findings.length > maxFindings) {
    warnings.push(
      `Temuan dipotong menjadi ${maxFindings} item (dari ${findings.length}) agar laporan tetap ringkas.`,
    );
  }

  return {
    findings: finalFindings,
    summary,
    recon,
    warnings: unique(warnings),
    toolRuns,
    durationMs: Date.now() - startedAt,
  };
}
