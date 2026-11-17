import { isHostAllowed } from './scope.js';

const SECURITY_HEADERS = [
  {
    header: 'content-security-policy',
    severity: 'low',
    title: 'Content-Security-Policy tidak ada',
    evidence: 'Response tidak mengirim header Content-Security-Policy.',
    remediation:
      'Terapkan CSP yang membatasi sumber script/style/frame. Mulai dari mode report-only, lalu enforce setelah dipantau.',
    reference: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
  },
  {
    header: 'strict-transport-security',
    severity: 'low',
    title: 'Strict-Transport-Security tidak ada',
    httpsOnly: true,
    evidence: 'Response HTTPS tidak mengirim header Strict-Transport-Security.',
    remediation:
      'Kirim header Strict-Transport-Security: max-age=31536000; includeSubDomains setelah seluruh subdomain siap HTTPS.',
    reference: 'https://owasp.org/www-project-secure-headers/#strict-transport-security',
  },
  {
    header: 'x-content-type-options',
    severity: 'low',
    title: 'X-Content-Type-Options tidak ada',
    evidence: 'Response tidak mengirim header X-Content-Type-Options: nosniff.',
    remediation: 'Kirim header X-Content-Type-Options: nosniff pada semua response.',
    reference: 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
  },
  {
    header: 'referrer-policy',
    severity: 'info',
    title: 'Referrer-Policy tidak ada',
    evidence: 'Response tidak mengirim header Referrer-Policy.',
    remediation:
      'Gunakan Referrer-Policy: strict-origin-when-cross-origin atau no-referrer sesuai kebutuhan.',
    reference: 'https://owasp.org/www-project-secure-headers/#referrer-policy',
  },
];

function finding({ title, severity, evidence, remediation, reference, url, type = 'misconfiguration' }) {
  return {
    tool: 'headers',
    type,
    severity,
    title,
    url,
    parameter: null,
    evidence,
    cwe: null,
    cve: null,
    remediation,
    reference,
    raw: null,
  };
}

export function analyzeHeaders({ status, headers, setCookies = [], finalUrl, scheme }) {
  const findings = [];
  const url = finalUrl ?? '';
  const get = (name) => headers[name] ?? headers[name.toLowerCase()] ?? null;

  for (const item of SECURITY_HEADERS) {
    if (item.httpsOnly && scheme !== 'https') continue;
    if (get(item.header)) continue;
    findings.push(
      finding({
        title: item.title,
        severity: item.severity,
        evidence: `${item.evidence} (HTTP ${status})`,
        remediation: item.remediation,
        reference: item.reference,
        url,
      }),
    );
  }

  const xfo = get('x-frame-options');
  const csp = get('content-security-policy');
  if (!xfo && !(csp && /frame-ancestors/i.test(csp))) {
    findings.push(
      finding({
        title: 'Proteksi clickjacking tidak ditemukan',
        severity: 'low',
        evidence:
          'Tidak ada X-Frame-Options dan CSP tidak memuat frame-ancestors. Halaman berpotensi di-embed di iframe.',
        remediation:
          'Kirim X-Frame-Options: DENY atau SAMEORIGIN, dan/atau CSP frame-ancestors yang sesuai.',
        reference: 'https://owasp.org/www-community/attacks/Clickjacking',
        url,
      }),
    );
  }

  if (setCookies.length) {
    const exposed = [];
    for (const cookie of setCookies.slice(0, 20)) {
      const [pair, ...attributes] = String(cookie).split(';');
      const name = pair.split('=')[0]?.trim();
      if (!name) continue;
      const names = attributes.map((attribute) =>
        attribute.trim().split('=')[0].toLowerCase(),
      );
      const missing = [];
      if (scheme === 'https' && !names.includes('secure')) missing.push('Secure');
      if (!names.includes('httponly')) missing.push('HttpOnly');
      if (!names.includes('samesite')) missing.push('SameSite');
      if (missing.length) exposed.push(`${name} (${missing.join(', ')})`);
    }

    if (exposed.length) {
      findings.push(
        finding({
          title: 'Cookie tanpa atribut keamanan lengkap',
          severity: 'low',
          evidence:
            'Nilai cookie tidak disertakan. Cookie berikut kehilangan atribut: ' +
            exposed.slice(0, 10).join('; '),
          remediation:
            'Tambahkan Secure dan HttpOnly pada cookie sesi, serta SameSite=Lax/Strict. Nilai cookie tidak boleh dicatat di laporan.',
          reference: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
          url,
        }),
      );
    }
  }

  const server = get('server');
  if (server && /\d+\.\d+/.test(server)) {
    findings.push(
      finding({
        title: 'Header Server membocorkan versi',
        severity: 'info',
        evidence: `Server: ${String(server).slice(0, 160)}`,
        remediation:
          'Sembunyikan versi produk di header Server (mis. konfigurasi server untuk tidak mengirim detail versi).',
        reference: 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
        url,
      }),
    );
  }

  const poweredBy = get('x-powered-by');
  if (poweredBy) {
    findings.push(
      finding({
        title: 'Header X-Powered-By membocorkan teknologi',
        severity: 'info',
        evidence: `X-Powered-By: ${String(poweredBy).slice(0, 160)}`,
        remediation: 'Nonaktifkan header X-Powered-By (mis. app.disable("x-powered-by")).',
        reference: 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
        url,
      }),
    );
  }

  return findings;
}

async function readBodyLimited(response, maxBytes) {
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
      const slice = value.length > remaining ? value.subarray(0, remaining) : value;
      chunks.push(slice);
      total += slice.length;
      if (slice.length < value.length) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function extractTitle(html) {
  const match = String(html ?? '').match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return null;
  return match[1]
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

/**
 * Probe HTTP dengan redirect manual. Redirect ke host di luar scope tidak diikuti.
 */
export async function probeTarget(
  targetUrl,
  { allowedDomains, userAgent, signal, timeoutMs = 12_000, maxRedirects = 5 } = {},
) {
  const startedAt = Date.now();
  const chain = [];
  let current = targetUrl;
  let redirectBlocked = false;
  let maxRedirectHit = false;

  for (let step = 0; step <= maxRedirects; step += 1) {
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const requestSignal = signal
      ? AbortSignal.any([signal, timeoutSignal])
      : timeoutSignal;

    const response = await fetch(current, {
      redirect: 'manual',
      signal: requestSignal,
      headers: {
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'user-agent': userAgent,
      },
    });

    const headers = Object.fromEntries(response.headers.entries());
    const setCookies =
      typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [];
    const location = response.headers.get('location');
    const isRedirect = [301, 302, 303, 307, 308].includes(response.status) && location;

    chain.push({ url: current, status: response.status, location: location ?? null });

    if (isRedirect) {
      let next;
      try {
        next = new URL(location, current);
      } catch {
        break;
      }
      if (!['http:', 'https:'].includes(next.protocol)) break;
      if (!isHostAllowed(next.hostname, allowedDomains)) {
        redirectBlocked = true;
        break;
      }
      current = next.toString();
      continue;
    }

    const body = await readBodyLimited(response, 256 * 1024);
    return {
      status: response.status,
      headers,
      setCookies,
      body,
      title: extractTitle(body),
      finalUrl: current,
      scheme: new URL(current).protocol.slice(0, -1),
      redirectChain: chain,
      redirectBlocked,
      elapsedMs: Date.now() - startedAt,
    };
  }

  const last = chain[chain.length - 1];
  if (last?.location) maxRedirectHit = true;

  return {
    status: last?.status ?? null,
    headers: {},
    setCookies: [],
    body: '',
    title: null,
    finalUrl: current,
    scheme: new URL(current).protocol.slice(0, -1),
    redirectChain: chain,
    redirectBlocked,
    maxRedirectHit,
    elapsedMs: Date.now() - startedAt,
  };
}
