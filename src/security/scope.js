import { isIP } from 'node:net';

export class SecurityError extends Error {
  constructor(message, { status = 400, code = 'security_error', details } = {}) {
    super(message);
    this.name = 'SecurityError';
    this.status = status;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function bareHost(hostname) {
  return String(hostname ?? '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}

function isHostname(value) {
  if (!value || value.length > 253) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(
    value,
  );
}

function isValidScopeHost(value) {
  return isIP(value) !== 0 || isHostname(value);
}

/**
 * Scope disimpan sebagai daftar pola:
 * - example.com   -> example.com dan seluruh subdomain
 * - *.example.com -> hanya subdomain, bukan apex
 * - 203.0.113.7   -> hanya IP tersebut
 */
export function parseAllowedDomains(raw) {
  const list = Array.isArray(raw) ? raw : String(raw ?? '').split(/[\s,]+/);
  const output = [];
  const seen = new Set();

  for (const item of list) {
    let entry = String(item ?? '')
      .trim()
      .toLowerCase();
    if (!entry) continue;

    if (/^https?:\/\//i.test(entry)) {
      try {
        entry = new URL(entry).hostname;
      } catch {
        throw new SecurityError(`Scope tidak valid: ${item}`, { code: 'invalid_scope' });
      }
    }

    entry = bareHost(entry);
    let wildcard = false;
    if (entry.startsWith('*.')) {
      wildcard = true;
      entry = entry.slice(2);
    }

    if (!isValidScopeHost(entry)) {
      throw new SecurityError(
        `Scope tidak valid: "${item}". Gunakan domain (contoh: example.com), wildcard (*.example.com), atau IP.`,
        { code: 'invalid_scope' },
      );
    }

    const normalized = `${wildcard ? '*.' : ''}${entry}`;
    if (!seen.has(normalized)) {
      seen.add(normalized);
      output.push(normalized);
    }
  }

  return output;
}

export function isHostAllowed(hostname, allowedDomains) {
  const host = bareHost(hostname);
  if (!host || !Array.isArray(allowedDomains)) return false;

  for (const pattern of allowedDomains) {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (host !== suffix && host.endsWith(`.${suffix}`)) return true;
      continue;
    }
    if (isIP(pattern) !== 0) {
      if (host === pattern) return true;
      continue;
    }
    if (host === pattern || host.endsWith(`.${pattern}`)) return true;
  }

  return false;
}

export function normalizeTarget(input, allowedDomains) {
  let raw = String(input ?? '').trim();
  if (!raw) {
    throw new SecurityError('Target kosong. Kirim domain atau URL.', {
      code: 'target_required',
    });
  }

  // Telegram kadang membungkus URL dengan <...>.
  raw = raw.replace(/^<|>$/g, '');

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new SecurityError(`Target tidak valid: ${input}`, { code: 'invalid_target' });
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new SecurityError('Hanya target http:// dan https:// yang didukung.', {
      code: 'invalid_target',
    });
  }
  if (url.username || url.password) {
    throw new SecurityError('URL dengan username/password tidak didukung.', {
      code: 'invalid_target',
    });
  }

  url.hash = '';
  const host = bareHost(url.hostname);
  if (!host) {
    throw new SecurityError(`Target tidak valid: ${input}`, { code: 'invalid_target' });
  }

  if (!isHostAllowed(host, allowedDomains)) {
    const scope = allowedDomains.length ? allowedDomains.join(', ') : '(belum diatur)';
    throw new SecurityError(
      `Target ${host} berada di luar scope. Scope saat ini: ${scope}. ` +
        'Tambahkan domain target ke SECURITY_ALLOWED_DOMAINS hanya jika kamu punya izin tertulis.',
      { status: 403, code: 'target_out_of_scope' },
    );
  }

  return {
    url: url.toString(),
    host,
    origin: url.origin,
    scheme: url.protocol.slice(0, -1),
    hasQuery: url.searchParams.size > 0,
    queryParamCount: new Set(url.searchParams.keys()).size,
  };
}

export function scopeInfo(allowedDomains, enabled) {
  return {
    enabled: Boolean(enabled),
    allowedDomains: [...allowedDomains],
    authorizationRequired: true,
    note:
      'Scan hanya berjalan pada domain di SECURITY_ALLOWED_DOMAINS dan setelah pengguna mengonfirmasi ' +
      'bahwa ia memiliki izin tertulis dari program bug bounty / pemilik target.',
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Regex untuk dalfox --include-url agar crawler/form action tetap berada di scope.
 */
export function buildScopeRegex(allowedDomains) {
  const patterns = allowedDomains.map((pattern) => {
    if (pattern.startsWith('*.')) {
      return `(?:[a-z0-9-]+\\.)+${escapeRegex(pattern.slice(2))}`;
    }
    if (isIP(pattern) !== 0) return escapeRegex(pattern);
    return `(?:[a-z0-9-]+\\.)*${escapeRegex(pattern)}`;
  });

  if (patterns.length === 0) return null;
  return `https?://(?:${patterns.join('|')})(?::\\d+)?(?:/|$)`;
}

export function isParameterizedUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && url.searchParams.size > 0;
  } catch {
    return false;
  }
}
