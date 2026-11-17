import dns from 'node:dns';
import { lookup as dnsLookup } from 'node:dns/promises';
import net from 'node:net';
import ipaddr from 'ipaddr.js';

export class SsrfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfError';
  }
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

const BLOCKED_SUFFIXES = ['.local', '.internal', '.home.arpa', '.localhost'];

/**
 * True hanya untuk IP publik unicast.
 * Loopback, private, link-local, CGNAT, ULA, multicast, reserved, dsb. dianggap tidak publik.
 */
export function isPublicIp(ip) {
  if (!ipaddr.isValid(ip)) return false;
  let address = ipaddr.parse(ip);
  if (address.kind() === 'ipv6' && address.isIPv4MappedAddress()) {
    address = address.toIPv4Address();
  }
  return address.range() === 'unicast';
}

/**
 * Validasi URL ad-hoc agar tidak menjadi celah SSRF.
 * Semua alamat hasil resolve harus IP publik, hostname internal diblokir,
 * dan redirect akan dicek ulang oleh fetchHtml.
 */
export async function assertPublicUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new SsrfError('URL tidak valid.');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError('Hanya URL http/https yang diizinkan.');
  }
  if (url.username || url.password) {
    throw new SsrfError('URL yang mengandung username/password tidak diizinkan.');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (!hostname) throw new SsrfError('Hostname kosong.');

  const lowered = hostname.toLowerCase();
  if (
    BLOCKED_HOSTNAMES.has(lowered) ||
    BLOCKED_SUFFIXES.some((suffix) => lowered.endsWith(suffix))
  ) {
    throw new SsrfError(`Host "${hostname}" diblokir (hostname internal).`);
  }

  const literalFamily = net.isIP(hostname);
  let addresses;
  if (literalFamily) {
    addresses = [{ address: hostname, family: literalFamily }];
  } else {
    try {
      addresses = await dnsLookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new SsrfError(`Host "${hostname}" tidak bisa di-resolve.`);
    }
  }

  if (!addresses.length) {
    throw new SsrfError(`Host "${hostname}" tidak punya alamat IP.`);
  }
  for (const entry of addresses) {
    if (!isPublicIp(entry.address)) {
      throw new SsrfError(
        `Host "${hostname}" mengarah ke alamat privat/reserved (${entry.address}); diblokir.`,
      );
    }
  }
  return url;
}

/**
 * Lookup khusus untuk Agent undici. Dipakai oleh request ad-hoc supaya
 * DNS resolution yang dipakai saat connect juga divalidasi (mitigasi DNS rebinding).
 */
export function guardedLookup() {
  return function lookup(hostname, options, callback) {
    dns.lookup(hostname, { ...options, all: true, verbatim: true }, (error, addresses) => {
      if (error) return callback(error);
      const list = Array.isArray(addresses)
        ? addresses
        : [{ address: addresses, family: options?.family || 4 }];

      for (const entry of list) {
        if (!isPublicIp(entry.address)) {
          return callback(
            new SsrfError(`Koneksi ke "${hostname}" diblokir (alamat privat: ${entry.address}).`),
          );
        }
      }

      if (options?.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
  };
}
