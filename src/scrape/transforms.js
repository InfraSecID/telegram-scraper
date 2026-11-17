/**
 * Parse angka dari teks hasil scraping.
 * Mendukung format Indonesia (1.234,56) maupun internasional (1,234.56),
 * simbol mata uang, spasi, dan tanda minus.
 *
 * Heuristik: satu separator dengan tepat 3 digit di belakang dianggap pemisah ribuan
 * (contoh "1.234" -> 1234). Untuk desimal 3 digit, tulis nilai tanpa pemisah ribuan.
 */
export function parseNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (value === null || value === undefined) return null;

  let text = String(value).trim();
  if (!text) return null;

  text = text.replace(/[^\d.,-]/g, '');
  if (!text) return null;

  const negative = text.startsWith('-');
  text = text.replace(/-/g, '');

  const lastComma = text.lastIndexOf(',');
  const lastDot = text.lastIndexOf('.');

  if (lastComma !== -1 && lastDot !== -1) {
    const decimalSeparator = lastComma > lastDot ? ',' : '.';
    const thousandsSeparator = decimalSeparator === ',' ? '.' : ',';
    text = text.split(thousandsSeparator).join('');
    const decimalIndex = text.lastIndexOf(decimalSeparator);
    text = `${text.slice(0, decimalIndex)}.${text.slice(decimalIndex + 1)}`;
  } else if (lastComma !== -1 || lastDot !== -1) {
    const separator = lastComma !== -1 ? ',' : '.';
    const parts = text.split(separator);
    if (parts.length > 2) {
      // 1.234.567 -> 1234567
      text = parts.join('');
    } else {
      const decimals = parts[1] ?? '';
      const integerPart = parts[0] ?? '';
      if (decimals.length === 3 && integerPart.length > 0 && integerPart.length <= 3) {
        text = parts.join('');
      } else {
        text = `${integerPart}.${decimals}`;
      }
    }
  }

  const parsed = Number(text);
  if (!Number.isFinite(parsed)) return null;
  return negative ? -parsed : parsed;
}

const registry = {
  trim: (value) => String(value).trim(),
  collapseWhitespace: (value) => String(value).replace(/\s+/g, ' ').trim(),
  lowercase: (value) => String(value).toLowerCase(),
  uppercase: (value) => String(value).toUpperCase(),
  number: (value) => parseNumber(value),
  int: (value) => {
    const parsed = parseNumber(value);
    return parsed === null ? null : Math.trunc(parsed);
  },
  absoluteUrl: (value, args, ctx) => {
    try {
      return new URL(String(value), ctx?.baseUrl).toString();
    } catch {
      return null;
    }
  },
  regex: (value, args) => {
    if (!args.pattern) throw new Error('transform "regex" membutuhkan properti "pattern"');
    const regex = new RegExp(args.pattern, args.flags ?? '');
    const match = regex.exec(String(value));
    if (!match) return null;
    const group = args.group ?? 0;
    return match[group] ?? null;
  },
  replace: (value, args) => {
    if (!args.pattern) throw new Error('transform "replace" membutuhkan properti "pattern"');
    const regex = new RegExp(args.pattern, args.flags ?? 'g');
    return String(value).replace(regex, args.replacement ?? '');
  },
  prefix: (value, args) => `${args.value ?? ''}${value}`,
  suffix: (value, args) => `${value}${args.value ?? ''}`,
  default: (value, args) => {
    if (value === null || value === undefined || value === '') return args.value ?? null;
    return value;
  },
  date: (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  },
  json: (value) => {
    try {
      return JSON.parse(String(value));
    } catch {
      return null;
    }
  },
};

export const transformNames = Object.keys(registry);

export function applyTransforms(value, transforms, ctx = {}) {
  let result = value;
  for (const transform of transforms ?? []) {
    const name = typeof transform === 'string' ? transform : transform?.name;
    const args = typeof transform === 'string' ? {} : transform ?? {};
    const fn = registry[name];
    if (!fn) throw new Error(`Transform "${name}" tidak dikenal`);

    if (result === null || result === undefined) {
      // Nilai kosong hanya bisa diselamatkan oleh transform "default".
      if (name === 'default') result = fn(result, args, ctx);
      continue;
    }
    result = fn(result, args, ctx);
  }
  return result;
}
