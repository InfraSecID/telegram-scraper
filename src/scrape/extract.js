import { applyTransforms } from './transforms.js';

function isBlank(value) {
  return (
    value === null ||
    value === undefined ||
    value === '' ||
    (Array.isArray(value) && value.length === 0)
  );
}

function readValue($, element, field) {
  const attr = field.attr ?? 'text';
  if (attr === 'text') {
    const text = $(element).text();
    return field.raw ? text : text.trim();
  }
  if (attr === 'html') return $(element).html();
  if (attr === 'outerHtml') return $.html(element);
  const value = $(element).attr(attr);
  return value === undefined ? null : value;
}

function selectMatches($, node, selector, scoped) {
  if (selector === '@') return node ? [node] : [];
  if (scoped && node) return $(node).find(selector).toArray();
  return $(selector).toArray();
}

function extractFields($, node, fields, ctx, scoped) {
  const result = {};

  for (const [name, field] of Object.entries(fields)) {
    try {
      let value;

      if (field.const !== undefined) {
        value = applyTransforms(field.const, field.transforms, ctx);
      } else {
        const matches = selectMatches($, node, field.selector, scoped);
        if (matches.length === 0) {
          value = null;
        } else if (field.multiple) {
          value = matches
            .map((element) => readValue($, element, field))
            .map((raw) => applyTransforms(raw, field.transforms, ctx))
            .filter((item) => !isBlank(item));
          if (value.length === 0) value = null;
        } else {
          value = applyTransforms(readValue($, matches[0], field), field.transforms, ctx);
        }
      }

      if (isBlank(value)) {
        ctx.warnings?.missing?.(name);
        if (field.default !== undefined) value = field.default;
      }

      result[name] = value === undefined ? null : value;
    } catch (error) {
      ctx.warnings?.add?.(`Field "${name}" error: ${error.message}`);
      result[name] = null;
    }
  }

  return result;
}

/** Ekstrak field dari satu elemen item (selector dicari di dalam elemen). */
export function extractItem($, node, fields, ctx = {}) {
  return extractFields($, node, fields, ctx, true);
}

/** Ekstrak field dari seluruh dokumen (dipakai untuk halaman detail). */
export function extractDocument($, fields, ctx = {}) {
  return extractFields($, null, fields, ctx, false);
}

export function createWarnings() {
  const messages = [];
  const missing = new Map();

  return {
    add(message) {
      if (!messages.includes(message)) messages.push(message);
    },
    missing(fieldName) {
      missing.set(fieldName, (missing.get(fieldName) ?? 0) + 1);
    },
    list() {
      const output = [...messages];
      for (const [field, count] of missing) {
        output.push(`Field "${field}" kosong/tidak ditemukan pada ${count} item`);
      }
      return output;
    },
  };
}
