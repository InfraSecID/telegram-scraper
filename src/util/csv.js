/**
 * Ubah array item hasil scrape menjadi CSV.
 * - Header diambil dari union semua key (maks 500 kolom).
 * - Nilai object/array disimpan sebagai JSON string.
 * - String yang diawali = + - @ diberi prefix apostrof untuk mencegah CSV formula injection.
 * - BOM ditambahkan agar Excel bisa membaca UTF-8 dengan benar.
 */
export function itemsToCsv(items) {
  if (!Array.isArray(items) || items.length === 0) return '\uFEFF';

  const keys = [];
  const seen = new Set();
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    for (const key of Object.keys(item)) {
      if (!seen.has(key)) {
        seen.add(key);
        keys.push(key);
      }
      if (keys.length >= 500) break;
    }
    if (keys.length >= 500) break;
  }

  const escape = (value) => {
    if (value === null || value === undefined) return '';
    let text;
    if (typeof value === 'object') {
      text = JSON.stringify(value);
    } else {
      text = String(value);
      if (typeof value === 'string' && /^[=+\-@]/.test(text)) {
        text = `'${text}`;
      }
    }
    if (/[",\r\n]/.test(text)) {
      return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
  };

  const lines = [keys.map(escape).join(',')];
  for (const item of items) {
    lines.push(keys.map((key) => escape(item?.[key])).join(','));
  }
  return `\uFEFF${lines.join('\r\n')}\r\n`;
}
