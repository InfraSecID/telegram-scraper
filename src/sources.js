import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import YAML from 'yaml';
import { transformNames } from './scrape/transforms.js';

const SOURCE_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,48}$/;

function isHttpUrl(value) {
  try {
    const url = new URL(String(value).replaceAll('{page}', '1'));
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

const HttpUrl = z
  .string()
  .min(1)
  .max(2048)
  .refine(isHttpUrl, { message: 'URL harus http(s) yang valid (boleh memakai placeholder {page})' });

const TransformName = z.string().refine(
  (name) => transformNames.includes(name),
  (name) => ({
    message: `Transform "${name}" tidak dikenal. Pilihan: ${transformNames.join(', ')}`,
  }),
);

const TransformSchema = z.union([
  TransformName,
  z
    .object({ name: TransformName })
    .passthrough()
    .refine(
      (transform) =>
        !['regex', 'replace'].includes(transform.name) ||
        typeof transform.pattern === 'string',
      { message: 'Transform regex/replace wajib punya properti "pattern"' },
    ),
]);

const FieldSchema = z
  .object({
    selector: z.string().min(1).max(1000).optional(),
    const: z.any().optional(),
    attr: z.string().min(1).max(200).optional(),
    multiple: z.boolean().optional(),
    raw: z.boolean().optional(),
    default: z.any().optional(),
    transforms: z.array(TransformSchema).max(20).optional(),
  })
  .strict()
  .refine((field) => field.selector !== undefined || field.const !== undefined, {
    message: 'Field harus punya "selector" atau "const"',
  });

const FieldsSchema = z
  .record(FieldSchema)
  .refine((fields) => Object.keys(fields).length > 0, { message: 'Minimal satu field' });

const RequestSchema = z
  .object({
    url: HttpUrl,
    startPage: z.number().int().min(0).max(100_000).default(1),
    maxPages: z.number().int().min(1).max(50).default(1),
    delayMs: z.number().int().min(0).max(60_000).default(1000),
    timeoutMs: z.number().int().min(1000).max(60_000).default(15_000),
    headers: z.record(z.string()).optional(),
    nextSelector: z.string().min(1).max(1000).optional(),
    respectRobots: z.boolean().optional(),
  })
  .strict();

const ListSchema = z
  .object({
    selector: z.string().min(1).max(1000),
    limit: z.number().int().min(1).max(1000).default(100),
  })
  .strict();

const DetailSchema = z
  .object({
    enabled: z.boolean().default(false),
    linkField: z.string().min(1).max(200).default('link'),
    fields: FieldsSchema.optional(),
    maxItems: z.number().int().min(1).max(100).default(25),
  })
  .strict()
  .refine((detail) => !detail.enabled || detail.fields, {
    message: 'detail.enabled=true membutuhkan detail.fields',
  });

export const SourceSchema = z
  .object({
    id: z.string().regex(SOURCE_ID_REGEX, {
      message: 'id harus huruf kecil/angka/underscore/strip, 2-49 karakter, diawali huruf/angka',
    }),
    name: z.string().min(1).max(120),
    description: z.string().max(500).optional(),
    enabled: z.boolean().default(true),
    request: RequestSchema,
    list: ListSchema,
    fields: FieldsSchema,
    dedupeKey: z.string().min(1).max(200).optional(),
    maxItems: z.number().int().min(1).max(5000).default(500),
    detail: DetailSchema.optional(),
    adhoc: z.boolean().optional(),
  })
  .strict();

export const AdhocSchema = z
  .object({
    url: HttpUrl,
    listSelector: z.string().min(1).max(1000),
    fields: FieldsSchema,
    limit: z.number().int().min(1).max(1000).optional(),
    maxPages: z.number().int().min(1).max(20).optional(),
    delayMs: z.number().int().min(0).max(60_000).optional(),
    respectRobots: z.boolean().optional(),
    dedupeKey: z.string().min(1).max(200).optional(),
  })
  .strict();

export function adhocToSource(input) {
  return SourceSchema.parse({
    id: 'adhoc',
    name: 'Ad-hoc scrape',
    enabled: true,
    request: {
      url: input.url,
      maxPages: input.maxPages ?? 1,
      delayMs: input.delayMs ?? 1000,
      respectRobots: input.respectRobots,
    },
    list: { selector: input.listSelector, limit: input.limit ?? 100 },
    fields: input.fields,
    dedupeKey: input.dedupeKey,
    maxItems: Math.max(1, input.limit ?? 100),
    adhoc: true,
  });
}

export function formatConfigError(error) {
  if (error instanceof z.ZodError) {
    return error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
  }
  return error?.message ?? String(error);
}

export function toSourceSummary(source) {
  return {
    id: source.id,
    name: source.name,
    description: source.description,
    enabled: source.enabled,
    request: {
      url: source.request.url,
      maxPages: source.request.maxPages,
      delayMs: source.request.delayMs,
    },
    list: { selector: source.list.selector, limit: source.list.limit },
    fields: Object.keys(source.fields).length,
    detailEnabled: Boolean(source.detail?.enabled),
    maxItems: source.maxItems,
  };
}

/**
 * Muat semua file YAML dari folder konfigurasi.
 * Error pada satu file tidak menghentikan file lain.
 */
export function loadSources(dir) {
  const sources = new Map();
  const errors = [];

  let files = [];
  try {
    files = readdirSync(dir)
      .filter((file) => /\.ya?ml$/i.test(file))
      .sort();
  } catch (error) {
    return {
      sources,
      errors: [{ file: dir, error: `Tidak bisa membaca folder konfigurasi: ${error.message}` }],
    };
  }

  for (const file of files) {
    const fullPath = path.join(dir, file);
    try {
      const raw = YAML.parse(readFileSync(fullPath, 'utf8'));
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new Error('Isi file harus berupa object YAML');
      }
      const source = SourceSchema.parse(raw);
      if (sources.has(source.id)) {
        throw new Error(`ID "${source.id}" duplikat dengan file lain`);
      }
      sources.set(source.id, source);
    } catch (error) {
      errors.push({ file, error: formatConfigError(error) });
    }
  }

  return { sources, errors };
}
