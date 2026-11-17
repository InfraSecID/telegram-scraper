import { loadSources } from '../src/sources.js';
import { scrapeSource } from '../src/scrape/engine.js';

const { sources, errors } = loadSources('config/sources');
if (errors.length) {
  console.error('Config error:', errors);
  process.exit(1);
}

const source = sources.get(process.argv[2] ?? 'books-demo');
if (!source) {
  console.error('Sumber tidak ditemukan. Pilihan:', [...sources.keys()].join(', '));
  process.exit(1);
}

console.log(`Scraping "${source.name}"...`);
const result = await scrapeSource(source, {
  limit: 5,
  maxPages: 1,
  respectRobots: true,
  userAgent: 'TelegramScraperBot/1.0 (smoke test)',
  maxItems: 20,
});

console.log(JSON.stringify(result.meta, null, 2));
console.table(result.items);
