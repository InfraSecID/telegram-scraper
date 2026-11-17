import pino from 'pino';

export function createLogger(level = 'info') {
  return pino({
    level,
    base: { app: 'telegram-scraper' },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
