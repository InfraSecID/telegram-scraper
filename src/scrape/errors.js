export class ScrapeError extends Error {
  constructor(message, { status, code } = {}) {
    super(message);
    this.name = 'ScrapeError';
    this.status = status;
    this.code = code;
  }
}
