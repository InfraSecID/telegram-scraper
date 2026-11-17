import { randomBytes } from 'node:crypto';

export function shortId(bytes = 5) {
  return randomBytes(bytes).toString('hex');
}
