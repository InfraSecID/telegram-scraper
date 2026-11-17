import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createSecurityRuntime } from '../src/security/runtime.js';
import { parseAllowedDomains } from '../src/security/scope.js';

async function createRuntime() {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'security-runtime-test-'));
  const scans = new Map();
  const db = {
    insertScan: (scan) => scans.set(scan.id, { ...scan }),
    getScan: (id) => scans.get(id) ?? null,
    markScanRunning: (id, startedAt) => {
      const scan = scans.get(id);
      if (scan) Object.assign(scan, { status: 'running', startedAt });
    },
    markScanFailed: (id, finishedAt, error) => {
      const scan = scans.get(id);
      if (scan) Object.assign(scan, { status: 'failed', finishedAt, error });
    },
    markScanCancelled: (id, finishedAt) => {
      const scan = scans.get(id);
      if (scan) Object.assign(scan, { status: 'cancelled', finishedAt });
    },
  };
  const config = {
    dataDir,
    timezone: 'Asia/Jakarta',
    security: {
      enabled: true,
      allowedDomains: parseAllowedDomains('127.0.0.1'),
      maxActiveScans: 1,
      maxQueue: 2,
      cooldownMs: 0,
      scanTimeoutMs: 60_000,
      bins: {},
      nucleiTemplates: null,
    },
  };
  return { runtime: createSecurityRuntime({ config, logger: {}, db }), dataDir };
}

test('runtime menolak scan host yang sama jika sudah berada dalam antrean', async () => {
  const { runtime, dataDir } = await createRuntime();
  try {
    const first = runtime.enqueue({ target: 'http://127.0.0.1:1', profile: 'quick' });
    await assert.rejects(
      runtime.enqueue({ target: 'http://127.0.0.1:2', profile: 'quick' }),
      (error) => error.code === 'scan_in_progress' && error.status === 409,
    );

    await runtime.shutdown();
    assert.equal((await first).status, 'cancelled');
  } finally {
    await runtime.shutdown();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('runtime menolak scan baru setelah shutdown', async () => {
  const { runtime, dataDir } = await createRuntime();
  try {
    await runtime.shutdown();

    await assert.rejects(
      runtime.enqueue({ target: 'http://127.0.0.1:1', profile: 'quick' }),
      (error) => error.code === 'security_shutting_down' && error.status === 503,
    );
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});
