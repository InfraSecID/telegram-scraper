import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

export const INSTALL_HINTS = {
  nuclei: 'https://github.com/projectdiscovery/nuclei/releases',
  httpx: 'https://github.com/projectdiscovery/httpx/releases',
  katana: 'https://github.com/projectdiscovery/katana/releases',
  subfinder: 'https://github.com/projectdiscovery/subfinder/releases',
  dalfox: 'https://github.com/hahwul/dalfox/releases',
  sqlmap: 'https://github.com/sqlmapproject/sqlmap',
  paramspider: 'https://github.com/devanshbatham/ParamSpider',
};

const TOOL_DEFS = [
  {
    name: 'nuclei',
    label: 'nuclei',
    detectArgs: ['-version'],
    versionRegex: /(?:Nuclei Engine Version|Current Version):\s*v?([0-9][\w.-]*)/i,
    validate: (text) => /nuclei/i.test(text),
  },
  {
    name: 'httpx',
    label: 'httpx (ProjectDiscovery)',
    detectArgs: ['-version'],
    versionRegex: /(?:Current Version|Version):\s*v?([0-9][\w.-]*)/i,
    validate: (text) => /projectdiscovery|current version/i.test(text),
  },
  {
    name: 'katana',
    label: 'katana',
    detectArgs: ['-h'],
    versionRegex: null,
    validate: (text) => /katana|usage:/i.test(text),
    noVersion: true,
  },
  {
    name: 'subfinder',
    label: 'subfinder',
    detectArgs: ['-version'],
    versionRegex: /(?:Current Version|Version):\s*v?([0-9][\w.-]*)/i,
    validate: (text) => /subfinder/i.test(text),
  },
  {
    name: 'dalfox',
    label: 'dalfox',
    detectArgs: ['--version'],
    versionRegex: /dalfox\s+v?([0-9][\w.-]*)/i,
    validate: (text) => /dalfox/i.test(text),
    majorVersion: 3,
  },
  {
    name: 'sqlmap',
    label: 'sqlmap',
    detectArgs: ['--version'],
    versionRegex: /([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:#[\w-]+)?)/,
    validate: (text) => /^[0-9]/.test(text.trim()),
  },
  {
    name: 'paramspider',
    label: 'paramspider',
    detectArgs: ['-h'],
    versionRegex: null,
    validate: (text) => /paramspider|usage:/i.test(text),
    noVersion: true,
  },
];

function appendLimited(chunks, chunk, state, maxBytes) {
  if (state.bytes >= maxBytes) {
    state.truncated = true;
    return;
  }
  const remaining = maxBytes - state.bytes;
  const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
  chunks.push(slice);
  state.bytes += slice.length;
  if (slice.length < chunk.length) state.truncated = true;
}

/**
 * Jalankan proses eksternal dengan timeout, abort signal, dan batas output.
 * Proses dijalankan dalam process group agar tool anak ikut dimatikan.
 */
export function runProcess({
  command,
  args = [],
  cwd,
  env,
  signal,
  timeoutMs = 30_000,
  maxOutputBytes = 16 * 1024 * 1024,
} = {}) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const stdoutChunks = [];
    const stderrChunks = [];
    const stdoutState = { bytes: 0, truncated: false };
    const stderrState = { bytes: 0, truncated: false };
    let settled = false;
    let timedOut = false;
    let aborted = false;
    let spawnError = null;
    let child;

    const finish = (code, signalName) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      resolve({
        code,
        signal: signalName,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        aborted,
        spawnError,
        truncated: stdoutState.truncated || stderrState.truncated,
        durationMs: Date.now() - startedAt,
      });
    };

    const killTree = (killSignal) => {
      if (!child?.pid) return;
      try {
        if (process.platform === 'win32') child.kill(killSignal);
        else process.kill(-child.pid, killSignal);
      } catch {
        // proses sudah mati
      }
    };

    const terminate = () => {
      killTree('SIGTERM');
      const hardKill = setTimeout(() => killTree('SIGKILL'), 2500);
      hardKill.unref?.();
    };

    const onAbort = () => {
      aborted = true;
      terminate();
    };

    let timer;
    try {
      child = spawn(command, args, {
        cwd,
        env: { ...process.env, NO_COLOR: '1', ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      });
    } catch (error) {
      resolve({
        code: null,
        signal: null,
        stdout: '',
        stderr: '',
        timedOut: false,
        aborted: false,
        spawnError: error,
        truncated: false,
        durationMs: Date.now() - startedAt,
      });
      return;
    }

    timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    timer.unref?.();

    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }

    child.stdout?.on('data', (chunk) =>
      appendLimited(stdoutChunks, chunk, stdoutState, maxOutputBytes),
    );
    child.stderr?.on('data', (chunk) =>
      appendLimited(stderrChunks, chunk, stderrState, maxOutputBytes),
    );

    child.once('error', (error) => {
      spawnError = error;
      finish(null, null);
    });
    child.once('close', (code, signalName) => finish(code, signalName));
  });
}

function pickVersion(text, regex) {
  if (!regex) return null;
  const match = text.match(regex);
  return match?.[1] ?? null;
}

export function createToolRegistry(config) {
  const security = config.security;
  const bins = security.bins;
  let cache = null;
  let cachedAt = 0;

  async function findTemplatesPath() {
    const candidates = [
      security.nucleiTemplates,
      path.join(homedir(), 'nuclei-templates'),
      '/opt/nuclei-templates',
    ].filter(Boolean);

    for (const candidate of candidates) {
      try {
        await access(candidate);
        return { path: candidate, available: true };
      } catch {
        // lanjut ke kandidat berikutnya
      }
    }

    return {
      path: security.nucleiTemplates ?? null,
      available: false,
      error: 'Template nuclei tidak ditemukan. Jalankan: nuclei -update-templates',
    };
  }

  async function detectOne(def, templates) {
    const command = bins[def.name];
    const result = await runProcess({
      command,
      args: def.detectArgs,
      timeoutMs: 15_000,
      maxOutputBytes: 256 * 1024,
    });

    const output = `${result.stdout}\n${result.stderr}`;
    const spawnMissing = result.spawnError?.code === 'ENOENT';
    const ok = !spawnMissing && !result.timedOut && def.validate(output);
    const version = ok ? pickVersion(output, def.versionRegex) : null;
    const major = version ? Number.parseInt(version.split('.')[0], 10) : null;

    let error = null;
    if (spawnMissing) error = `Binary "${command}" tidak ditemukan.`;
    else if (result.timedOut) error = 'Deteksi tool timeout.';
    else if (!ok) error = 'Binary tidak merespons seperti yang diharapkan.';

    if (ok && def.majorVersion && Number.isFinite(major) && major < def.majorVersion) {
      return {
        name: def.name,
        label: def.label,
        available: false,
        configured: true,
        version,
        path: command,
        error: `Butuh ${def.name} v${def.majorVersion}+ (terdeteksi v${version}).`,
        installHint: INSTALL_HINTS[def.name],
      };
    }

    return {
      name: def.name,
      label: def.label,
      available: ok,
      configured: true,
      version,
      path: command,
      error,
      installHint: ok ? undefined : INSTALL_HINTS[def.name],
      ...(def.name === 'nuclei'
        ? {
            templates: templates ?? { available: false, path: null },
          }
        : {}),
    };
  }

  async function detect(force = false) {
    const fresh = cache && Date.now() - cachedAt < 60_000;
    if (!force && fresh) return cache;

    const templates = await findTemplatesPath();
    const statuses = await Promise.all(TOOL_DEFS.map((def) => detectOne(def, templates)));
    const builtin = {
      name: 'headers',
      label: 'Header & cookie checks (built-in)',
      available: true,
      configured: true,
      builtin: true,
      version: null,
      path: null,
    };
    cache = [...statuses, builtin];
    cachedAt = Date.now();
    return cache;
  }

  async function getStatus(name) {
    const statuses = await detect();
    return statuses.find((tool) => tool.name === name) ?? null;
  }

  async function isAvailable(name) {
    const status = await getStatus(name);
    return Boolean(status?.available);
  }

  return {
    detect,
    getStatus,
    isAvailable,
    get bins() {
      return bins;
    },
  };
}

export function toolStatusSummary(statuses) {
  const available = statuses.filter((tool) => tool.available).map((tool) => tool.name);
  const missing = statuses.filter((tool) => !tool.available).map((tool) => tool.name);
  return { available, missing, total: statuses.length };
}
