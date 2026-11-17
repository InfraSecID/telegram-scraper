import { mkdirSync } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  source_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  params TEXT NOT NULL DEFAULT '{}',
  origin TEXT NOT NULL DEFAULT 'api',
  chat_id TEXT,
  items_count INTEGER,
  error TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);

CREATE TABLE IF NOT EXISTS results (
  job_id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (job_id) REFERENCES jobs (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  host TEXT NOT NULL,
  profile TEXT NOT NULL CHECK (profile IN ('quick', 'standard', 'deep')),
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  origin TEXT NOT NULL DEFAULT 'api',
  chat_id TEXT,
  authorized_by TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '{}',
  recon TEXT NOT NULL DEFAULT '{}',
  warnings TEXT NOT NULL DEFAULT '[]',
  tool_runs TEXT NOT NULL DEFAULT '[]',
  error TEXT,
  duration_ms INTEGER,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_scans_created_at ON security_scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_scans_status ON security_scans (status);
CREATE INDEX IF NOT EXISTS idx_security_scans_host ON security_scans (host);

CREATE TABLE IF NOT EXISTS security_findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  tool TEXT,
  type TEXT,
  category TEXT,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT,
  parameter TEXT,
  evidence TEXT,
  cwe TEXT,
  cve TEXT,
  remediation TEXT,
  reference TEXT,
  raw TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES security_scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_findings_scan_id ON security_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings (severity);

CREATE TABLE IF NOT EXISTS security_reports (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('markdown', 'json')),
  path TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (scan_id, format),
  FOREIGN KEY (scan_id) REFERENCES security_scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_reports_scan_id ON security_reports (scan_id);

CREATE TABLE IF NOT EXISTS security_deliveries (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT 'markdown',
  to_email TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
  message_id TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES security_scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_deliveries_scan_id ON security_deliveries (scan_id);
`;

function mapJob(row) {
  if (!row) return null;
  let params = {};
  try {
    params = JSON.parse(row.params ?? '{}');
  } catch {
    params = {};
  }
  return {
    id: row.id,
    sourceId: row.source_id,
    sourceName: row.source_name,
    status: row.status,
    params,
    origin: row.origin,
    chatId: row.chat_id,
    itemsCount: row.items_count,
    error: row.error,
    createdAt: row.created_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    hasResults: Boolean(row.has_results),
  };
}

function parseJson(value, fallback) {
  try {
    const parsed = JSON.parse(value);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function mapScan(row) {
  if (!row) return null;
  return {
    id: row.id,
    target: row.target,
    host: row.host,
    profile: row.profile,
    status: row.status,
    origin: row.origin,
    chatId: row.chat_id,
    authorizedBy: row.authorized_by,
    findingsCount: row.findings_count,
    summary: parseJson(row.summary, {}),
    recon: parseJson(row.recon, {}),
    warnings: parseJson(row.warnings, []),
    toolRuns: parseJson(row.tool_runs, []),
    error: row.error,
    durationMs: row.duration_ms,
    createdAt: row.created_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
  };
}

function mapFinding(row) {
  if (!row) return null;
  return {
    id: row.id,
    scanId: row.scan_id,
    tool: row.tool,
    type: row.type,
    category: row.category,
    severity: row.severity,
    title: row.title,
    url: row.url,
    parameter: row.parameter,
    evidence: row.evidence,
    cwe: row.cwe,
    cve: row.cve,
    remediation: row.remediation,
    reference: row.reference,
    raw: row.raw,
    createdAt: row.created_at,
  };
}

export function openDb(dataDir) {
  mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'scraper.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.exec(SCHEMA);

  const insertJobStmt = db.prepare(`
    INSERT INTO jobs (id, source_id, source_name, status, params, origin, chat_id, created_at)
    VALUES (@id, @sourceId, @sourceName, @status, @params, @origin, @chatId, @createdAt)
  `);
  const getJobStmt = db.prepare(`
    SELECT j.*, EXISTS(SELECT 1 FROM results r WHERE r.job_id = j.id) AS has_results
    FROM jobs j WHERE j.id = ?
  `);
  const markRunningStmt = db.prepare(`
    UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?
  `);
  const markSucceededStmt = db.prepare(`
    UPDATE jobs SET status = 'succeeded', finished_at = ?, items_count = ?, error = NULL WHERE id = ?
  `);
  const markFailedStmt = db.prepare(`
    UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?
  `);
  const saveResultsStmt = db.prepare(`
    INSERT INTO results (job_id, json, bytes, created_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(job_id) DO UPDATE SET
      json = excluded.json,
      bytes = excluded.bytes,
      created_at = excluded.created_at
  `);
  const getResultsStmt = db.prepare('SELECT json, bytes, created_at FROM results WHERE job_id = ?');
  const deleteJobStmt = db.prepare('DELETE FROM jobs WHERE id = ?');
  const statsStmt = db.prepare('SELECT status, COUNT(*) AS count FROM jobs GROUP BY status');
  const recoverStaleStmt = db.prepare(`
    UPDATE jobs
    SET status = 'failed', finished_at = ?, error = 'Server restart saat job masih berjalan'
    WHERE status IN ('queued', 'running')
  `);

  const insertScanStmt = db.prepare(`
    INSERT INTO security_scans
      (id, target, host, profile, status, origin, chat_id, authorized_by, created_at)
    VALUES
      (@id, @target, @host, @profile, @status, @origin, @chatId, @authorizedBy, @createdAt)
  `);
  const getScanStmt = db.prepare('SELECT * FROM security_scans WHERE id = ?');
  const markScanRunningStmt = db.prepare(`
    UPDATE security_scans SET status = 'running', started_at = ? WHERE id = ?
  `);
  const markScanSucceededStmt = db.prepare(`
    UPDATE security_scans
    SET status = 'succeeded',
        finished_at = ?,
        findings_count = ?,
        summary = ?,
        recon = ?,
        warnings = ?,
        tool_runs = ?,
        duration_ms = ?,
        error = NULL
    WHERE id = ?
  `);
  const markScanFailedStmt = db.prepare(`
    UPDATE security_scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?
  `);
  const markScanCancelledStmt = db.prepare(`
    UPDATE security_scans SET status = 'cancelled', finished_at = ? WHERE id = ?
  `);
  const recoverStaleScansStmt = db.prepare(`
    UPDATE security_scans
    SET status = 'failed', finished_at = ?, error = 'Server restart saat scan masih berjalan'
    WHERE status IN ('queued', 'running')
  `);
  const deleteFindingsStmt = db.prepare('DELETE FROM security_findings WHERE scan_id = ?');
  const insertFindingStmt = db.prepare(`
    INSERT INTO security_findings
      (id, scan_id, tool, type, category, severity, title, url, parameter,
       evidence, cwe, cve, remediation, reference, raw, created_at)
    VALUES
      (@id, @scanId, @tool, @type, @category, @severity, @title, @url, @parameter,
       @evidence, @cwe, @cve, @remediation, @reference, @raw, @createdAt)
  `);
  const getFindingsStmt = db.prepare(`
    SELECT * FROM security_findings
    WHERE scan_id = ?
    ORDER BY
      CASE severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
      END,
      title ASC
  `);
  const insertReportStmt = db.prepare(`
    INSERT INTO security_reports (id, scan_id, format, path, bytes, created_at)
    VALUES (@id, @scanId, @format, @path, @bytes, @createdAt)
    ON CONFLICT(scan_id, format) DO UPDATE SET
      path = excluded.path,
      bytes = excluded.bytes,
      created_at = excluded.created_at
  `);
  const getReportStmt = db.prepare(
    'SELECT * FROM security_reports WHERE scan_id = ? AND format = ?',
  );
  const listReportsStmt = db.prepare(
    'SELECT * FROM security_reports WHERE scan_id = ? ORDER BY format ASC',
  );
  const insertDeliveryStmt = db.prepare(`
    INSERT INTO security_deliveries
      (id, scan_id, format, to_email, status, message_id, error, created_at)
    VALUES
      (@id, @scanId, @format, @toEmail, @status, @messageId, @error, @createdAt)
  `);
  const listDeliveriesStmt = db.prepare(
    'SELECT * FROM security_deliveries WHERE scan_id = ? ORDER BY created_at DESC',
  );
  const securityStatsStmt = db.prepare(`
    SELECT status, COUNT(*) AS count FROM security_scans GROUP BY status
  `);

  function insertJob(job) {
    insertJobStmt.run({
      id: job.id,
      sourceId: job.sourceId,
      sourceName: job.sourceName,
      status: job.status,
      params: JSON.stringify(job.params ?? {}),
      origin: job.origin ?? 'api',
      chatId: job.chatId ?? null,
      createdAt: job.createdAt,
    });
  }

  function getJob(id) {
    return mapJob(getJobStmt.get(id));
  }

  function listJobs({ limit = 20, status } = {}) {
    const clauses = [];
    const params = [];
    if (status) {
      clauses.push('j.status = ?');
      params.push(status);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const sql = `
      SELECT j.*, EXISTS(SELECT 1 FROM results r WHERE r.job_id = j.id) AS has_results
      FROM jobs j
      ${where}
      ORDER BY j.created_at DESC
      LIMIT ?
    `;
    params.push(limit);
    return db.prepare(sql).all(...params).map(mapJob);
  }

  function markRunning(id, startedAt) {
    markRunningStmt.run(startedAt, id);
  }

  function markSucceeded(id, finishedAt, itemsCount) {
    markSucceededStmt.run(finishedAt, itemsCount, id);
  }

  function markFailed(id, finishedAt, error) {
    markFailedStmt.run(finishedAt, String(error).slice(0, 2000), id);
  }

  function saveResults(jobId, json) {
    saveResultsStmt.run(jobId, json, Buffer.byteLength(json), new Date().toISOString());
  }

  function getResults(jobId) {
    const row = getResultsStmt.get(jobId);
    if (!row) return null;
    return { json: row.json, bytes: row.bytes, createdAt: row.created_at };
  }

  function deleteJob(id) {
    return deleteJobStmt.run(id).changes > 0;
  }

  function stats() {
    const output = { queued: 0, running: 0, succeeded: 0, failed: 0 };
    for (const row of statsStmt.all()) {
      output[row.status] = row.count;
    }
    return output;
  }

  function recoverStaleJobs() {
    return recoverStaleStmt.run(new Date().toISOString()).changes;
  }

  // ===== Security / bug bounty =====

  function insertScan(scan) {
    insertScanStmt.run({
      id: scan.id,
      target: scan.target,
      host: scan.host,
      profile: scan.profile,
      status: scan.status ?? 'queued',
      origin: scan.origin ?? 'api',
      chatId: scan.chatId ?? null,
      authorizedBy: scan.authorizedBy ?? null,
      createdAt: scan.createdAt,
    });
  }

  function getScan(id) {
    return mapScan(getScanStmt.get(id));
  }

  function listScans({ limit = 20, status } = {}) {
    const clauses = [];
    const params = [];
    if (status) {
      clauses.push('status = ?');
      params.push(status);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(limit);
    return db
      .prepare(`SELECT * FROM security_scans ${where} ORDER BY created_at DESC LIMIT ?`)
      .all(...params)
      .map(mapScan);
  }

  function markScanRunning(id, startedAt) {
    markScanRunningStmt.run(startedAt, id);
  }

  function markScanSucceeded(id, result) {
    const summary = result.summary ?? { total: result.findings?.length ?? 0 };
    markScanSucceededStmt.run(
      result.finishedAt ?? new Date().toISOString(),
      summary.total ?? result.findings?.length ?? 0,
      JSON.stringify(summary),
      JSON.stringify(result.recon ?? {}),
      JSON.stringify(result.warnings ?? []),
      JSON.stringify(result.toolRuns ?? []),
      result.durationMs ?? null,
      id,
    );
  }

  function markScanFailed(id, finishedAt, error) {
    markScanFailedStmt.run(finishedAt, String(error).slice(0, 4000), id);
  }

  function markScanCancelled(id, finishedAt) {
    markScanCancelledStmt.run(finishedAt, id);
  }

  function saveFindings(scanId, findings) {
    const createdAt = new Date().toISOString();
    const transaction = db.transaction(() => {
      deleteFindingsStmt.run(scanId);
      for (const item of findings) {
        insertFindingStmt.run({
          id: item.id,
          scanId,
          tool: item.tool ?? null,
          type: item.type ?? null,
          category: item.category ?? null,
          severity: item.severity ?? 'info',
          title: item.title ?? 'Temuan',
          url: item.url ?? null,
          parameter: item.parameter ?? null,
          evidence: item.evidence ?? null,
          cwe: item.cwe ?? null,
          cve: item.cve ?? null,
          remediation: item.remediation ?? null,
          reference: item.reference ?? null,
          raw: item.raw ?? null,
          createdAt,
        });
      }
    });
    transaction();
  }

  function getFindings(scanId) {
    return getFindingsStmt.all(scanId).map(mapFinding);
  }

  function saveReport(scanId, report) {
    insertReportStmt.run({
      id: `${scanId}-${report.format}`,
      scanId,
      format: report.format,
      path: report.path,
      bytes: report.bytes,
      createdAt: report.createdAt ?? new Date().toISOString(),
    });
  }

  function getReport(scanId, format) {
    const row = getReportStmt.get(scanId, format);
    if (!row) return null;
    return {
      id: row.id,
      scanId: row.scan_id,
      format: row.format,
      path: row.path,
      bytes: row.bytes,
      createdAt: row.created_at,
    };
  }

  function listReports(scanId) {
    return listReportsStmt.all(scanId).map((row) => ({
      id: row.id,
      scanId: row.scan_id,
      format: row.format,
      path: row.path,
      bytes: row.bytes,
      createdAt: row.created_at,
    }));
  }

  function recordDelivery(delivery) {
    insertDeliveryStmt.run({
      id: delivery.id,
      scanId: delivery.scanId,
      format: delivery.format ?? 'markdown',
      toEmail: delivery.toEmail,
      status: delivery.status,
      messageId: delivery.messageId ?? null,
      error: delivery.error ? String(delivery.error).slice(0, 2000) : null,
      createdAt: delivery.createdAt ?? new Date().toISOString(),
    });
  }

  function listDeliveries(scanId) {
    return listDeliveriesStmt.all(scanId).map((row) => ({
      id: row.id,
      scanId: row.scan_id,
      format: row.format,
      toEmail: row.to_email,
      status: row.status,
      messageId: row.message_id,
      error: row.error,
      createdAt: row.created_at,
    }));
  }

  function getScanDetail(id) {
    const scan = getScan(id);
    if (!scan) return null;
    return {
      scan,
      findings: getFindings(id),
      reports: listReports(id),
      deliveries: listDeliveries(id),
    };
  }

  function securityStats() {
    const output = { queued: 0, running: 0, succeeded: 0, failed: 0, cancelled: 0 };
    for (const row of securityStatsStmt.all()) {
      output[row.status] = row.count;
    }
    return output;
  }

  function recoverStaleScans() {
    return recoverStaleScansStmt.run(new Date().toISOString()).changes;
  }

  return {
    insertJob,
    getJob,
    listJobs,
    markRunning,
    markSucceeded,
    markFailed,
    saveResults,
    getResults,
    deleteJob,
    stats,
    recoverStaleJobs,

    insertScan,
    getScan,
    listScans,
    markScanRunning,
    markScanSucceeded,
    markScanFailed,
    markScanCancelled,
    saveFindings,
    getFindings,
    saveReport,
    getReport,
    listReports,
    recordDelivery,
    listDeliveries,
    getScanDetail,
    securityStats,
    recoverStaleScans,

    close: () => db.close(),
  };
}
