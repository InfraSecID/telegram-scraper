import test from 'node:test';
import assert from 'node:assert/strict';
import {
  dedupeFindings,
  extractParameterUrls,
  parseDalfoxJson,
  parseHttpxJsonl,
  parseNucleiJsonl,
  parseSqlmapOutput,
  parseSubfinderOutput,
  summarizeFindings,
} from '../src/security/scanner.js';

test('parseHttpxJsonl mengambil field utama dari JSONL', () => {
  const line = JSON.stringify({
    url: 'https://example.com/',
    status_code: 200,
    title: 'Contoh',
    tech: ['Nginx', 'PHP'],
    webserver: 'nginx/1.24.0',
    content_type: 'text/html',
  });
  const result = parseHttpxJsonl(`log noise\n${line}\n`);
  assert.equal(result.statusCode, 200);
  assert.equal(result.title, 'Contoh');
  assert.deepEqual(result.tech, ['Nginx', 'PHP']);
  assert.equal(result.server, 'nginx/1.24.0');
  assert.equal(parseHttpxJsonl('bukan json'), null);
});

test('parseNucleiJsonl memetakan severity, tipe, CWE, dan evidence', () => {
  const entry = {
    'template-id': 'xss-reflected',
    'matcher-name': 'body',
    'matched-at': 'https://example.com/search?q=test',
    'extracted-results': ['<script>alert(1)</script>'],
    'curl-command': 'curl -X GET https://example.com/search?q=test',
    info: {
      name: 'Reflected XSS',
      severity: 'high',
      description: 'Input tercermin tanpa encoding.',
      tags: ['xss', 'owasp-top-10'],
      classification: { 'cwe-id': ['CWE-79'], 'cve-id': null },
      reference: ['https://owasp.org/xss'],
      remediation: 'Encode output.',
    },
  };
  const findings = parseNucleiJsonl(`${JSON.stringify(entry)}\n`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].tool, 'nuclei');
  assert.equal(findings[0].type, 'xss');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].cwe, 'CWE-79');
  assert.match(findings[0].evidence, /Input tercermin/);
  assert.match(findings[0].evidence, /alert/);
});

test('parseDalfoxJson membedakan XSS reflected dan DOM', () => {
  const payload = {
    findings: [
      {
        type: 'V',
        inject_type: 'inHTML',
        detection_method: 'reflection',
        param: 'q',
        payload: '<script>alert(1)</script>',
        evidence: 'Payload terpantul di body',
        severity: 'High',
        data: 'https://example.com/search?q=test',
        cwe: 'CWE-79',
      },
      {
        type: 'A',
        inject_type: 'inDOM',
        detection_method: 'ast',
        param: 'next',
        payload: '#javascript:alert(1)',
        severity: 'Medium',
        data: 'https://example.com/#/page',
      },
      {
        type: 'V',
        inject_type: 'inHTML',
        detection_method: 'dom-verification',
        param: 'id',
        payload: '<svg onload=alert(1)>',
        severity: 'High',
        data: 'https://example.com/item?id=1',
      },
    ],
  };
  const findings = parseDalfoxJson(JSON.stringify(payload));
  assert.equal(findings.length, 3);
  assert.equal(findings[0].type, 'xss');
  assert.equal(findings[0].parameter, 'q');
  assert.equal(findings[1].type, 'dom_xss');
  assert.equal(findings[1].severity, 'medium');
  assert.equal(findings[2].type, 'xss');
  assert.equal(findings[2].severity, 'high');
  assert.match(findings[2].title, /terverifikasi/);
  assert.deepEqual(parseDalfoxJson('bukan json'), []);
});

test('parseSqlmapOutput mendeteksi parameter rentan dan mengabaikan output aman', () => {
  const output = `
[INFO] testing connection
GET parameter 'id' is vulnerable. Do you want to keep testing? [Y/n]
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1
back-end DBMS: MySQL >= 5.0
`;
  const findings = parseSqlmapOutput(output, { target: 'https://example.com/item?id=1' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'sqli');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].parameter, 'id');
  assert.match(findings[0].evidence, /boolean-based blind/);

  assert.deepEqual(
    parseSqlmapOutput('[INFO] all tested parameters do not appear to be injectable'),
    [],
  );
});

test('extractParameterUrls hanya mengambil URL berparameter dalam scope', () => {
  const text = `
https://example.com/search?q=test
https://api.example.com/item?id=2
https://evil.test/?id=3
https://example.com/plain
`;
  const urls = extractParameterUrls(text, {
    allowedDomains: ['example.com'],
    limit: 10,
  });
  assert.deepEqual(urls, [
    'https://example.com/search?q=test',
    'https://api.example.com/item?id=2',
  ]);
});

test('parseSubfinderOutput memfilter host di luar scope', () => {
  const output = 'api.example.com\nwww.example.com\nevil.test\nexample.com.evil.test\n';
  const hosts = parseSubfinderOutput(output, { allowedDomains: ['example.com'] });
  assert.deepEqual(hosts, ['api.example.com', 'www.example.com']);
});

test('dedupeFindings menghapus duplikat, mengurutkan severity, dan membatasi jumlah', () => {
  const base = {
    tool: 'nuclei',
    type: 'xss',
    title: 'XSS',
    url: 'https://example.com/?q=1',
    parameter: 'q',
  };
  const findings = [
    { ...base, severity: 'low' },
    { ...base, severity: 'low' },
    { ...base, severity: 'critical' },
    { ...base, severity: 'medium', parameter: 'x' },
    { ...base, severity: 'info', parameter: 'y' },
  ];
  const result = dedupeFindings(findings, 3);
  assert.equal(result.length, 3);
  assert.equal(result[0].severity, 'critical');
  assert.equal(result[1].severity, 'medium');
  assert.equal(result[2].severity, 'low');
});

test('summarizeFindings menghitung total per severity', () => {
  const summary = summarizeFindings([
    { severity: 'high' },
    { severity: 'high' },
    { severity: 'low' },
    { severity: 'info' },
  ]);
  assert.deepEqual(summary, {
    critical: 0,
    high: 2,
    medium: 0,
    low: 1,
    info: 1,
    total: 4,
  });
});
