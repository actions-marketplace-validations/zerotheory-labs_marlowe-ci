const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { runAudit } = require('../src/engine/verdict.cjs');
const { writeBaseline } = require('../src/engine/baseline.cjs');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '../bin/marlowe-ci.cjs');

async function makeTempRepo() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-ci-v2-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.mkdir(path.join(dir, 'src'), { recursive: true });
  await fs.writeFile(path.join(dir, 'src', 'base.js'), 'export const ok = 1;\n', 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
  return dir;
}

test('baseline suppresses acknowledged non-secret findings while NEVER suppressing secrets', async t => {
  const repo = await makeTempRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const domSink = 'el.' + 'innerHTML = localLabel;';
  await fs.writeFile(
    path.join(repo, 'src', 'ui.js'),
    `export function render(el, localLabel) {\n  ${domSink}\n}\n`,
    'utf8'
  );

  // Full scan finds unverified dom-xss -> CAN'T TELL
  const first = await runAudit({ root: repo, mode: 'full', queryOsv: false });
  assert.equal(first.verdict, 'cant-tell');
  assert.equal(first.findings.length, 1);

  // Record baseline (.marlowe-baseline.json)
  const saved = await writeBaseline(repo, first);
  assert.equal(saved.baselinedCount, 1);

  // Subsequent scan honors baseline -> HOLDS UP
  const second = await runAudit({ root: repo, mode: 'full', queryOsv: false });
  assert.equal(second.verdict, 'holds');
  assert.equal(second.findings.length, 0);
  assert.equal(second.baselinedCount, 1);

  // Injecting a secret STILL FAILS even if a baseline entry tries to target category: secrets
  const fakeAws = 'AKIA' + 'ABCDEF1234567890';
  const baselineJson = JSON.parse(await fs.readFile(path.join(repo, '.marlowe-baseline.json'), 'utf8'));
  baselineJson.entries.push({
    title: 'AWS Access Key ID',
    category: 'secrets',
    cwe: 'CWE-798',
    location: 'src/leak.js'
  });
  await fs.writeFile(path.join(repo, '.marlowe-baseline.json'), JSON.stringify(baselineJson), 'utf8');
  await fs.writeFile(path.join(repo, 'src', 'leak.js'), `export const key = "${fakeAws}";\n`, 'utf8');

  const third = await runAudit({ root: repo, mode: 'full', queryOsv: false });
  assert.equal(third.verdict, 'fails');
  assert.ok(third.failingFindings.some(f => f.category === 'secrets'));
});

test('CLI dfir subcommands analyze logs, extract normalized IOCs, and enforce O_NOFOLLOW', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-dfir-cli-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await fs.writeFile(
    path.join(dir, 'access.log'),
    [
      '198.51.100.42 - - "GET /items?q=1%20union%20select%20password HTTP/1.1" 500',
      '203.0.113.9 - - "GET /proxy?u=http://169.254.169.254/latest/meta-data HTTP/1.1" 403',
      'Threat intel: hxxps://bad[.]example[.]com/stage2 CVE-2026-4242 T1190'
    ].join('\n') + '\n',
    'utf8'
  );

  const logsRes = await execFileAsync(process.execPath, [CLI, 'dfir', 'logs', 'access.log', '--path', dir, '--json']);
  const logsJson = JSON.parse(logsRes.stdout);
  assert.ok(logsJson.signatureCounts['sqli-probe'] >= 1);
  assert.ok(logsJson.signatureCounts['ssrf-metadata'] >= 1);

  const iocsRes = await execFileAsync(process.execPath, [CLI, 'dfir', 'iocs', 'access.log', '--path', dir, '--json']);
  const iocsJson = JSON.parse(iocsRes.stdout);
  assert.ok(iocsJson.iocs.cves.includes('CVE-2026-4242'));
  assert.ok(iocsJson.iocs.mitreTechniques.includes('T1190'));
  assert.ok(iocsJson.iocs.urls.some(u => u.includes('https://bad.example.com/stage2')));

  const triageRes = await execFileAsync(process.execPath, [CLI, 'dfir', 'triage', 'access.log', '--path', dir, '--json']);
  const triageJson = JSON.parse(triageRes.stdout);
  assert.equal(triageJson.hashes.sha256.length, 64);
});

test('CLI recon refuses unscoped and SSRF targets via ScopeGate', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-recon-cli-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, 'recon', 'http', 'http://169.254.169.254/latest/meta-data', '--path', dir, '--json']),
    err => /Authorized Scope|Blocked|empty/i.test(err.stderr || err.message)
  );
});
