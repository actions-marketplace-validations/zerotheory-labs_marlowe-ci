const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { runAction } = require('../src/github-action.cjs');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '../bin/marlowe-ci.cjs');

test('marlowe-ci init --all is idempotent and preserves existing user settings', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-init-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await fs.mkdir(path.join(dir, '.claude'), { recursive: true });
  await fs.writeFile(
    path.join(dir, '.claude', 'settings.json'),
    JSON.stringify({
      customKey: true,
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo user-hook' }] }]
      }
    }),
    'utf8'
  );

  // Run init twice to assert strict idempotency
  await execFileAsync(process.execPath, [CLI, 'init', '--all', '--path', dir]);
  await execFileAsync(process.execPath, [CLI, 'init', '--all', '--path', dir]);

  const claudeSettings = JSON.parse(await fs.readFile(path.join(dir, '.claude', 'settings.json'), 'utf8'));
  assert.equal(claudeSettings.customKey, true);
  assert.equal(claudeSettings.hooks.PreToolUse.length, 2);
  assert.equal(claudeSettings.hooks.PostToolUse.length, 1);
  assert.equal(claudeSettings.hooks.Stop.length, 1);

  const mcp = JSON.parse(await fs.readFile(path.join(dir, '.mcp.json'), 'utf8'));
  assert.equal(mcp.mcpServers.marlowe.args.includes('mcp'), true);

  const workflow = await fs.readFile(path.join(dir, '.github', 'workflows', 'marlowe-ci.yml'), 'utf8');
  assert.ok(workflow.includes('zerotheory-labs/marlowe-ci@v0.1.0'));

  const preCommit = await fs.readFile(path.join(dir, '.git', 'hooks', 'pre-commit'), 'utf8');
  assert.equal(preCommit.match(/marlowe-ci-pre-commit start/g).length, 1);
});

test('GitHub Action runner writes SARIF v2.1.0, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY, and sets exitCode on FAILS', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-gha-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.writeFile(path.join(dir, 'ok.js'), 'export const a = 1;\n', 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'base'], { cwd: dir });

  await execFileAsync('git', ['checkout', '-b', 'feat/test'], { cwd: dir });
  const fakeKey = 'AKIA' + 'ABCDEF1234567890';
  await fs.writeFile(path.join(dir, 'secret.js'), `export const k = "${fakeKey}";\n`, 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'add secret'], { cwd: dir });

  const outFile = path.join(dir, 'gh_output.txt');
  const sumFile = path.join(dir, 'gh_summary.md');
  await fs.writeFile(outFile, '', 'utf8');
  await fs.writeFile(sumFile, '', 'utf8');

  const savedEnv = { ...process.env };
  const prevExitCode = process.exitCode;
  t.after(() => {
    process.env = savedEnv;
    process.exitCode = prevExitCode;
  });

  process.env.GITHUB_WORKSPACE = dir;
  process.env.GITHUB_BASE_REF = 'main';
  process.env.GITHUB_OUTPUT = outFile;
  process.env.GITHUB_STEP_SUMMARY = sumFile;
  process.env.INPUT_MODE = 'diff';
  process.env.INPUT_QUERY_OSV = 'false';
  process.env.INPUT_SARIF_FILE = 'out/marlowe.sarif';

  const result = await runAction();
  assert.equal(result.verdict, 'fails');
  assert.equal(process.exitCode, 1);

  const outputs = await fs.readFile(outFile, 'utf8');
  assert.ok(outputs.includes('verdict=fails'));
  assert.ok(outputs.includes('findings-count=1'));

  const summary = await fs.readFile(sumFile, 'utf8');
  assert.ok(summary.includes('Marlowe CI Verdict: **FAILS**'));

  const sarif = JSON.parse(await fs.readFile(path.join(dir, 'out', 'marlowe.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 1);
});
