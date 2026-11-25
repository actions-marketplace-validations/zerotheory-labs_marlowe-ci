const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '../bin/marlowe-ci.cjs');

test('MCP stdio server handles initialize, tools/list, and tools/call over newline-delimited JSON-RPC 2.0', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-mcp-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.writeFile(path.join(dir, 'hello.js'), 'export const hello = "world";\n', 'utf8');
  await fs.writeFile(path.join(dir, '.marlowe-scope.json'), JSON.stringify({ targets: ['https://example.com'] }), 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });

  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'marlowe_scan_diff', arguments: { query_osv: false } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'marlowe_triage_artifact', arguments: { path: 'hello.js' } } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'marlowe_check_scope', arguments: { target: 'http://169.254.169.254/latest' } } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'marlowe_doctor', arguments: {} } }
  ];

  const responses = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'mcp', '--path', dir], {
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });
    child.on('error', reject);
    child.on('close', code => {
      assert.equal(code, 0, `MCP exited ${code}: ${stderr}`);
      const lines = stdout.trim().split('\n').filter(Boolean);
      resolve(lines.map(l => JSON.parse(l)));
    });
    for (const req of requests) {
      child.stdin.write(JSON.stringify(req) + '\n');
    }
    child.stdin.end();
  });

  // notifications/initialized produces no response; 6 request IDs -> 6 JSON lines
  assert.equal(responses.length, 6);
  const byId = Object.fromEntries(responses.map(r => [r.id, r]));

  assert.equal(byId[1].result.serverInfo.name, 'marlowe-ci');
  assert.equal(byId[1].result.protocolVersion, '2025-03-26');

  const toolNames = byId[2].result.tools.map(tool => tool.name);
  assert.deepEqual(toolNames, [
    'marlowe_scan_diff',
    'marlowe_scan_workspace',
    'marlowe_audit_dependencies',
    'marlowe_triage_artifact',
    'marlowe_check_scope',
    'marlowe_doctor'
  ]);

  const scanRes = JSON.parse(byId[3].result.content[0].text);
  assert.equal(scanRes.verdict, 'holds');

  const triageRes = JSON.parse(byId[4].result.content[0].text);
  assert.equal(triageRes.path, 'hello.js');
  assert.ok(typeof triageRes.hashes.sha256 === 'string');

  // Out-of-scope SSRF check returns isError: true
  assert.equal(byId[5].result.isError, true);

  const doctorRes = JSON.parse(byId[6].result.content[0].text);
  assert.equal(doctorRes.totalCount, 9);
});
