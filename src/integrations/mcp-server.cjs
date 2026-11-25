const readline = require('node:readline');
const path = require('node:path');
const { assertTargetInScope } = require('../core/cyber-scope.cjs');
const { resolveWithinRoot, walkWorkspace, readRegularTextFile, loadScopeConfig } = require('../core/fs-safe.cjs');
const { triageArtifact, auditDependencies } = require('../core/cyber-analyzers.cjs');
const { detectSecurityTools } = require('../core/cyber-toolchain.cjs');
const { loginPath, DEFAULT_PATH } = require('../core/toolchain.cjs');
const { runAudit } = require('../engine/verdict.cjs');

const SERVER_INFO = {
  name: 'marlowe-ci',
  version: '0.1.1'
};

const MCP_TOOLS = [
  {
    name: 'marlowe_scan_diff',
    description: 'Audit the current git working-tree, staged changes, or branch diff against a base ref. Returns Marlowe verdict (holds / fails / cant-tell), findings, Can\'t Tell items, and SARIF summary.',
    inputSchema: {
      type: 'object',
      properties: {
        base_ref: { type: 'string', description: 'Optional git base ref (e.g. main or origin/main) to compare HEAD against.' },
        staged: { type: 'boolean', description: 'Audit staged git index changes only.' },
        fail_on: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], description: 'Minimum severity that triggers FAILS verdict (default: high).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev for known dependency CVEs when manifests changed (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_scan_workspace',
    description: 'Run a full static audit (secrets, reachable code sinks, dependency advisories) across a workspace directory.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative path or . (default: .).' },
        fail_on: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], description: 'Minimum severity threshold (default: high).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev advisory database (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_audit_dependencies',
    description: 'Inventory pinned dependencies across package.json, package-lock.json, pnpm-lock.yaml, requirements.txt, pyproject.toml, go.mod, and Cargo.lock, emit CycloneDX 1.5 SBOM metadata, and check OSV.dev.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative directory or manifest path (default: .).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_triage_artifact',
    description: 'Read-only static triage of a regular workspace file or binary: hashes, Shannon byte entropy, ELF/Mach-O/PE/PDF/PCAP format identification, and masked strings.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative path to artifact.' }
      },
      required: ['path'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_check_scope',
    description: 'Validate a URL, hostname, or IP against .marlowe-scope.json / .marlowe.json and Marlowe SSRF/DNS-rebinding guards before probing.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target URL, hostname, or IP address.' }
      },
      required: ['target'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_doctor',
    description: 'Detect which of the 9 supported local security CLIs (semgrep, trivy, gitleaks, osv-scanner, nmap, nuclei, tshark, radare2, otool) are installed on verified PATH.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false
    }
  }
];

async function executeMcpTool(name, args = {}, { root = process.cwd() } = {}) {
  const signal = new AbortController().signal;
  const scope = await loadScopeConfig(root);

  switch (name) {
    case 'marlowe_scan_diff': {
      const res = await runAudit({
        root,
        mode: 'diff',
        baseRef: typeof args.base_ref === 'string' ? args.base_ref.trim() : '',
        staged: Boolean(args.staged),
        failOn: typeof args.fail_on === 'string' ? args.fail_on : 'high',
        queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
        scopeConfig: scope,
        signal
      });
      return {
        verdict: res.verdict,
        verdictLabel: res.verdictLabel,
        scannedFiles: res.scannedFiles,
        changedFiles: res.changedFiles,
        findings: res.findings,
        failingFindingsCount: res.failingFindings.length,
        cantTellReasons: res.cantTellReasons,
        dnaFlags: res.dnaFlags,
        dependencySummary: res.dependencySummary,
        durationMs: res.durationMs
      };
    }

    case 'marlowe_scan_workspace': {
      const relTarget = typeof args.path === 'string' && args.path.trim() ? args.path.trim() : '.';
      const resolved = await resolveWithinRoot(root, relTarget);
      const res = await runAudit({
        root: resolved.fullPath,
        mode: 'full',
        failOn: typeof args.fail_on === 'string' ? args.fail_on : 'high',
        queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
        scopeConfig: scope,
        signal
      });
      return {
        verdict: res.verdict,
        verdictLabel: res.verdictLabel,
        scannedFiles: res.scannedFiles,
        findings: res.findings,
        failingFindingsCount: res.failingFindings.length,
        cantTellReasons: res.cantTellReasons,
        dependencySummary: res.dependencySummary,
        durationMs: res.durationMs
      };
    }

    case 'marlowe_audit_dependencies': {
      const relTarget = typeof args.path === 'string' && args.path.trim() ? args.path.trim() : '.';
      const resolved = await resolveWithinRoot(root, relTarget);
      const fs = require('node:fs/promises');
      const stat = await fs.stat(resolved.fullPath);
      return auditDependencies(
        resolved.rootReal,
        resolved.fullPath,
        {
          isDirectory: stat.isDirectory(),
          queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
          scope,
          relativePath: (r, f) => path.relative(r, f).split(path.sep).join('/'),
          walk: walkWorkspace,
          readText: readRegularTextFile
        },
        signal
      );
    }

    case 'marlowe_triage_artifact': {
      if (typeof args.path !== 'string' || !args.path.trim()) {
        throw new Error('path is required.');
      }
      const resolved = await resolveWithinRoot(root, args.path.trim());
      return triageArtifact(resolved.fullPath, resolved.relPath, signal);
    }

    case 'marlowe_check_scope': {
      if (typeof args.target !== 'string' || !args.target.trim()) {
        throw new Error('target is required.');
      }
      const checked = await assertTargetInScope(args.target.trim(), scope);
      return { allowed: true, ...checked };
    }

    case 'marlowe_doctor': {
      const commandPath = (await loginPath({ shell: process.env.SHELL || '', root, env: process.env })) || process.env.PATH || DEFAULT_PATH;
      return detectSecurityTools(commandPath, { root });
    }

    default:
      throw new Error(`Unknown tool "${name}".`);
  }
}

async function handleJsonRpcMessage(msg, context = {}) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') {
    return {
      jsonrpc: '2.0',
      id: msg?.id ?? null,
      error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request.' }
    };
  }

  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id') && msg.id !== undefined;
  const method = msg.method;

  if (method === 'notifications/initialized' || (!hasId && String(method).startsWith('notifications/'))) {
    return null;
  }

  if (method === 'initialize') {
    const protocolVersion = typeof msg.params?.protocolVersion === 'string' && msg.params.protocolVersion
      ? msg.params.protocolVersion
      : '2025-03-26';
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO
      }
    };
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id: msg.id, result: {} };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: { tools: MCP_TOOLS }
    };
  }

  if (method === 'tools/call') {
    const name = msg.params?.name;
    const args = msg.params?.arguments || {};
    try {
      const data = await executeMcpTool(name, args, context);
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          isError: false
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: `Error: ${err.message}` }],
          isError: true
        }
      };
    }
  }

  if (!hasId) return null;

  return {
    jsonrpc: '2.0',
    id: msg.id,
    error: { code: -32601, message: `Method not found: ${method}` }
  };
}

function startMcpServer({ root = process.cwd() } = {}) {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const writeLine = obj => {
    if (obj) process.stdout.write(JSON.stringify(obj) + '\n');
  };

  let chain = Promise.resolve();
  rl.on('line', line => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      let msg;
      try {
        msg = JSON.parse(trimmed);
      } catch (err) {
        writeLine({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: `Parse error: ${err.message}` }
        });
        return;
      }
      const response = await handleJsonRpcMessage(msg, { root });
      writeLine(response);
    }).catch(err => {
      process.stderr.write(`[marlowe-ci mcp] Unhandled error: ${err.stack || err.message}\n`);
    });
  });

  return new Promise(resolve => {
    rl.once('close', () => chain.then(() => resolve(0)));
  });
}

module.exports = {
  SERVER_INFO,
  MCP_TOOLS,
  executeMcpTool,
  handleJsonRpcMessage,
  startMcpServer
};
