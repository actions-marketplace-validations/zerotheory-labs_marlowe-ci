const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { redactSecrets } = require('./cyber-scope.cjs');
const { triageArtifact } = require('./cyber-analyzers.cjs');
const { resolveToolBinary, safeSearchDirs } = require('./cyber-toolchain.cjs');
const { DEFAULT_PATH } = require('./toolchain.cjs');
const {
  resolveWithinRoot,
  readRegularTextFile,
  walkWorkspace
} = require('./fs-safe.cjs');

const execFileAsync = promisify(execFile);

const BEEFILE_NAME_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile)$/i;
const BPF_SOURCE_NAME_RE = /\.(?:bpf|upatch)\.c$/i;
const SHIRUDO_ARTIFACT_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile|[^/]+\.(?:bpf|upatch)\.c|[^/]+\.(?:bee|upatch))$/i;
const SHIRUDO_DRAFT_PATH_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile|[^/]+\.(?:bpf|upatch)\.c)$/i;

const HEX_NONCE_RE = /^[0-9a-fA-F]{8,128}$/;
const AK_NAME_RE = /^[0-9a-zA-Z:._-]{4,128}$/;

function isBeefilePath(relPath) {
  return BEEFILE_NAME_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isBpfSourcePath(relPath) {
  return BPF_SOURCE_NAME_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isShirudoArtifactPath(relPath) {
  return SHIRUDO_ARTIFACT_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isShirudoDraftPath(relPath) {
  return SHIRUDO_DRAFT_PATH_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function stripTomlComment(line) {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inDouble && ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === '#' && !inSingle && !inDouble) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseTomlValue(rawVal) {
  const s = String(rawVal || '').trim();
  if (!s) return '';
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    const items = [];
    let cur = '';
    let inSingle = false;
    let inDouble = false;
    let escaped = false;
    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      if (escaped) {
        cur += ch;
        escaped = false;
        continue;
      }
      if (inDouble && ch === '\\') {
        cur += ch;
        escaped = true;
        continue;
      }
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      if (ch === ',' && !inSingle && !inDouble) {
        items.push(parseTomlValue(cur));
        cur = '';
        continue;
      }
      cur += ch;
    }
    if (cur.trim()) items.push(parseTomlValue(cur));
    return items;
  }
  return s;
}

function parseBeefile(text) {
  const pkg = {};
  const upatches = [];
  const selectors = [];
  const rawKeys = [];
  const parseWarnings = [];

  let section = '';
  let currentUpatch = null;
  const lines = String(text || '').split(/\r?\n/);

  let bufLine = '';
  let bufStartLine = 0;

  const processStatement = (stmt, lineNum) => {
    const trimmed = stmt.trim();
    if (!trimmed) return;

    if (trimmed.startsWith('[[')) {
      const m = /^\[\[([^\]]+)\]\]$/.exec(trimmed);
      if (!m) {
        parseWarnings.push({ line: lineNum, message: `Malformed TOML array table header: ${trimmed.slice(0, 80)}` });
        return;
      }
      section = m[1].trim();
      if (section === 'upatches') {
        currentUpatch = {
          line: lineNum,
          source: '',
          type: '',
          unload: '',
          id: '',
          treeId: '',
          selectorLabels: {}
        };
        upatches.push(currentUpatch);
      }
      return;
    }

    if (trimmed.startsWith('[')) {
      const m = /^\[([^\]]+)\]$/.exec(trimmed);
      if (!m) {
        parseWarnings.push({ line: lineNum, message: `Malformed TOML section header: ${trimmed.slice(0, 80)}` });
        return;
      }
      section = m[1].trim();
      return;
    }

    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      parseWarnings.push({ line: lineNum, message: `Unexpected TOML line without "=" at line ${lineNum}` });
      return;
    }

    const key = trimmed.slice(0, eq).trim().replace(/^["']|["']$/g, '');
    const value = parseTomlValue(trimmed.slice(eq + 1));
    rawKeys.push({ section, key, value, line: lineNum });

    if (section === 'package') {
      pkg[key] = value;
      return;
    }

    if (section === 'upatches' && currentUpatch) {
      if (key === 'source' || key === 'type' || key === 'unload' || key === 'id') {
        currentUpatch[key] = typeof value === 'string' ? value : String(value || '');
      }
      return;
    }

    if (section === 'upatches.tree' && currentUpatch) {
      if (key === 'id') currentUpatch.treeId = typeof value === 'string' ? value : String(value || '');
      return;
    }

    if (
      (section === 'upatches.tree.selector.labels' || section === 'upatches.selector.labels') &&
      currentUpatch
    ) {
      const vals = Array.isArray(value) ? value.map(v => String(v)) : [String(value)];
      currentUpatch.selectorLabels[key] = vals;
      selectors.push({ upatchLine: currentUpatch.line, key, values: vals, line: lineNum });
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const clean = stripTomlComment(lines[i]);
    if (!bufLine) bufStartLine = i + 1;
    bufLine += (bufLine ? '\n' : '') + clean;
    const openBrackets = (bufLine.match(/\[/g) || []).length;
    const closeBrackets = (bufLine.match(/\]/g) || []).length;
    if (openBrackets > closeBrackets && !bufLine.trim().startsWith('[')) {
      continue;
    }
    processStatement(bufLine, bufStartLine);
    bufLine = '';
  }
  if (bufLine.trim()) processStatement(bufLine, bufStartLine);

  return { package: pkg, upatches, selectors, rawKeys, parseWarnings };
}

async function auditBeefile(relPath, text, { root = '' } = {}) {
  const parsed = parseBeefile(text);
  const findings = [];
  const cantTellReasons = [];
  const lines = String(text || '').split(/\r?\n/);

  // 1. Embedded private key material or operator key pointers
  const pemRe = new RegExp('-----BEGIN ' + '(?:[A-Z0-9 ]* )?PRIVATE KEY-----', 'i');
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (pemRe.test(ln)) {
      findings.push({
        title: 'Private signing key embedded inside Shirudo Beefile',
        severity: 'critical',
        category: 'secrets',
        cwe: 'CWE-798',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: redactSecrets(ln.trim().slice(0, 180)).text,
        remediation: 'Remove signing key material from Beefile; keep ML-DSA-87 operator keys strictly in an external keys directory outside version control.'
      });
    }
  }

  for (const entry of parsed.rawKeys) {
    const valStr = Array.isArray(entry.value) ? entry.value.join(',') : String(entry.value || '');
    if (
      /^(?:keys_dir|private_key|signing_key|key_path|ml_dsa_key)$/i.test(entry.key) ||
      (/\.(?:pem|key)(?:$|\b)/i.test(valStr) && !/\.pub\.pem$/i.test(valStr))
    ) {
      findings.push({
        title: `Shirudo operator signing key reference in Beefile (${entry.key})`,
        severity: 'critical',
        category: 'secrets',
        cwe: 'CWE-798',
        reachability: 'reachable',
        location: `${relPath}:${entry.line}`,
        evidence: redactSecrets(`${entry.key} = ${JSON.stringify(entry.value)}`).text,
        remediation: 'Pass --keys-dir only via operator CLI invocation outside the repository; never commit private key paths or key material inside Beefile.'
      });
    }

    // 2. Plaintext http:// OCI/registry URL or embedded credentials
    if (typeof entry.value === 'string') {
      if (/\bhttp:\/\//i.test(entry.value) && !/^http:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/i.test(entry.value)) {
        findings.push({
          title: 'Plaintext http:// registry or artifact URL in Shirudo Beefile',
          severity: 'high',
          category: 'config',
          cwe: 'CWE-319',
          reachability: 'reachable',
          location: `${relPath}:${entry.line}`,
          evidence: redactSecrets(`${entry.key} = "${entry.value}"`).text,
          remediation: 'Use TLS-protected oci:// or https:// endpoints so signed .bee upatch artifacts cannot be downgraded or tampered in transit.'
        });
      }
      if (/(?:oci|https?):\/\/[^/\s:@]+:[^@\s/'"]+@/i.test(entry.value)) {
        findings.push({
          title: 'Embedded registry credentials in Shirudo Beefile URL',
          severity: 'high',
          category: 'secrets',
          cwe: 'CWE-798',
          reachability: 'reachable',
          location: `${relPath}:${entry.line}`,
          evidence: redactSecrets(`${entry.key} = "${entry.value}"`).text,
          remediation: 'Remove embedded credentials from Beefile registry URLs and authenticate out-of-band via OCI credential helpers.'
        });
      }
    }
  }

  // 3. Package & upatch structure checks
  if (!parsed.package.name || !String(parsed.package.name).trim()) {
    findings.push({
      title: 'Missing [package].name in Shirudo Beefile',
      severity: 'medium',
      category: 'config',
      cwe: 'CWE-1188',
      reachability: 'reachable',
      location: `${relPath}:1`,
      evidence: '[package] name is empty or missing',
      remediation: 'Declare [package] name = "<shield-name>" in Beefile so SPDX SBOM and signed tree metadata remain attributable.'
    });
  }

  if (!parsed.upatches.length) {
    findings.push({
      title: 'Shirudo Beefile defines zero [[upatches]] entries',
      severity: 'medium',
      category: 'config',
      cwe: 'CWE-1188',
      reachability: 'reachable',
      location: `${relPath}:1`,
      evidence: 'No [[upatches]] sections found',
      remediation: 'Define at least one scoped [[upatches]] block referencing a verified BPF or runtime shield artifact.'
    });
  }

  const baseDirRel = path.posix.dirname(String(relPath || '').replace(/\\/g, '/'));
  for (const up of parsed.upatches) {
    const src = String(up.source || '').trim();
    if (!src) {
      findings.push({
        title: 'Shirudo [[upatches]] entry missing source field',
        severity: 'medium',
        category: 'config',
        cwe: 'CWE-1188',
        reachability: 'reachable',
        location: `${relPath}:${up.line}`,
        evidence: '[[upatches]] block has no source = "..."',
        remediation: 'Specify a workspace-relative source path inside [[upatches]].'
      });
      continue;
    }

    const normSrc = src.replace(/\\/g, '/');
    if (path.posix.isAbsolute(normSrc) || normSrc.split('/').includes('..')) {
      findings.push({
        title: 'Path traversal or absolute path in Shirudo upatch.source',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-22',
        reachability: 'reachable',
        location: `${relPath}:${up.line}`,
        evidence: `source = "${src}"`,
        remediation: 'Keep upatch.source relative to the Beefile package directory with no ".." segments or absolute paths.'
      });
      continue;
    }

    const selectorKeys = Object.keys(up.selectorLabels || {});
    const hasWildcardSelector = selectorKeys.some(k => {
      const vals = up.selectorLabels[k] || [];
      return k === '*' || vals.some(v => v.trim() === '*');
    });
    if (!selectorKeys.length || hasWildcardSelector) {
      cantTellReasons.push({
        code: 'shirudo-upatch-wildcard-selector',
        path: relPath,
        line: up.line,
        message: `Shirudo upatch "${src}" at ${relPath}:${up.line} has ${hasWildcardSelector ? 'a "*" wildcard selector' : 'no selector.labels'}; scope fleet blast radius before signing.`
      });
    }

    if (root) {
      const joinedRel = baseDirRel && baseDirRel !== '.' ? path.posix.join(baseDirRel, normSrc) : normSrc;
      let exists = false;
      try {
        const res = await resolveWithinRoot(root, joinedRel);
        await fs.access(res.fullPath);
        exists = true;
      } catch {
        exists = false;
      }
      if (!exists) {
        cantTellReasons.push({
          code: 'shirudo-upatch-missing-source',
          path: relPath,
          line: up.line,
          message: `Referenced upatch artifact "${src}" (${joinedRel}) was not found inside workspace.`
        });
      }

      if (/\.(?:bpf\.o|bee|upatch)$/i.test(normSrc)) {
        const siblingBase = normSrc.replace(/\.(?:bpf\.o|bee|upatch)$/i, '');
        let hasSource = false;
        for (const ext of ['.bpf.c', '.upatch.c']) {
          const siblingRel = baseDirRel && baseDirRel !== '.' ? path.posix.join(baseDirRel, `${siblingBase}${ext}`) : `${siblingBase}${ext}`;
          try {
            const sibRes = await resolveWithinRoot(root, siblingRel);
            await fs.access(sibRes.fullPath);
            hasSource = true;
            break;
          } catch {
            // Try next extension
          }
        }
        if (!hasSource) {
          cantTellReasons.push({
            code: 'shirudo-upatch-opaque-object',
            path: relPath,
            line: up.line,
            message: `Upatch "${src}" references compiled bytecode/object with no sibling Plain BPF C source (${siblingBase}.bpf.c) to inspect.`
          });
        }
      }
    }
  }

  return { parsed, findings, cantTellReasons };
}

function auditBpfUpatchSource(relPath, text) {
  const findings = [];
  const cantTellReasons = [];
  const src = String(text || '');
  const lines = src.split(/\r?\n/);

  const SCOPING_HINT_RE = /\b(?:bpf_get_current_pid_tgid|bpf_get_current_uid_gid|bpf_get_current_comm|bpf_get_current_cgroup_id|d_name|inode|comm|pid|uid|tgid|cgroup)\b/;
  const BROAD_HOOK_RE = /\bSEC\s*\(\s*["'](?:lsm\/|kprobe\/|tracepoint\/syscalls\/|raw_tp\/)[^"']*["']\s*\)/g;
  const HAS_LICENSE_RE = /\bSEC\s*\(\s*["']license["']\s*\)|char\s+(?:_?license|LICENSE)\s*\[\s*\]/i;

  const hasGlobalScopeFilter = SCOPING_HINT_RE.test(src);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;

    if (/\bbpf_probe_write_user\s*\(/.test(line)) {
      findings.push({
        title: 'Unsafe bpf_probe_write_user() helper inside Shirudo BPF upatch',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-787',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Avoid modifying arbitrary userspace memory with bpf_probe_write_user(); prefer scoped LSM return checks or read-only ringbuf telemetry.'
      });
    }

    if (/\bbpf_override_return\s*\(/.test(line) && !/\/\/\s*shirudo-guard:/i.test(line)) {
      findings.push({
        title: 'Unguarded bpf_override_return() in Shirudo BPF upatch',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-284',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Restrict bpf_override_return() to tightly scoped error injection paths and document an explicit "// shirudo-guard: <justification>" rationale.'
      });
    }

    if (/\bbpf_send_signal(?:_thread)?\s*\(\s*(?:9|SIGKILL)\b/.test(line) && !hasGlobalScopeFilter) {
      findings.push({
        title: 'Unfiltered SIGKILL inside Shirudo BPF upatch risk of host-wide DoS',
        severity: 'medium',
        category: 'appsec',
        cwe: 'CWE-400',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Guard bpf_send_signal(SIGKILL) behind explicit process/cgroup/uid/inode predicates (e.g., bpf_get_current_comm or bpf_get_current_cgroup_id).'
      });
    }
  }

  if (!HAS_LICENSE_RE.test(src)) {
    cantTellReasons.push({
      code: 'shirudo-bpf-missing-license',
      path: relPath,
      line: null,
      message: `Shirudo BPF C source "${relPath}" is missing SEC("license") declaration; verifier acceptance cannot be confirmed.`
    });
  }

  let match;
  let broadLine = null;
  while ((match = BROAD_HOOK_RE.exec(src)) !== null) {
    const before = src.slice(0, match.index);
    broadLine = before.split('\n').length;
    break;
  }
  if (broadLine !== null && !hasGlobalScopeFilter) {
    cantTellReasons.push({
      code: 'shirudo-bpf-unbounded-hook',
      path: relPath,
      line: broadLine,
      message: `Broad kernel hook in "${relPath}" (line ${broadLine}) lacks process/cgroup/inode scoping predicates; verify unintended workloads are not disrupted.`
    });
  }

  return {
    findings,
    cantTellReasons,
    summary: `Audited ${relPath}: ${findings.length} finding(s), ${cantTellReasons.length} Can't Tell item(s).`
  };
}

function summarizeEvidenceDoc(parsed) {
  if (!parsed || typeof parsed !== 'object') return {};
  const loaded = Array.isArray(parsed.upatches)
    ? parsed.upatches.length
    : Array.isArray(parsed.loaded_upatches)
      ? parsed.loaded_upatches.length
      : null;
  const events = Array.isArray(parsed.events)
    ? parsed.events.length
    : Array.isArray(parsed.event_log)
      ? parsed.event_log.length
      : null;
  return {
    keys: Object.keys(parsed).slice(0, 20),
    hasQuote: Boolean(parsed.quote || parsed.tpm_quote || parsed.attestation),
    loadedUpatchesCount: loaded,
    eventLogCount: events
  };
}

async function inspectShirudoTarget(root, relTarget = '.', signal = new AbortController().signal) {
  const resolved = await resolveWithinRoot(root, relTarget || '.');
  const stat = await fs.stat(resolved.fullPath);

  const candidates = [];
  if (stat.isDirectory()) {
    const walkState = { truncated: false, deadline: Date.now() + 10000 };
    for await (const fullPath of walkWorkspace(resolved.fullPath, signal, walkState)) {
      const rel = path.relative(resolved.rootReal, fullPath).split(path.sep).join('/');
      if (isShirudoArtifactPath(rel)) {
        candidates.push({ fullPath, relPath: rel });
      }
      if (candidates.length >= 200) break;
    }
  } else {
    candidates.push({ fullPath: resolved.fullPath, relPath: resolved.relPath });
  }

  const findings = [];
  const cantTellReasons = [];
  const inspectedFiles = [];

  if (!candidates.length) {
    cantTellReasons.push({
      code: 'shirudo-no-artifacts',
      path: resolved.relPath,
      line: null,
      message: `No Shirudo Beefile, .bpf.c/.upatch.c source, or .bee/.upatch package found under "${resolved.relPath}".`
    });
  }

  for (const cand of candidates) {
    signal.throwIfAborted?.();
    if (isBeefilePath(cand.relPath)) {
      const text = await readRegularTextFile(cand.fullPath);
      const res = await auditBeefile(cand.relPath, text, { root: resolved.rootReal });
      findings.push(...res.findings);
      cantTellReasons.push(...res.cantTellReasons);
      inspectedFiles.push({ path: cand.relPath, kind: 'beefile', packageName: res.parsed.package.name || '', upatches: res.parsed.upatches.length });
    } else if (isBpfSourcePath(cand.relPath)) {
      const text = await readRegularTextFile(cand.fullPath);
      const res = auditBpfUpatchSource(cand.relPath, text);
      findings.push(...res.findings);
      cantTellReasons.push(...res.cantTellReasons);
      inspectedFiles.push({ path: cand.relPath, kind: 'bpf-source' });
    } else if (/\.(?:bee|upatch)$/i.test(cand.relPath)) {
      const tri = await triageArtifact(cand.fullPath, cand.relPath, signal);
      inspectedFiles.push({ path: cand.relPath, kind: 'package-binary', sha256: tri.hashes.sha256, entropy: tri.entropy, format: tri.format });
      const sibC = cand.relPath.replace(/\.(?:bee|upatch)$/i, '.bpf.c');
      let hasSib = false;
      try {
        const sibRes = await resolveWithinRoot(resolved.rootReal, sibC);
        await fs.access(sibRes.fullPath);
        hasSib = true;
      } catch {
        hasSib = false;
      }
      if (!hasSib) {
        cantTellReasons.push({
          code: 'shirudo-binary-artifact',
          path: cand.relPath,
          line: null,
          message: `Compiled Shirudo package "${cand.relPath}" (SHA-256 ${tri.hashes.sha256.slice(0, 16)}…, entropy ${tri.entropy}/8.00) has no sibling .bpf.c source for static review.`
        });
      }
    }
  }

  const failing = findings.filter(f => f.category === 'secrets' || f.severity === 'critical' || f.severity === 'high');
  let verdict = 'holds';
  let verdictLabel = 'HOLDS UP';
  if (failing.length > 0 || findings.some(f => f.severity === 'medium')) {
    // Critical/High findings always FAILS; medium Beefile/BPF config bugs also FAILS when explicit shirudo audit runs
    if (failing.length > 0 || findings.length > 0) {
      verdict = 'fails';
      verdictLabel = 'FAILS';
    }
  }
  if (verdict === 'holds' && cantTellReasons.length > 0) {
    verdict = 'cant-tell';
    verdictLabel = "CAN'T TELL";
  }

  return {
    verdict,
    verdictLabel,
    workspace: resolved.rootReal,
    target: resolved.relPath,
    inspectedCount: inspectedFiles.length,
    inspectedFiles,
    findings,
    cantTellReasons,
    summary: `Shirudo audit (${resolved.relPath}) → ${verdictLabel}: ${inspectedFiles.length} artifact(s), ${findings.length} finding(s), ${cantTellReasons.length} Can't Tell item(s).`
  };
}

async function verifyShirudoAttestation({
  root = process.cwd(),
  evidencePath,
  nonce = '',
  akName = '',
  commandPath = '',
  execFileImpl = execFileAsync
} = {}) {
  if (typeof evidencePath !== 'string' || !evidencePath.trim()) {
    throw new Error('evidence_path is required.');
  }
  const cleanNonce = String(nonce || '').trim();
  const cleanAk = String(akName || '').trim();
  if (cleanNonce && !HEX_NONCE_RE.test(cleanNonce)) {
    throw new Error('Invalid nonce: expected 8-128 hex characters.');
  }
  if (cleanAk && !AK_NAME_RE.test(cleanAk)) {
    throw new Error('Invalid ak_name: expected 4-128 alphanumeric, :, ., _, or - characters.');
  }

  const resolved = await resolveWithinRoot(root, evidencePath.trim());
  const raw = await readRegularTextFile(resolved.fullPath, 2 * 1024 * 1024);
  let parsedEvidence;
  try {
    parsedEvidence = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in attestation evidence file "${resolved.relPath}": ${err.message}`);
  }
  const evidenceSummary = summarizeEvidenceDoc(parsedEvidence);

  const searchPath = commandPath || process.env.PATH || DEFAULT_PATH;
  const binaryPath = await resolveToolBinary('shirudo', searchPath, resolved.rootReal);
  if (!binaryPath) {
    return {
      verdict: 'cant-tell',
      verdictLabel: "CAN'T TELL",
      verified: false,
      cliAvailable: false,
      evidencePath: resolved.relPath,
      evidenceSummary,
      reason: 'shirudo CLI is not installed on verified PATH; TPM 2.0 quote could not be cryptographically verified.',
      installHint: 'https://github.com/shirudo-dev/shirudo'
    };
  }

  const argv = ['attest', 'verify', `--evidence=${resolved.fullPath}`];
  if (cleanNonce) argv.push(`--nonce=${cleanNonce}`);
  if (cleanAk) argv.push(`--ak-name=${cleanAk}`);

  const safeDirs = await safeSearchDirs(searchPath, resolved.rootReal);
  const env = {
    PATH: safeDirs.join(process.platform === 'win32' ? ';' : ':') || DEFAULT_PATH,
    HOME: process.env.HOME || '',
    TMPDIR: process.env.TMPDIR || '',
    LANG: 'en_US.UTF-8',
    NO_COLOR: '1'
  };

  try {
    const { stdout = '', stderr = '' } = await execFileImpl(binaryPath, argv, {
      timeout: 15000,
      env
    });
    return {
      verdict: 'holds',
      verdictLabel: 'HOLDS UP',
      verified: true,
      cliAvailable: true,
      binaryPath,
      evidencePath: resolved.relPath,
      evidenceSummary,
      output: redactSecrets(String(stdout || stderr || 'TPM 2.0 attestation verified.').trim().slice(0, 4000)).text
    };
  } catch (err) {
    const combined = `${err?.stdout || ''}\n${err?.stderr || ''}\n${err?.message || ''}`.trim();
    return {
      verdict: 'fails',
      verdictLabel: 'FAILS',
      verified: false,
      cliAvailable: true,
      binaryPath,
      evidencePath: resolved.relPath,
      evidenceSummary,
      reason: redactSecrets(combined.slice(0, 4000) || 'Shirudo attestation verification failed.').text
    };
  }
}

async function inspectShirudoStatus({
  root = process.cwd(),
  commandPath = '',
  execFileImpl = execFileAsync
} = {}) {
  const absRoot = await fs.realpath(path.resolve(root));
  const searchPath = commandPath || process.env.PATH || DEFAULT_PATH;
  const binaryPath = await resolveToolBinary('shirudo', searchPath, absRoot);
  if (!binaryPath) {
    return {
      verdict: 'cant-tell',
      verdictLabel: "CAN'T TELL",
      cliAvailable: false,
      reason: 'shirudo CLI is not installed on verified PATH.',
      installHint: 'https://github.com/shirudo-dev/shirudo'
    };
  }

  const safeDirs = await safeSearchDirs(searchPath, absRoot);
  const env = {
    PATH: safeDirs.join(process.platform === 'win32' ? ';' : ':') || DEFAULT_PATH,
    HOME: process.env.HOME || '',
    TMPDIR: process.env.TMPDIR || '',
    LANG: 'en_US.UTF-8',
    NO_COLOR: '1'
  };

  try {
    const { stdout = '', stderr = '' } = await execFileImpl(binaryPath, ['status', '--json', '--show-full'], {
      timeout: 10000,
      env
    });
    let status = null;
    try {
      status = JSON.parse(stdout);
    } catch {
      status = null;
    }
    return {
      verdict: 'holds',
      verdictLabel: 'HOLDS UP',
      cliAvailable: true,
      binaryPath,
      status,
      output: redactSecrets(String(stdout || stderr).trim().slice(0, 4000)).text
    };
  } catch (err) {
    const combined = `${err?.stdout || ''}\n${err?.stderr || ''}\n${err?.message || ''}`.trim();
    return {
      verdict: 'fails',
      verdictLabel: 'FAILS',
      cliAvailable: true,
      binaryPath,
      reason: redactSecrets(combined.slice(0, 4000) || 'shirudo status failed.').text
    };
  }
}

module.exports = {
  isBeefilePath,
  isBpfSourcePath,
  isShirudoArtifactPath,
  isShirudoDraftPath,
  parseBeefile,
  auditBeefile,
  auditBpfUpatchSource,
  inspectShirudoTarget,
  verifyShirudoAttestation,
  inspectShirudoStatus
};
