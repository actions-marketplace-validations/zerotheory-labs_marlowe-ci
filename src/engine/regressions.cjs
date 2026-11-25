const TLS_WEAKEN_RE = /\brejectUnauthorized\s*:\s*false\b|\bInsecureSkipVerify\s*:\s*true\b|\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b/;
const SUPPRESSION_RE = /\b(?:nosemgrep|gitleaks:allow|trivy:ignore|bandit:\s*skip|@ts-nocheck)\b|\/\/\s*nolint\b|eslint-disable(?:-next-line)?\s+security\b/i;

const SECURITY_CONTROLS = [
  { id: 'csp', label: 'Content-Security-Policy', re: /Content-Security-Policy/i },
  { id: 'hsts', label: 'Strict-Transport-Security', re: /Strict-Transport-Security/i },
  { id: 'helmet', label: 'helmet middleware', re: /\bhelmet\s*\(/ },
  { id: 'csrf', label: 'CSRF guard', re: /\bcsrf\b/i },
  { id: 'rate-limit', label: 'rate limiter', re: /\brateLimit\b/ },
  { id: 'context-isolation', label: 'contextIsolation: true', re: /\bcontextIsolation\s*:\s*true\b/ },
  { id: 'sandbox', label: 'sandbox: true', re: /\bsandbox\s*:\s*true\b/ },
  { id: 'shell-false', label: 'shell: false', re: /\bshell\s*:\s*false\b/ },
  { id: 'nofollow', label: 'O_NOFOLLOW', re: /\bO_NOFOLLOW\b/ },
  { id: 'scope-guard', label: 'assertTargetInScope', re: /\bassertTargetInScope\b/ },
  { id: 'auth-middleware', label: 'authentication/authorization check', re: /\b(?:requireAuth|authenticate|authorize)\b/ },
  { id: 'bpf-license', label: 'BPF SEC("license") declaration', re: /SEC\s*\(\s*["']license["']\s*\)/ }
];

const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|test_[^/]+\.py$/i;
const SKIP_TEST_RE = /\b(?:it|test|describe)\.skip\s*\(|\bx(?:it|describe)\s*\(|@pytest\.mark\.skip|\bt\.Skip\s*\(/;
const SECURITY_TEST_HINT_RE = /\b(?:auth|login|session|token|jwt|rbac|acl|csrf|xss|ssrf|sqli|tls|scope|security|secret|permission|shirudo|upatch|ebpf|bpf|attest|tpm)\b/i;
const SENSITIVE_SURFACE_PATH_RE = /(?:^|\/)(?:beefile|auth|login|session|oauth|jwt|rbac|acl|crypto|tls|scope|security|middleware|dockerfile|containerfile|\.github\/workflows\/).*/i;
const NON_CODE_DOC_RE = /\.(?:md|mdx|rst|txt)$/i;
const METADATA_JSON_RE = /(?:^|\/)(?:server|package|package-lock|tsconfig|jsconfig|composer|manifest)\.json$/i;

function isTestFilePath(relPath) {
  return TEST_FILE_RE.test(String(relPath || ''));
}

function isSensitiveSurfacePath(relPath) {
  const p = String(relPath || '');
  return (SENSITIVE_SURFACE_PATH_RE.test(p) || /\.(?:tf|beefile|bpf\.c|upatch\.c|bee|upatch)$/i.test(p)) && !isTestFilePath(p);
}

function isCommentOrRuleLine(rawText) {
  const trimmed = String(rawText || '').trim();
  if (!trimmed) return true;
  if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return true;
  if (/^(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=|^\s*(?:regex|re)\s*:/.test(trimmed)) return true;
  return false;
}

function detectGuardrailRegressions(diffFiles = []) {
  const findings = [];
  const cantTellReasons = [];
  const changedSensitivePaths = [];
  let hasTouchedTestFile = false;

  for (const file of diffFiles) {
    if (!file || file.status === 'deleted' || file.isBinary) continue;
    const relPath = file.path;
    const isTest = isTestFilePath(relPath);
    if (isTest) hasTouchedTestFile = true;
    else if (isSensitiveSurfacePath(relPath)) changedSensitivePaths.push(relPath);

    const added = Array.isArray(file.addedLines) ? file.addedLines : [];
    const removed = Array.isArray(file.removedLines) ? file.removedLines : [];

    for (const entry of added) {
      const text = String(entry.text || '');
      if (!isCommentOrRuleLine(text) && TLS_WEAKEN_RE.test(text)) {
        findings.push({
          title: 'TLS certificate verification disabled in diff',
          severity: 'high',
          category: 'crypto',
          cwe: 'CWE-295',
          reachability: 'reachable',
          location: `${relPath}:${entry.line}`,
          evidence: text.trim().slice(0, 220),
          remediation: 'Remove TLS verification bypass flags so certificate trust and hostname verification remain enforced.'
        });
      }

      if (!/^(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=/.test(text.trim()) && SUPPRESSION_RE.test(text)) {
        cantTellReasons.push({
          code: 'guardrail-suppression-added',
          path: relPath,
          line: entry.line,
          message: `Security suppression comment added at ${relPath}:${entry.line} (${text.trim().slice(0, 120)}); verify justification manually.`
        });
      }

      if (isTest && !isCommentOrRuleLine(text) && SKIP_TEST_RE.test(text)) {
        const contextWindow = added
          .filter(l => Math.abs(l.line - entry.line) <= 4)
          .map(l => l.text)
          .join(' ');
        if (SECURITY_TEST_HINT_RE.test(`${relPath} ${contextWindow}`)) {
          cantTellReasons.push({
            code: 'guardrail-security-test-disabled',
            path: relPath,
            line: entry.line,
            message: `Security-related test skipped at ${relPath}:${entry.line}; verify coverage was not silently bypassed.`
          });
        }
      }
    }

    if (!isTest && !NON_CODE_DOC_RE.test(relPath) && !METADATA_JSON_RE.test(relPath) && removed.length) {
      const addedBlob = added.map(l => l.text).join('\n');
      for (const ctrl of SECURITY_CONTROLS) {
        const removedMatch = removed.find(r => !isCommentOrRuleLine(r.text) && ctrl.re.test(r.text));
        if (removedMatch && !ctrl.re.test(addedBlob)) {
          cantTellReasons.push({
            code: 'guardrail-security-control-removed',
            path: relPath,
            line: removedMatch.line,
            message: `Removed ${ctrl.label} check in ${relPath} (former line ${removedMatch.line}) without re-introducing it in the same file.`
          });
        }
      }
    }
  }

  if (changedSensitivePaths.length && !hasTouchedTestFile) {
    const sample = changedSensitivePaths.slice(0, 3).join(', ');
    const more = changedSensitivePaths.length > 3 ? ` (+${changedSensitivePaths.length - 3} more)` : '';
    cantTellReasons.push({
      code: 'sensitive-surface-untested',
      path: changedSensitivePaths[0],
      line: null,
      message: `Security-sensitive surface modified without any test changes (${sample}${more}).`
    });
  }

  return { findings, cantTellReasons };
}

module.exports = {
  isTestFilePath,
  isSensitiveSurfacePath,
  detectGuardrailRegressions
};
