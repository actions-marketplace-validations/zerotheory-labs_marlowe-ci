const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { DEFAULT_SCOPE, validateScopeConfig } = require('./cyber-scope.cjs');

const ENV_TEMPLATE_RE = /^\.env\.(?:example|sample|template)$/i;
const PROTECTED_SEGMENTS_RE = /^(\.git|\.ssh|\.aws|\.gnupg|\.codex|\.shirudo|shirudo-keys|\.npmrc|\.netrc|\.pypirc|\.env(?:\..*)?|.*\.(?:pem|key))$/i;

const SKIP_DIRS = new Set([
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.uv-cache',
  '.cache',
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  '.tox',
  '.nox',
  '.next',
  '.nuxt',
  '.turbo',
  '.parcel-cache',
  'dist',
  'release',
  'test-results',
  'playwright-report'
]);

function isProtectedSegment(segment) {
  if (!segment || typeof segment !== 'string') return false;
  if (ENV_TEMPLATE_RE.test(segment)) return false;
  return PROTECTED_SEGMENTS_RE.test(segment);
}

function isProtectedRelPath(relPath) {
  if (typeof relPath !== 'string' || !relPath.trim()) return true;
  const normalized = relPath.replace(/\\/g, '/').replace(/^\.\//, '');
  const segments = normalized.split('/').filter(Boolean);
  if (!segments.length) return true;
  for (const seg of segments) {
    if (seg === '..' || isProtectedSegment(seg)) return true;
  }
  return false;
}

async function resolveWithinRoot(root, relOrAbs) {
  if (typeof relOrAbs !== 'string' || !relOrAbs.trim() || relOrAbs.includes('\0')) {
    throw new Error('Invalid workspace path.');
  }
  const rootReal = await fs.realpath(path.resolve(root));
  const candidate = path.isAbsolute(relOrAbs)
    ? path.resolve(relOrAbs)
    : path.resolve(rootReal, relOrAbs);

  let targetReal;
  try {
    targetReal = await fs.realpath(candidate);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      const parentReal = await fs.realpath(path.dirname(candidate)).catch(() => null);
      if (!parentReal) throw new Error(`Path parent does not exist: ${relOrAbs}`);
      if (parentReal !== rootReal && !parentReal.startsWith(rootReal + path.sep)) {
        throw new Error(`Path "${relOrAbs}" escapes workspace root.`);
      }
      targetReal = path.join(parentReal, path.basename(candidate));
    } else {
      throw err;
    }
  }

  if (targetReal !== rootReal && !targetReal.startsWith(rootReal + path.sep)) {
    throw new Error(`Path "${relOrAbs}" escapes workspace root.`);
  }

  const rel = path.relative(rootReal, targetReal).split(path.sep).join('/');
  if (rel && isProtectedRelPath(rel)) {
    throw new Error(`Access to protected credential/sensitive path "${rel}" is denied.`);
  }

  return { rootReal, fullPath: targetReal, relPath: rel || '.' };
}

async function readRegularTextFile(fullPath, maxBytes = 250000) {
  let handle;
  try {
    handle = await fs.open(fullPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink > 1) {
      throw new Error('Expected a regular file without symlinks or hard links.');
    }
    if (stat.size > maxBytes) {
      throw new Error(`File exceeds ${maxBytes}-byte text inspection limit.`);
    }
    const buf = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buf, offset, stat.size - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const slice = buf.subarray(0, offset);
    if (slice.subarray(0, Math.min(slice.length, 4096)).includes(0)) {
      throw new Error('Binary file skipped for text inspection.');
    }
    return slice.toString('utf8');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readRegularBuffer(fullPath, maxBytes = 10 * 1024 * 1024) {
  let handle;
  try {
    handle = await fs.open(fullPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink > 1) {
      throw new Error('Expected a regular file without symlinks or hard links.');
    }
    if (stat.size > maxBytes) {
      throw new Error(`File exceeds ${maxBytes}-byte inspection limit.`);
    }
    const buf = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buf, offset, stat.size - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    return buf.subarray(0, offset);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function* walkWorkspace(startDir, signal, state = { truncated: false, deadline: Date.now() + 12000 }) {
  const queue = [path.resolve(startDir)];
  let visited = 0;
  while (queue.length) {
    if (signal?.aborted) signal.throwIfAborted();
    if (state.deadline && Date.now() > state.deadline) {
      state.truncated = true;
      break;
    }
    const dir = queue.pop();
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const subdirs = [];
    for (const entry of entries) {
      if (signal?.aborted) signal.throwIfAborted();
      if (++visited > 15000 || (state.deadline && Date.now() > state.deadline)) {
        state.truncated = true;
        break;
      }
      if (entry.name === '.DS_Store' || entry.isSymbolicLink() || isProtectedSegment(entry.name)) {
        continue;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) subdirs.push(full);
      } else if (entry.isFile()) {
        yield full;
      }
    }
    queue.push(...subdirs.reverse());
  }
}

async function loadScopeConfig(root) {
  if (!root) return { ...DEFAULT_SCOPE };
  for (const filename of ['.marlowe-scope.json', '.marlowe.json']) {
    const candidate = path.join(root, filename);
    let handle;
    try {
      handle = await fs.open(candidate, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 65536) continue;
      const buf = Buffer.alloc(stat.size);
      if (stat.size > 0) await handle.read(buf, 0, stat.size, 0);
      const parsed = JSON.parse(buf.toString('utf8'));
      const source = parsed && typeof parsed.scope === 'object' ? parsed.scope : parsed;
      return validateScopeConfig(source);
    } catch {
      // Missing or invalid config falls through to next candidate / default scope.
    } finally {
      await handle?.close().catch(() => {});
    }
  }
  return { ...DEFAULT_SCOPE };
}

module.exports = {
  ENV_TEMPLATE_RE,
  PROTECTED_SEGMENTS_RE,
  SKIP_DIRS,
  isProtectedSegment,
  isProtectedRelPath,
  resolveWithinRoot,
  readRegularTextFile,
  readRegularBuffer,
  walkWorkspace,
  loadScopeConfig
};
