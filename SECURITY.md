# Security Policy

## Supported Versions

| Version | Supported | Runtime |
| --- | --- | --- |
| `0.1.x` | Yes | Node.js `>=20.0.0` (macOS, Linux, Windows, GitHub Actions `node20`) |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities in Marlowe CI / Guard (such as `ScopeGate` / SSRF bypasses, `PROTECTED_SEGMENTS_RE` / symlink traversal bypasses, hook `stdout` JSON injection, or CLI argument/shell injection).

Report vulnerabilities privately through **GitHub Private Vulnerability Reporting**:

- `https://github.com/zerotheory-labs/marlowe-ci/security/advisories/new`

Or contact `access@zerotheorylabs.com` with reproduction steps, expected boundary vs. observed behavior, and commit hash.

## Enforced Trust Boundaries

- **Workspace & Symlink Confinement (`src/core/fs-safe.cjs`):** File inspections open files with `O_RDONLY | O_NOFOLLOW`, verify `stat.isFile()` and `nlink === 1`, resolve symlinks against the realpath of the workspace root, and refuse protected secret paths (`.git`, `.ssh`, `.aws`, `.gnupg`, `.codex`, `.npmrc`, `.netrc`, `.pypirc`, `.env` / `.env.*` other than safe templates, `*.pem`, `*.key`).
- **ScopeGate & SSRF Confinement (`src/core/cyber-scope.cjs`):** Network targets validate against `.marlowe-scope.json` / `.marlowe.json` and refuse loopback, RFC1918, link-local, cloud metadata (`169.254.169.254`), and embedded URL credentials unless explicitly authorized.
- **No Shell Interpolation (`shell: false`):** All git commands (`execFile('git', ...)`) and external security CLIs (`spawn(binaryPath, argv, { shell: false })`) execute without shell interpolation against clean, workspace-excluded `PATH` directories.
- **Hook & MCP Stdout Purity:** Claude Code hooks (`marlowe-ci claude ...`) and the `stdio` MCP server (`marlowe-ci mcp`) emit strictly framed JSON on `stdout`; diagnostics never leak into `stdout`.
