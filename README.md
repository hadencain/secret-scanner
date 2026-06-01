# secret-scanner

Scans source files for committed secrets. Integrates with git as a pre-commit hook to block commits before they happen.

## Files

| File | Purpose |
|------|---------|
| `scanner.py` | Core scanner and CLI entry point |
| `patterns.py` | Regex pattern library and skip lists |
| `install-hook.py` | Installs scanner as a git pre-commit hook |
| `config.json` | Allowlist and ignore paths |

## Usage

**Scan a directory:**
```bash
python scanner.py /path/to/project
```

**Scan current directory:**
```bash
python scanner.py
```

**With entropy mode** (catches high-entropy strings not matching named patterns — more coverage, more false positives):
```bash
python scanner.py --entropy
```

**Filter by minimum severity:**
```bash
python scanner.py --severity critical
```

**Scan specific files:**
```bash
python scanner.py --files secrets.env config.py
```

## Install as a git pre-commit hook

```bash
python install-hook.py --repo /path/to/your/project
```

After installation, every `git commit` in that repo will automatically scan staged files. Secrets found → commit blocked.

**With entropy mode enabled in the hook:**
```bash
python install-hook.py --repo /path/to/your/project --entropy
```

**Overwrite an existing hook:**
```bash
python install-hook.py --repo /path/to/your/project --force
```

**Bypass the hook when needed:**
```bash
git commit --no-verify
```

**Uninstall:** delete `.git/hooks/pre-commit` in the target repo.

## What it detects

| Pattern | Severity |
|---------|---------|
| AWS Access Key ID (`AKIA...`) | critical |
| AWS Secret Access Key | critical |
| Private keys (RSA, EC, DSA, OpenSSH, PEM) | critical |
| GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | critical |
| Anthropic API key (`sk-ant-...`) | critical |
| OpenAI API key (`sk-...`) | critical |
| Google API key (`AIza...`) | critical |
| Database connection strings (postgres, mysql, mongodb, redis) | critical |
| JDBC connection strings with passwords | critical |
| Slack bot/user tokens | critical |
| Slack webhook URLs | high |
| Password assignments in config/env files | high |
| Secret key / API key assignments | high |
| Auth/access token assignments | high |
| Google OAuth client secrets | high |
| JWT tokens | medium |
| High-entropy strings (opt-in via `--entropy`) | medium |

## Suppressing false positives

Edit `config.json`:

- **`allowlist`** — if any string in this list appears on a line, that line is skipped. Add placeholder values, example keys, or any known-safe strings here.
- **`ignore_paths`** — directories to skip entirely (relative to scan root).

Example:
```json
{
  "ignore_paths": ["tests/fixtures", "docs/examples"],
  "allowlist": ["REPLACE_WITH_YOUR_KEY", "example-token-here"]
}
```

## Limitations

- The pre-commit hook only protects the machine it's installed on. It is not committed to the repo, so other contributors must install it themselves.
- For team-wide enforcement, run `scanner.py` in CI against the full diff.
- Named patterns cover well-known formats. Novel or internal key formats may require adding custom entries to `patterns.py`.
