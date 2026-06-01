#!/usr/bin/env python3
"""
Install the secret scanner as a git pre-commit hook in a target repo.
Usage: python install-hook.py --repo /path/to/your/project
"""

import argparse
import os
import stat
import sys
from pathlib import Path

SCANNER_PATH = (Path(__file__).parent / "scanner.py").resolve()

HOOK_TEMPLATE = """#!/bin/sh
# Secret scanner pre-commit hook — installed by install-hook.py
# Runs on staged files only. Blocks commit if secrets are found.

SCANNER="{scanner_path}"
PYTHON="{python_exe}"

if [ ! -f "$SCANNER" ]; then
    echo "[secret-scanner] WARNING: scanner not found at $SCANNER — skipping"
    exit 0
fi

# Get list of staged files (added or modified)
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
    exit 0
fi

echo "[secret-scanner] Scanning staged files..."

# Pass staged files to scanner
$PYTHON "$SCANNER" --files $STAGED{entropy_flag}

STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo ""
    echo "[secret-scanner] Commit blocked. Fix the above findings or add to allowlist in config.json"
    echo "[secret-scanner] To bypass (dangerous): git commit --no-verify"
fi

exit $STATUS
"""

def find_python() -> str:
    # Prefer the python that's running this script
    return sys.executable


def install(repo_path: Path, entropy: bool = False, force: bool = False):
    git_dir = repo_path / ".git"
    if not git_dir.is_dir():
        print(f"Error: {repo_path} is not a git repository (no .git directory found)")
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists() and not force:
        print(f"A pre-commit hook already exists at {hook_path}")
        print("Use --force to overwrite it.")
        sys.exit(1)

    python_exe = find_python()
    entropy_flag = " --entropy" if entropy else ""

    hook_content = HOOK_TEMPLATE.format(
        scanner_path=str(SCANNER_PATH).replace("\\", "/"),
        python_exe=str(python_exe).replace("\\", "/"),
        entropy_flag=entropy_flag,
    )

    hook_path.write_text(hook_content)

    # Make executable (matters on Linux/Mac; no-op on Windows but harmless)
    current = stat.S_IMODE(os.stat(hook_path).st_mode)
    os.chmod(hook_path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Hook installed at: {hook_path}")
    print(f"Scanner:           {SCANNER_PATH}")
    print(f"Python:            {python_exe}")
    print(f"Entropy mode:      {'on' if entropy else 'off'}")
    print()
    print("Every 'git commit' in this repo will now run the secret scanner on staged files.")
    print("To uninstall: delete", hook_path)


def main():
    parser = argparse.ArgumentParser(
        description="Install the secret scanner as a git pre-commit hook."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="Path to the git repository (default: current directory)",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable entropy-based scanning in the hook",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing pre-commit hook",
    )
    args = parser.parse_args()

    install(args.repo.resolve(), entropy=args.entropy, force=args.force)


if __name__ == "__main__":
    main()
