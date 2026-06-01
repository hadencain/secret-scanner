#!/usr/bin/env python3
"""
Secret scanner — finds credentials and secrets in source files.
Usage: python scanner.py [path] [options]
"""

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from patterns import PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS

# ── ANSI colors ──────────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
GREEN = "\033[92m"

def _no_color():
    return not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def c(text, *codes):
    if _no_color():
        return text
    return "".join(codes) + text + RESET


# ── Entropy ───────────────────────────────────────────────────────────────────

ENTROPY_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
ENTROPY_MIN_LENGTH = 20
ENTROPY_THRESHOLD = 4.5  # bits per char — tuned to reduce false positives

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def _find_high_entropy_strings(line: str):
    """Yield (token, entropy) for suspicious high-entropy tokens on a line."""
    import re
    # Extract runs of base64/hex-looking characters
    for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", line):
        # Skip tokens that are clearly just words/paths
        if token.count("/") > 3:
            continue
        entropy = _shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            yield token, entropy


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    file: Path
    line_number: int
    line_content: str
    pattern_name: str
    severity: str
    matched_text: str = ""
    match_start: int = -1
    match_end: int = -1


# ── Config loading ────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "ignore_paths": [],
    "ignore_patterns": [],
    "allowlist": [],
}

def load_config(config_path: Optional[Path]) -> dict:
    if config_path and config_path.exists():
        with open(config_path) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    # Look for config.json next to scanner.py
    default = Path(__file__).parent / "config.json"
    if default.exists():
        with open(default) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG


# ── Core scanner ──────────────────────────────────────────────────────────────

def _should_skip_path(path: Path, config: dict) -> bool:
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for ignore in config.get("ignore_paths", []):
        try:
            path.relative_to(ignore)
            return True
        except ValueError:
            pass
    return False


SEVERITY_ORDER = ["low", "medium", "high", "critical"]

def _spans_overlap(a_start, a_end, b_start, b_end) -> bool:
    return a_start < b_end and b_start < a_end


def _deduplicate_line_findings(findings: list) -> list:
    """Drop lower-severity findings whose match span overlaps a higher-severity one."""
    if len(findings) <= 1:
        return findings

    keep = []
    for i, a in enumerate(findings):
        dominated = False
        for j, b in enumerate(findings):
            if i == j:
                continue
            if a.match_start < 0 or b.match_start < 0:
                continue
            if not _spans_overlap(a.match_start, a.match_end, b.match_start, b.match_end):
                continue
            a_rank = SEVERITY_ORDER.index(a.severity)
            b_rank = SEVERITY_ORDER.index(b.severity)
            if b_rank > a_rank:
                dominated = True
                break
            if b_rank == a_rank and j < i:
                dominated = True
                break
        if not dominated:
            keep.append(a)
    return keep


def _is_allowlisted(line: str, config: dict) -> bool:
    for entry in config.get("allowlist", []):
        if entry in line:
            return True
    return False


def scan_file(path: Path, config: dict, entropy: bool = False) -> list[Finding]:
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        if _is_allowlisted(line, config):
            continue

        line_findings = []

        for name, pattern, severity in PATTERNS:
            match = pattern.search(line)
            if match:
                line_findings.append(Finding(
                    file=path,
                    line_number=lineno,
                    line_content=line.strip(),
                    pattern_name=name,
                    severity=severity,
                    matched_text=match.group(0)[:80],
                    match_start=match.start(),
                    match_end=match.end(),
                ))

        line_findings = _deduplicate_line_findings(line_findings)

        if entropy:
            for token, ent in _find_high_entropy_strings(line):
                already = any(token in f.matched_text for f in line_findings)
                if not already:
                    line_findings.append(Finding(
                        file=path,
                        line_number=lineno,
                        line_content=line.strip(),
                        pattern_name="High-entropy string",
                        severity="medium",
                        matched_text=f"{token[:40]}... (entropy={ent:.2f})",
                    ))

        findings.extend(line_findings)

    return findings


def scan_path(root: Path, config: dict, entropy: bool = False, files_only: list = None) -> list[Finding]:
    """Scan a directory tree or a list of specific files."""
    all_findings = []

    if files_only is not None:
        targets = [Path(f) for f in files_only]
    elif root.is_file():
        targets = [root]
    else:
        targets = (p for p in root.rglob("*") if p.is_file())

    for path in targets:
        if _should_skip_path(path, config):
            continue
        all_findings.extend(scan_file(path, config, entropy=entropy))

    return all_findings


# ── Output ────────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "critical": RED,
    "high": YELLOW,
    "medium": CYAN,
    "low": DIM,
}

def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "")
    return c(f"[{severity.upper()}]", BOLD, color)


def print_findings(findings: list[Finding], root: Path):
    if not findings:
        print(c("No secrets found.", GREEN, BOLD))
        return

    # Group by file
    by_file: dict[Path, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath, file_findings in sorted(by_file.items()):
        try:
            rel = filepath.relative_to(root)
        except ValueError:
            rel = filepath
        print(f"\n{c(str(rel), BOLD, CYAN)}")
        for f in file_findings:
            badge = _severity_badge(f.severity)
            print(f"  {badge} line {f.line_number}  {c(f.pattern_name, BOLD)}")
            print(f"    {c(f.line_content[:120], DIM)}")

    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    print(f"\n{c('-' * 60, DIM)}")
    print(
        f"{c(str(total), BOLD)} finding(s): "
        f"{c(str(critical) + ' critical', BOLD, RED)}  "
        f"{c(str(high) + ' high', BOLD, YELLOW)}"
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan files for secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Also flag high-entropy strings (more coverage, more false positives)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config JSON file",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        metavar="FILE",
        help="Scan specific files instead of walking a directory (used by git hook)",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Only report findings at or above this severity level",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    root = Path(args.path).resolve()

    findings = scan_path(root, config, entropy=args.entropy, files_only=args.files)

    # Filter by severity if requested
    if args.severity:
        order = ["low", "medium", "high", "critical"]
        min_idx = order.index(args.severity)
        findings = [f for f in findings if order.index(f.severity) >= min_idx]

    print_findings(findings, root)

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
