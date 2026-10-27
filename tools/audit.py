#!/usr/bin/env python3
"""Scan Fathom sources for credential-shaped strings and unsafe C calls.

The script looks at src, include, tests, CMakeLists.txt, and README.md.
It does not scan itself, and it does not scan third_party.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_FILES = [
    ROOT / "CMakeLists.txt",
    ROOT / "README.md",
]
SCAN_DIRS = [ROOT / "src", ROOT / "include", ROOT / "tests"]
SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".txt", ".cmake"}

PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws-temp-key", re.compile(r"ASIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("live-secret", re.compile(r"sk_live_[0-9A-Za-z]+")),
    ("api-key-assignment", re.compile(r"api_key\s*=\s*['\"][^'\"]+['\"]", re.I)),
    ("aws-secret-assignment", re.compile(r"aws_secret_access_key\s*=\s*['\"][^'\"]+['\"]", re.I)),
    ("strcpy", re.compile(r"\bstrcpy\s*\(")),
    ("strcat", re.compile(r"\bstrcat\s*\(")),
    ("sprintf", re.compile(r"(?<!sn)printf\s*\(")),
    ("gets", re.compile(r"\bgets\s*\(")),
    ("scanf", re.compile(r"\bscanf\s*\(")),
    ("system", re.compile(r"\bsystem\s*\(")),
    ("popen", re.compile(r"\bpopen\s*\(")),
    ("mktemp", re.compile(r"\bmktemp\s*\(")),
]


def files() -> list[Path]:
    found: list[Path] = []
    for path in SCAN_FILES:
        if path.is_file():
            found.append(path)
    for directory in SCAN_DIRS:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in SUFFIXES and "third_party" not in path.parts:
                found.append(path)
    return found


def main() -> int:
    findings = 0
    for path in files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                print(f"{path.relative_to(ROOT)}:{line}: {name}")
                findings += 1
    if findings:
        print(f"{findings} finding(s)", file=sys.stderr)
        return 1
    print("audit: no credential or unsafe-call findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
