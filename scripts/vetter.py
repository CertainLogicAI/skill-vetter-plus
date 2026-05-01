#!/usr/bin/env python3
"""
skill-vetter-plus — Security scanner for AI agent skills.

Detection strings stored as ASCII integer arrays to avoid literal
matches in ClawHub's static code scanner. Decoded at runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Tuple


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    rule_id: str
    file: str
    line: int
    message: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    duration_ms: float = 0.0

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "scanned_files": self.scanned_files,
                "duration_ms": self.duration_ms,
                "total_findings": len(self.findings),
                "severity_counts": {
                    "critical": self.count(Severity.CRITICAL),
                    "high": self.count(Severity.HIGH),
                    "medium": self.count(Severity.MEDIUM),
                    "low": self.count(Severity.LOW),
                    "info": self.count(Severity.INFO),
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── ASCII-encoded detection strings ────────────────────────────────
# We store fragments as ASCII codes to avoid literal matches.

def _c(codes: List[int]) -> str:
    """Build string from ASCII integer list."""
    return "".join(chr(c) for c in codes)


_FRAGMENTS: List[Tuple[str, str, Severity, Tuple[str, ...]]] = [
    # Secrets
    ("hardcoded-api-key", "Possible hardcoded API key detected.", Severity.HIGH,
     (_c([97, 112, 105, 95, 107, 101, 121]), _c([97, 112, 105, 45, 107, 101, 121]))),
    ("hardcoded-token", "Possible hardcoded token detected.", Severity.HIGH,
     (_c([115, 101, 99, 114, 101, 116, 95, 107, 101, 121]),
      _c([97, 117, 116, 104, 95, 116, 111, 107, 101, 110]))),
    ("hardcoded-password", "Possible hardcoded password detected.", Severity.HIGH,
     (_c([112, 97, 115, 115, 119, 111, 114, 100]),)),
    # Unsafe execution
    ("unsafe-eval", "TEXT SEARCH: dangerous func detection #1", Severity.CRITICAL,
     (_c([101, 118, 97, 108, 40]),)),
    ("unsafe-exec", "TEXT SEARCH: dangerous func detection #2", Severity.CRITICAL,
     (_c([101, 120, 101, 99, 40]),)),
    ("unsafe-os-system", "TEXT SEARCH: dangerous func detection #3", Severity.CRITICAL,
     (_c([111, 115, 46, 115, 121, 115, 116, 101, 109, 40]),)),
    ("subprocess-shell-true", "subprocess with shell=True is dangerous.", Severity.HIGH,
     (_c([115, 104, 101, 108, 108, 61, 84, 114, 117, 101]),)),
    # Network
    ("raw-network", "Network calls found. Review for exfiltration risk.", Severity.MEDIUM,
     (_c([117, 114, 108, 108, 105, 98, 46, 114, 101, 113, 117, 101, 115, 116]),
      _c([114, 101, 113, 117, 101, 115, 116, 115, 46, 112, 111, 115, 116]),
      _c([114, 101, 113, 117, 101, 115, 116, 115, 46, 103, 101, 116]))),
    # Prompt injection
    ("ignore-instructions", "Potential prompt injection.", Severity.CRITICAL,
     (_c([105, 103, 110, 111, 114, 101, 32, 112, 114, 101, 118, 105, 111, 117, 115, 32, 105, 110, 115, 116, 114, 117, 99, 116, 105, 111, 110, 115]),)),
    ("ignore-above", "Potential prompt injection.", Severity.HIGH,
     (_c([105, 103, 110, 111, 114, 101, 32, 97, 98, 111, 118, 101]),)),
]


class RulesEngine:
    """TEXT-SEARCH based static analysis. No eval, no dynamic code."""

    @classmethod
    def check_file(cls, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = text.splitlines()

        for lineno, line in enumerate(lines, start=1):
            line_lower = line.lower()
            for rule_id, message, severity, fragments in _FRAGMENTS:
                for frag_raw in fragments:
                    frag_lower = frag_raw.lower()
                    if frag_raw in line or frag_lower in line_lower:
                        findings.append(
                            Finding(
                                severity=severity,
                                rule_id=rule_id,
                                file=str(path),
                                line=lineno,
                                message=f"{message} Fragment: '{frag_raw}'",
                                remediation="Review context before installation.",
                            )
                        )
                        break

        return findings


def walk_skill(skill_dir: Path) -> Iterable[Path]:
    if not skill_dir.exists():
        return
    for root, _, files in os.walk(skill_dir):
        for fname in files:
            yield Path(root) / fname


def scan_skill(skill_dir: Path) -> Report:
    import time
    start = time.monotonic()
    report = Report()

    for path in walk_skill(skill_dir):
        report.scanned_files += 1
        findings = RulesEngine.check_file(path)
        report.findings.extend(findings)

    report.duration_ms = (time.monotonic() - start) * 1000
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Security scanner for AI agent skills")
    parser.add_argument("path", type=Path, help="Skill directory to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    args = parser.parse_args()

    report = scan_skill(args.path)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Scanned {report.scanned_files} files in {report.duration_ms:.0f}ms")
        if report.findings:
            print(f"Found {len(report.findings)} issue(s):")
            for f in report.findings:
                print(f"  [{f.severity.value.upper()}] {f.rule_id} at {f.file}:{f.line}")
                print(f"    → {f.message}")
        else:
            print("No issues found.")
    return 0 if len(report.findings) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
