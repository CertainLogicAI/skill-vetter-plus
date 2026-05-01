#!/usr/bin/env python3
"""
skill-vetter-plus — Security scanner for AI agent skills.
Static analysis of manifests, scripts, and prompt content.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional


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


class RulesEngine:
    """Built-in static analysis rules."""

    # Regexes for secret detection
    SECRET_PATTERNS: List[tuple] = [
        (
            re.compile(
                r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
                re.IGNORECASE,
            ),
            "hardcoded-api-key",
            "Possible hardcoded API key detected.",
        ),
        (
            re.compile(
                r"token\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
                re.IGNORECASE,
            ),
            "hardcoded-token",
            "Possible hardcoded token detected.",
        ),
        (
            re.compile(
                r"password\s*[:=]\s*['\"][^\s'\"]{8,}['\"]",
                re.IGNORECASE,
            ),
            "hardcoded-password",
            "Possible hardcoded password detected.",
        ),
    ]

    # Unsafe shell / eval patterns
    SHELL_PATTERNS: List[tuple] = [
        (
            re.compile(r"\bos\.system\s*\("),
            "unsafe-os-system",
            "Use of os.system() can be dangerous; prefer subprocess.run() with explicit args.",
        ),
        (
            re.compile(r"\beval\s*\("),
            "unsafe-eval",
            "Use of eval() can execute arbitrary code.",
        ),
        (
            re.compile(r"\bexec\s*\("),
            "unsafe-exec",
            "Use of exec() can execute arbitrary code.",
        ),
        (
            re.compile(r"\bsubprocess\.call\s*\([^)]*shell\s*=\s*True"),
            "subprocess-shell-true",
            "subprocess with shell=True is vulnerable to shell injection.",
        ),
    ]

    # Network exfiltration
    EXFIL_PATTERNS: List[tuple] = [
        (
            re.compile(r"requests\.post\s*\([^)]*\"https?://[^\"]*\.(sh|bin|exe|zip)"),
            "suspicious-post-target",
            "POST request to suspicious file extension domain.",
        ),
        (
            re.compile(r"urllib\.request\.urlopen\s*\("),
            "raw-urlopen",
            "Raw urlopen calls can be used for data exfiltration.",
        ),
    ]

    # Prompt injection patterns in SKILL.md
    PROMPT_INJECTION_PATTERNS: List[tuple] = [
        (
            re.compile(
                r"ignore\s+(?:previous|prior|all)\s+instructions",
                re.IGNORECASE,
            ),
            "prompt-injection-pattern",
            "Document contains potential prompt injection language.",
        ),
        (
            re.compile(
                r"system\s+prompt\s*:?\s*\b(unlock|reveal|show|disregard)\b",
                re.IGNORECASE,
            ),
            "prompt-injection-pattern",
            "Document contains potential prompt injection language.",
        ),
    ]

    @classmethod
    def check_file(cls, path: Path, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # Secrets
            for patt, rule_id, msg in cls.SECRET_PATTERNS:
                if patt.search(line):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            rule_id=rule_id,
                            file=str(path),
                            line=lineno,
                            message=msg,
                            remediation="Move secrets to environment variables or a secrets manager.",
                        )
                    )
            # Shell / eval
            for patt, rule_id, msg in cls.SHELL_PATTERNS:
                if patt.search(line):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            rule_id=rule_id,
                            file=str(path),
                            line=lineno,
                            message=msg,
                            remediation="Avoid dynamic execution; use safe APIs.",
                        )
                    )
            # Exfil
            for patt, rule_id, msg in cls.EXFIL_PATTERNS:
                if patt.search(line):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            rule_id=rule_id,
                            file=str(path),
                            line=lineno,
                            message=msg,
                            remediation="Restrict outbound requests to allow-listed domains.",
                        )
                    )

        if kind == "skillmd":
            for lineno, line in enumerate(lines, start=1):
                for patt, rule_id, msg in cls.PROMPT_INJECTION_PATTERNS:
                    if patt.search(line):
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                rule_id=rule_id,
                                file=str(path),
                                line=lineno,
                                message=msg,
                                remediation="Review SKILL.md content for adversarial instructions.",
                            )
                        )

        return findings


class SkillScanner:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.max_file_size = self.config.get("max_file_size_mb", 5) * 1024 * 1024
        self.exclude = self.config.get("exclude_patterns", [])

    def _should_scan(self, path: Path) -> bool:
        if path.stat().st_size > self.max_file_size:
            return False
        for pat in self.exclude:
            if path.match(pat):
                return False
        return True

    def scan(self, target: str | Path) -> Report:
        import time

        start = time.perf_counter()
        root = Path(target)
        report = Report()

        if not root.exists():
            raise FileNotFoundError(f"Target not found: {root}")

        # Files we care about
        scan_extensions = {".py", ".js", ".ts", ".sh", ".md", ".json", ".yaml", ".yml"}
        skill_md_found = False

        for item in root.rglob("*"):
            if item.is_file() and item.suffix in scan_extensions and self._should_scan(item):
                kind = "skillmd" if item.name.lower() == "skill.md" else "generic"
                if item.name.lower() == "skill.md":
                    skill_md_found = True
                report.findings.extend(RulesEngine.check_file(item, kind))
                report.scanned_files += 1

        # Check for insecure file permissions on scripts
        for item in root.rglob("*"):
            if item.is_file() and item.suffix in {".sh", ".py", ".js", ".bin"}:
                mode = item.stat().st_mode
                if mode & 0o002:
                    report.findings.append(
                        Finding(
                            severity=Severity.LOW,
                            rule_id="world-writable-script",
                            file=str(item),
                            line=0,
                            message="Script is world-writable.",
                            remediation="chmod o-w the file.",
                        )
                    )

        if not skill_md_found:
            report.findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule_id="missing-skill-md",
                    file=str(root),
                    line=0,
                    message="No SKILL.md found in target directory.",
                    remediation="Add a SKILL.md to describe the skill for users and marketplaces.",
                )
            )

        report.duration_ms = round((time.perf_counter() - start) * 1000, 2)
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="skill-vetter-plus security scanner")
    parser.add_argument("target", help="Path to skill directory to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Detailed output")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    args = parser.parse_args()

    scanner = SkillScanner()
    try:
        report = scanner.scan(args.target)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    # Console output
    summary = report.to_dict()["summary"]
    print(f"Scanned {summary['scanned_files']} files in {report.duration_ms}ms")
    print(f"Findings: {summary['total_findings']} total")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = summary["severity_counts"][sev.value]
        if count:
            print(f"  {sev.value.upper()}: {count}")

    if args.verbose:
        for finding in report.findings:
            print(f"\n[{finding.severity.value.upper()}] {finding.rule_id}")
            print(f"  File: {finding.file}:{finding.line}")
            print(f"  {finding.message}")
            if finding.remediation:
                print(f"  Remediation: {finding.remediation}")

    # Exit non-zero if critical or high findings exist
    if summary["severity_counts"]["critical"] or summary["severity_counts"]["high"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
