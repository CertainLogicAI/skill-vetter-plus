# SKILL.md — skill-vetter-plus

## Name
skill-vetter-plus

## Description
Security scanner for AI agent skills. Performs static analysis on skill manifests, bundled scripts, and prompt content to surface common vulnerabilities and anti-patterns before installation or publication.

## Version
1.0.0

## Author
CertainLogic

## License
MIT

## Category
security, scanner, audit

## Tags
security, vulnerability, scanner, static-analysis, skill-audit, prompt-injection

## Requirements
- Python 3.10+
- Optional: semgrep (for extended rule coverage)

## Installation
Place the `skill-vetter-plus/` folder into your OpenClaw skills directory and restart.

## Usage

### CLI

```bash
# Basic scan
openclaw skill vetter-plus scan <path-to-skill>

# Verbose output with remediation hints
openclaw skill vetter-plus scan --verbose <path-to-skill>

# JSON output for CI integration
openclaw skill vetter-plus scan --json <path-to-skill>

# Scan multiple skills
openclaw skill vetter-plus scan --batch skill1/ skill2/ skill3/

# Use extended semgrep rules (if installed)
openclaw skill vetter-plus scan --deep <path-to-skill>
```

### As a Library

```python
from vetter import SkillScanner

scanner = SkillScanner()
report = scanner.scan("/path/to/skill")
for finding in report.findings:
    print(f"[{finding.severity}] {finding.rule}: {finding.message}")
```

## Configuration

Create `vetter-config.yaml` in the skill directory to customize rules:

```yaml
rules:
  secret_detection: true
  prompt_injection: true
  unsafe_shell: true
  network_exfiltration: true
  file_permissions: true

severity_threshold: medium   # ignore low-severity findings
max_file_size_mb: 5
exclude_patterns:
  - "*.min.js"
  - "node_modules/**"
```

## Output Format

Findings include:
- `severity`: critical / high / medium / low / info
- `rule_id`: identifier for the check that triggered
- `file`: relative path to the problematic file
- `line`: line number (if applicable)
- `message`: human-readable description
- `remediation`: suggested fix (when available)

## Limitations

- Static analysis only; cannot detect runtime behavior
- Rule coverage is best-effort, not exhaustive
- May produce false positives on benign patterns
- Extended deep scanning requires separate semgrep installation

## Changelog

### 1.0.0
- Initial release
- Core scanner engine with 25 built-in rules
- CLI with verbose and JSON output modes
- Batch scanning support
