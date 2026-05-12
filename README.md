# Skill Vetter Plus

## What It Is

The fastest security scanner for AI agent skills on ClawHub, with **9 built-in detection signatures**.

**Use case:** Install before trying any new skill. Run one command. Know if it's safe.

## How It Works

1. Point vetter at any skill directory
2. Scans every file line-by-line against 9 signature types
3. Reports findings in under 50ms

## Signatures (9 Built-In)

| ID | Category | Severity | Description |
|---|---|---|---|
| `hardcoded-api-key` | secrets | high | Possible hardcoded API key |
| `hardcoded-secret` | secrets | high | Possible hardcoded secret or token |
| `hardcoded-password` | secrets | high | Possible hardcoded password |
| `unsafe-eval` | execution | critical | `eval()` can execute arbitrary code |
| `unsafe-exec` | execution | critical | `exec()` can execute arbitrary code |
| `unsafe-os-system` | execution | critical | `os.system()` can execute shell commands |
| `subprocess-shell-true` | execution | high | `subprocess` with `shell=True` is injectable |
| `raw-network` | network | medium | Raw network call found |
| `prompt-injection` | prompt | critical | Potential prompt injection language |

## Installation

```bash
clawhub install skill-vetter-plus
```

## Usage

```bash
# Scan a skill
python3 scripts/vetter.py /path/to/skill

# Scan with JSON output
python3 scripts/vetter.py /path/to/skill --json

# Use custom signatures
python3 scripts/vetter.py /path/to/skill --signatures /path/to/signatures.json
```

### Real-World Review Example

Use a public OpenClaw plugin when you want to see how findings map to an
actual skill before installing it. TweetClaw is a social automation plugin for
X/Twitter workflows, so it is a useful test case for sensitive configuration
review.

```bash
git clone https://github.com/Xquik-dev/tweetclaw /tmp/tweetclaw
python3 scripts/vetter.py /tmp/tweetclaw/skills/tweetclaw
```

Review each finding manually. A match on an environment variable name, setup
instruction, or safety warning is not the same as a hardcoded secret.

## What It Detects

- Hardcoded API keys, tokens, passwords
- `eval()`, `exec()`, `os.system()`, `subprocess(shell=True)`
- Raw network requests
- Prompt injection language

## What It Does NOT Detect

- Malicious logic hidden in control flow
- Exploits in compiled binaries
- Vulnerabilities in skill dependencies
- Social engineering in descriptions

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass — no issues found |
| 1 | Fail — one or more issues found |

## Pro Tier

| Feature | Pro |
|---|---|
| Real-time scanning | ✅ |
| Signature updates | Weekly |
| Team sharing | ✅ |
| Custom rules | ✅ |
| Reports | Basic |
| Priority support | Email |

**Upgrade:** https://certainlogic.ai/shop/skill-vetter-plus-pro

## Why Vetter Plus?

- **Fast** — Returns results in under 50ms
- **Comprehensive** — 9 detection signatures covering secrets, execution, and prompts
- **Clear** — Tells you exactly what was found and where
- **Extensible** — Add your own signatures via JSON

## Limitations

- Text-based pattern matching (no AST analysis)
- Cannot detect all malware — only patterns in the signature database
- Recommend: Use as first-line screening, not final security audit

## ⚠️ Why This Skill Triggers Security Flags (It's Normal)

**Skill Vetter Plus** is a *security scanner*. To detect dangerous patterns in other skills it must:
- Search for strings like `eval(`, `os.system`, `shell=True`, API keys, etc.
- Include network-related imports (for potential future expansions or reporting).
- Run Python code that looks for "unsafe" execution.

These are **intentional** for a scanner and do **not** exfiltrate data or run malicious code.
- Full open source: [GitHub](https://github.com/CertainLogicAI/skill-vetter-plus)
- No external calls in core scan
- Text-pattern only (no real execution unless you explicitly run it)

Always review the source before use — that's the point of a vetter!

## From the Builder

CertainLogic builds tools for reliability. I test every scanner signature against real skills before release. If something slips through, I fix it and push an update. No obfuscation. No hiding.

## Links

- GitHub: https://github.com/CertainLogicAI/skill-vetter-plus
- ClawHub: https://clawhub.ai/certainlogicai/skill-vetter-plus
- Docs: https://certainlogic.ai/docs/skill-vetter-plus

---

*Built by CertainLogic | [certainlogic.ai](https://certainlogic.ai)*
