# skill-vetter-plus

A security scanner for AI agent skills. Checks skill manifests, bundled scripts, and prompt content for common vulnerabilities and anti-patterns before installation or publication.

## What It Does

- Scans `SKILL.md` files for prompt-injection patterns and overly broad permissions
- Detects hardcoded secrets, API keys, and tokens in bundled scripts
- Flags unsafe shell commands, eval-like patterns, and network exfiltration risks
- Checks file permissions and executable bits on bundled resources
- Generates a structured risk report with severity ratings

## What It Does NOT Do

- Does not guarantee a skill is safe (new attack vectors emerge constantly)
- Does not perform full static analysis equivalent to professional SAST tools
- Does not inspect dependencies of dependencies beyond one level
- Cannot validate runtime behavior, only static content

## Installation

### OpenClaw

Place the `skill-vetter-plus/` folder into your skills directory:

```bash
cp -r skill-vetter-plus ~/.openclaw/skills/
```

Restart OpenClaw or reload skills.

### ClawHub

```bash
openclaw skill install skill-vetter-plus
```

## Quick Start

```bash
# Scan a single skill directory
openclaw skill vetter-plus scan /path/to/skill-to-check

# Scan with full output
openclaw skill vetter-plus scan --verbose /path/to/skill-to-check

# Scan and output JSON for CI pipelines
openclaw skill vetter-plus scan --json /path/to/skill-to-check > report.json
```

## Requirements

- Python 3.10+
- No external API keys required for basic scanning
- Optional: `semgrep` for deeper static analysis (install separately)

## License

MIT — see [LICENSE](LICENSE)

## Attribution

See [ATTRIBUTION.md](ATTRIBUTION.md) for third-party tools and data sources.
