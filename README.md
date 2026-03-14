<div align="center">

# Claude Bug Hunter

**AI-powered bug bounty hunting from your terminal.**

<sub>by <a href="https://github.com/shuvonsec">shuvonsec</a></sub>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Skill-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)
[![GitHub Stars](https://img.shields.io/github/stars/shuvonsec/claude-bug-bounty?style=flat-square&color=yellow)](https://github.com/shuvonsec/claude-bug-bounty/stargazers)

[Quick Start](#quick-start) &nbsp;&middot;&nbsp; [Architecture](#architecture) &nbsp;&middot;&nbsp; [Tools](#tool-reference) &nbsp;&middot;&nbsp; [Vuln Classes](#vulnerability-classes) &nbsp;&middot;&nbsp; [Install](#installation)

</div>

---

Point Claude Code at any bug bounty target. It maps the attack surface, runs your scanners, validates findings through a 4-gate checklist, and writes submission-ready reports -- all from a single conversation.

### Why this exists

Most bug bounty toolkits give you a bag of scripts. This one gives you a **co-pilot that reasons about what to test and why.** Claude reads your recon output, prioritizes by payout likelihood, and drives 25+ tools in the right order.

- **Not a wrapper** -- Claude understands the methodology, not just the commands
- **End-to-end** -- from subdomain enumeration to a formatted HackerOne report
- **Battle-tested** -- built from real submissions across HackerOne, Bugcrowd, Intigriti, and Immunefi

---

## The Trilogy

| Repo | Purpose |
|:-----|:--------|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | Full hunting pipeline -- recon, scanning, validation, reporting |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security -- 10 bug classes, Foundry PoCs, Immunefi case studies |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Ingest 500+ public writeups and generate Claude skill files |

`public-skills-builder` generates knowledge &rarr; `web3-bounty-ai-skills` holds it &rarr; `claude-bug-bounty` runs the hunt.

---

## Quick Start

**1. Clone and install**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh
```

**2. Install the Claude Code skill**

```bash
mkdir -p ~/.claude/skills/bug-bounty
cp SKILL.md ~/.claude/skills/bug-bounty/SKILL.md
```

**3. Hunt**

```bash
claude
# "Run recon on target.com and tell me what to hunt"
# "I found a potential IDOR on /api/invoices — validate it"
# "Write a HackerOne report for this SSRF finding"
```

<details>
<summary><strong>Or run the pipeline directly (no Claude Code)</strong></summary>

```bash
python3 hunt.py --target hackerone.com          # Full automated hunt
./recon_engine.sh target.com                     # Step 1: Recon
python3 learn.py --tech "nextjs,graphql,jwt"     # Step 2: Intel
python3 hunt.py --target target.com --scan-only  # Step 3: Scan
python3 validate.py                              # Step 4: Validate
python3 report_generator.py findings/            # Step 5: Report
```

</details>

---

## Advanced Multi-Agent Framework (`scanner.py`)

`scanner.py` is the production-grade successor to `hunt.py`.  It provides:

- **Multi-target parallel processing** with bounded concurrency
- **Groq & Cerebras LLM integration** for AI-assisted triage and cluster summaries
- **Phase checkpointing** and `--resume` support
- **Failure isolation** — one failing target never crashes the rest
- **Strict scope enforcement** with allowlists
- **Dry-run mode** for safe configuration validation
- **Structured JSON logging** and SQLite persistence

### Setup — LLM providers

```bash
# Copy the example env file
cp .env.example .env

# Edit .env and fill in your API keys
# Groq: https://console.groq.com
GROQ_API_KEY=gsk_...

# Cerebras: https://cloud.cerebras.ai
CEREBRAS_API_KEY=...

# Choose primary provider
LLM_PROVIDER=groq          # or: cerebras
LLM_FALLBACK_PROVIDER=cerebras   # optional fallback

# Install LangChain provider packages
pip install langchain-groq         # for Groq
pip install langchain-cerebras     # for Cerebras
```

### CLI examples

```bash
# Basic scan (dry-run — no network requests)
python3 scanner.py example.com --dry-run

# Full scan with authorization ID (required for active phases)
python3 scanner.py example.com --auth-id AUTH-2024-001

# Multiple targets from a file, deep profile
python3 scanner.py -l targets.txt --profile deep --auth-id AUTH-001

# Crawl-only (recon without nuclei scanning)
python3 scanner.py example.com --crawl-only --auth-id AUTH-001

# Use Cerebras as LLM provider
python3 scanner.py example.com --provider cerebras --auth-id AUTH-001

# Resume a previous run (skips completed phases)
python3 scanner.py example.com --resume --auth-id AUTH-001

# Fine-grained control
python3 scanner.py example.com \
  --profile deep \
  --threads 5 \
  --rate-limit 20 \
  --severity critical,high,medium \
  --scope-allowlist .example.com,.api.example.com \
  --auth-id AUTH-2024-001

# Nightly full-coverage scan
python3 scanner.py example.com --profile nightly --auth-id AUTH-001
```

### Scan profiles

| Profile | Threads | Rate (req/s) | Nuclei severities |
|---------|---------|--------------|-------------------|
| `quick` | 10 | 50 | critical, high |
| `deep` | 15 | 30 | critical, high, medium |
| `nightly` | 20 | 20 | critical, high, medium, low |

### Output structure

```
output/
└── run-20240101T120000-abc123/
    ├── global_summary.json       # Cross-target summary
    ├── run.log.json              # Structured JSON log (all events)
    ├── scans.db                  # SQLite persistence
    └── example.com/
        ├── report.md             # Markdown report with AI summary
        ├── findings_dedup.json   # Deduplicated findings
        ├── findings.json         # Raw nuclei output
        ├── checkpoint.json       # Resume checkpoint
        ├── subdomains.txt
        ├── alive_subdomains.txt
        ├── all_urls.txt
        ├── filtered_urls.txt
        ├── params.txt
        └── alive_params.txt
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `GROQ_API_KEY` | Groq API key |
| `CEREBRAS_API_KEY` | Cerebras API key |
| `LLM_PROVIDER` | Primary LLM provider (`groq` \| `cerebras`) |
| `LLM_MODEL` | Override model name |
| `LLM_FALLBACK_PROVIDER` | Fallback provider if primary fails |
| `AUTHORIZATION_ID` | Authorization ID for active scan phases |

> ⚠️ **Authorized use only.**  Never run active scan phases against systems you do not have explicit written permission to test.  Supply a valid `--auth-id` that references your scope agreement.

---

## Architecture

```
┌─────────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   Target    │───▶│  Recon   │───▶│  Learn   │───▶│   Hunt   │───▶│  Report  │
│  Selection  │    │  Engine  │    │  Intel   │    │ Scanner  │    │  Writer  │
└─────────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
 target_selector    recon_engine    learn.py        hunt.py         report_gen
 mindmap.py         subfinder       CVE hunter      IDOR/SSRF/XSS   validate.py
                    httpx/katana    H1 Hacktivity   OAuth/Race/LLM   4 gates
                    nuclei          Threat model    zero_day_fuzzer  CVSS 3.1
```

Each stage feeds the next. Claude orchestrates the entire flow, or you can run any stage independently.

---

## Tool Reference

### Core Pipeline

| Tool | Role |
|:-----|:-----|
| `hunt.py` | Master orchestrator -- chains recon, scan, and report stages |
| `recon_engine.sh` | Subdomain enum, DNS resolution, live host detection, URL crawling |
| `learn.py` | Pulls CVEs and disclosed reports for detected tech stacks |
| `mindmap.py` | Generates prioritized attack mindmap with test checklist |
| `validate.py` | 4-gate validation -- scope, impact, duplicate check, CVSS scoring |
| `report_generator.py` | Outputs formatted HackerOne/Bugcrowd/Intigriti reports |

### Vulnerability Scanners

| Tool | What it hunts |
|:-----|:-------------|
| `h1_idor_scanner.py` | Object-level and field-level IDOR via parameter swapping |
| `h1_mutation_idor.py` | GraphQL mutation IDOR -- cross-account object access |
| `h1_oauth_tester.py` | OAuth misconfigs -- PKCE, state bypass, redirect_uri abuse |
| `h1_race.py` | Race conditions -- parallel timing, TOCTOU, limit overrun |
| `zero_day_fuzzer.py` | Smart fuzzer for logic bugs, edge cases, and access control |
| `cve_hunter.py` | Tech stack fingerprinting matched against known CVEs |
| `vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |

### AI / LLM Security

| Tool | What it hunts |
|:-----|:-------------|
| `hai_probe.py` | AI chatbot IDOR, prompt injection, data exfiltration |
| `hai_payload_builder.py` | Prompt injection payloads -- direct, indirect, ASCII smuggling |
| `hai_browser_recon.js` | Browser-side recon of AI feature endpoints |

### Utilities

| Tool | Role |
|:-----|:-----|
| `sneaky_bits.py` | JS secret finder and endpoint extractor from bundles |
| `target_selector.py` | Scores and ranks bug bounty programs by ROI |
| `scripts/dork_runner.py` | Google dork automation for passive recon |
| `scripts/full_hunt.sh` | Shell wrapper for the complete pipeline |

---

## What's Inside SKILL.md

The skill file is the brain -- **1,200+ lines** of structured hunting methodology that Claude loads on demand.

| Section | Contents |
|:--------|:---------|
| A→B Bug Signal Method | Chain hunting -- when bug A confirms, systematically find B and C |
| Recon Protocol | 30-minute recon playbook, subdomain enum, tech fingerprinting |
| Bug Classes | 18+ vulnerability classes with detection patterns and bypass tables |
| Bypass Tables | SSRF IP bypass (11), open redirect bypass (11), file upload bypass (10) |
| Validation Gates | 7-Question Gate + 4-gate system, CVSS 3.1, always-rejected list |
| Report Templates | HackerOne, Bugcrowd, Intigriti, Immunefi submission formats |
| Grep Patterns | Language-specific dangerous patterns (JS, Python, PHP, Go, Ruby, Rust) |
| AI/LLM Hunting | ASI01-ASI10 framework for agentic AI security testing |
| Chain Table | 8 low findings that become valid bugs when chained correctly |
| Web3 Auditing | 10 Solidity bug classes, Foundry PoC templates, DeFi attack patterns |

---

## Vulnerability Classes

### Web Application

| Class | Techniques |
|:------|:-----------|
| IDOR | Object-level, field-level, GraphQL mutation, UUID enumeration |
| SSRF | Redirect chain, DNS rebinding, cloud metadata, protocol abuse |
| XSS | Reflected, stored, DOM, postMessage, CSP bypass, mXSS |
| SQL Injection | Error-based, blind, time-based, ORM bypass, second-order |
| OAuth | Missing PKCE, state bypass, redirect_uri abuse, implicit downgrade |
| Race Conditions | Parallel requests, TOCTOU, limit overrun, coupon reuse |
| Cache Poisoning | Unkeyed headers, parameter cloaking, fat GET |
| Business Logic | Price manipulation, workflow skip, negative quantity, role escalation |
| File Upload | Extension bypass, MIME confusion, polyglots, path traversal |
| XXE | Classic entity injection, blind OOB via DNS/HTTP |
| HTTP Smuggling | CL.TE, TE.CL, TE.TE, H2.CL request tunneling |

### AI / LLM

| Class | Techniques |
|:------|:-----------|
| Prompt Injection | Direct override, indirect via document/URL, jailbreak chains |
| Chatbot IDOR | Cross-account history access, conversation ID enumeration |
| System Prompt Leak | Extraction via roleplay, encoding bypass, token boundary probing |
| LLM RCE | Code execution via tool use, sandbox escape |
| ASCII Smuggling | Invisible unicode as covert exfil channels |

### Web3 / DeFi

| Class | Techniques |
|:------|:-----------|
| Reentrancy | Single-function, cross-function, cross-contract, read-only |
| Flash Loan | Price oracle manipulation, collateral inflation |
| Access Control | Missing modifiers, misconfigured roles, function visibility |
| Integer Issues | Overflow, underflow, precision loss, division-before-multiply |
| Signature Replay | Missing nonce, chain ID omission, front-running |

---

## Directory Structure

```
claude-bug-bounty/
├── scanner.py                  # ★ New: Advanced multi-agent framework CLI
├── SKILL.md                    # Claude Code skill (1,200+ lines of methodology)
├── hunt.py                     # Legacy master orchestrator (still works)
├── recon_engine.sh             # Subdomain + URL discovery
├── learn.py                    # CVE + disclosure intel
├── mindmap.py                  # Attack surface mapper
├── validate.py                 # 4-gate finding validator
├── report_generator.py         # Report writer
├── h1_idor_scanner.py          # IDOR scanner
├── h1_mutation_idor.py         # GraphQL IDOR scanner
├── h1_oauth_tester.py          # OAuth tester
├── h1_race.py                  # Race condition tester
├── zero_day_fuzzer.py          # Smart fuzzer
├── cve_hunter.py               # CVE matcher
├── vuln_scanner.sh             # Nuclei/Dalfox/SQLMap wrapper
├── hai_probe.py                # AI chatbot tester
├── hai_payload_builder.py      # Prompt injection generator
├── hai_browser_recon.js        # Browser-side AI recon
├── sneaky_bits.py              # JS secret finder
├── target_selector.py          # Program ROI scorer
│
├── llm/                        # ★ New: LLM provider integration
│   ├── config.py               # Provider config (Groq / Cerebras)
│   ├── factory.py              # Model factory with fallback
│   └── prompts.py              # Triage / remediation prompt helpers
│
├── models/                     # ★ New: Type-safe pipeline models
│   ├── state.py                # TypedDict state (run, target, finding)
│   └── policy.py               # Scope enforcement + safety guardrails
│
├── agents/                     # ★ New: Pipeline agents
│   ├── orchestrator.py         # Multi-target parallel orchestrator
│   ├── recon.py                # Recon agent (subfinder → httpx → katana)
│   ├── scanner.py              # Scanner agent (nuclei + dedup)
│   └── reporter.py             # Markdown + JSON report generator
│
├── utils/                      # ★ New: Shared utilities
│   ├── scope.py                # Scope matching helper
│   ├── url_filter.py           # URL dedup / static-asset filtering
│   ├── db.py                   # SQLite persistence layer
│   └── logging_utils.py        # Structured JSON logging
│
├── tests/                      # ★ New: Unit tests
│   ├── test_scope.py           # Scope matching tests
│   ├── test_url_filter.py      # URL filtering tests
│   └── test_llm_factory.py     # Provider selection / fallback tests
│
├── .env.example                # ★ New: Environment variable template
├── docs/
│   ├── payloads.md             # Complete payload arsenal
│   ├── advanced-techniques.md  # A→B chaining, mobile, CI/CD, framework playbooks
│   └── smart-contract-audit.md # Web3 audit guide
├── web3/                       # Smart contract skill chain (10 files)
├── scripts/
│   ├── dork_runner.py          # Google dork automation
│   └── full_hunt.sh            # Full pipeline wrapper
├── wordlists/                  # 5 wordlists (common, params, API, dirs, sensitive)
├── recon/                      # Recon output (per target)
├── findings/                   # Validated findings
└── reports/                    # Submission-ready reports
```


---

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq
```

### Install

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh
cp config.example.json config.json  # Add your API keys
```

This installs 18+ tools: `subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`, `waybackurls`, `gau`, `dalfox`, `ffuf`, `anew`, `qsreplace`, `assetfinder`, `gf`, `interactsh-client`, `sqlmap`, `XSStrike`, `SecretFinder`, `LinkFinder`, and nuclei-templates.

---

## Contributing

PRs welcome. Good contributions:

- New vulnerability scanners or detection modules
- Payload additions to `docs/payloads.md`
- Claude prompt templates for specific bug classes
- Platform support (YesWeHack, Synack, HackenProof)
- Real-world methodology improvements

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

---

## Contact

| | |
|:--|:--|
| GitHub | [shuvonsec](https://github.com/shuvonsec) |
| Email | [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com) |
| Twitter | [@shuvonsec](https://x.com/shuvonsec) |
| LinkedIn | [shuvonsec](https://linkedin.com/in/shuvonsec) |

---

## Legal

**For authorized security testing only.** Only test targets within an approved bug bounty scope. Never test systems without explicit permission. Follow responsible disclosure practices. Read each program's rules of engagement before hunting.

---

<div align="center">

MIT License

**Built by bug hunters, for bug hunters.**

If this helped you find a bug, consider leaving a star.

</div>
