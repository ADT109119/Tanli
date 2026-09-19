<p align="center">
  <img src="assets/logo.png" alt="Tanli logo" width="160" />
</p>

<h1 align="center">探驪 Tanli</h1>

<p align="center">
  <em>"The pearl worth a thousand taels of gold lies beneath the chin of the dragon, in the deepest of nine abysses." — Zhuangzi</em>
</p>

<p align="center">
  <strong>English</strong> | <a href="docs/README.zh-TW.md">繁體中文</a>
</p>

<p align="center">
  <a href="#license">License: Apache-2.0</a> ·
  <a href="SECURITY.md">Security &amp; Responsible Use</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <img src="assets/banner.jpg" alt="Tanli banner — dive into the target, back with the findings" width="92%" />
</p>

**An autonomous red-team agent** that assesses both LLM applications and classic web services. Dive into the abyss of the target; come back with the pearl of the finding.

Tanli is an autonomous red-team testing agent: you give it an authorized target, and it plans multi-step attack paths on its own, invokes tools, runs probes, judges results, and produces a structured security report with reproduction steps.

> **Authorized testing only.** Scanning or attacking any system without authorization is illegal in most jurisdictions. By using this tool you agree to test only targets for which you hold explicit written authorization. See [SECURITY.md](SECURITY.md).

## Why "Tanli" (探驪)

The name comes from the idiom 探驪得珠 ("diving for the dragon's pearl"; also written 探珠驪頷), from the Zhuangzi, chapter Lie Yukou: the pearl is said to hide beneath the chin of the 驪龍, a dark dragon that dwells in the deepest abyss — to win it, one must dive to the bottom of the abyss, wait for the dragon to fall asleep, and seize it only then. It originally meant winning a treasure of immense value, and later also described writing that grasps the very essence of a subject.

Red teaming is that same dive: the truly critical vulnerabilities hide in the depths of the system, with defenses coiled beside them like the sleeping dragon — you plan stealthily, take your moment, and retrieve the pearl.

- **The abyss** = the target system (a black box of unknown depth)
- **The sleeping dragon** = the defenses you must not wake (low-noise, stealthy tradecraft)
- **The strike** = multi-step autonomous planning: probe → hypothesize → exploit → judge → review
- **The pearl** = the real vulnerability (with a CVSS score and a PoC)

## Dual attack surface

| Track | Targets | Framework covered |
|:--|:--|:--|
| **LLM applications** | LLM APIs, RAG systems, AI agents | OWASP GenAI LLM Top 10 (jailbreaks, prompt injection, system-prompt leakage, excessive agency, output handling…) |
| **Web services** | Web apps, REST/GraphQL APIs | OWASP Top 10 2021 (injection, authn, access control, misconfiguration, SSRF…) |

## Core capabilities

- **Multi-step autonomous execution**: DAG planner + ReAct execution loop; the attack surface is routed automatically by target type
- **Scanner automation**: nuclei / sqlmap / OWASP ZAP run fully autonomously inside Docker sandboxes; results are converted into findings automatically
- **LLM attack playbooks**: five OWASP GenAI playbooks — baseline control + sentinel markers + deterministic rules + an LLM-judge second pass for false-positive filtering
- **Automatic CVSS v3.1 scoring**: the official formula embedded (zero deviation from the authoritative library across all 2,592 vectors), with severity/category → vector mapping
- **Human review gate**: every High/Critical finding is flagged "awaiting human confirmation"; the CLI warns explicitly until the report is finalized, so drafts never get published as official reports
- **Signed authorization model**: localhost-only by default; widening scope requires an Ed25519 JWS-signed credential plus mandatory Scope Statement validation — crossing the line aborts the run
- **Offline lab self-test**: built-in `TargetLab` (a pure-stdlib dual-behavior vulnerable/hardened lab including an LLM chat endpoint); one `self-test` command validates the whole engine end-to-end — no Docker, no external network
- **Reporting**: Markdown reports with CVSS vectors, PoC reproduction steps, exfiltrated data / achieved impact, and remediation advice deduplicated by OWASP category

## Installation

Requires Python >= 3.11.

```bash
git clone https://github.com/ADT109119/Tanli.git && cd Tanli
pip install -e .

# smoke test (no dependencies)
tanli --help
```

Full-auto scanner mode requires Docker (pulls the official nuclei/sqlmap/zap images); the LLM judge requires any OpenAI-compatible endpoint (optional — falls back to deterministic rules without it).

## Quick start

```bash
# 1. Offline self-test: spins up the local lab, 7 assertions end-to-end (recommended first step)
tanli self-test

# 2. Preview the plan against a local target (no actual attacks)
tanli run http://127.0.0.1:8080 -t web_service --dry-run

# 3. Fully automated web scan (scanners + judge + CVSS + report)
tanli run http://127.0.0.1:8080 -t web_service --scanners all

# 4. LLM app red-team (target is an OpenAI-compatible chat/completions endpoint)
tanli run http://127.0.0.1:8080 -t llm_app --scanners llm_playbook

# 5. Single scanner / single playbook
tanli scan http://127.0.0.1:8080 --scanner nuclei
tanli run http://127.0.0.1:8080 -t llm_app --playbook playbooks/llm/playbook_1.yaml

# 6. CVE lookup: exact CVE id, or product-level (ALL published CVEs of a package/framework)
tanli cve CVE-2025-55182
tanli cve django -e pip            # GHSA + OSV merged, no version filter
tanli cve nginx                    # non-package ecosystems fall back to NVD keyword search

# 7. Autonomous agent mode: LLM tool-loop plans every step itself
#    (fingerprint -> product-level CVE lookup -> dynamic attempt; never trusts
#     self-reported versions). All tools run inside ScopeGuard/read-only/budget fences.
tanli agent http://127.0.0.1:8080 --steps 30 --probes 60
tanli agent TARGET --auth-cred credential.jws --public-key signer_public.pem --read-only
```

`--scanners`: `auto` (default: web → all, llm_app → playbooks) | `none` | `web_config` | `nuclei` | `sqlmap` | `zap` | `llm_playbook`.
ZAP depth: `--zap-mode baseline|full|api`; nuclei narrowing: `--nuclei-severity`, `--nuclei-exclude-protocols`.

## Authorization model

The default scope is limited to `localhost` / `127.0.0.1` / `example.com`. Operating against any internal or external target requires a signed credential:

```bash
# Issue an authorization credential with an Ed25519 private key
tanli gen-cred --scope scope.yaml --key signer_private.pem --out credential.jws

# Run with the credential
tanli run TARGET --auth-cred credential.jws --public-key signer_public.pem
```

ScopeGuard checks every request against the credential scope; any violation aborts the run with an audit trail. This is a hard gate, not a warning.

## LLM judge setup

Judging uses any OpenAI-compatible endpoint, provider-agnostic:

```bash
export REDTEAM_JUDGE_BASE_URL="https://your-endpoint/v1"   # vLLM / ollama / cloud — anything
export REDTEAM_JUDGE_MODEL="your-model"
export REDTEAM_JUDGE_API_KEY="***"          # optional for local endpoints
```

- Deterministic parameters (`temperature=0`, fixed seed) for reproducibility
- Graceful degradation without an endpoint: LLM judging is skipped, deterministic rules only — the scan flow is unaffected

## LLM attack playbooks

| Playbook | OWASP GenAI | Attack surface |
|:--|:--|:--|
| llm-001 | LLM01 | Direct jailbreak / guardrail bypass (DAN roleplay, prefill, obfuscation) |
| llm-002 | LLM08 | Indirect prompt injection (hidden context / RAG override) |
| llm-003 | LLM02 | System-prompt leakage (instruction self-disclosure / translation / roleplay) |
| llm-004 | LLM10 | Insecure output handling (Markdown/HTML XSS, hybrid) |
| llm-005 | LLM03 | Excessive agency introspection (tool/plan self-disclosure) |

Safety by design: all payloads are benignized (`payload_policy: benign`), token-budget circuit breaker, and any playbook with side effects requires an authorization credential.

Playbooks double as the autonomous agent's **attack-theory knowledge base**: `tanli agent` exposes a `get_playbook` tool (catalog / keyword / OWASP filters) so the LLM plans against standard procedures instead of improvising — no vector store needed, the YAMLs are the knowledge base, fully auditable. Web methodology playbooks (e.g. web-006 SQLi flow) are queryable reference; execution still goes through the scanner pipeline under ScopeGuard/read-only fences.

## Reports

Every run outputs `report_<target>_<timestamp>.md`:

1. Executive summary with severity statistics (including the count of unreviewed high-risk findings)
2. OWASP category rollup (including the OWASP GenAI LLM surface)
3. Per finding: CVSS v3.1 vector and score, PoC reproduction steps, evidence, human-review status
4. Remediation advice: category → OWASP class → generic three-tier mapping, automatically deduplicated

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q          # 131 tests, fully offline
tanli self-test           # lab end-to-end, 7 assertions
```

- Specification: `SPECIFICATION-FINAL.md` (v3.4, planned collaboratively by the agy + opencode dual-agent pipeline)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Security policy: [SECURITY.md](SECURITY.md)

## Project status

M1–M6 complete: CLI / authorization model / planner / scanner bridge / findings conversion / LLM judge / five attack playbooks / CVSS scoring layer / report gate & remediation advice / dual-behavior lab self-test. All 131 tests green.

## License

[Apache-2.0](LICENSE)
