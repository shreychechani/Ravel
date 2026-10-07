# Ravel

**Reachability-aware security triage for Python codebases.**

Ravel builds a knowledge graph of a Python codebase, then uses it to answer a question scanners can't: *which findings actually matter?* It does this by tracing whether flagged code is reachable from an untrusted entry point — turning a wall of ~200 scanner alerts into a short, ranked list of the ones that are real.

> **Status (2026-10-07):** Phases 0–4 built and the web view works. The Phase 3
> checkpoint passes (precision ×8.57, recall retained 100% on two labelled repos);
> LLM triage ships disabled because it does not yet beat reachability alone.
> Details: [`docs/BUILD-PLAN.md`](./docs/BUILD-PLAN.md).

---

## Quick start

```bash
uv sync                                         # Python 3.12, via uv
uv run ravel scan eval/fixtures/vuln_shop       # scanners → reachability → ranked list
uv run ravel scan https://github.com/owner/repo --ref <commit>   # any git URL

npm --prefix web install && npm --prefix web run build
uv run ravel serve eval/fixtures/vuln_shop      # web view on http://127.0.0.1:8765

uv run python -m eval.run                       # precision + recall vs. baselines
```

Give `--venv <the repo's virtualenv>` so third-party calls resolve (coverage is
printed on every run). Optional tools are reported, never silently skipped:
`gitleaks`, `osv-scanner` (+ `ravel osv-db update`), `semgrep` (with your own
`--semgrep-config`). LLM features (`--triage`, `ravel summarize`) default to an
offline mock; use `--llm-provider ollama --model llama3.2:3b` for a local model
or `--llm-provider openai` with your own key. See [`docs/DEMO.md`](./docs/DEMO.md).

---

## The problem

Security scanners report ~200 findings on a mid-size repo. Maybe ~8 are real — the rest are already sanitized, unreachable, or dead code. Teams check the first thirty, hit noise, and stop reading the report forever.

Detection was never the problem. Scanners read one file at a time and have no model of how the system connects. **Ravel builds that model first**, then filters findings by whether untrusted input can actually reach them.

**The claim we defend:** improve precision of scanner output **≥3×** while retaining **≥85%** of real vulnerabilities.

---

## What it does

One code graph, read three ways:

- **Which security findings matter?** — trace reachability from untrusted entry points.
- **What does this codebase do?** — auto-generated summaries that regenerate from the code.
- **What would a migration cost?** — deprecated APIs and outdated dependencies, classified by reachability.

The graph is the asset; everything else is an application of it.

---

## How it works

```mermaid
flowchart TD
    A[git clone] --> B[tree-sitter parse]
    B --> C[Code graph<br/>nodes · edges · entry points]
    C --> D[Security scanners<br/>Semgrep · Bandit · gitleaks · OSV]
    D --> E[~200 normalized findings]
    E --> F{Reachable from<br/>untrusted input?<br/>deterministic · no LLM}
    C -. graph context .-> F
    F -->|yes| G[~20 findings that matter]
    F -->|no| X[set aside<br/>unreachable / dead / sanitized]
    G --> H[Context assembly from graph]
    H --> I[LLM verdict<br/>structured JSON]
    I --> J[Rank<br/>exploitability × blast radius]
    J --> K[Ranked findings · traced paths<br/>CLI / JSON / web]

    style F fill:#6366f1,color:#ffffff
    style G fill:#22c55e,color:#ffffff
```

The **reachability filter is deterministic and LLM-free** — it's the core of the product. The LLM only adds a verdict on top of an already-filtered set, with graph context, and its output is structured JSON.

---

## Tech stack

| Layer | Choice |
|---|---|
| Parsing | tree-sitter (`py-tree-sitter`) |
| Name resolution | Jedi + `ast` |
| Import graph | Python `ast` |
| Graph ops | NetworkX |
| Storage | Postgres + pgvector (planned; scans are in-memory + JSON today) |
| Scanners | Semgrep OSS · Bandit · gitleaks · OSV-Scanner |
| LLM | Small model for summaries, larger for triage — swappable (local / BYO-key) |
| API | FastAPI |
| Frontend | Next.js + Tailwind + react-flow + dagre |

---

## Principles

- **Python only** for v1. Architecture stays language-agnostic.
- **Never write custom detection rules** — we wrap mature scanners and add the layer above.
- **Unresolved call edges are marked `unknown`, never dropped** — dropping them silently hides real vulnerabilities.
- **Coverage and recall are always reported next to precision** — the claims are only as good as the map.
- **Local-first, read-only.** Never requests write access. Never phones home.

---

## Scope (v1)

**In:** Python parsing · call + import graph · entry-point detection (Flask, FastAPI, Django) · scanner integration · reachability filtering · LLM triage · function/module summaries · deprecated-API + outdated-dependency reports · CLI + JSON + single-page web view · evaluation harness against CVE-patched repos.

**Not in v1:** patch generation · Q&A chat · non-Python languages · hosting/auth/multi-tenancy · custom detection rules · runtime data ingestion · cross-repo graphs.

---

## Repository layout

```
ravel/
  ingest/       file discovery, git URL cloning
  graph/        tree-sitter parse, Jedi resolution, imports, entry points, env discovery
  scanners/     Bandit · Semgrep · OSV-Scanner · gitleaks wrappers + normalization
  triage/       reachability, ranking, context assembly, LLM providers, verdict cache
  summarize/    bottom-up summaries, content-hash cache
  deps/         installed distributions, import names, versions
  api/          ravel serve (FastAPI, localhost only)
  report.py     the scan report the CLI --json and the web view share
  cli/          ravel index · scan · serve · summarize · osv-db
web/            Next.js + react-flow + dagre web view (static export)
eval/           fixtures, ground truth, eval.run harness, graph checks
docs/
```

---

## Documentation

- **[`docs/ROADMAP.md`](./docs/ROADMAP.md)** — plain-English, step-by-step tour of what we're building (start here).
- **[`PRODUCT.md`](./PRODUCT.md)** — the source of truth: data model, success metrics, non-negotiables, incremental-update logic, build order.
- **[`docs/BUILD-PLAN.md`](./docs/BUILD-PLAN.md)** — the phased, checkpoint-gated technical plan.
- **[`docs/reference/veloce-reuse-map.md`](./docs/reference/veloce-reuse-map.md)** — what we port / reference / drop from the Arcflow & CodeClean reference codebases.
- **[`AGENTS.md`](./AGENTS.md)** — tool-agnostic rules for AI coding agents contributing to Ravel.
