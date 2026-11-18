# Ravel — Product & Implementation Reference

> Single source of truth for what Ravel is and how we build it.
> Read this first, every time. No timelines here — only the product and the plan.
> **Status: pre-build. Nothing is implemented yet.** Do not scaffold or generate code unless a specific piece is explicitly requested.

---

## 1. What Ravel is

Ravel builds a **knowledge graph of a Python codebase**, then reads that one graph three different ways to answer questions single-file tools cannot:

1. **Which security findings actually matter?** — by tracing whether flagged code is reachable from an untrusted entry point.
2. **What does this codebase do?** — auto-generated documentation that regenerates from the code instead of rotting.
3. **What would this migration really cost?** — deprecated APIs and outdated dependency usage, classified by reachability.

**The graph is the asset. Everything else is an application of it.** All three questions are the same graph traversal read three ways.

---

## 2. The core thesis

Security scanners report ~200 findings on a mid-size repo. Maybe ~8 are real. The rest are already sanitized, unreachable, or dead. Teams check ~30, hit noise, and stop reading the report forever.

**Detection was never the problem.** Scanners read one file at a time and have no model of how the system connects. Ravel builds that model first, then filters findings by whether they are actually reachable from untrusted input.

### The measurable claim (this is what the whole product defends)

> Improve precision of scanner output **≥3×** while retaining **≥85%** of real vulnerabilities.

Everything in the repo exists to support or test this claim.

---

## 3. Architecture

```
INGESTION        git clone → tree-sitter parse → function/class nodes
                 ↓
CODE GRAPH       nodes + edges + entry points + external refs     ← the asset
                 ↓                              ↓
WIKI PIPELINE                          SECURITY PIPELINE
bottom-up summaries                    Semgrep · Bandit · gitleaks · OSV
                 ↓                              ↓
                 └──────────┬───────────────────┘
                            ↓
TRIAGE ENGINE    1. reachability (deterministic, no LLM)
                 2. context assembly from graph
                 3. LLM verdict (structured output)
                 4. rank: exploitability × blast radius
                            ↓
OUTPUT           ranked findings · traced paths · CLI / JSON / web
```

### Pipeline, stage by stage

| Stage | In | Out | Notes |
|---|---|---|---|
| 1. Parse | repo | function/class nodes with content hashes | tree-sitter. Chunk at function boundaries, never fixed-size text blocks. |
| 2. Graph | nodes | call / import / inherit edges, tagged entry points | Entry points classified untrusted vs internal. |
| 3. Scan | repo | ~200 normalized findings | Wrap existing scanners; map each finding to a node. |
| 4. Reachability | ~200 findings | ~60 with traced paths | **Deterministic. No LLM. This is the core contribution.** |
| 5. Triage | ~60 | ~20 with verdicts | LLM with graph context; structured JSON output only. |
| 6. Rank | verdicts | ranked report | reachability class × confidence × blast radius. |

### Where the LLM sits (and where it must not)

**The LLM never sees the raw findings.** It runs *last*, only on the findings that reachability has already kept (~20 of ~200), each wrapped in graph context (flagged code + its callers + module summary). Two layers sit on top of detection, in strict order:

1. **Reachability — deterministic, no LLM.** Cuts ~200 → ~20 by tracing whether untrusted input can reach the flagged code. Reproducible and cheap. This is the core contribution.
2. **LLM triage — on the survivors only.** A verdict (real / false-positive / needs-review) plus reasoning, as structured JSON, cached and budget-capped.

Handing raw scanner output straight to the LLM is the anti-pattern we reject: expensive, slow, and it rates noise as confidently as signal. And triage must **earn its slot** — if it doesn't beat reachability-alone on the eval harness, ship it disabled (§10). Both layers are Ravel's contribution.

---

## 4. Data model

```python
Node:
    id, kind (file|module|class|function)
    qualified_name, file_path, start_line, end_line
    source_hash          # content hash — drives all caching
    docstring, summary   # summary generated lazily
    embedding

Edge:
    src_id, dst_id
    kind (calls|imports|inherits|defines)
    resolved: bool       # False = target could not be statically determined

EntryPoint:
    node_id
    kind (http_route|api_handler|cron|cli|celery_task)
    trust (untrusted|internal)   # THE critical distinction

ExternalRef:
    node_id, package, version, symbol
    # needed for dependency/deprecation analysis — must exist from day one;
    # retrofitting means a full re-index

Finding:
    id, source (semgrep|bandit|gitleaks|osv)
    node_id, rule_id, raw_severity, cwe
    static_evidence:   { reachable: enum, path: [node_ids], blast_radius: int }
    runtime_evidence:  nullable          # Sentry integration — NOT v1
    graph_diff:        nullable          # reachability-change detection — NOT v1
    verdict, confidence, reasoning
    patch: nullable                      # NOT v1
```

The nullable fields are deliberate placeholders for post-v1 features so no migration is needed later. **Do not build them.**

---

## 5. Tech stack

| Layer | Choice | Note |
|---|---|---|
| Parsing | tree-sitter (`py-tree-sitter`) | |
| Name resolution | Jedi + `ast` | Slow; cache results. Expect timeouts on large repos. |
| Import graph | Python `ast` (`ravel/graph/imports.py`) | Resolves against our own discovered files, so loose top-level scripts (`manage.py`) and `src/` layouts work too; grimp was dropped — it only graphs packages and mutates `sys.path`. |
| Graph ops | NetworkX | In-memory is fine at our scale (~3k nodes / 18k edges per 50k LOC). |
| Storage | Postgres + pgvector | One DB for relational + vector. Do not add a separate vector store. |
| Scanners | Semgrep OSS, Bandit, gitleaks, OSV-Scanner | |
| LLM | Small model for leaf summaries, larger for triage | 10–20× cost difference. Must be swappable — support local (Ollama) and BYO-key. |
| API | FastAPI | |
| Frontend | Next.js + Tailwind + react-flow + dagre | dagre for layout — **not** d3-force (it jitters between renders). |
| Git | GitPython | For incremental re-index. |
| Eval | pytest + a results table | Reproducible from one command. |

---

## 6. Non-negotiables

Decisions already made. Do not relitigate in code or review unless explicitly asked.

| Rule | Why |
|---|---|
| **Python target only (v1)** | Multi-language doubles graph work for zero added insight. Architecture stays language-agnostic; v1 ships Python. |
| **Never write custom detection rules** | Semgrep/Bandit/gitleaks have a decade of refinement. Our contribution is the layer above. |
| **Unresolved edges are marked `unknown`, never dropped** | Treating an unresolvable call as "no call" silently demotes a real vulnerability. Worst failure mode available to us. |
| **Report graph coverage as a visible metric** | "84% of call sites resolved" must appear in output. Claims are only as good as the map. |
| **Recall is always reported next to precision** | Cutting 200 findings to 12 is trivial if you discard real ones. |
| **Cache keys are content hashes, never paths or line numbers** | Line numbers shift on any edit above them. |
| **Local-first, read-only** | Never request write access to a repo. Never phone home. LLM layer must be swappable (local model / user's own API key). |

### Working conventions

- **Type hints everywhere.** This is a static-analysis tool; untyped code here is embarrassing.
- **No `print()`** — structured logging only; output goes through the CLI formatter.
- **Every LLM call is cached and budget-capped** — a hard per-run token limit with a kill switch, not a soft warning.
- **Tests use real repo fixtures**, not synthetic Python strings. Bugs live in real-world code patterns.
- **Never commit API keys.** `.env` is gitignored; `.env.example` documents required vars.
- When a design decision isn't covered here, **ask rather than assume** — several choices look arbitrary but aren't.

---

## 7. Scope

### In scope for v1
- Python parsing, call graph, import graph, entry-point detection (Flask, FastAPI, Django)
- Repos up to ~50k LOC
- Scanner integration + normalization
- Reachability filtering
- LLM triage with graph context
- Function/module summaries (as triage context, not as a docs product)
- Deprecated API + outdated dependency reports, classified by reachability
- CLI + JSON output, single-page web view showing traced paths
- Evaluation harness against CVE-patched OSS repos

### Explicitly NOT in v1
If a task seems to require one of these, **stop and ask.**
- Patch / fix generation
- Q&A chat interface over the codebase
- Languages other than Python
- Hosting, auth, multi-tenancy, GitHub App, PR comments
- Custom detection rules
- Runtime data ingestion (Sentry)
- Cross-repo graphs

---

## 8. Incremental update logic

Full index is expensive and runs once. After that:

1. `git diff --name-only OLD..NEW` → changed files.
2. Re-parse only those files → new content hashes.
3. Unchanged hash → keep existing summary, embedding, verdict.
4. Changed hash → mark dirty, rebuild its edges.
5. Cascade upward **only if** the regenerated summary is materially different from the old one — otherwise every commit regenerates the whole doc tree and the cost saving is destroyed.
6. Invalidate any finding whose stored reachability path contains a dirty node.

**Known trap — renames:** a rename looks like delete + add. Detect renames by matching content hash across the diff, or you get dangling edges plus a phantom node the dead-code check will happily flag.

**Known trap — verdict cache keys:** triage verdicts depend on the flagged code *plus* its callers *plus* the module summary. Key the verdict cache on a hash of the assembled context, not just the node.

---

## 9. Success metrics

| Metric | Target | Failure threshold |
|---|---|---|
| Graph coverage (call sites resolved) | ≥80% | <60% invalidates all reachability claims |
| Finding→node mapping rate | ≥95% | <85% |
| Precision improvement vs raw scanner | ≥3× | <1.5× means no product |
| Recall retained | ≥85% of known CVEs | <70% is disqualifying |
| Cold index cost, 25k LOC | <$3 | >$10 |
| Cold index time, 25k LOC | <10 min | >30 min |

---

## 10. Build order (dependency sequence, not a schedule)

Rough order, each stage depends on the one before it:

```
parse → graph → entry points → scanners → eval harness
      → reachability → summaries → triage → ranking → web view → benchmark writeup
```

- The **eval harness is built early**, before triage — not at the end. It must be owned by someone *not* building the triage layer. Marking your own homework produces a number nobody believes.
- **Decision checkpoints** (not deadlines — reassess when reached):
  - *Graph correctness:* is the call graph correct on ~20 hand-checked cases? If not, stop everything and fix — all downstream work is a function of graph quality.
  - *Reachability value:* did reachability filtering improve precision? If not, the core hypothesis is wrong — write it up honestly and reconsider.
  - *Triage value:* does LLM triage add anything over reachability alone? If not, ship it disabled. A clean negative result beats a component kept because it was built.
- **If scope must be cut, cut in this order:** web view → summaries → LLM triage. **Reachability + a measured eval is still a complete project.**

---

## 11. Repository layout

Flat `ravel/` package (**not** `src/ravel/` — a flat layout installs reliably
with uv/hatchling; the `src` variant produced flaky editable installs here).
Subpackages that are scaffolded but not yet implemented are tagged with the phase
they arrive in.

```
ravel/                package root  (import ravel)
  __main__.py         `python -m ravel …`  (deterministic CLI entry)
  models.py           Node / Edge / EntryPoint / ExternalRef / Finding
  core/               hashing, structured logging, config
  ingest/             repo load + tree-sitter file discovery
  graph/              node/edge construction, resolution, entry points
  cli/                Typer CLI (`ravel index …`)
  scanners/           scanner wrappers + normalization              [Phase 2]
  triage/             reachability, context assembly, verdict, rank  [Phase 3–4]
  summarize/          bottom-up summaries, hash-based caching        [Phase 4]
  deps/               deprecated-API + outdated-dependency analysis  [Phase 5]
  store/              Postgres + pgvector models, migrations         [later]
tests/                pytest suite (real fixtures, not synthetic strings)
eval/
  fixtures/           sample apps used as parse/graph fixtures
  repos/              benchmark repo pins (commit SHAs)              [Phase 2]
  truth/              ground-truth vulnerability files               [Phase 2]
  run.py              reproducible from one command                  [Phase 2]
web/                  Next.js frontend                               [Phase 5]
docs/                 ROADMAP, BUILD-PLAN, BENCHMARK, DEMO
```

Root files: `pyproject.toml` (uv), `uv.lock`, `AGENTS.md`, `CLAUDE.md`,
`PRODUCT.md`, `README.md`, `.gitignore`.

---

## 12. Team split

Three contributors. Suggested ownership:

- **Graph & ingestion** — parsing, resolution, entry points, incremental updates.
- **Security pipeline** — scanner wrappers, normalization, reachability, ranking.
- **LLM & interface** — summarization, triage, CLI/web output, eval harness.

The eval harness is owned by someone who is *not* building triage.
