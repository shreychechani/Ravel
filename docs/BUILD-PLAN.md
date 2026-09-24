# Ravel — Build Plan

> How we go from pre-build to a defensible v1. Expands PRODUCT.md §10 into
> actionable, checkpoint-gated phases, and names exactly what to **port** from
> the vendored reference codebases.
>
> **Read first:** [`PRODUCT.md`](../PRODUCT.md) (source of truth),
> [`docs/reference/veloce-reuse-map.md`](reference/veloce-reuse-map.md) (what to
> port / reference / drop), [`AGENTS.md`](../AGENTS.md) (rules for contributors).

The spine: **build one graph correctly → prove reachability filtering works →
then decide whether triage/UI earn their place.** Every phase is a vertical
slice with a hard exit checkpoint. Never build downstream of an unproven layer.

Reference code lives at `reference/Arcflow/` and `reference/CodeClean/`
(read-only, gitignored). It is **JS/browser/regex** — we **port logic to
Python**, we do not import or run it. See the reuse map before porting anything.

---

## Status (2026-09-16)

Legend: ✅ done · 🚧 partial / in progress · ⬜ not started.

| Phase | State | One-line |
|---|---|---|
| 0 — Foundation | 🚧 | scaffold + tooling + domain model + hashing done; ORM/Postgres persistence, LLM abstraction, CVE fixtures + CI not yet |
| 1 — Graph slice | 🚧 | parse → Jedi call resolution → `calls` + `defines` + `inherits` + `imports` edges + coverage + FastAPI/Flask entry points done; Django routes, dependency-aware Jedi env, and the correctness checkpoint remain |
| 2 — Scanners + eval | ⬜ | not started |
| 3 — Reachability | ⬜ | not started (the core contribution) |
| 4 — Triage + ranking | ⬜ | not started |
| 5 — Interface + deps + incremental | ⬜ | not started |

Per-phase markers below carry the detail.

---

## Phase 0 — Foundation (rails before features)

**Goal:** a repo you can build in, with the data model + fixtures locked so
nothing needs re-indexing later.

- ✅ Scaffold the §11 layout (flat `ravel/{ingest,graph,scanners,triage,summarize,deps,store,cli}`, `web/`, `eval/`, `docs/`).
- ✅ Tooling: `uv`, `ruff` + `mypy` (type hints everywhere), `pytest`. Structured logging, no `print()`.
- 🚧 Data model as code. **Done:** the domain model exists as Pydantic (`ravel/models.py`) — `Node / Edge / EntryPoint / ExternalRef / Finding` incl. the post-v1 nullable fields (`runtime_evidence`, `graph_diff`, `patch`), no logic on them (§4). **Not yet:** SQLAlchemy + Alembic + Postgres/pgvector persistence — `ravel/store/` is still a stub.
- ✅ Content-hash utility (`ravel/core/hashing.py`) — the cache-key primitive.
- ⬜ LLM abstraction (interface only): swappable provider (Ollama / BYO key), token budget + kill switch. `triage/` `summarize/` are stubs.
- 🚧 Fixtures: FastAPI + Flask sample apps in `eval/fixtures/`. Django polls app (`eval/fixtures/django_app`) ✅. **Not yet:** SHA-pinned CVE-patched OSS repos for eval.

**Port / reference:** none yet.
**Exit (🚧):** `ravel index <fixture>` runs and emits valid graph rows ✅; CI green ⬜ (no `.github/workflows` yet).

---

## Phase 1 — Graph slice (the make-or-break)

**Goal:** parse → resolve → graph → entry points, on **one** fixture, done right.
This is where Ravel beats Arcflow.

- 🚧 Ingest: tree-sitter parse Python → function/class `Node`s with `source_hash`, docstring ✅. GitPython clone of remote repos ⬜ (local paths only so far).
- 🚧 Resolution (the quality bar): Jedi + `ast` for scope-accurate call resolution ✅ (`ravel/graph/resolve.py`). Import graph ✅ via Python `ast` (`ravel/graph/imports.py`) — **not grimp**: grimp only graphs packages (misses `manage.py` / root scripts) and mutates `sys.path`.
- 🚧 Edges in NetworkX (`MultiDiGraph`, keyed by kind): `calls` ✅ with **unresolved → `resolved=False`, marked `unknown`, never dropped** ✅ (§6). `defines` ✅ (file → def, class → method, def → nested def). `inherits` ✅ (Jedi-resolved; unresolvable base → `unknown`, third-party base → ExternalRef). `imports` ✅ (file → file; missing in-repo module → `unknown`, third-party → ExternalRef).
- 🚧 ExternalRef from imports ✅ (package + symbol from call resolution); `version` field ⬜ (not populated yet).
- ✅ Coverage metric: "% of call sites resolved" emitted in the CLI (§6).

**Port from reference:**
- 🚧 `reference/Arcflow/js/analysis/parser-routes.js` → Python entry-point detection. **FastAPI/Flask `@app.get`/`@router.*`/`@app.route(..., methods=[...])` done** (`ravel/graph/entrypoints.py`, tree-sitter AST). **Django `urlpatterns` ⬜** (needs cross-module view resolution). `authProtected` regex **deliberately not ported** → all HTTP routes stay `untrusted`; auth ≠ trusted input (§6).
- ⬜ Entry-point / dead-code **exclusion lists** in `graph-builder.js` (`main`, `create_app`, `on_startup`, migration `upgrade`/`downgrade`, `test_*`, dunders) — not needed until CLI/script entry detection or dead-code lands.
- ✅ `getParserProvenance` idea → parser provenance surfaced (`PROVENANCE`, coverage metric).
- **Reference only (do not port as-is):** `parser-callgraph.js`, `graph-builder.js` call-linking — heuristic; we resolve properly instead.

**🚩 Checkpoint (§10) — ⬜ NOT YET RUN:** call graph correct on **~20 hand-checked cases**, coverage **≥80%**. If not — stop everything and fix. All downstream value depends on graph quality. (Current: exact on the FastAPI/Flask fixtures, but no real benchmark repo hand-checked yet. Coverage is 76.9% on sample_app and 25% on django_app — **every** miss is a third-party symbol Jedi can't see because the fixture's deps aren't installed in Ravel's env. The gate is meaningless until Jedi resolves against the *scanned* repo's environment.)

---

## Phase 2 — Scanners + eval harness (parallel, *different owner*) — ⬜ not started

**Goal:** real findings, normalized and mapped to nodes; a scoreboard we trust.

- Wrap Semgrep OSS · Bandit · gitleaks · OSV-Scanner → normalize each to the `Finding` schema; map each finding to a node (target ≥95%). We never write detection rules (§6).
- Eval harness — **built early, owned by whoever is NOT building triage** (§10, §12): `eval/run.py`, pinned CVE repos, ground-truth files, reproducible from one command. **Always reports precision *and* recall together** (§6).

**Port from reference:**
- `reference/Arcflow/js/analysis/osv-scan.js` + `reference/CodeClean/js/analysis/dep-scan.js` → OSV.dev `querybatch` plumbing, severity mapping, and `getUpgradeSuggestion` (fixed-version extraction). (OSV-Scanner CLI is primary; this is the fallback + report shape.)
- `reference/Arcflow/js/analysis/parser-security.js` Python taxonomy (pickle, `subprocess shell=True`, `yaml.load`, `verify=False`, weak hash, entropy) → a **normalization cross-reference** to line up Semgrep/Bandit rule IDs. **Not** a detector.

**Exit:** raw scanner precision/recall baseline printed per fixture — the number reachability must beat.

---

## Phase 3 — Reachability (the core contribution) — ⬜ not started

**Goal:** filter findings by whether untrusted input can reach them.
**Deterministic, no LLM.**

- For each finding's node, trace back through call/import edges to any **untrusted** `EntryPoint`. Record `reachable` enum, `path` (node_ids), `blast_radius`. `unknown` edges stay in the path honestly.
- Rank by reachability class.

**Port from reference:** graph traversal only; NetworkX gives SCC/paths natively. Keep the "suggest which edge to cut" idea from `reference/CodeClean/js/analysis/circular-deps.js` for the deps report.

**🚩 Checkpoint (§10) — the project's decision gate:** **≥3× precision** while retaining **≥85% recall**, per Phase 2's harness. Pass → we have a product. Fail → core hypothesis is wrong; write it up honestly and reconsider.

---

## Phase 4 — Triage + ranking (LLM, only if Phase 3 passes) — ⬜ not started

- Context assembly from the graph (flagged code + callers + module summary). Bottom-up summaries, hash-cached.
- Verdict: structured JSON only, cached, budget-capped. **Cache key = hash of the *assembled context*, not the node** (§8 trap).
- Rank: reachability class × confidence × blast radius.

**Port from reference:** none — this layer is absent from both (it's Ravel's novel contribution). The "AI-ready, priority-tiered prompt" idea in CodeClean's README is informative for context assembly only.

**🚩 Checkpoint:** does triage add anything over reachability alone? If not, **ship it disabled** (§10).

---

## Phase 5 — Interface + deps + incremental — ⬜ not started

- Output: CLI + JSON, then single-page web view (Next.js + react-flow + **dagre**, not d3-force) showing traced paths.
- Deps report: deprecated-API + outdated-dependency, classified by reachability (reuses Phase 2 OSV work).
- Incremental (§8): git-diff → content-hash caching → **rename detection by content hash** → invalidate findings whose stored path contains a dirty node.

**Reference (view taxonomy only, we don't port the JS):** `reference/Arcflow/js/renderers/*` and `js/components/*` show the graph-view vocabulary; ours is react-flow + dagre.

**Cut order if time is short (§10):** web view → summaries → LLM triage.
**Reachability + a measured eval is already a complete project.**

---

## Reference index (which file feeds which phase)

| Reference file | Phase | Use |
|---|---|---|
| `Arcflow/js/analysis/parser-routes.js` | 1 | Port: entry-point detection + trust hint |
| `Arcflow/js/analysis/graph-builder.js` | 1 | Reference: exclusion lists; not the call-linking |
| `Arcflow/js/analysis/parser-core.js` | 1 | Idea: parser provenance = coverage metric |
| `Arcflow/js/analysis/parser-callgraph.js` | 1 | Reference only: heuristic resolution (we replace) |
| `Arcflow/js/analysis/osv-scan.js` | 2 | Port: OSV plumbing + severity |
| `CodeClean/js/analysis/dep-scan.js` | 2 | Port: OSV + upgrade suggestions |
| `Arcflow/js/analysis/parser-security.js` | 2 | Reference: Python taxonomy for normalization |
| `CodeClean/js/analysis/circular-deps.js` | 3/5 | Reference: SCC + break-edge suggestion |
| `CodeClean/js/analysis/dead-code.js` | 5 | Reference: dead-code heuristics + exclusions |
| `Arcflow/js/renderers/*`, `js/components/*` | 5 | Reference: view taxonomy only |
