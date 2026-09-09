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

## Phase 0 — Foundation (rails before features)

**Goal:** a repo you can build in, with the data model + fixtures locked so
nothing needs re-indexing later.

- Scaffold the §11 layout (`src/{ingest,graph,scanners,triage,summarize,deps,store,cli}`, `web/`, `eval/`, `docs/`).
- Tooling: `uv` (or poetry), `ruff` + `mypy` (type hints everywhere), `pytest`. Structured logging, no `print()`.
- Data model as code: SQLAlchemy + Alembic for `Node / Edge / EntryPoint / ExternalRef / Finding` on Postgres + pgvector. **Add the post-v1 nullable columns now** (`runtime_evidence`, `graph_diff`, `patch`) so we never migrate — but build no logic for them (§4).
- Content-hash utility — the cache-key primitive for the whole system.
- LLM abstraction (interface only): swappable provider (Ollama / BYO key), hard token budget + kill switch. Default to latest Claude (small model for summaries, Opus-class for triage). Wire later.
- Fixtures: pin by SHA a few small Flask/FastAPI/Django apps + the CVE-patched OSS repos for eval.

**Port / reference:** none yet.
**Exit:** `ravel index <fixture>` runs, emits valid (empty) graph rows; CI green.

---

## Phase 1 — Graph slice (the make-or-break)

**Goal:** parse → resolve → graph → entry points, on **one** fixture, done right.
This is where Ravel beats Arcflow.

- Ingest: GitPython clone → tree-sitter parse Python → function/class `Node`s with `source_hash`, docstring.
- Resolution (the quality bar): Jedi + `ast` for scope-accurate call resolution; `grimp` for the import graph. Replaces Arcflow's name+import heuristic — the biggest accuracy gap in their engine.
- Edges in NetworkX: `calls / imports / inherits / defines`. **Unresolved edges → `resolved=False`, marked `unknown`, never dropped** (§6).
- ExternalRef from imports (package/version/symbol) — must exist from day one.
- Coverage metric: emit "% of call sites resolved" (§6).

**Port from reference:**
- `reference/Arcflow/js/analysis/parser-routes.js` → Python entry-point detection (Flask/FastAPI/Django `@app.route`, `@router.*`, `urlpatterns`). Its `authProtected` middleware regex → `trust` hint.
- Entry-point / dead-code **exclusion lists** in `reference/Arcflow/js/analysis/graph-builder.js` (`main`, `create_app`, `on_startup`, migration `upgrade`/`downgrade`, `test_*`, dunders) → so we don't mislabel real entry points.
- `getParserProvenance` in `reference/Arcflow/js/analysis/parser-core.js` → the "coverage as a visible metric" idea (tree-sitter vs fallback per file).
- **Reference only (do not port as-is):** `parser-callgraph.js`, `graph-builder.js` call-linking — heuristic; we resolve properly instead.

**🚩 Checkpoint (§10):** call graph correct on **~20 hand-checked cases**, coverage **≥80%**. If not — stop everything and fix. All downstream value depends on graph quality.

---

## Phase 2 — Scanners + eval harness (parallel, *different owner*)

**Goal:** real findings, normalized and mapped to nodes; a scoreboard we trust.

- Wrap Semgrep OSS · Bandit · gitleaks · OSV-Scanner → normalize each to the `Finding` schema; map each finding to a node (target ≥95%). We never write detection rules (§6).
- Eval harness — **built early, owned by whoever is NOT building triage** (§10, §12): `eval/run.py`, pinned CVE repos, ground-truth files, reproducible from one command. **Always reports precision *and* recall together** (§6).

**Port from reference:**
- `reference/Arcflow/js/analysis/osv-scan.js` + `reference/CodeClean/js/analysis/dep-scan.js` → OSV.dev `querybatch` plumbing, severity mapping, and `getUpgradeSuggestion` (fixed-version extraction). (OSV-Scanner CLI is primary; this is the fallback + report shape.)
- `reference/Arcflow/js/analysis/parser-security.js` Python taxonomy (pickle, `subprocess shell=True`, `yaml.load`, `verify=False`, weak hash, entropy) → a **normalization cross-reference** to line up Semgrep/Bandit rule IDs. **Not** a detector.

**Exit:** raw scanner precision/recall baseline printed per fixture — the number reachability must beat.

---

## Phase 3 — Reachability (the core contribution)

**Goal:** filter findings by whether untrusted input can reach them.
**Deterministic, no LLM.**

- For each finding's node, trace back through call/import edges to any **untrusted** `EntryPoint`. Record `reachable` enum, `path` (node_ids), `blast_radius`. `unknown` edges stay in the path honestly.
- Rank by reachability class.

**Port from reference:** graph traversal only; NetworkX gives SCC/paths natively. Keep the "suggest which edge to cut" idea from `reference/CodeClean/js/analysis/circular-deps.js` for the deps report.

**🚩 Checkpoint (§10) — the project's decision gate:** **≥3× precision** while retaining **≥85% recall**, per Phase 2's harness. Pass → we have a product. Fail → core hypothesis is wrong; write it up honestly and reconsider.

---

## Phase 4 — Triage + ranking (LLM, only if Phase 3 passes)

- Context assembly from the graph (flagged code + callers + module summary). Bottom-up summaries, hash-cached.
- Verdict: structured JSON only, cached, budget-capped. **Cache key = hash of the *assembled context*, not the node** (§8 trap).
- Rank: reachability class × confidence × blast radius.

**Port from reference:** none — this layer is absent from both (it's Ravel's novel contribution). The "AI-ready, priority-tiered prompt" idea in CodeClean's README is informative for context assembly only.

**🚩 Checkpoint:** does triage add anything over reachability alone? If not, **ship it disabled** (§10).

---

## Phase 5 — Interface + deps + incremental

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
