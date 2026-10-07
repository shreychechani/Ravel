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

## Status (2026-10-07)

Legend: ✅ done · 🚧 partial / in progress · ⬜ not started.

| Phase | State | One-line |
|---|---|---|
| 0 — Foundation | ✅ (one deferral) | scaffold, tooling, domain model, hashing, swappable LLM provider (mock / Ollama / OpenAI-compatible), fixtures, **CI green** (`.github/workflows/ci.yml`: ruff, mypy, pytest, web build). **Deferred (decided 2026-10-07):** SQLAlchemy/Alembic/Postgres persistence — nothing yet needs it; scans run in memory with JSON output |
| 1 — Graph slice | ✅ | checkpoint passed on flaskr (42/42, 81.6% coverage); PyCG 98.3% / 71.2%; dynamic-oracle recall 89.7%. Added: scan a **git URL** (`--ref`), **`ExternalRef.version`** from the target env, tree-sitter pinned <0.26 after a segfault on PyGoat. Still wanted: an independent re-check of the flaskr ground truth |
| 2 — Scanners + eval | ✅ | Bandit, Semgrep (local rules), OSV-Scanner (offline DB) and **gitleaks** (default rules, `--redact`) all wrapped; **eval harness** `uv run python -m eval.run` (pinned repos + venvs, keep-all / severity / random-N / Ravel / Ravel+triage, precision next to recall) |
| 3 — Reachability | ✅ **checkpoint PASSED** | reachable / unknown / unreachable + path + blast radius; ranking. Pooled over vulpy-bad + flaskr: precision 11.7% → 100% (**×8.57**, gate ×3), recall retained **100%** (gate 85%), end-to-end recall 55.6%. Caveats: 2 repos; vulpy labels written after seeing output — **needs an independent re-check**; PyGoat scanned but not yet labelled |
| 4 — Triage + ranking | ✅ built · ❌ **triage checkpoint FAILED** | context assembly, CWE prompts, content-hash verdict cache, token budget + kill switch; **bottom-up summaries** (`ravel summarize`). With llama3.2 3B, triage dropped one real SQLi (read `'%s' %` as a parameterised query): recall retained 100% → 80%, no precision gain → **ships disabled** (`--no-triage` default). Retest with a stronger model |
| 5 — Interface + deps + incremental | 🚧 | **web view done** (`ravel serve`: ranked findings, traced paths, AI verdicts). Deps/migration report, Code Wiki pages, incremental re-index: not started |

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
- ✅ Dependency-aware resolution (`ravel/graph/environment.py`): Jedi resolves against the **scanned repo's** virtualenv (in-repo `.venv`/`venv`/`env`, or `--venv`), found **statically** — `site-packages` + `.pth` editable-install paths, never executing the repo's interpreter (so not Jedi's `environment_path`). sys.path = Ravel's stdlib + the target's deps only; Ravel's own `site-packages` no longer leaks in. The env used is shown in the CLI and JSON.

**Port from reference:**
- 🚧 `reference/Arcflow/js/analysis/parser-routes.js` → Python entry-point detection. **FastAPI/Flask `@app.get`/`@router.*`/`@app.route(..., methods=[...])` done** (`ravel/graph/entrypoints.py`, tree-sitter AST). **Django `urlpatterns` ✅** — route calls inside `urlpatterns` found structurally, views resolved by reference with Jedi; `X.as_view()` marks the class + its HTTP-verb methods; `include()` skipped; wrapper calls unwrapped; unresolvable views logged as warnings. `authProtected` regex **deliberately not ported** → all HTTP routes stay `untrusted`; auth ≠ trusted input (§6).
- ⬜ Entry-point / dead-code **exclusion lists** in `graph-builder.js` (`main`, `create_app`, `on_startup`, migration `upgrade`/`downgrade`, `test_*`, dunders) — not needed until CLI/script entry detection or dead-code lands.
- ✅ `getParserProvenance` idea → parser provenance surfaced (`PROVENANCE`, coverage metric).
- **Reference only (do not port as-is):** `parser-callgraph.js`, `graph-builder.js` call-linking — heuristic; we resolve properly instead.

**🚩 Checkpoint (§10) — ✅ PASSED (2026-09-27), narrowly:** call graph correct on **~20 hand-checked cases**, coverage **≥80%**.
- Fixture: `eval/fixtures/flaskr` — Flask's tutorial app, vendored unmodified at pallets/flask `d73fa1c` (BSD-3). Ground truth: `eval/ground_truth/flaskr_graph.toml` — 35 exhaustive in-repo `calls` edges + 4 wrong-target traps + 2 must-stay-`unknown` calls.
- Result (`uv run python -m eval.graph_checkpoint --venv <venv with flask + pytest>`): **42/42 cases, edge precision 100%, edge recall 100%, coverage 81.6%** (151/185). `tests/test_graph_checkpoint.py` locks the cases in CI; the coverage half needs the venv, so it's a manual run.
- Two resolver bugs the checkpoint caught, both fixed: (1) a call through a parameter or local alias (`cb()`, `f = helper; f()`) was drawn as an edge to the *enclosing* function — now Jedi `infer`s the bound value, else `unknown`; (2) reusing one `jedi.Script` per file made later pytest-fixture calls silently fail to resolve (order-dependent) — now a fresh Script per site (61.6% → 80.8%).
- Caveats: one small fixture; 0.8 pts above the gate; the remaining 34 misses are sqlite calls through Flask's dynamic `g.db` and untyped test-client chains. 12 edges were added to the ground truth *after* the first run (11 pytest-fixture calls; 1 decorator application, confirmed by PyCG's convention and the dynamic oracle — both flagged in the file) — **an independent re-check of the ground truth is still wanted** (§6: don't mark your own homework). A second, larger real repo should be added before Phase 3 leans on this.

**External graph checks (from `research/`, items 1.1 · 1.2 · 1.4):**
- ✅ **PyCG micro-benchmark** (`eval/pycg_bench.py`; 119 published ground-truth programs, vendored Apache-2.0 at `eval/benchmarks/pycg`): **precision 98.3%, recall 71.2%**, 73/119 exact. Every miss is classified `no_node` (7, lambdas) / `unknown` (47, flagged) / **`silent` (16, the §6 failure mode)**. `tests/test_pycg_bench.py` ratchets these floors. The benchmark drove three resolver fixes: bare `@decorator` application and `raise Cls` are now call sites, and `eval`/`exec` calls are `unknown` (silent 30 → 16, recall 65.8% → 71.2%). Remaining silent misses: implicit `__iter__`/`__next__` from `for` loops (8), decorator-replaced functions (3), lambda bodies (2), Jedi's non-C3 MRO on diamond inheritance (2), 1 kwargs default.
- ✅ **Dynamic-oracle recall** (`eval/dynamic_recall.py` + `eval/oracle/trace_calls.py`; Sui et al.): runs flaskr's own tests on a throwaway copy, records the repo-internal calls that actually happen, and scores the static graph against them. **39 observed, 35 recovered: 89.7%.** Misses: 3 × `wrapped_view → view` (flagged `unknown`), 1 test-only monkeypatch. Eval-only: the product never executes scanned code.
- ⬜ JARVIS FastAPI macro ground truth (1.3; licence unclear), DyPyBench recall repos (1.5), Pysa entry-point cross-check (1.6).

---

## Phase 2 — Scanners + eval harness (parallel, *different owner*) — ✅ done

**Goal:** real findings, normalized and mapped to nodes; a scoreboard we trust.

- Wrap Semgrep OSS · Bandit · gitleaks · OSV-Scanner → normalize each to the `Finding` schema; map each finding to a node (target ≥95%). We never write detection rules (§6).
  - ✅ Scanner contract (`ravel/scanners/base.py`): a scanner that is missing or fails is *reported* (`not_installed` / `failed`), never silently skipped — lost scanners are lost recall.
  - ✅ **Bandit** (`ravel/scanners/bandit.py`): runs on exactly the files the graph was built from; Bandit parses, never executes. Default rule set.
  - ✅ **Normalization** (`ravel/scanners/normalize.py`): each finding anchored on the innermost function/class holding its line, else the FILE node (module-level); mapping rate reported with the function-vs-file split (fixtures: 100%). Finding ids are content hashes of scanner + rule + node `source_hash` + flagged line text — they survive code moving and change when the code does (§6, tested).
  - ✅ **Cross-scanner dedupe** (research/07 2.4): same node + same CWE (else rule) + same line → one group; duplicates are grouped for scoring, never dropped from the report.
  - ✅ `ravel scan PATH [--venv] [--json]`: scanner status table (unintegrated scanners listed as such), mapping rate, graph coverage + Python env, findings.
  - ✅ **Semgrep** (`ravel/scanners/semgrep.py`) — *decided 2026-09-27: user-supplied local rules only.* Ravel ships no rules (the public `semgrep-rules` repo is under the Semgrep Rules License) and refuses registry configs (`p/…`, `auto`, URLs), which download on every run. Runs with metrics and the version check off, so a scan makes no network call. No `--semgrep-config` → reported `not_configured`, never silently skipped. Rule ids drop the rules' on-disk location so finding ids stay path-free.
  - ✅ **Non-Python findings** (Semgrep scans templates too): kept in the report with no node, counted as `non_python`, outside the Python mapping-rate gate — on flaskr, 5 CSRF hits in Jinja templates (a Django rule misfiring on Flask).
  - ✅ **OSV-Scanner** (`ravel/scanners/osv.py`) — *decided 2026-09-27: offline database only.* `ravel osv-db update` is the one explicit network step (downloads the PyPI DB, ~34 MB, into `$RAVEL_OSV_DB`); scans run `--offline --offline-vulnerabilities` and report the DB date. No DB → `not_configured`, never an implicit download. OSV's own alias groups (CVE/GHSA/PYSEC) are one finding each; primary id prefers the CVE. Severity bands and fixed-version suggestion ported from Arcflow `osv-scan.js` / CodeClean `dep-scan.js`, fixed to ignore GIT ranges (Arcflow offered commit hashes as versions).
  - ✅ **Dependency findings on the graph**: one finding per advisory, linked (`anchors`) to every node importing the package — never duplicated per importer. PyPI→import names read from the target env's `dist-info` (`PyYAML`→`yaml`; `ravel/deps/distributions.py`). A package the repo never imports but another installed package requires (Django → sqlparse) is linked **via** that package — never called unused. Only nothing-imports-and-nothing-requires is `unused_dependency`; with no env it's `dependency_unknown`. Neither will be treated as unreachable.
  - Django fixture now pins its April-2021 `pip freeze` (`eval/fixtures/django_app/requirements.txt`): OSV finds **46 advisories — 37 in Django 3.2 (incl. critical SQLi CVE-2021-35042, fixed 3.2.5) and 9 in sqlparse 0.4.1, linked via Django**.
  - ⬜ **gitleaks** (Go binary on PATH).
  - First real signal: Bandit reports **38 findings on flaskr, 35 of them `assert` in test files (B101)** — none reachable from a request. That's the noise Phase 3 must cut, without Ravel suppressing any rule.
- Eval harness — **built early, owned by whoever is NOT building triage** (§10, §12): `eval/run.py`, pinned CVE repos, ground-truth files, reproducible from one command. **Always reports precision *and* recall together** (§6).

**Port from reference:**
- `reference/Arcflow/js/analysis/osv-scan.js` + `reference/CodeClean/js/analysis/dep-scan.js` → OSV.dev `querybatch` plumbing, severity mapping, and `getUpgradeSuggestion` (fixed-version extraction). (OSV-Scanner CLI is primary; this is the fallback + report shape.)
- `reference/Arcflow/js/analysis/parser-security.js` Python taxonomy (pickle, `subprocess shell=True`, `yaml.load`, `verify=False`, weak hash, entropy) → a **normalization cross-reference** to line up Semgrep/Bandit rule IDs. **Not** a detector.

**Exit:** raw scanner precision/recall baseline printed per fixture — the number reachability must beat.

---

## Phase 3 — Reachability (the core contribution) — ✅ done, checkpoint passed

**Goal:** filter findings by whether untrusted input can reach them.
**Deterministic, no LLM.**

- For each finding's node, trace back through call/import edges to any **untrusted** `EntryPoint`. Record `reachable` enum, `path` (node_ids), `blast_radius`. `unknown` edges stay in the path honestly.
- Rank by reachability class.

**Port from reference:** graph traversal only; NetworkX gives SCC/paths natively. Keep the "suggest which edge to cut" idea from `reference/CodeClean/js/analysis/circular-deps.js` for the deps report.

**🚩 Checkpoint (§10) — the project's decision gate:** **≥3× precision** while retaining **≥85% recall**, per Phase 2's harness. Pass → we have a product. Fail → core hypothesis is wrong; write it up honestly and reconsider.

---

## Phase 4 — Triage + ranking (LLM, only if Phase 3 passes) — ✅ built; triage checkpoint failed → disabled by default

- Context assembly from the graph (flagged code + callers + module summary). Bottom-up summaries, hash-cached.
- Verdict: structured JSON only, cached, budget-capped. **Cache key = hash of the *assembled context*, not the node** (§8 trap).
- Rank: reachability class × confidence × blast radius.

**Port from reference:** none — this layer is absent from both (it's Ravel's novel contribution). The "AI-ready, priority-tiered prompt" idea in CodeClean's README is informative for context assembly only.

**🚩 Checkpoint:** does triage add anything over reachability alone? If not, **ship it disabled** (§10).

---

## Phase 5 — Interface + deps + incremental — 🚧 web view done

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
