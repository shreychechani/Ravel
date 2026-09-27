# 07 — Action Items Derived from the Research

A proposal list, not a commitment. BUILD-PLAN checkpoints still gate everything:
**nothing here is built downstream of an unpassed checkpoint.** Items that touch
the data model or scope are marked **ASK** (PRODUCT.md §6: ask rather than assume).

Effort: S ≈ hours · M ≈ a day or two · L ≈ a week+.

---

## Phase 1 — Graph slice (current phase)

| # | Action | Source | Effort | Where |
|---|---|---|---|---|
| 1.1 (✅ built — `eval/pycg_bench.py`) | **PyCG micro-benchmark scorer**: map Ravel `qualified_name` → PyCG `module.func`, score each `snippets/<cat>/<case>/callgraph.json`, report precision/recall per category | PyCG | S–M | `eval/pycg_bench.py` |
| 1.2 (✅ built — in `eval/pycg_bench.py`) | In 1.1, split misses into **"marked `unknown`"** vs **"silently missing"**. The second is a §6 violation to fix, the first is fine | Soundiness manifesto | S | same |
| 1.3 | Score against **JARVIS FastAPI** macro ground truth (check artifact license first) | JARVIS | M | `eval/` |
| 1.4 (✅ built on flaskr — `eval/dynamic_recall.py`) | **Dynamic-oracle recall**: run a fixture's tests under `sys.monitoring`, collect repo-internal `(caller, callee)` pairs, report "% of observed calls in static graph" next to call-site coverage | Sui et al.; DyPyBench | M | `eval/` + CLI metric |
| 1.5 | Pick 2–3 DyPyBench projects ≤50k LOC as recall-oracle repos | DyPyBench | M | `eval/repos/` |
| 1.6 | Cross-check Flask/Django/FastAPI entry-point coverage against **Pysa source models** (knowledge, not rules) | Pysa | S | `ravel/graph/entrypoints.py` tests |

**Why now:** 1.1–1.4 make the Phase 1 checkpoint ("correct on ~20 hand-checked cases, ≥80% coverage") externally checkable instead of self-graded.

## Phase 2 — Scanners + eval harness

| # | Action | Source | Effort | Where |
|---|---|---|---|---|
| 2.1 | Build `eval/truth/` from **PyVul**: filter to web apps ≤50k LOC with detectable entry points; pin vulnerable SHA + fix SHA; hand-verify each | PyVul | L | `eval/repos/`, `eval/truth/` |
| 2.2 | Add **Vul4Py** cases as the **recall anchor**: exploit proves reachability, so Ravel filtering one out is a hard failure | Vul4Py | M | `eval/truth/` |
| 2.3 | Harness prints **baselines**: keep-all, severity-only, random-N (seeded, averaged) | Kang et al. | S | `eval/run.py` |
| 2.4 | **Dedupe** findings across scanners before scoring | Kang et al. | S | `ravel/scanners/` normalisation |
| 2.5 | Report **recall-retained** (vs scanner-found) *and* **end-to-end recall** (vs all truth) | ICSE '26 Python SAST study | S | `eval/run.py` |
| 2.6 | **Split tuning vs report set by repo**; lint that no CVE/fix text reaches triage context | Kang et al. | S | `eval/` |
| 2.7 | Get the ICSE '26 Python SAST study artifact; use its real-world set as an extra scanner baseline | ICSE '26 study | M | `eval/` |

## Phase 3 — Reachability

| # | Action | Source | Effort | Where |
|---|---|---|---|---|
| 3.1 | **ASK:** extend `Reachability` enum → `reachable`, `reachable_via_unknown`, `internal_only`, `unreachable`, `unanalysable`; only `unreachable` is filtered | Mir et al. (lower bound); soundiness | S (+ decision) | `ravel/models.py` |
| 3.2 | Report **filter exposure**: # filtered findings with an `unknown` edge within k hops of their ancestry | Mir et al. | S | reachability output |
| 3.3 | Note in write-up: control-flow reachability ≠ data-flow reachability; IFDS (PyFlow) is the v2 path | PyFlow; CPG | — | docs |

## Phase 4 — Triage + ranking (only if Phase 3 passes)

| # | Action | Source | Effort | Where |
|---|---|---|---|---|
| 4.1 | **Per-hop triage** along `static_evidence.path`; hop verdicts cached by context hash and shared across findings | LLM4PFA | M–L | `ravel/triage/` |
| 4.2 | **Per-CWE question templates** (SQLi, XSS, path traversal, cmd injection, deserialization, SSRF) | ZeroFalse | M | `ravel/triage/prompts/` |
| 4.3 | **Consistency check** (N=3) on low-confidence verdicts; split → `needs-review`; counts against budget cap | LLM adjudication w/ error reduction | S | `ravel/triage/` |
| 4.4 | Test an **open-weight local model** (gpt-oss-20b via Ollama) + CC against a hosted model | same | M | eval |
| 4.5 | Checkpoint table: raw / reachability-only / single-prompt / per-hop / per-hop+CC / (sample) agentic baseline | Sifting the Noise | M | `eval/run.py` |
| 4.6 | Summaries: reverse-topological over **SCC-condensed** graph; deterministic **truthfulness guard** (named identifiers must resolve) | RepoAgent; DocAgent | M | `ravel/summarize/` |
| 4.7 | Measure whether module summaries improve triage (with/without ablation) | DocAgent ablation idea | S | eval |
| 4.8 | Rank tuple: `(reachability_class, KEV, EPSS bucket, verdict×confidence, blast_radius)`; KEV/EPSS from an **offline snapshot** (no phone-home) | EPSS, KEV, SSVC | M | `ravel/triage/rank.py` |

## Phase 5 — Interface + deps + incremental

| # | Action | Source | Effort | Where |
|---|---|---|---|---|
| 5.1 | SARIF export with the traced path in `codeFlows` (renders in GitHub / VS Code) | SARIF 2.1.0 | M | output |
| 5.2 | **VEX export** (CycloneDX / OpenVEX) with `code_not_reachable` justification backed by the graph | CycloneDX VEX, OpenVEX | M | output |
| 5.3 | Deps: function-level reachability only with advisory symbols; else **patch-derived** (labelled) ; else package-level | OSV schema; Ponta et al. | L | `ravel/deps/` |
| 5.4 | Deps: report **bloated deps** (declared, never imported/called) | Bloat beneath Python's Scales | S | `ravel/deps/` |
| 5.5 | Deps: disclose **blind spot** for native code vendored in wheels (reachability `unknown` past native boundary) | Cross-ecosystem; PyXray | S | deps report |
| 5.6 | Incremental: invalidate stored paths when a **new edge into** the path appears, not only when a path node changes; test on CrossCommitVuln-Bench | CrossCommitVuln-Bench | M | incremental logic |

## Post-v1 ideas (ASK before any of these; several are out of v1 scope per PRODUCT.md §7)

- LLM-inferred **sources/entry points** for unsupported frameworks (IRIS-style, sources only, never sinks).
- LLM **type hints** to resolve `unknown` edges, labelled and excluded from the coverage metric (EMSE LLM call-graph study).
- **IFDS data-flow reachability** (PyFlow) as a stronger reachability class.
- **Cross-language stitching** into C extensions (PyXray ideas, *no AGPL code*).
- **FP memory** from user feedback (Memoir), off during benchmark runs.
- Wiki as a product, evaluated on **CodeWikiBench** vs DeepWiki.

## License notes

| Artifact | License | OK to… |
|---|---|---|
| PyCG | Apache-2.0 (archived) | Use benchmark with attribution |
| PyXray | **AGPL-3.0** | Read paper only; **do not port or vendor code** |
| JARVIS artifact | not stated | Ask authors / check zip before redistributing ground truth |
| PyVul, Vul4Py | check on release | Confirm before committing truth files derived from them |
| Pysa models | ⚠ believed MIT | Confirm before copying any model file |
