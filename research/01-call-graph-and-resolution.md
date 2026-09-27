# 01 — Call Graph & Name Resolution (Phase 1)

Everything downstream is a function of graph quality (PRODUCT.md §10). This
file collects the work on building and *measuring* Python call graphs.

Current Ravel state (BUILD-PLAN, Phase 1): Jedi + `ast` resolution in
`ravel/graph/resolve.py`, `unknown` edges kept, call-site coverage emitted,
dependency-aware Jedi env in `ravel/graph/environment.py`, hand-checked
checkpoint harness in `eval/graph_checkpoint.py` (flaskr fixture).

---

## PyCG: Practical Call Graph Generation in Python

- **Citation:** Vitalis Salis, Thodoris Sotiropoulos, Panos Louridas, Diomidis Spinellis, Dimitris Mitropoulos. ICSE 2021.
- **Link:** https://arxiv.org/abs/2103.00587
- **Artifact:** https://github.com/vitsalis/PyCG (**Apache-2.0**, **archived**: no further development)
- **Verified:** ✅
- **Key result:** Practical, flow-insensitive, assignment-graph-based call graphs for Python. It was the state of the art until JARVIS. It ships a **micro-benchmark of small programs with ground-truth call graphs**.
- **Benchmark layout (checked in repo):**
  - `micro-benchmark/snippets/<category>/<case>/{main.py, callgraph.json, README.md}`
  - 18 categories: `args, assignments, builtins, classes, decorators, dicts, direct_calls, dynamic, exceptions, external, functions, generators, imports, kwargs, lambdas, lists, mro, returns`
  - Ground-truth format (`args/call/callgraph.json`):
    ```json
    { "main.func": ["main.param_func"], "main.param_func": [], "main": ["main.func"] }
    ```
    Keys are module-qualified callers (module = file stem). Values are the complete callee list, so it scores both precision and recall.
  - A second folder, `micro-benchmark-key-errs/`, also exists.
- **Ravel takeaway:**
  - Write an adapter that maps Ravel's `qualified_name` to PyCG's `module.func` naming and scores each case: exact-match, precision, recall, split by category.
  - This gives a **published external number** for the Phase 1 checkpoint alongside the hand-checked flaskr cases. Per-category failures (`dynamic`, `lambdas`, `dicts`) show exactly where Jedi falls short.
  - Categories Jedi can't resolve should appear as `unknown` edges, not missing ones. The adapter should count "missing but marked unknown" separately from "silently missing" (PRODUCT.md §6).
- **Lands in:** Phase 1 → new `eval/pycg_bench.py` (or an extra mode in `eval/graph_checkpoint.py`).
- **Caveats:** The benchmark programs are tiny and synthetic. They measure resolver *capability*, not real-repo coverage. Run the flaskr/real-repo checks as well.

---

## JARVIS: Scalable and Precise Application-Centered Call Graph Construction for Python

- **Citation:** Kaifeng Huang, Yixuan Yan, Bihuan Chen, Zixin Tao, Xin Peng. arXiv 2305.05949 (v1 May 2023, last revised Sep 2024). Project site says submitted to **TOSEM**.
- **Link:** https://arxiv.org/abs/2305.05949
- **Artifact:** https://pythonjarvis.github.io/ → repo https://github.com/pythonJaRvis/pythonJaRvis.github.io (Jarvis.zip; `dataset/` + `ground_truth/`). License not stated on the site.
- **Verified:** ✅
- **Key result:** Compared with PyCG: **≥67% faster, 84% higher precision, ≥20% higher recall**. Evaluated on a **135-program micro-benchmark** (extends PyCG's) and a **6-app macro-benchmark: FastAPI, HTTPie, Scrapy, Lightning, Airflow, Sherlock**.
- **How:** Keeps a **type graph per function** (type relations of identifiers), does **flow-sensitive intra-procedural** plus inter-procedural analysis, and builds the call graph on the fly. It has an "application-centered" mode that analyses only what the application reaches in its dependencies, which is how Ravel scopes dependencies too.
- **Ravel takeaway:**
  - The **macro-benchmark ground truth for FastAPI** is a real-framework call graph we could score against. That's more realistic than the micro-benchmark.
  - If Jedi coverage stalls on real repos, study JARVIS's per-function type graph design before adding more heuristics.
  - Its application-centered idea matches Ravel's ExternalRef approach: don't graph all of site-packages, only what is reached.
- **Lands in:** Phase 1 (benchmark), possibly a resolver fallback later.
- **Caveats:** Artifact targets Python 3.8. Check the artifact's license before using its ground truth in a published benchmark.

---

## On the Recall of Static Call Graph Construction in Practice

- **Citation:** Li Sui, Jens Dietrich, Amjed Tahir, George Fourtounis. ICSE 2020.
- **Link:** https://dl.acm.org/doi/10.1145/3377811.3380441
- **Verified:** ✅
- **Key result:** On 31 real Java programs, measured against a **dynamic oracle** (calls recorded while running built-in and synthesised tests): median static call-graph recall **0.884**. With dynamic-feature support it's **0.935**, at a large performance cost. **Adding precision barely moves recall**: they are separate concerns. The main sources of unsoundness were natives and VM-initiated calls, not reflection.
- **Ravel takeaway:**
  - Ravel's "% call sites resolved" only counts call sites Ravel *saw*. It says nothing about edges that never appear. Add a **dynamic-oracle recall** metric: run a fixture's test suite under `sys.setprofile` / `sys.monitoring` (3.12+), collect `(caller, callee)` pairs inside repo code, and report "static graph recovered X% of observed calls".
  - The "precision ≠ recall" finding supports keeping `unknown` edges instead of dropping them to look precise.
  - Python equivalents of "VM-initiated calls": framework dispatch (Flask/Django calling views), `__dunder__` methods, decorators, signal handlers, ORM metaclass magic (the 4 remaining Django misses). These are the categories to track.
- **Lands in:** Phase 1 coverage metric (PRODUCT.md §9 "graph coverage"). Could run in `eval/`.
- **Caveats:** Java study; the method transfers, the numbers don't.

---

## DyPyBench: A Benchmark of Executable Python Software

- **Citation:** Islem Bouzenia, Bajaj Piyush Krishan, Michael Pradel. Proc. ACM Softw. Eng. 1 (FSE), Article 16, July 2024.
- **Link:** https://arxiv.org/abs/2403.00539
- **Verified:** ✅
- **Key result:** **50 open-source Python projects, 681k LOC, 30k test cases**, fully configured to execute. Ships **dynamic call graphs** from execution and integrates with the DynaPyt dynamic-analysis framework.
- **Ravel takeaway:** A ready-made **dynamic oracle** for the Sui-style recall metric, with no need to set up 50 test environments ourselves. Pick the projects ≤50k LOC (Ravel's v1 scope) and compare Ravel's static graph with DyPyBench's dynamic graph.
- **Lands in:** Phase 1 checkpoint and ongoing regression metric.
- **Caveats:** Dynamic graphs under-approximate (only exercised paths), so use them for *recall*, never for precision.

---

## An Empirical Study of LLMs for Type and Call Graph Analysis in Python and JavaScript

- **Citation:** Ashwin Prasad Shivarpatna Venkatesh, Rose Sunil, Samkutty Sabu, Amir M. Mir, Sofia Reis, Eric Bodden. Accepted in **EMSE** journal.
- **Link:** https://arxiv.org/abs/2410.00603
- **Verified:** ✅
- **Key result:** Across 24 LLMs, **traditional tools (PyCG, Jelly) consistently beat LLMs at call-graph construction**, with LLMs weak on completeness and soundness. LLMs **beat** traditional tools (HeaderGen, HiTyper) at **type inference**. Benchmarks: SWARM-CG, SWARM-JS, extended TypeEvalPy (77,268 annotations).
- **Ravel takeaway:**
  - Evidence to cite for PRODUCT.md §3's rule that reachability must be deterministic with no LLM. LLMs are measurably worse at the exact task reachability depends on.
  - A possible **post-v1** idea: LLM-*inferred types* as hints to resolve an `unknown` edge. Any such edge would need to be labelled (e.g. `resolved_by="llm_type_hint"`) and never counted as statically resolved in the coverage metric. Not v1. Ask before building (PRODUCT.md §6/§7).
  - The **SWARM-CG** benchmark is another call-graph ground truth to evaluate against.
- **Lands in:** Rationale for the Phase 3 design; post-v1 idea.

---

## PyFlow: An Inter-procedural Static Analysis Framework for Python

- **Citation:** arXiv 2608.07026 (2026).
- **Link:** https://arxiv.org/abs/2608.07026
- **Verified:** ✅ (abstract page)
- **Key result:** A generic **IFDS**-based interprocedural solver for Python with a multi-stage IR. The solver, supergraph, fixed point and summary caching are handled for you, and you plug in the dataflow domain. Its taint analysis had the **highest recall and F1** against DevSkim, Dlint, Bandit, Bearer, CodeQL, Pysa, Semgrep and Snyk on the ICSE '26 Python SAST datasets (see [02](02-eval-benchmarks-and-ground-truth.md)).
- **Ravel takeaway:**
  - Ravel's reachability is *call-graph* reachability (can control reach the flagged node from an untrusted entry?). IFDS is *data-flow* reachability (can tainted data reach it?). The data-flow version is the natural v2 upgrade for precision: control-reachable but data-unreachable findings are a big share of the remaining false positives.
  - Also a competitor to benchmark against in the write-up.
- **Lands in:** Post-v1 (Phase 3 v2). Note it now so the `static_evidence.reachable` enum can later grow a "data-flow confirmed" level without a migration.
- **Caveats:** Preprint. Framework support (Flask/Django/FastAPI) isn't stated in the abstract.

---

## Background: dynamic features and soundness (⚠ from memory)

- **"In Defense of Soundiness: A Manifesto"**: Livshits, Sridharan, Smaragdakis, Lhoták, Amaral, Chang, Guyer, Khedker, Møller, Vardoulakis. CACM 58(2), Feb 2015. ✅ link: https://cacm.acm.org/opinion/in-defense-of-soundiness/ · PDF https://www.doc.ic.ac.uk/~livshits/papers/pdf/cacm15.pdf
  - Every practical analysis is "soundy": it over-approximates most features and deliberately under-approximates a known subset. The manifesto asks tools to **state which features they skip**. That is Ravel's `unknown`-edge policy plus the coverage metric, so cite it in the write-up.
- **Åkerblom, Stendahl, Tumlin, Wrigstad, "Tracing Dynamic Features in Python Programs"**, MSR 2014. ⚠ link not re-verified.
  - Empirical frequency of `eval`, `getattr`, monkey-patching and similar features in real Python. Useful to justify which dynamic categories Ravel leaves as `unknown`.

---

## Summary: what Phase 1 should take

| Idea | Source | Effort |
|---|---|---|
| Score resolver on PyCG micro-benchmark, per category | PyCG | S |
| Score on JARVIS FastAPI macro ground truth | JARVIS | M |
| Dynamic-oracle recall metric (`sys.setprofile`/`sys.monitoring`) | Sui et al., DyPyBench | M |
| Count "missing but `unknown`" separately from "silently missing" | Soundiness, PRODUCT §6 | S |
| Leave room in `reachable` enum for data-flow confirmation | PyFlow | S (schema only) |
