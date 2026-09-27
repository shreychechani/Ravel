# 03 — Reachability, Dependency Reachability & Taint Models (Phases 3 & 5)

Reachability is Ravel's core contribution (PRODUCT.md §3). This file collects:
(A) evidence that reachability filtering works at all, (B) dependency and
cross-language reachability for the deps report, (C) taint / entry-point
knowledge we can reuse *without* writing detection rules.

---

## Part A — Evidence that reachability filtering cuts noise

### On the Effect of Transitivity and Granularity on Vulnerability Propagation in the Maven Ecosystem

- **Citation:** Amir M. Mir, Mehdi Keshani, Sebastian Proksch. SANER 2023, pp. 201–211.
- **Link:** https://arxiv.org/abs/2301.07972 · IEEE: https://ieeexplore.ieee.org/document/10123571/
- **Artifact:** Replication package https://zenodo.org/records/7540493
- **Verified:** ✅
- **Key result:** 3M Maven packages, whole-program call graphs plus reachability. About a **third of packages are vulnerable via transitive dependencies**, but only about **1% have a reachable call to the vulnerable method**. Callable-level analysis gives a *lower bound* on propagation, while package-level analysis over-approximates.
- **Ravel takeaway:**
  - The strongest academic evidence for the thesis: dependency-level alerts are about 30× over-reported. Cite it in the write-up.
  - "Callable-level = lower bound" is also a **warning**: function-level reachability *under*-approximates when the call graph misses edges. That's why Ravel's `unknown` edges must keep a finding in a "possibly reachable" class rather than dropping it.
- **Lands in:** Phase 3 rationale; Phase 5 deps report.
- **Caveats:** Java/Maven. The Python ratio is unmeasured, and measuring it could be a Ravel contribution.

### Endor Labs: Reachability Analysis (industry)

- **Links:** https://www.endorlabs.com/learn/reachability-analysis · docs https://docs.endorlabs.com/scan/sca/reachability-analysis · report https://www.endorlabs.com/lp/dependency-management-report
- **Verified:** ✅ (vendor pages)
- **Key claims:** Function-level reachability cuts SCA findings by **~92%** (up to 97%). Customers report 80–99% reductions compared with package-name matching. About **95% of vulns sit in transitive dependencies**. Requires a successful build to generate full call graphs.
- **Ravel takeaway:** This is the commercial bar. Endor does this for **dependencies (SCA)**. Ravel applies reachability to **first-party SAST findings** (Semgrep/Bandit) *and* dependencies, from untrusted entry points specifically. That difference is Ravel's positioning.
- **Caveats:** **Vendor marketing, not peer-reviewed.** Cite as "vendor-reported".

### Semgrep Supply Chain / Snyk reachability (⚠ from memory)

- Semgrep Supply Chain and Snyk also market reachability for dependency vulns (mostly usage-of-vulnerable-symbol matching, not whole-program call graphs). Worth a competitor-comparison paragraph. Check their current docs before citing.

---

## Part B — Dependency & cross-language reachability (deps report, Phase 5)

### PyXray: Practical Cross-Language Call Graph Construction through Object Layout Analysis

- **Citation:** Georgios Alexopoulos, Thodoris Sotiropoulos, Georgios Gousios, Zhendong Su, Dimitris Mitropoulos. **ICSE 2026.**
- **Link:** https://dl.acm.org/doi/10.1145/3744916.3764555 · program page https://conf.researchr.org/details/icse-2026/icse-2026-research-track/38/PyXray-Practical-Cross-Language-Call-Graph-Construction-through-Object-Layout-Analys
- **Artifact:** https://github.com/grgalex/pyxray (**AGPL-3.0**)
- **Verified:** ✅
- **Key result:** Builds a unified **cross-language call graph** (Python ↔ C/C++/Rust extensions) via dependency resolution, **bridge recovery** (which native function a Python-visible name binds to, found through object layout analysis) and graph stitching. Analyses NumPy and PyTorch in minutes. Applications: **cross-language vulnerability reachability** and bloat analysis.
- **Ravel takeaway:**
  - Today a call from Python into a C extension ends Ravel's graph at an `ExternalRef`. PyXray shows how to follow it. That's post-v1, but the ExternalRef `symbol` field should already record the exact Python-visible symbol so a bridge could attach later.
  - For v1: when an OSV advisory is for a native library bundled in a wheel, report the finding with reachability `unknown` (can't see past the boundary), not `unreachable`.
- **Lands in:** Phase 5 deps report (v1: honest `unknown`; later: stitching).
- **Caveats:** **AGPL-3.0: do not vendor or port code from it.** Reading the paper for ideas is fine. Ravel is local-first but may be distributed, and AGPL would be viral.

### Cross-Ecosystem Vulnerability Analysis for Python Applications

- **Citation:** Georgios Alexopoulos, Nikolaos Alexopoulos, Thodoris Sotiropoulos, Charalambos Mitropoulos, Zhendong Su, Dimitris Mitropoulos. arXiv 2603.18693 (2026).
- **Link:** https://arxiv.org/abs/2603.18693
- **Verified:** ✅
- **Key result:** Recovers **provenance of native libraries vendored inside Python wheels** (hash-matching against OS package history, plus dynamic version extraction), then runs the first cross-ecosystem reachability analysis. **73.4%** exact provenance over 1,878 packages (**94.9%** for libraries with ≥1 CVE). **39** directly vulnerable packages in the top 100k (47M+ monthly downloads), **312** transitively affected, **54** vulns fixed after disclosure.
- **Ravel takeaway:** OSV-Scanner only sees *declared* dependencies. Vendored native libraries (e.g. a bundled libxml2 inside a wheel) are invisible to it. At minimum, the deps report should **state this blind spot** ("vendored native code not analysed"), in line with the coverage-as-a-metric rule.
- **Lands in:** Phase 5 deps report (disclosure of the blind spot).
- **Caveats:** Preprint.

### Bloat beneath Python's Scales: A Fine-Grained Inter-Project Dependency Analysis

- **Link:** https://dl.acm.org/doi/10.1145/3660821 (Proc. ACM Softw. Eng., FSE 2024)
- **Verified:** ✅ (search result)
- **Key result:** More than **50% of PyPI dependencies are bloated** (declared but unused), and **15% of defects** in utilised packages sit in bloated regions.
- **Ravel takeaway:** Ravel's graph can report "dependency declared but never imported/called" for free, a cheap and high-value line in the deps report. A vuln in a bloated dependency has the simplest fix: remove the dependency.
- **Lands in:** Phase 5 deps report.

### Getting vulnerable *symbols* for Python advisories (the hard part)

Function-level dependency reachability needs "which function in package X is vulnerable?" Python advisories usually don't say.

- **OSV schema**: https://ossf.github.io/osv-schema/ ⚠. Go advisories carry `ecosystem_specific.imports[].symbols`. PyPI advisories (mostly GHSA/PYSEC) usually give only version ranges.
- Options, in order of honesty:
  1. If the advisory lists symbols, use them.
  2. Else derive candidate symbols from the **fix commit diff** (functions changed in the patch). This is what PyVul's function-level labels are. Label these "patch-derived", lower confidence.
  3. Else mark as **package-level only**, reachability = "package imported" vs "package not imported". Never claim function-level unreachability without symbols.
- **Ponta, Plate, Sabetta, "Detection, assessment and mitigation of vulnerabilities in open source dependencies"**, EMSE 2020 (Eclipse Steady / SAP). ⚠ link not re-verified: https://doi.org/10.1007/s10664-020-09830-x. It pioneered the "code-centric, patch-derived vulnerable constructs + reachability" approach for Java. It's the closest prior art for option 2.

---

## Part C — Taint & entry-point knowledge we can reuse (without writing detection rules)

### Pysa (Meta): taint models for Django / Flask

- **Links:** https://pyre-check.org/docs/pysa-basics/ · model generators https://pyre-check.org/docs/pysa-model-generators/ · shipping models https://pyre-check.org/docs/pysa-shipping-rules-models/ · Django model PR https://github.com/facebook/pyre-check/pull/412
- **Verified:** ✅
- **What:** `.pysa` model files declare taint **sources** (e.g. `django.http.request.HttpRequest.GET: TaintSource[UserControlled]`) and sinks. The repo ships `django_sources_sinks.pysa`, `flask_sources_sinks.pysa` and stubs under `stubs/taint/…` and `stubs/third_party_taint/…`. **Model generators** auto-create models, for example marking all Django view parameters as user-controlled.
- **Ravel takeaway:**
  - Pysa's **source** models are a curated list of "where untrusted input enters" per framework. That's knowledge for **entry-point detection** (`ravel/graph/entrypoints.py`), not a detection rule. Use it as a cross-reference to check Ravel's Flask/Django/FastAPI entry-point coverage, the same way BUILD-PLAN uses Arcflow's taxonomy.
  - Pysa's *sink* models and rules are **detection**. Do not port them (PRODUCT.md §6 "never write custom detection rules").
  - Pysa itself could be a **5th scanner** wrapped in Phase 2, but it needs a full Pyre type-check setup. Probably not v1.
- **Lands in:** Phase 1 entry-point cross-check; Phase 2 optional scanner.
- **Caveats:** MIT-licensed (⚠ confirm). Porting *knowledge* (which attribute is user-controlled) is fine. Check the license before copying files.

### IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities

- **Citation:** Ziyang Li, Saikat Dutta, Mayur Naik. arXiv 2405.17238 (v3 Apr 2025), ICLR 2025 (⚠ venue from memory; the abstract page doesn't state it).
- **Link:** https://arxiv.org/abs/2405.17238
- **Artifact:** https://github.com/iris-sast/iris
- **Verified:** ✅
- **Key result:** An LLM **infers taint source/sink specs** for third-party APIs, feeds them into CodeQL, then filters alerts with context. On **CWE-Bench-Java** (120 manually validated vulns) it detects **55 vs CodeQL's 27**, improves false discovery rate by 5 points, and found 4 previously unknown vulns.
- **Ravel takeaway:**
  - **Conflict:** inferring *sinks* is writing detection rules by another route. **Out of scope** (PRODUCT.md §6).
  - **Allowed variant (post-v1, ask first):** LLM-inferred **sources / entry points** for frameworks Ravel has no hand-written detector for (Tornado, Starlette, aiohttp, Celery). Output would be marked `inferred` with low confidence and never used to *drop* a finding.
  - The contextual filtering stage is covered in [04](04-llm-triage.md).
- **Lands in:** Post-v1 idea.

### Code Property Graphs

- **Citation:** Fabian Yamaguchi, Nico Golde, Daniel Arp, Konrad Rieck. IEEE S&P 2014, pp. 590–604.
- **Link:** https://dl.acm.org/doi/10.1109/SP.2014.44 · dblp https://dblp.org/rec/conf/sp/YamaguchiGAR14.html
- **Verified:** ✅
- **Key result:** Merges AST + CFG + PDG into one graph and queries vulnerabilities as graph traversals. 88 Linux kernel vulns found (18 new, 15 CVEs).
- **Ravel takeaway:** The foundational citation for "the graph is the asset; every question is a traversal" (PRODUCT.md §1). Ravel's graph is currently the *call/import/inherit* layer of a CPG. Adding CFG/PDG edges later is the route to data-flow reachability (see PyFlow in [01](01-call-graph-and-resolution.md)). Joern (open-source CPG tool) is the practical descendant: https://joern.io ⚠.

---

## Design implications for Phase 3 (derived)

1. **Reachability classes.** `ravel/models.py` currently has `Reachability = reachable | unreachable | unknown`. The papers here argue for splitting it further, strongest evidence first. This is a proposal: changing the enum is a data-model decision, so ask first (PRODUCT.md §6).
   - `reachable`: a path from an untrusted entry point with all edges resolved
   - `reachable_via_unknown`: a path exists only if one or more `unknown` edges are assumed to connect
   - `internal_only`: reachable only from `internal` entry points (cron, CLI)
   - `unreachable`: no path, and the node has **no** incoming `unknown` edges in its ancestry
   - `unanalysable`: finding couldn't be mapped to a node, or sits past a native boundary

   Only `unreachable` is filtered. Everything else is ranked. (Mir et al. lower-bound warning; soundiness manifesto.)
2. **Report the filter's own recall risk**: count how many filtered findings had any `unknown` edge within k hops, so a reviewer can see the exposure.
3. **Dependency findings**: function-level only with symbols, patch-derived with a label, otherwise package-level (Part B).
