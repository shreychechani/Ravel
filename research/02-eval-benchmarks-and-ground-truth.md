# 02 — Eval Harness, Benchmarks & Ground Truth (Phase 2)

The measurable claim is **≥3× precision while retaining ≥85% recall**
(PRODUCT.md §2). This file covers where the ground truth comes from, what
raw scanners actually score, and how studies like ours have fooled themselves.

Current Ravel state: `eval/graph_checkpoint.py` + `eval/ground_truth/flaskr_graph.toml`
(graph checkpoint only). No vulnerability ground truth yet. `eval/repos/` and
`eval/truth/` are planned in PRODUCT.md §11.

---

## Part A — Methodology (read before building `eval/run.py`)

### Detecting False Alarms from Automatic Static Analysis Tools: How Far are We?

- **Citation:** Hong Jin Kang, Khai Loong Aw, David Lo. ICSE 2022.
- **Link:** https://arxiv.org/abs/2202.05982 · https://dl.acm.org/doi/10.1145/3510003.3510214
- **Artifact:** https://github.com/soarsmu/SA_retrospective
- **Verified:** ✅
- **Key result:** Earlier work reported **near-perfect** actionable-warning classifiers ("Golden Features" + SVM). Kang et al. found that this came from:
  1. **Label leakage**: a feature measured the share of actionable warnings, i.e. it encoded the label.
  2. **Data duplication**: many test warnings also appeared in training.

  Once fixed, the classifier was **only marginally better than "always predict actionable"**.
- **Ravel takeaway (these become eval rules):**
  1. **Always print trivial baselines** next to Ravel: *keep-all* (raw scanner), *severity-only* (keep HIGH/CRITICAL), *random-N* (same N as Ravel keeps, averaged over seeds). "3×" means 3× over raw, and Ravel must also beat severity-only.
  2. **Deduplicate findings** across scanners (Semgrep + Bandit often flag the same line) *before* computing precision, or duplicates inflate it.
  3. **Split by repository**, never by finding, for anything tuned (triage prompts, thresholds). Tune on repos A–M, report on N–Z.
  4. **Ground truth never feeds features.** CVE labels must not leak into the context the triage LLM sees (e.g. the fix commit message or a CVE ID in a comment).
  5. The eval owner is not the triage builder (PRODUCT.md §10). This paper is the reason that rule exists.
- **Lands in:** Phase 2, `eval/run.py` design.

### Machine Learning for Actionable Warning Identification: A Comprehensive Survey

- **Link:** https://arxiv.org/abs/2312.00324
- **Verified:** ✅ (search result; not read in full)
- **Ravel takeaway:** Map of the "actionable warning" literature, useful for the related-work section of the benchmark write-up.

---

## Part B — Vulnerability ground truth (Python)

### PyVul: An Empirical Study of Vulnerabilities in Python Packages and Their Detection

- **Citation:** Haowei Quan, Junjie Wang, Xinzhe Li, Terry Yue Zhuo, Xiao Chen, Xiaoning Du. arXiv 2509.04260 (2025).
- **Link:** https://arxiv.org/abs/2509.04260
- **Verified:** ✅
- **Key result:** **1,157 publicly reported, developer-verified vulnerabilities** in Python packages, annotated at **commit and function level**. LLM-assisted cleaning gives **100% commit-level / 94% function-level label accuracy**. Finds that existing detection tools fall far short on real-world Python vulns, and that multi-language packages are more vulnerable.
- **Ravel takeaway:**
  - The **primary candidate source for `eval/truth/`**. Function-level labels map directly onto Ravel's function `Node`s, so "is the vulnerable function reachable, and did Ravel keep the finding on it?" can be scored per function.
  - Filter to: pure-Python web apps / services (Flask, Django, FastAPI) ≤50k LOC with an identifiable untrusted entry point. Library-only packages have no HTTP entry point, so reachability has nothing to anchor to.
  - Pin each repo at the **pre-fix commit SHA** (vulnerable) and keep the **fix SHA** for sanity checks (PRODUCT.md §7 "CVE-patched OSS repos").
- **Lands in:** Phase 2, `eval/repos/` + `eval/truth/`.
- **Caveats:** Preprint. Check the dataset license before redistributing ground-truth files. ~6% function-level label noise, so hand-verify every case that enters the benchmark.

### Vul4Py: Benchmarking Automated Vulnerability Repair in Python with Paired Exploit and Functional Oracles

- **Citation:** Tan Bui, Ting Zhang, Ferdian Thung, Yunpeng Xiong, Penghao Jiang, Xin Zhou, David Lo. arXiv 2608.00692 (2026).
- **Link:** https://arxiv.org/abs/2608.00692
- **Verified:** ✅
- **Key result:** **100 real vulnerabilities from 60 projects, 60 CWEs, 2017–2025**. Each has an **exploit oracle** (fails on vulnerable code, passes on fixed) plus the project's own pytest functional oracle.
- **Ravel takeaway:**
  - An exploit that works is **proof of reachability**. That makes these the strongest possible ground truth for "Ravel must NOT filter this out". Use them as the **recall anchor**: any Vul4Py vuln with a finding on it that Ravel marks unreachable is a hard failure worth investigating.
  - The exploit also names the entry point that reaches the bug, so it doubles as entry-point detection ground truth.
- **Lands in:** Phase 2 truth set; Phase 3 checkpoint recall check.
- **Caveats:** Preprint. Built for repair, so check that each case has a web/CLI entry point Ravel can detect.

### CrossCommitVuln-Bench: Multi-Commit Python Vulnerabilities Invisible to Per-Commit Static Analysis

- **Link:** https://arxiv.org/abs/2604.21917
- **Verified:** ✅ (search result)
- **Key result:** **15 real Python CVEs** where the exploitable condition was introduced **across several commits**, so per-commit analysis misses them.
- **Ravel takeaway:** A test set for **incremental mode** (PRODUCT.md §8). If only the dirty nodes' reachability is re-checked, a vuln that became reachable because a *different* file gained a route can be missed. Stored paths must be invalidated when a new edge *into* the path appears, not only when a node on it changes.
- **Lands in:** Phase 5 (incremental).

### Other Python vulnerability datasets (search results, not read in full)

| Dataset | Link | Notes |
|---|---|---|
| PyCode-Vul | https://www.kaggle.com/datasets/oulabspring/pycode-vul-a-benchmark-dataset-for-python | 17,811 function-level samples (7,899 vulnerable). Function snippets without whole repos, so of limited use for reachability. |
| RepoPairBench | (via search; see DREA https://arxiv.org/abs/2607.13439) | 100 Python vuln-fix pairs, 2021–2025, repo-level |
| PATCHEVAL | https://arxiv.org/abs/2511.11019 | Real-world vuln patching benchmark; possible extra CVE source |
| CVEfixes / MoreFixes / CrossVul | ⚠ from memory | Large multi-language CVE→fix-commit datasets; filter to Python |

---

## Part C — What raw scanners score on Python (the baseline to beat)

### An Empirical Study on Static Application Security Testing (SAST) Tools for Python

- **Citation:** Liu Zhuohang, Zhi Wang, Haotong Liu (Nankai University), Wanpeng Li (University of Liverpool). **ICSE 2026, Distinguished Paper Award.**
- **Link:** https://conf.researchr.org/details/icse-2026/icse-2026-research-track/30/An-Empirical-Study-on-Static-Application-Security-Testing-SAST-Tools-for-Python
- **Verified:** ✅ (conference abstract)
- **Key result:** 8 tools picked from 117 candidates. On **real-world** Python vulns, **no single tool detects more than 40%**, and **all 8 combined reach only 66.7%**. Tools do much better on synthetic datasets than on real code.
- **Ravel takeaway:**
  - **Recall has a ceiling Ravel cannot fix.** Ravel filters scanner output, so its recall is bounded by the scanners' own recall. The eval must report **two recalls**:
    - *Recall retained* = real vulns Ravel kept ÷ real vulns the scanners found. This is the ≥85% target.
    - *End-to-end recall* = real vulns Ravel kept ÷ all real vulns in ground truth. Honest context, bounded by roughly 40–67%.

    Otherwise a reviewer will say "you only catch 30% of CVEs".
  - Their synthetic and real-world datasets (reused by PyFlow) are a ready scanner benchmark. Get the artifact.
  - Their root-cause analysis of misses tells us which CWE classes to exclude from the claim.
- **Lands in:** Phase 2 baseline, benchmark write-up.

### Other SAST comparison results (search results; context only)

| Source | Link | Figure |
|---|---|---|
| PyFlow eval (ICSE '26 datasets) | https://arxiv.org/abs/2608.07026 | Semgrep ~83% precision / ~66% recall on injected vulns |
| SAST-Genius | https://arxiv.org/abs/2509.15433 | Semgrep 35.7% precision → 89.5% with LLM layer (their setup) |
| LLM command-injection study (Python) | https://arxiv.org/abs/2505.15088 | Bandit ~44% precision on command injection |
| Static analysis tools for secure code review (ISSTA '24) | https://dl.acm.org/doi/10.1145/3650212.3680313 | Multi-tool study |

These numbers vary wildly because every study defines "finding" and "true positive" differently. **Ravel must publish its own baseline on its own benchmark** and not quote these as its baseline.

---

## Part D — Benchmarks for other layers

| Benchmark | Layer | Link | Use |
|---|---|---|---|
| PyCG micro-benchmark | Call graph | https://github.com/vitsalis/PyCG | See [01](01-call-graph-and-resolution.md) |
| JARVIS macro-benchmark | Call graph | https://pythonjarvis.github.io/ | FastAPI ground truth |
| SWARM-CG | Call graph | via https://arxiv.org/abs/2410.00603 | Extra call-graph truth |
| DyPyBench | Call-graph recall (dynamic) | https://arxiv.org/abs/2403.00539 | Dynamic oracle |
| OWASP Benchmark | Triage | https://owasp.org/www-project-benchmark/ (⚠) | **Java only**, but most LLM-triage papers report on it; useful only to compare triage *methods* |
| CWE-Bench-Java | Triage | https://github.com/iris-sast/iris | Java, 120 manually validated vulns (IRIS) |
| CodeWikiBench | Summaries | https://arxiv.org/abs/2510.24428 | See [05](05-summaries-and-wiki.md) |

---

## Eval-harness checklist (derived)

- [ ] Ground truth = pinned repo SHA + vulnerable function(s) + CWE + entry point (if known) + source dataset ID
- [ ] Every truth case hand-verified (PyVul has ~6% function-level noise)
- [ ] Findings deduped across scanners before scoring
- [ ] Baselines printed: keep-all, severity-only, random-N
- [ ] Precision **and** recall-retained **and** end-to-end recall printed together
- [ ] Graph coverage printed per repo (claims void below 60%, PRODUCT.md §9)
- [ ] Tuning set and report set split **by repo**
- [ ] No CVE text / fix-commit info reachable by the triage context builder
- [ ] One command, reproducible (PRODUCT.md §5)
