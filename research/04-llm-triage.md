# 04 — LLM Triage of Static-Analysis Findings (Phase 4)

Triage runs **only on findings reachability kept**, with graph context, as
structured JSON, cached and budget-capped. It must **earn its slot** against
reachability-alone or ship disabled (PRODUCT.md §3, §10). Every paper below is
read through that lens.

> Almost all of these evaluate on **Java or C** (OWASP Benchmark, CWE-Bench-Java,
> Juliet). None evaluates on Python web apps with reachability-pre-filtered input.
> Their numbers will not carry over. Use them for *method* ideas, and measure
> everything on Ravel's own eval.

---

## LLM4PFA: Minimizing False Positives in Static Bug Detection via LLM-Enhanced Path Feasibility Analysis

- **Citation:** Xueying Du, Kai Yu, Chong Wang, Yi Zou, Wentai Deng, Zuoyu Ou, Xin Peng, Lingming Zhang, Yiling Lou. arXiv 2506.10322 (Jun 2025).
- **Link:** https://arxiv.org/abs/2506.10322
- **Verified:** ✅
- **Key result:** Filters **72–96% of false positives**, **41.1–105.7%** better than baselines, while **missing only 3 of 45 true bugs**. Splits whole-path feasibility into **function-by-function** reasoning: an LLM agent extracts the constraints for each function, and an **SMT solver** checks whether they can all hold together. Agent planning decides what extra context to fetch.
- **Ravel takeaway (the main design idea for Phase 4):**
  - Ravel's reachability already produces the **path** (`static_evidence.path`, a list of node_ids from entry point to flagged node). Triage can follow it **hop by hop**: "Given tainted input arriving as param `x`, does it reach the call to `callee` unsanitized?" → `{propagates: yes|no|unsure, sanitizer: str|null, reason}`.
  - **Caching:** each hop's verdict is keyed on `hash(caller source + callee signature + question)`. Many findings share path prefixes (the same route handler → the same service function), so hop verdicts are **reused across findings**. That's a real cost saving under the budget cap. It fits PRODUCT.md §8's rule that verdict cache keys hash the assembled context.
  - The finding verdict is derived from the hop verdicts: any `no` → likely FP; all `yes` → likely real; any `unsure` → `needs-review`.
  - A reviewer can see *which hop* killed a finding, which is much easier to audit than one opaque verdict.
  - SMT is probably overkill for web-app taint (the questions are about sanitization, not arithmetic constraints). Take the decomposition, skip the solver.
- **Lands in:** Phase 4, `ravel/triage/` context assembly + verdict.
- **Caveats:** Preprint; C/C++ bug types (NPD etc.), not web taint.

---

## Using LLMs to Adjudicate Static-Analysis Alerts with Error Reduction Techniques

- **Link:** https://arxiv.org/abs/2607.09979 (2026)
- **Verified:** ✅ (abstract page)
- **Key result:** On Juliet, FormAI and SV-COMP, mid-tier reasoning models (o4-mini, gpt-oss-120b, gpt-oss-20b) plus two error-reduction techniques reach **≥98% recall and ≥94.8% specificity on every suite**:
  - **Consistency Check (CC):** run N times, require the verdicts to agree. CC alone was enough on Juliet and SV-COMP.
  - **LLM Reasoning Evaluation (LRE):** run N times, then have the LLM pick a verdict after reading all N reasonings. Needed alongside CC on FormAI.
  - Also: a program synthesised to **trigger** the flaw was **never validated for a false alarm**. A valid trigger is strong evidence the finding is real.
- **Ravel takeaway:**
  - **CC maps onto Ravel's three verdicts:** unanimous → `real`/`false-positive`, split → `needs-review`. Cheap to implement, and it makes the verdict's uncertainty visible instead of hiding it.
  - Cost: N× tokens. Run CC only on findings where a single run's confidence is below a threshold, and count it against the per-run budget cap.
  - **Open-weight models (gpt-oss-20b) did well.** That matters for Ravel's **local-first / Ollama** requirement: a local model with CC might be good enough. Test it on the eval.
  - Trigger synthesis = patch/exploit generation → **out of v1 scope** (PRODUCT.md §7).
- **Lands in:** Phase 4 verdict step.
- **Caveats:** Synthetic C benchmarks (Juliet is notoriously easy).

---

## Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering

- **Link:** https://arxiv.org/abs/2601.22952 (Jan 2026)
- **Verified:** ✅
- **Key result:** Compares **Aider, OpenHands, SWE-agent** as FP filters. On the OWASP Benchmark the FP rate dropped from **>92% to as low as 6.3%**. On real-world Java with CodeQL alerts, up to **93.3%** FP identification.
- **Ravel takeaway:**
  - **Agentic triage** (the model explores the repo with tools) is the strongest current approach, and also the most expensive and least reproducible. Ravel's position: **the graph replaces the exploration**. Ravel hands the model exactly the path, callers and summaries an agent would have searched for. The eval question for Phase 4 is whether graph-assembled context matches agent exploration at a fraction of the tokens. If it does, that's a publishable result.
  - Use as an **upper-bound baseline** in the triage eval if budget allows (run one agent on a sample).
- **Lands in:** Phase 4 checkpoint comparison.
- **Caveats:** Java; OWASP Benchmark is synthetic.

---

## ZeroFalse: Improving Precision in Static Analysis with LLMs

- **Citation:** Mohsen Iranmanesh, Sina Moradi Sabet, Sina Marefat, Ali Javidi Ghasr, Allison Wilson, Iman Sharafaldin, Mohammad A. Tayebi. arXiv 2510.02534 (Oct 2025).
- **Link:** https://arxiv.org/abs/2510.02534
- **Verified:** ✅
- **Key result:** Adds flow-sensitive traces, context and **CWE-specific knowledge** to analyzer output. **CWE-specialized prompts consistently beat generic prompts.** F1 **0.912** on OWASP Java Benchmark and **0.955** on OpenVuln, with precision and recall both above 90%. Ten LLMs benchmarked, and reasoning models did best. Includes a survey of predecessors (LLM4SA, LLM4FPM).
- **Ravel takeaway:**
  - **Per-CWE prompt templates**: the "is this sanitized?" question differs for SQLi (parameterized query?), XSS (autoescape?), path traversal (normalised + prefix-checked?), command injection (`shell=False` + list args?), deserialization (trusted source?). Findings carry a `cwe`, so select the template by CWE. This isn't a detection rule. It's how the question is framed for a finding a scanner already raised.
  - Include the **flow trace** in context (Ravel has it: `static_evidence.path`).
- **Lands in:** Phase 4 prompts (`ravel/triage/`).

---

## Memoir: Learning, Verifying, and Evolving False-Positive Memories for SAST Tools

- **Citation:** Shenyuan Guan, Qiaodan Hou, Yanjun Chen, Xincheng Wen, Jia Feng, Keke Lian, Cuiyun Gao. arXiv 2608.09181 (2026).
- **Link:** https://arxiv.org/abs/2608.09181
- **Verified:** ✅
- **Key result:** Turns historical FP alerts into **structured semantic memories** (LLM annotation → pattern clustering → synthesis), retrieves relevant memories for new alerts, verifies them against taxonomy consistency and security invariants, and feeds validated results back in. Reports **F1 99.43%** (P 100%, R 98.88%) on CWE-Bench-Java plus production systems, and it generalises across SAST tools without retraining.
- **Ravel takeaway:**
  - Relevant to **incremental re-runs** (PRODUCT.md §8): once a user marks a finding as FP, Ravel could store a *pattern* (e.g. "`subprocess.run` with list args and no `shell=True` in this repo's `utils/shell.py` wrapper") and reuse it, not only the exact hash-keyed verdict.
  - **Risk for the eval:** memories learned on eval repos are **leakage** (Kang et al., [02](02-eval-benchmarks-and-ground-truth.md)). Any memory feature must be off during benchmark runs, or trained only on the tuning split.
  - pgvector is already in the stack for memory retrieval.
- **Lands in:** Post-v1 idea (it's a user-feedback loop, which v1 doesn't have).
- **Caveats:** Preprint; the near-perfect numbers call for Kang-style scepticism.

---

## Other entries (search results; skim)

| Paper | Link | One-line |
|---|---|---|
| SAST-Genius: LLM-driven hybrid SAST framework | https://arxiv.org/abs/2509.15433 | Semgrep + LLM: 35.7% → 89.5% precision in their setup |
| QASecClaw: multi-agent FP reduction in SAST | https://arxiv.org/abs/2605.01885 | Multi-agent variant |
| Refute-or-Promote: adversarial stage-gated multi-agent review | https://arxiv.org/abs/2604.19049 | One agent argues FP, one argues real; could inform a two-sided prompt |
| LLM-Driven Adaptive Source–Sink Identification and FP Mitigation | https://dl.acm.org/doi/10.1145/3773365.3773410 | Source/sink inference + FP filtering |
| Can Open-Source LLM Agents Replace SAST Tools? | https://arxiv.org/abs/2606.11672 | Detection-side; context only |
| An Empirical Analysis of CodeQL False Positives (Java) | https://arxiv.org/abs/2609.04535 | Root causes of CodeQL FPs; informs CWE templates |
| Comparison of SAST tools and LLMs for repo-level vuln detection | https://arxiv.org/abs/2407.16235 | Repo-level comparison |

---

## Phase 4 design sketch (derived; not a commitment)

```
for finding in kept_by_reachability:                # never raw findings (PRODUCT §3)
    template = CWE_TEMPLATES[finding.cwe]           # ZeroFalse
    hops = pairwise(finding.static_evidence.path)
    for caller, callee in hops:                     # LLM4PFA decomposition
        key = hash(src(caller), sig(callee), template.id)   # context-hash cache key (PRODUCT §8)
        verdict[hop] = cache.get(key) or llm(template, caller, callee, module_summary)
    v = combine(hop verdicts)                       # any 'no' → FP; any 'unsure' → needs-review
    if v.confidence < τ:
        v = consistency_check(v, n=3)               # CC; split → needs-review
    record(v)                                       # structured JSON, budget-capped
```

**Checkpoint comparison table** (Phase 4 exit):

| Configuration | Precision | Recall retained | Tokens | $ |
|---|---|---|---|---|
| Raw scanners | | | 0 | 0 |
| Reachability only | | | 0 | 0 |
| + single-prompt triage | | | | |
| + per-hop triage | | | | |
| + per-hop + CC | | | | |
| (optional) agentic baseline, sample | | | | |

If no triage row beats "reachability only" on precision at equal recall, ship triage disabled (PRODUCT.md §10).
