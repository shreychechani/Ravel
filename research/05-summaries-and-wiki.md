# 05 — Summaries & Wiki Pipeline

In v1, summaries exist **as triage context, not as a docs product** (PRODUCT.md §7).
They are bottom-up, hash-cached, and cascade upward only when materially
changed (§8). Summaries are second in the cut order (§10), so keep this lean.

---

## RepoAgent: An LLM-Powered Open-Source Framework for Repository-level Code Documentation Generation

- **Citation:** Qinyu Luo et al. (Tsinghua University, Siemens AG). EMNLP 2024 System Demonstrations.
- **Link:** https://arxiv.org/abs/2402.16667 · ACL Anthology https://aclanthology.org/2024.emnlp-demo.46/
- **Verified:** ✅ (first author from memory ⚠)
- **What:** Filters to Python files, builds a project tree from **AST** meta-info for classes/functions, then uses **Jedi** to extract **bi-directional references** between objects. That turns the tree into a **DAG**, and docs are generated in topological order (callees before callers) so each object's doc can use its dependencies' docs. It updates docs **incrementally** on commit via a git hook, regenerating only changed objects and their dependents. It beat human-written docs in blind preference tests.
- **Ravel takeaway:**
  - **Almost the same architecture as Ravel** (AST + Jedi + dependency DAG + incremental on git diff). It's the closest reference implementation for `ravel/summarize/`. Read their incremental-update logic against PRODUCT.md §8 step 5 (cascade only if materially different). RepoAgent regenerates dependents on *any* change, which is the cost trap §8 warns about.
  - Topological order needs an **acyclic** graph, and real call graphs have cycles (mutual recursion). Collapse SCCs (NetworkX `condensation`) and summarise each SCC as a unit.
- **Lands in:** Phase 4 summaries.
- **Caveats:** Check the license before porting code (⚠ believed Apache-2.0).

---

## DocAgent: A Multi-Agent System for Automated Code Documentation Generation

- **Citation:** Dayu Yang et al. arXiv 2504.08725 (Apr 2025), from Meta ⚠.
- **Link:** https://arxiv.org/abs/2504.08725
- **Verified:** ✅
- **What:** **Topological processing order** plus specialised agents (Reader, Searcher, Writer, Verifier, Orchestrator). The evaluation framework scores **Completeness, Helpfulness, Truthfulness**. An ablation confirms that **topological order matters**.
- **Ravel takeaway:**
  - Independent evidence that **bottom-up (dependency-first) order** improves quality, which supports PRODUCT.md's bottom-up design.
  - The **Truthfulness** check (does the summary mention entities that don't exist?) is cheap to run deterministically against Ravel's graph: every identifier a summary names should resolve to a node or ExternalRef. That makes hallucinated summaries detectable without an LLM judge, and matters because summaries feed triage context.
  - A five-agent system is overkill for v1. Use one small model per leaf (PRODUCT.md §5).
- **Lands in:** Phase 4 summaries (truthfulness check).

---

## CodeWiki: Evaluating AI's Ability to Generate Holistic Documentation for Large-Scale Codebases

- **Citation:** Anh Nguyen Hoang, Minh Le-Anh, Bach Le, Nghi D. Q. Bui. **ACL 2026.**
- **Link:** https://arxiv.org/abs/2510.24428
- **Verified:** ✅
- **What:** Repo-level docs across 7 languages through hierarchical decomposition, recursive multi-agent processing, and diagrams. **CodeWikiBench** provides rubric-based, LLM-judged evaluation. Scores **68.79%** vs DeepWiki **64.06%**, with the largest gains on scripting languages (+10.47%).
- **Ravel takeaway:** If the wiki ever becomes a product (post-v1), CodeWikiBench is the ready-made quality metric and DeepWiki the named competitor. For v1, skip.
- **Lands in:** Post-v1.

---

## Other entries

| Paper | Link | Note |
|---|---|---|
| Memory-guided long-horizon agentic framework for hierarchical repo docs | https://arxiv.org/abs/2605.14563 | Consistency across a large doc tree |
| Reversa: reverse documentation engineering for legacy software | https://arxiv.org/abs/2605.18684 | Docs as specs for AI agents |
| The Illusion of Agentic Complexity in README Generation | https://arxiv.org/abs/2606.30524 | Single-agent RAG ≈ multi-agent. Supports keeping it simple |

---

## Design implications (derived)

1. Order: summarise in reverse topological order over the **SCC-condensed** call graph.
2. Cache key: `hash(node source + child summary hashes)`. A child change only propagates if the child's *summary* changes materially (PRODUCT.md §8.5). Define "materially" as embedding cosine distance > τ, or an LLM yes/no judgement, and measure which is cheaper.
3. Truthfulness guard: every identifier in a summary must resolve in the graph; otherwise regenerate once, then flag.
4. Summaries are **triage context**. Measure whether they help: run the Phase 4 eval with and without module summaries in context.
