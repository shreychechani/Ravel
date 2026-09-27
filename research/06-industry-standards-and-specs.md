# 06 — Industry White Papers, Standards & Specs

Industry experience papers (why developers ignore static analysis),
prioritisation standards for the ranking step, output formats, and docs for
the tools in Ravel's stack.

---

## Part A — Industry experience papers

### Lessons from Building Static Analysis Tools at Google

- **Citation:** Caitlin Sadowski, Edward Aftandilian, Alex Eagle, Liam Miller-Cushon, Ciera Jaspan. CACM 61(4), 2018, pp. 58–66.
- **Link:** https://cacm.acm.org/research/lessons-from-building-static-analysis-tools-at-google/ · DOI https://dl.acm.org/doi/10.1145/3188720
- **Verified:** ✅
- **Key points:** Filing FindBugs results as bugs failed (**84% never fixed**). What worked was integration into code review (Tricorder), strict control of false positives, and treating the **developer's perception** as the metric. It introduced the **"effective false positive"** idea: any report a developer doesn't act on counts as a false positive, whatever its technical correctness. Google aims to keep it below about 10% (⚠ threshold from memory; confirm in the paper).
- **Ravel takeaway:**
  - The industrial version of PRODUCT.md §2's "teams stop reading the report forever". **Quote it in the pitch.**
  - "Effective FP" suggests the eval should also report **actionable-precision**: of what Ravel ranks top-N, how many would a developer fix? That's measurable later with user studies. For v1, note it as future work.
- **Also see:** *Software Engineering at Google*, ch. 20 "Static Analysis": https://abseil.io/resources/swe-book/html/ch20.html ✅

### Tricorder: Building a Program Analysis Ecosystem (⚠ from memory)

- **Citation:** Sadowski, van Gogh, Jaspan, Söderberg, Winter. ICSE 2015. Link not re-verified.
- **Point:** "Not useful" feedback button per finding, and analyzers disabled when they cross an FP threshold. For Ravel post-v1, a per-rule usefulness signal could feed ranking.

### A Few Billion Lines of Code Later: Using Static Analysis to Find Bugs in the Real World (⚠ from memory)

- **Citation:** Bessey, Block, Chelf, Chou, Fulton, Hallem, Henri-Gros, Kamsky, McPeak, Engler (Coverity). CACM 53(2), 2010. DOI https://doi.org/10.1145/1646353.1646374 (not re-verified).
- **Point:** Commercial static analysis dies on false positives and on explaining results. Output that *explains* (Ravel's traced paths) matters as much as output that is correct.

### Why Don't Software Developers Use Static Analysis Tools to Find Bugs? (⚠ from memory)

- **Citation:** Johnson, Song, Murphy-Hill, Bowdidge. ICSE 2013. DOI https://doi.org/10.1109/ICSE.2013.6606613 (not re-verified).
- **Point:** Interviews name **false positives and poor explanations** as the top barriers, which is Ravel's problem statement in developers' own words.

### In Defense of Soundiness: A Manifesto

- See [01](01-call-graph-and-resolution.md). ✅ https://cacm.acm.org/opinion/in-defense-of-soundiness/

---

## Part B — Prioritisation standards (Phase 4 ranking, Phase 5 deps report)

PRODUCT.md §3 ranks by **exploitability × blast radius**. For dependency (OSV)
findings, public signals exist for "exploitability". Use them rather than
inventing a score.

| Standard | What it gives | Link | Ravel use |
|---|---|---|---|
| **EPSS** (FIRST) | Daily probability (0–1) that a CVE is exploited in the wild in the next 30 days | https://www.first.org/epss/ ⚠ | Exploitability factor for OSV findings with a CVE ID. Free API. Note: calling it is a network request, so make it opt-in or use a cached offline snapshot (**local-first, never phone home**, PRODUCT.md §6) |
| **CISA KEV** | Catalog of CVEs known to be exploited | https://www.cisa.gov/known-exploited-vulnerabilities-catalog ⚠ | Boolean "known exploited" → rank to top if also reachable. Downloadable JSON, so it can be vendored offline |
| **SSVC** (CERT/CC, CISA) | Decision tree (Exploitation × Exposure × Automatable × Impact) → Track / Track* / Attend / Act | https://github.com/CERTCC/SSVC ⚠ · https://certcc.github.io/SSVC/ ⚠ | Ravel's reachability is a strong **Exposure** signal. Emitting an SSVC-style decision is more defensible than a bespoke score |
| **CVSS v4.0** | Base severity; Ravel's `raw_severity` comes from scanners | https://www.first.org/cvss/v4-0/ ⚠ | Keep as input, never as the ranking. CVSS ignores reachability, which is the whole point |
| **CWE** / CWE Top 25 | Weakness taxonomy; `Finding.cwe` | https://cwe.mitre.org/ ⚠ | Normalisation key across scanners; selects triage template ([04](04-llm-triage.md)) |

**Suggested rank tuple** (derived, not a commitment):
`(reachability_class, KEV, EPSS bucket, triage verdict × confidence, blast_radius)`, sorted lexicographically. Reachability always dominates, which is Ravel's thesis.

---

## Part C — Output & data formats

| Spec | Link | Ravel use |
|---|---|---|
| **SARIF 2.1.0** (OASIS) | https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html ⚠ | Export format. Put `static_evidence.path` in `codeFlows` / `threadFlows` so GitHub code scanning and VS Code SARIF viewers render the traced path natively. Put reachability class and verdict in `properties`. Arcflow already exports SARIF (BUILD-PLAN reference index) |
| **OSV schema** | https://ossf.github.io/osv-schema/ ⚠ | Advisory format from OSV-Scanner. Check `affected[].ecosystem_specific` / `database_specific` for symbol info ([03](03-reachability-and-dependencies.md) Part B) |
| **CycloneDX** (SBOM + VEX) | https://cyclonedx.org/ ⚠ | Its **VEX** (Vulnerability Exploitability eXchange) has a standard field for "not affected: vulnerable code not reachable" (`code_not_reachable` justification ⚠). Emitting VEX from Ravel's reachability is a standards-compliant way to publish "this CVE doesn't affect us" |
| **OpenVEX** | https://github.com/openvex/spec ⚠ | Lighter VEX alternative with the same justification semantics (`vulnerable_code_not_in_execute_path` ⚠) |

VEX output is a strong differentiator: few tools produce VEX backed by an actual call-graph path. It belongs in Phase 5 output.

---

## Part D — Stack docs (quick links)

All ⚠ (well-known URLs, not re-fetched):

| Tool | Docs | Relevant section |
|---|---|---|
| tree-sitter / py-tree-sitter | https://tree-sitter.github.io/tree-sitter/ · https://github.com/tree-sitter/py-tree-sitter | Queries, node types |
| Jedi | https://jedi.readthedocs.io/ | `Script.goto`, `infer`, `Project`, environments |
| NetworkX | https://networkx.org/documentation/stable/ | `MultiDiGraph`, `condensation`, `all_simple_paths`, `ancestors` |
| Semgrep OSS | https://semgrep.dev/docs/ | JSON output, taint mode (for normalisation only) |
| Bandit | https://bandit.readthedocs.io/ | Test IDs → CWE mapping |
| gitleaks | https://github.com/gitleaks/gitleaks | JSON report |
| OSV-Scanner | https://google.github.io/osv-scanner/ | Offline mode (local-first) |
| pgvector | https://github.com/pgvector/pgvector | HNSW indexes |
| React Flow / dagre | https://reactflow.dev/ · https://github.com/dagrejs/dagre | Phase 5 web view |
| Python `sys.monitoring` (3.12+) | https://docs.python.org/3/library/sys.monitoring.html | Low-overhead dynamic call tracing for the recall oracle ([01](01-call-graph-and-resolution.md)) |
