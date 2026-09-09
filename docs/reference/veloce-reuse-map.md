# Arcflow + CodeClean → Ravel reuse map

> How the two owner-approved Veloce-AI codebases actually work, and which parts
> we can carry into Ravel. Written after reading the analysis engines of both.
> Source repos read at: `Veloce-AI/Arcflow`, `Veloce-AI/CodeClean` (JS, browser-side).

---

## 1. What these two actually are

Both are **client-side, offline, multi-language JavaScript analyzers** that run
entirely in a browser tab (also shipped as VS Code webview extensions). Nothing
is server-side; there is no database; there is no LLM.

- **Arcflow** (~13.2k LOC JS) — the heavier engine. Parses a repo, builds a
  cross-file function call graph + import graph, detects API routes, runs
  regex/heuristic security + secret detection, queries OSV.dev for CVEs, and
  renders ~10 D3/WebGL graph views.
- **CodeClean** (~7.3k LOC JS) — a code-quality layer. It **reuses Arcflow's
  parser** (its own `js/analysis/parser-*.js` are literal stubs that say
  *"will be replaced by Arcflow copy"*) and adds ~20 quality analyzers
  (dead code, circular deps, complexity, smells, memory leaks, perf, a11y…),
  each as one module under `js/analysis/`, plus a 0–100 health scorer.

**Relationship:** Arcflow is the parsing/graph/security engine; CodeClean is
Arcflow's parser + a bank of quality checks + a score. For Ravel, Arcflow is
the more relevant of the two.

---

## 2. How Arcflow works (the pipeline)

Entry point: `graph-builder.js → buildAnalysisData()`, run inside a Web Worker
(it literally slices its own `<script>` source between two marker comments and
`importScripts()` acorn/babel/tree-sitter into the worker).

1. **Parse / extract** (`parser-core.js`, `parser-extract.js`)
   - File classification by extension (code / text / binary).
   - Function + class extraction. **Python is regex + indentation tracking**
     (tracks `class`/`def`/`async def`, decorators, dunder/private, method vs
     function, `self`/`cls`). **JS/TS uses a real AST** (Babel transform → acorn
     walk).
2. **Call detection** (`parser-findcalls.js`, `parser-callgraph.js`)
   - **Python call detection uses tree-sitter (WASM)** — walks the CST, counts
     every identifier that matches a known function name and isn't a definition.
     Falls back to a string/comment-stripped tokenizer if tree-sitter is
     unavailable. **This is the same grammar family Ravel plans to use.**
   - Import resolution (`resolveCallGraphImportPath`, `extractCallGraphImportMap`)
     is multi-language and **path/candidate-based** — it guesses the target file
     by trying a list of extension suffixes against a path map.
3. **Graph assembly** (`graph-builder.js`)
   - `resolveCallDefinitions()` links a call to a definition by: same-file first,
     else single unique definition, else via the file's import map.
     **This is name + import heuristic, not scope-accurate resolution.**
   - Produces `connections[]` (cross-file edges), `fnStats` (callers/counts),
     dead-function list, circular-dep list, coupling metric.
4. **Detections** — `detectSecurity`, `detectApiRoutes`, `detectComponents`,
   `detectPatterns`, duplicates, layer violations, complexity/MI/cognitive-CC.
5. **Output** — one big `dataObj` consumed by the D3 renderers.

---

## 3. Component-by-component reuse verdict for Ravel

Legend: **Port** = reimplement this logic in Python; **Reference** = read for
patterns/taxonomy, don't port; **Drop** = not relevant to Ravel.

| Arcflow / CodeClean piece | File | Verdict for Ravel | Why |
|---|---|---|---|
| Python function/class extraction | `parser-extract.js` | **Reference** | Regex+indentation. Ravel uses tree-sitter + `ast`, which is strictly better. Their edge-case handling (decorators, dunder, staticmethod/classmethod, async) is a useful checklist. |
| Python call detection (tree-sitter CST walk) | `parser-findcalls.js` | **Reference/Port** | Confirms the tree-sitter approach. Ravel goes further with Jedi/`ast` scope resolution. |
| Import resolution (path-candidate) | `parser-callgraph.js` | **Reference** | Ravel uses `grimp` for the import graph, which is purpose-built. Their multi-lang heuristics aren't needed (Python-only v1). |
| Call-graph assembly / definition linking | `graph-builder.js` | **Reference** | Name+import heuristic — **too imprecise for reachability**. This is exactly the accuracy gap Ravel's Jedi resolution must close. |
| **API route / entry-point detection** | `parser-routes.js` | **Port** ✅ | Flask/FastAPI/Django decorators + `urlpatterns` — directly Ravel's EntryPoint detection. The `authProtected` middleware heuristic maps onto trust (untrusted vs internal). |
| **OSV.dev CVE query** | `osv-scan.js`, `dep-scan.js` | **Port/Reference** ✅ | Clean `querybatch` usage + `getUpgradeSuggestion` (extracts fixed version from `affected.ranges.events`). Ravel plans the OSV-Scanner CLI (more robust), but this is a good fallback + the report shape is reusable. |
| **Circular deps (Tarjan's SCC)** | `circular-deps.js` | **Reference** | Real algorithm — but NetworkX gives SCC for free once Ravel has the import graph. Keep the "suggest which edge to cut" idea. |
| Dead-code heuristics + exclusion lists | `dead-code.js`, `graph-builder.js` | **Port (the lists)** ✅ | The framework-entrypoint allowlist (`main`, `create_app`, `on_startup`, migration `upgrade`/`downgrade`, `test_*`, dunders) is exactly the domain knowledge Ravel needs so it doesn't flag real entry points as dead. Feeds the §8 "rename trap". |
| Regex/substring security detection | `parser-security.js` | **Reference only** ⚠️ | This is single-file regex matching (`content.includes('eval(')`) — **the exact noise Ravel exists to replace with Semgrep/Bandit/gitleaks.** Do NOT port as a detector. Its Python taxonomy (pickle, `subprocess shell=True`, `yaml.load`, `verify=False`, weak hash, entropy scan) is a useful cross-check + normalization vocabulary. |
| Finding schema / severity ordering | `parser-security.js`, `scorer.js` | **Reference** | `{severity,title,file,path,line,endLine,desc,code}` and severity penalties inform Ravel's normalized `Finding` + ranking. |
| Parser provenance metric | `parser-core.js` (`getParserProvenance`) | **Port (the idea)** ✅ | "tree-sitter vs regex-fallback per file" reported as a stat = Ravel's non-negotiable "report graph coverage as a visible metric." |
| ~15 quality analyzers (complexity, smells, perf, a11y, memory…) | CodeClean `js/analysis/*` | **Drop for v1** | Out of Ravel's v1 scope (security triage + deps). Revisit only if a docs/quality product is added later. |
| D3 / WebGL / React UI, Web Worker source-slicing | `renderers/*`, `components/*` | **Drop** | Ravel is FastAPI + Next.js + react-flow + dagre, server-side. None of this transfers. |

---

## 4. The one honest caveat

Ravel's entire thesis is that **regex, single-file detection is the problem** —
and that a **scope-accurate graph + reachability** is the fix. Arcflow/CodeClean
are, by design, the regex/single-file/heuristic world:

- their **security detection** is substring matching, and
- their **call graph** is name+import heuristic, not resolved.

So "build Ravel *on top of* them" only works in one direction: **lift the
tedious, correct-enough domain knowledge** (route patterns, dependency-file
parsing, OSV plumbing, secret regexes, framework entry-point exclusion lists,
finding/severity vocabulary, the provenance-as-metric idea) and **rebuild the
two load-bearing parts — call-graph resolution and detection — the Ravel way**
(tree-sitter + Jedi/`ast` + grimp for the graph; Semgrep/Bandit/gitleaks/OSV for
detection). Carrying their detector or their call-graph resolver directly would
import the exact false-positive problem Ravel is meant to kill.

**Net:** they're an excellent reference implementation and a real head-start on
the boring 40% (parsing scaffold, framework patterns, deps, OSV, taxonomies).
They are not a foundation for the novel 60% (accurate reachability + triage).

---

## 5. Concrete first things to port

1. `parser-routes.js` Python section → Ravel `graph/entrypoints` (Flask/FastAPI/
   Django), plus `authProtected` → trust classification.
2. `osv-scan.js` + `getUpgradeSuggestion` → Ravel `deps` (OSV path + upgrade hints).
3. Dead-code framework-entrypoint exclusion lists → Ravel entry-point seeds and
   dead-code guardrails.
4. Python security taxonomy from `parser-security.js` → a mapping table to line
   up Semgrep/Bandit rule IDs against, for normalization + eval ground-truth.
