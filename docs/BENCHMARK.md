# Ravel — Benchmark writeup

> The last step of the build order (PRODUCT.md §10): what the numbers say, how
> to reproduce them, and what they do **not** prove yet. Numbers re-run on
> 2026-11-19 from `main`; they match the ones recorded at each checkpoint.

## In plain words

Security scanners report every suspicious line. Most of those lines can't be
reached by someone outside the app, so the real bugs are buried in noise. Ravel
maps the code, finds the "front doors" (web routes), and keeps only the
warnings a request can actually reach.

On the two repos we have labelled, scanners raised **60 warnings, 7 of them
real**. Ravel kept **7, all 7 real**, and dropped none of the real ones.
That is 8.57× the precision of reading every warning, with no recall lost.
The LLM triage layer made things **worse** with the small local model we
tried, so it ships turned off.

The sample is small (two repos, nine real bugs), and the labels were written
by the people who built Ravel. Treat these numbers as an early signal, not as
proof. The open items are at the end.

## Reproduce

```sh
uv run python -m eval.run                          # Phase 3: reachability
uv run python -m eval.graph_checkpoint --venv <v>  # Phase 1: graph, 42 cases
uv run python -m eval.pycg_bench                   # PyCG micro-benchmark
uv run python -m eval.dynamic_recall --venv <v>     # dynamic-oracle recall
uv run python -m eval.run --triage --llm-provider ollama --model llama3.2:3b
```

Repos are pinned by commit SHA in `eval/ground_truth/*_vulns.toml`, each with a
virtualenv built from its pinned requirements. Scanned code is never executed.
The dynamic-oracle check is the one exception: it is eval-only and runs
flaskr's own tests on a throwaway copy.

## 1. The graph is correct enough to build on

Everything below depends on the call graph, so it was checked first.

| Check | Result | Gate |
|---|---|---|
| flaskr hand-checked cases (`eval/ground_truth/flaskr_graph.toml`) | **42 / 42**, edge precision 100%, edge recall 100% | ~20 cases |
| Call-site coverage on flaskr | **81.6%** (151 / 185) | ≥ 80% |
| PyCG micro-benchmark (119 programs) | precision **98.3%**, recall **71.2%** | ratchet in CI |
| Dynamic oracle (flaskr's own tests) | **35 / 39** observed calls recovered (89.7%) | — |

Unresolved calls are kept and marked `unknown`, never dropped (§6). On PyCG,
16 misses are still *silent*, meaning there is no edge and no `unknown` marker.
Most come from implicit `__iter__`/`__next__` in `for` loops. These are listed
in BUILD-PLAN Phase 1.

## 2. Reachability: the decision gate (Phase 3) — PASS

| Method | Kept | True pos. | Precision | Recall retained | End-to-end recall |
|---|---:|---:|---:|---:|---:|
| keep-all (raw scanners) | 60 | 7 | 11.7% | 100% | 55.6% |
| severity ≥ medium | 16 | 6 | 37.5% | 100% | 55.6% |
| random-N (same N as Ravel) | 7.0 | 2.2 | 32.0% | 39.9% | 22.2% |
| **Ravel (reachable + unknown)** | **7** | **7** | **100%** | **100%** | **55.6%** |

Pooled over **vulpy-bad** (an intentionally vulnerable Flask app with 9 labelled
bugs and 22 findings, coverage 97.5%) and **flaskr** (Flask's tutorial app,
no known bugs, 38 findings, coverage 81.6%). Gate: ≥ 3× precision while keeping
≥ 85% recall. Result: **×8.57, recall retained 100%.**

How to read it:

- **flaskr measures noise.** All 38 findings are false positives: 35 are
  `assert` in test files, and the rest are the tutorial's documented dev
  placeholders. Ravel marks all 38 unreachable. No scanner rule was suppressed
  to get there.
- **Severity filtering is the cheap alternative, and it does worse.** It keeps
  16 findings and loses one true positive. Ravel keeps 7 and loses none.
- **Random-N is the sanity check.** Keeping 7 findings at random retains only
  40% of the real cases, so the gain comes from the graph and not from keeping
  fewer findings.
- **End-to-end recall is 55.6% (5 / 9), and Ravel can't change that.**
  Ravel only filters, so it can't find a bug that no scanner reported. On
  vulpy, no scanner flagged the unsigned session cookie, template XSS, CSRF or
  brute force. Template XSS needs Semgrep with user-supplied rules, and Semgrep
  was not installed for this run (it is reported as such, never silently
  skipped).
- **Phase 5 change, eval unchanged.** Dependency advisories that are imported
  but used only through unresolved calls are now `unknown` instead of
  `unreachable`. The numbers above were the same before and after that change.

## 3. LLM triage (Phase 4) — FAIL, ships disabled

With `llama3.2:3b` through Ollama, triage called one real SQL injection a
false positive (it read `'%s' %` formatting as a parameterised query). Recall
retained fell from **100% to 80%**, with no precision gain because Ravel's
list was already 100% precise. PRODUCT.md §10 says a component that adds
nothing ships disabled, so `--no-triage` is the default. Verdicts are still
cached by a hash of the assembled context, and are budget-capped, so the
retest with a stronger model costs one command.

## 4. Dependency report (Phase 5)

There is no labelled benchmark for this part yet. It is checked by the
planted fixture `eval/fixtures/legacy_shop`, whose expected answers are in its
README and in the tests. On `django_app`, OSV reports 46 advisories (37 in
Django 3.2, including critical SQLi CVE-2021-35042, and 9 in sqlparse via
Django). Each is classified by reachability.

## What this does not prove yet

These are listed here so the result isn't read as stronger than it is (§6):

1. **Two repos, nine real bugs.** One small honest mistake moves these
   percentages a lot. At least one more labelled real-world repo is needed.
   OWASP PyGoat is already scanned but has no labels yet.
2. **We marked our own homework.** vulpy's labels were written *after* we saw
   Ravel's output, under a rule fixed in advance (see the header of
   `vulpy_bad_vulns.toml`). The flaskr graph ground truth gained 12 edges after
   the first run. Both need an independent re-check by someone who did not
   build reachability or triage (AGENTS.md §6, PRODUCT.md §10).
3. **Routes only.** Entry points are Flask, FastAPI and Django HTTP routes.
   CLI scripts, task queues and other entry points aren't detected, so code
   reached only through them shows as unreachable.
4. **Triage was tested with only one small model.** The failure says
   nothing about larger models yet.
5. **Semgrep was not part of this run.** A run with a local Semgrep rule set
   would raise keep-all recall on vulpy (template XSS). It would also show
   whether Ravel keeps findings that have no Python node: they are kept, and
   counted as `non_python`.
