# Vendored benchmark: PyCG micro-benchmark

Ground-truth call graphs for 119 small Python programs in 18 categories, from
the PyCG paper (Salis et al., "PyCG: Practical Call Graph Generation in
Python", ICSE 2021, https://arxiv.org/abs/2103.00587). Copied **unmodified**.

- Upstream: https://github.com/vitsalis/PyCG — `micro-benchmark/snippets/`
- Pinned commit: `8d5dc40837803beef1d8d379fbf2cdad6cd94641` (repo archived)
- License: Apache-2.0 (`LICENCE`)

Each case is `snippets/<category>/<case>/` with `main.py` (plus any imported
modules) and `callgraph.json`: `{caller: [every callee]}`, names
module-qualified (`main.MyClass.func`), module-level code as the module name
(`main`). Scored by `eval/pycg_bench.py`.
