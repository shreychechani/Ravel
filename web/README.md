# Ravel web view

A single page for one scan report: ranked findings, the traced path from an
untrusted entry point to each one (react-flow + dagre), and the AI review.

It is a static export served by `ravel serve` on 127.0.0.1, which also provides
the `/api/report` and `/api/scan` endpoints the page calls.

```bash
npm --prefix web install
npm --prefix web run build          # writes web/out
uv run ravel serve <repo> --venv <repo's virtualenv>
```

The report shape is defined in `ravel/report.py`; `lib/report.ts` mirrors it.
