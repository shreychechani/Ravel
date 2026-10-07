"""The web view's backend: one scan report, served on localhost.

Local-first (PRODUCT.md §6): ``ravel serve`` binds to 127.0.0.1 only, reads the
repo, and never writes to it. The report is the same document ``ravel scan
--json`` writes (``ravel.report``), so the browser shows exactly what the CLI
measured. A rescan can switch LLM triage on or off; triage still runs only on
reachability survivors, cached and budget-capped, because it goes through the
same ``scan_repo`` path as the CLI.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ravel.core.logging import get_logger

log = get_logger("ravel.api.server")

Report = dict[str, Any]
ScanFn = Callable[[bool], Report]  # triage on/off -> report

_NO_UI = """<!doctype html><meta charset="utf-8"><title>Ravel</title>
<body style="font-family:system-ui;max-width:640px;margin:64px auto;line-height:1.5">
<h1>Ravel API is running</h1>
<p>The web view has not been built yet. From the repository root run:</p>
<pre>npm --prefix web install
npm --prefix web run build</pre>
<p>then restart <code>ravel serve</code>. The raw report is at
<a href="/api/report">/api/report</a>.</p></body>"""


class ScanRequest(BaseModel):
    triage: bool = False


class ReportStore:
    """Holds the current report; scans lazily and one at a time."""

    def __init__(self, scan: ScanFn | None = None, report: Report | None = None) -> None:
        if scan is None and report is None:
            raise ValueError("ReportStore needs a scan function or a fixed report")
        self._scan = scan
        self._report = report
        self._lock = threading.Lock()

    @property
    def can_rescan(self) -> bool:
        return self._scan is not None

    def get(self) -> Report:
        with self._lock:
            if self._report is None:
                assert self._scan is not None
                self._report = self._scan(False)
            return self._report

    def rescan(self, triage: bool) -> Report:
        if self._scan is None:
            raise RuntimeError("this report was loaded from a file; there is no repo to rescan")
        with self._lock:
            self._report = self._scan(triage)
            return self._report


def load_report(path: Path) -> Report:
    data: Report = json.loads(path.read_text(encoding="utf-8"))
    if "findings" not in data:
        raise ValueError(f"{path} is not a Ravel scan report (no 'findings')")
    return data


def create_app(store: ReportStore, ui_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Ravel", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True, "can_rescan": store.can_rescan}

    @app.get("/api/report")
    def report() -> Report:
        return store.get()

    @app.post("/api/scan")
    def scan(req: ScanRequest) -> Report:
        if not store.can_rescan:
            raise HTTPException(409, "report loaded from a file; start ravel serve on a repo")
        try:
            return store.rescan(req.triage)
        except Exception as exc:  # surfaced to the UI, never swallowed
            log.warning("rescan failed: %s", exc)
            raise HTTPException(500, f"scan failed: {exc}") from exc

    if ui_dir is not None and (ui_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")
    else:

        @app.get("/", response_class=HTMLResponse)
        def no_ui() -> str:
            return _NO_UI

    return app
