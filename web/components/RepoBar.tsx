"use client";

import { useState } from "react";

const EXAMPLES: { label: string; target: string; ref?: string; note: string }[] = [
  { label: "Demo shop", target: "eval/fixtures/vuln_shop", note: "planted bugs · local" },
  {
    label: "vulpy",
    target: "https://github.com/fportantier/vulpy",
    ref: "5249cc8b05a1c37f6b2f757b1cf16a509c327122",
    note: "vulnerable Flask app",
  },
  { label: "PyGoat", target: "https://github.com/adeyosemanputra/pygoat", note: "OWASP Django labs" },
  { label: "Flask tutorial", target: "eval/fixtures/flaskr", note: "no known bugs · local" },
];

/** Where the user says what to scan: a git URL or a local folder, like Arcflow's URL bar. */
export function RepoBar({
  initial,
  busy,
  onOpen,
  large = false,
}: {
  initial?: string | null;
  busy: boolean;
  onOpen: (target: string, ref: string, venv: string) => void;
  large?: boolean;
}) {
  const [target, setTarget] = useState(initial ?? "");
  const [ref, setRef] = useState("");
  const [venv, setVenv] = useState("");
  const [more, setMore] = useState(false);
  const submit = () => target.trim() && onOpen(target.trim(), ref.trim(), venv.trim());

  return (
    <div className="flex w-full flex-col gap-2">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className={`flex w-full items-center gap-2 rounded-xl border border-line bg-card shadow-sm focus-within:border-ink ${large ? "p-2" : "p-1"}`}
      >
        <span className="pl-2 text-muted" aria-hidden>
          ⌕
        </span>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="github.com/owner/repo  or  /path/to/project"
          className={`min-w-0 flex-1 bg-transparent font-mono outline-none ${large ? "py-2 text-base" : "py-1 text-sm"}`}
          aria-label="Repository URL or folder"
        />
        <button
          type="button"
          onClick={() => setMore(!more)}
          className="rounded-lg px-2 py-1 text-xs text-muted hover:text-ink"
          title="Commit / branch and virtualenv"
        >
          {more ? "less" : "options"}
        </button>
        <button
          type="submit"
          disabled={busy || !target.trim()}
          className={`rounded-lg bg-ink font-semibold text-paper disabled:opacity-40 ${large ? "px-5 py-2.5" : "px-4 py-1.5 text-sm"}`}
        >
          {busy ? "Scanning…" : "Scan"}
        </button>
      </form>
      {more && (
        <div className="flex flex-wrap gap-2 text-sm">
          <input
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            placeholder="commit, tag or branch (URLs only)"
            className="min-w-[220px] flex-1 rounded-lg border border-line bg-card px-3 py-1.5 font-mono outline-none focus:border-ink"
          />
          <input
            value={venv}
            onChange={(e) => setVenv(e.target.value)}
            placeholder="the repo's virtualenv, for full coverage (optional)"
            className="min-w-[280px] flex-[2] rounded-lg border border-line bg-card px-3 py-1.5 font-mono outline-none focus:border-ink"
          />
        </div>
      )}
      {large && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted">Try:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.label}
              disabled={busy}
              onClick={() => {
                setTarget(ex.target);
                setRef(ex.ref ?? "");
                onOpen(ex.target, ex.ref ?? "", "");
              }}
              className="rounded-full border border-line bg-card px-3 py-1 hover:border-ink disabled:opacity-40"
            >
              <b>{ex.label}</b> <span className="text-muted">· {ex.note}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
