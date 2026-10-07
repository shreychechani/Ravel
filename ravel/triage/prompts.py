"""CWE-informed prompt templates and structured JSON instructions (research/04 ZeroFalse).

Prompts evaluate whether reachability-filtered findings represent genuine
vulnerabilities along the traced path, or are false positives due to defense-in-depth,
parameterization, or framework-level sanitization.
"""

from __future__ import annotations

from dataclasses import dataclass

from ravel.triage.context import AssembledContext

SYSTEM_PROMPT = """You are Ravel's security triage adjudicator.
You evaluate findings confirmed statically reachable from an untrusted entry point.
Determine whether the finding is a REAL vulnerability, a FALSE POSITIVE, or NEEDS HUMAN REVIEW.

Respond with valid JSON matching exactly this schema:
{
  "verdict": "real" | "false_positive" | "needs_review",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<concise 1-3 sentence explanation citing code specifics>"
}

Definitions:
- "real": Untrusted input reaches sink unsanitized, making code exploitable.
- "false_positive": Defensive controls (parameterization, sanitizers, type-checks) neutralize risk.
- "needs_review": Logic is ambiguous, dynamic, or insufficient context exists.

Do not include any Markdown formatting or code fences outside the JSON object.
"""


@dataclass(frozen=True)
class PromptTemplate:
    template_id: str
    focus_question: str


TEMPLATES: dict[str, PromptTemplate] = {
    "CWE-89": PromptTemplate(
        template_id="cwe-89-sqli",
        focus_question=(
            "Examine whether input reaching the query is parameterized. "
            "Does untrusted data get interpolated/concatenated directly into SQL queries "
            "without parameterized placeholders or ORM protection?"
        ),
    ),
    "CWE-78": PromptTemplate(
        template_id="cwe-78-cmdi",
        focus_question=(
            "Examine process execution calls (subprocess, os.system, popen). "
            "Is untrusted input executed in a shell (`shell=True`), or is it passed "
            "as unquoted arguments to command execution?"
        ),
    ),
    "CWE-79": PromptTemplate(
        template_id="cwe-79-xss",
        focus_question=(
            "Examine response and template rendering. "
            "Is untrusted data output into HTML/HTTP responses without auto-escaping "
            "or proper sanitization?"
        ),
    ),
    "CWE-22": PromptTemplate(
        template_id="cwe-22-path-traversal",
        focus_question=(
            "Examine filesystem operations. "
            "Can user input traverse directory boundaries (`../`) without path normalization, "
            "realpath canonicalization, or prefix boundary verification?"
        ),
    ),
    "CWE-502": PromptTemplate(
        template_id="cwe-502-deserialization",
        focus_question=(
            "Examine serialization/deserialization calls (pickle, yaml, marshal). "
            "Is untrusted data deserialized using unsafe loaders without type restrictions "
            "or digital signatures?"
        ),
    ),
    "default": PromptTemplate(
        template_id="generic-sast",
        focus_question=(
            "Examine whether the untrusted input flowing along the traced path reaches "
            "the dangerous sink in an exploitable state, or if adequate defensive checks "
            "prevent exploitation."
        ),
    ),
}


def get_template(cwe: str | None) -> PromptTemplate:
    if cwe and cwe.upper() in TEMPLATES:
        return TEMPLATES[cwe.upper()]
    return TEMPLATES["default"]


def build_triage_prompt(context: AssembledContext) -> tuple[str, str, str]:
    """Return ``(prompt, system_prompt, template_id)`` for a finding's context."""
    template = get_template(context.cwe)

    prompt = f"""Review the following reachability-filtered security finding:

{context.canonical_text}

Specific Evaluation Focus:
{template.focus_question}

Provide your structured verdict (real, false_positive, or needs_review) in JSON format.
"""
    return prompt, SYSTEM_PROMPT, template.template_id
