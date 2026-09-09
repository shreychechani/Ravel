"""Parse Python source into function/class nodes with tree-sitter.

Confirmed viable by reference/Arcflow/js/analysis/parser-findcalls.js, which
already drives Python via tree-sitter. Here we use it as the primary (not
fallback) parser, since v1 is Python-only.
"""

from __future__ import annotations

from typing import Any

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from ravel.core.hashing import content_hash
from ravel.ingest.loader import SourceFile
from ravel.models import Node, NodeKind

PROVENANCE = "tree-sitter:python"

_PY_LANGUAGE = Language(tspython.language())
_STRING_PREFIXES = "rbfuRBFU"


def _make_parser() -> Parser:
    try:
        return Parser(_PY_LANGUAGE)
    except TypeError:  # older py-tree-sitter API
        parser = Parser()
        parser.language = _PY_LANGUAGE
        return parser


_PARSER = _make_parser()


def _row(point: Any) -> int:
    """tree-sitter Point is row/column; support both attr and index forms."""
    return int(point.row) if hasattr(point, "row") else int(point[0])


def parse_file(source: SourceFile) -> list[Node]:
    """Extract every function and class definition from a source file."""
    data = source.content.encode("utf-8")
    tree = _PARSER.parse(data)
    out: list[Node] = []
    _walk(tree.root_node, data, source, [], out)
    return out


def _walk(node: Any, data: bytes, source: SourceFile, prefix: list[str], out: list[Node]) -> None:
    for child in node.named_children:
        if child.type in ("function_definition", "class_definition"):
            name_node = child.child_by_field_name("name")
            if name_node is None:
                _walk(child, data, source, prefix, out)
                continue
            name = data[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace")
            qname = ".".join([*prefix, name])
            kind = NodeKind.CLASS if child.type == "class_definition" else NodeKind.FUNCTION
            text = data[child.start_byte : child.end_byte]
            start_line = _row(child.start_point) + 1
            end_line = _row(child.end_point) + 1
            out.append(
                Node(
                    id=f"{source.rel_path}::{qname}::L{start_line}",
                    kind=kind,
                    qualified_name=qname,
                    file_path=source.rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    source_hash=content_hash(text),
                    docstring=_docstring(child, data),
                )
            )
            # Recurse into the body so nested defs / methods get a qualified prefix.
            _walk(child, data, source, [*prefix, name], out)
        else:
            _walk(child, data, source, prefix, out)


def _docstring(def_node: Any, data: bytes) -> str | None:
    body = def_node.child_by_field_name("body")
    if body is None:
        return None
    for stmt in body.named_children:
        if stmt.type != "expression_statement" or not stmt.named_children:
            return None  # docstring must be the first statement
        inner = stmt.named_children[0]
        if inner.type != "string":
            return None
        raw = data[inner.start_byte : inner.end_byte].decode("utf-8", "replace")
        return _clean_docstring(raw)
    return None


def _clean_docstring(raw: str) -> str | None:
    s = raw.strip()
    # Strip a string prefix (r, b, f, u and combinations) if present.
    i = 0
    while i < len(s) and s[i] in _STRING_PREFIXES:
        i += 1
    if i < len(s) and s[i] in "\"'":
        s = s[i:]
    for quote in ('"""', "'''", '"', "'"):
        if s.startswith(quote) and s.endswith(quote) and len(s) >= 2 * len(quote):
            s = s[len(quote) : -len(quote)]
            break
    return s.strip() or None
