# pygoat_views — parser regression fixture

`views.py` is `introduction/views.py` from OWASP PyGoat
(https://github.com/adeyosemanputra/pygoat) at commit `19d17cc8874861142b330636d068bbde54e86b85`,
copied unmodified under its MIT licence (`LICENSE.md`).

tree-sitter 0.26.0 segfaults while Ravel walks this file's syntax tree
(around the `@csrf_exempt` decorator on `xxe_parse`); 0.25.2 parses it.
`tests/test_parse.py` keeps it parsing in a subprocess, so a crash fails the
test instead of killing the test run.
