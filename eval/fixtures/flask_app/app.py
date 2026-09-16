"""A tiny Flask app — a real fixture for entry-point detection.

Exercises the three decorator shapes we care about: generic ``@app.route``,
``@app.route(..., methods=[...])``, and the Flask 2.0+ verb shorthand
``@app.get``. ``_helper`` is deliberately undecorated — it must not be flagged
as an entry point.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    name = request.form["user"]
    return _helper(name)


@app.get("/health")
def health():
    return "healthy"


def _helper(name):
    return name.strip()
