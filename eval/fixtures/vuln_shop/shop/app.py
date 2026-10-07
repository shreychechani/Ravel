"""Planted-vulnerability shop API (see ../README.md). Never deploy."""
import pickle
import subprocess

from flask import Flask, request

from shop.db import find_product, find_product_safe

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return str(find_product(term))


@app.route("/search-safe")
def search_safe():
    term = request.args.get("q", "")
    return str(find_product_safe(term))


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    return run_ping(host)


def run_ping(host):
    # unsanitized host goes straight into a shell
    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()


@app.route("/cart", methods=["POST"])
def load_cart():
    return str(pickle.loads(request.get_data()))
