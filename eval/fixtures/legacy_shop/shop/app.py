"""Order API written before Python 3.12 (see ../README.md). Never deploy."""
import datetime

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/orders", methods=["POST"])
def create_order():
    return jsonify(placed=placed_at())


def placed_at():
    # naive UTC timestamp: datetime.utcnow() is deprecated since Python 3.12
    return datetime.datetime.utcnow().isoformat()


@app.route("/today")
def today():
    return jsonify(date=datetime.datetime.now(datetime.timezone.utc).date().isoformat())
