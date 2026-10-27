import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    cur = sqlite3.connect("shop.db").cursor()
    cur.execute(f"SELECT * FROM orders WHERE customer = '{request.args['name']}'")
    return {"orders": cur.fetchall()}


if __name__ == "__main__":
    app.run(debug=True)
