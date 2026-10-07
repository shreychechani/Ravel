"""Database helpers."""
import sqlite3


def find_product(term):
    conn = sqlite3.connect("shop.db")
    query = "SELECT * FROM products WHERE name = '%s'" % term
    return conn.execute(query).fetchall()


def find_product_safe(term):
    conn = sqlite3.connect("shop.db")
    query = "SELECT * FROM products WHERE name = ?"
    return conn.execute(query, (term,)).fetchall()
