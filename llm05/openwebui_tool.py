"""
title: LLM05 Order Lookup
description: Demo nastroj pro LLM05 (Improper Output Handling). Vyhledava objednavky prihlaseneho zakaznika ve fiktivni databazi.
version: 0.1
"""

import json
import sqlite3

from pydantic import BaseModel, Field

# Fiktivni data, databaze se vytvari v pameti pri kazdem volani (nic se neuklada ani nemaze).
ORDERS = [
    (1001, "Jan Novak", "Notebook Lenovo", 18990, "Brno, Kounicova 12"),
    (1002, "Jan Novak", "Mys Logitech", 590, "Brno, Kounicova 12"),
    (1003, "Maria Horvath", "Telefon Samsung", 12490, "Praha, Vinohradska 45"),
    (1004, "Maria Horvath", "Notebook Dell", 24990, "Praha, Vinohradska 45"),
    (1005, "Petr Svoboda", "Monitor LG", 5490, "Ostrava, Nadrazni 8"),
    (1006, "Eva Kralova", "Tablet Apple", 15990, "Olomouc, Masarykova 3"),
]

LOGGED_IN_CUSTOMER = "Jan Novak"


def _create_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE orders (id INTEGER, customer TEXT, product TEXT, price INTEGER, address TEXT)"
    )
    conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", ORDERS)
    return conn


class Tools:
    class Valves(BaseModel):
        mode: str = Field(
            default="vulnerable",
            description="vulnerable = vystup modelu se vklada primo do SQL, guarded = parametrizovany dotaz",
        )

    def __init__(self):
        self.valves = self.Valves()

    def search_my_orders(self, product: str) -> str:
        """
        Search the logged-in customer's orders by product name.
        :param product: Product name or part of it, e.g. "Notebook".
        :return: JSON with the executed query and the matching orders.
        """
        conn = _create_db()
        try:
            if self.valves.mode == "guarded":
                query = "SELECT id, customer, product, price, address FROM orders WHERE customer = ? AND product LIKE ?"
                rows = conn.execute(
                    query, (LOGGED_IN_CUSTOMER, f"%{product}%")
                ).fetchall()
            else:
                query = (
                    "SELECT id, customer, product, price, address FROM orders "
                    f"WHERE customer = '{LOGGED_IN_CUSTOMER}' AND product LIKE '%{product}%'"
                )
                rows = conn.execute(query).fetchall()
        except sqlite3.Error as e:
            return json.dumps(
                {"mode": self.valves.mode, "query": query, "error": str(e)},
                ensure_ascii=False,
            )
        finally:
            conn.close()

        orders = [
            {
                "id": r[0],
                "customer": r[1],
                "product": r[2],
                "price_czk": r[3],
                "address": r[4],
            }
            for r in rows
        ]
        return json.dumps(
            {"mode": self.valves.mode, "query": query, "orders": orders},
            ensure_ascii=False,
        )
