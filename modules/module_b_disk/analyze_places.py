"""Small CLI for manually inspecting a copied places.sqlite database."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="Path to an acquired places.sqlite copy")
    parser.add_argument("--onion", help="Optional onion-address substring to find")
    args = parser.parse_args()

    connection = sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM moz_historyvisits LIMIT 20")
        rows = cursor.fetchall()
        print(f"History row count (maximum 20 shown): {len(rows)}")
        for row in rows:
            print(row)

        if args.onion:
            cursor.execute("SELECT url FROM moz_places WHERE url LIKE ?", (f"%{args.onion}%",))
            print(cursor.fetchall())
    finally:
        connection.close()


if __name__ == "__main__":
    main()
