"""
One-time (or reset-anytime) setup script.

This is DIFFERENT from mcp_server/db.py:
  - init_db.py  (this file) -> BUILDS security.db from schema.sql + seed.sql
  - mcp_server/db.py        -> only OPENS a connection to security.db
                                (assumes it already has tables + data)

Run this whenever you want to (re)create the database from scratch:
    cd db
    python init_db.py

Or from the project root:
    python db/init_db.py
"""

import sqlite3
from pathlib import Path

# This file lives in db/, so everything is relative to this folder.
DB_DIR = Path(__file__).parent
SCHEMA_PATH = DB_DIR / "schema.sql"
SEED_PATH = DB_DIR / "seed.sql"
DB_PATH = DB_DIR / "security.db"


def init_db():
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"schema.sql not found at {SCHEMA_PATH}")
    if not SEED_PATH.exists():
        raise FileNotFoundError(f"seed.sql not found at {SEED_PATH}")

    conn = sqlite3.connect(DB_PATH)

    print(f"Building schema from {SCHEMA_PATH} ...")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    print(f"Loading seed data from {SEED_PATH} ...")
    with open(SEED_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    conn.commit()

    # Quick sanity check so you SEE it worked, not just hope it did.
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print("Tables created:", tables)

    for table in ("users", "devices", "incidents", "policies"):
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        print(f"  {table}: {count} row(s)")

    conn.close()
    print(f"\nDatabase ready at: {DB_PATH}")


if __name__ == "__main__":
    init_db()