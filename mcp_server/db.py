import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "db" / "security.db"


def get_connection() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"security.db not found at {DB_PATH}. "
            f"Build it from db/schema.sql + db/seed.sql first."
        )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn