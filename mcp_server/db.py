import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "db" / "security.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # يخلي النتائج ترجع باسم العمود
    return conn