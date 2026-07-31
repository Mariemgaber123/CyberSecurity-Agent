import sqlite3

from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "db" / "security.db"

def list_resources():
    return [
        {
            "uri": "policy://critical-device-isolation",
            "name": "Critical Device Isolation Policy"
        },
        {
            "uri": "policy://incident-closure",
            "name": "Incident Closure Policy"
        }
    ]


def read_resource(uri):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if uri == "policy://critical-device-isolation":

        cur.execute("""
            SELECT content
            FROM policies
            WHERE title='Critical Device Isolation Policy'
        """)

    elif uri == "policy://incident-closure":

        cur.execute("""
            SELECT content
            FROM policies
            WHERE title='Incident Closure Policy'
        """)

    else:
        conn.close()
        return None

    result = cur.fetchone()

    conn.close()

    if result:
        return result[0]

    return None 