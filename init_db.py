import sqlite3

conn = sqlite3.connect("db/security.db")
cur = conn.cursor()

# Create tables
with open("db/schema.sql", "r", encoding="utf-8") as f:
    cur.executescript(f.read())

# Insert seed data
with open("db/seed.sql", "r", encoding="utf-8") as f:
    cur.executescript(f.read())

conn.commit()
conn.close()

print("Database initialized successfully!")