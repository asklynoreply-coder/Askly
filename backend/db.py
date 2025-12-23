import sqlite3
from pathlib import Path

DB_PATH = Path("data.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn, open("schema.sql", "r", encoding="utf-8") as f:
        conn.executescript(f.read())
        conn.commit()

if __name__ == "__main__":
    init_db()
    print("Base initialisée.")
