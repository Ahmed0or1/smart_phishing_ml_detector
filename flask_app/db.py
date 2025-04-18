import sqlite3
import os

def get_connection():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "phishing_data.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def initialize_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            long_url TEXT,
            domain TEXT,
            malicious_count INTEGER,
            suspicious_count INTEGER,
            reputation TEXT,
            creation_date TEXT,
            ssl_valid_from TEXT,
            ssl_valid_until TEXT,
            ssl_issuer TEXT,
            dns_total_records INTEGER,
            dns_key_records TEXT,
            whois_registrant TEXT,
            whois_registrar TEXT,
            whois_domain_status TEXT,
            whois_expiration_date TEXT,
            model_prediction TEXT,
            archive_url TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

if __name__ == '__main__':
    initialize_db()
    print("Database and table 'history' created successfully.")
