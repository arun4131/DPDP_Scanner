#!/usr/bin/env python3
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

DB_NAME = "obfuscated_pii_test"
HOST = "localhost"
PORT = 5433
USER = "apple"
PASSWORD = ""

def create_database():
    conn = psycopg2.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, dbname="postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS {DB_NAME};")
    cur.execute(f"CREATE DATABASE {DB_NAME};")
    cur.close()
    conn.close()
    print(f"> Created database {DB_NAME}")

def seed_data():
    conn = psycopg2.connect(host=HOST, port=PORT, user=USER, password=PASSWORD, dbname=DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE obfuscated_user_data (
            id SERIAL PRIMARY KEY,
            col_01 VARCHAR(100), -- Bank Account Numbers
            col_02 VARCHAR(10),  -- CVVs
            col_03 VARCHAR(20),  -- Cheque Numbers
            col_04 VARCHAR(30),  -- UAN Numbers
            col_05 VARCHAR(50),  -- FASTag IDs
            col_06 VARCHAR(50),  -- Loan Account Numbers
            col_07 VARCHAR(20),  -- MICR Codes
            col_08 VARCHAR(50),  -- Aadhaar Numbers
            col_09 VARCHAR(20),  -- PAN Numbers
            col_10 VARCHAR(100)  -- Emails
        );
    """)

    # Seed 100 rows of test data
    for i in range(1, 101):
        bank_acct = f"912345678{i:03d}"           # 12-digit bank account number
        cvv = f"{(i % 900) + 100}"              # 3-digit CVV
        cheque_no = f"100{i:03d}"                # 6-digit cheque number
        uan = f"100987654{i:03d}"               # 12-digit UAN number
        fastag = f"FT1234567890{i:04d}"          # FASTag ID
        loan_acct = f"LN-9876543{i:03d}"         # Loan account number
        micr = f"400240{i:03d}"                 # 9-digit MICR code
        aadhaar = f"2345 6789 {1000 + i}"       # Valid 12-digit Aadhaar
        pan = f"ABCDE{1000 + i}F"               # Valid PAN format
        email = f"user_{i}@example.com"         # Valid Email

        cur.execute("""
            INSERT INTO obfuscated_user_data
            (col_01, col_02, col_03, col_04, col_05, col_06, col_07, col_08, col_09, col_10)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """, (bank_acct, cvv, cheque_no, uan, fastag, loan_acct, micr, aadhaar, pan, email))

    conn.commit()
    cur.close()
    conn.close()
    print("> Successfully seeded 100 rows of obfuscated test data!")

if __name__ == "__main__":
    create_database()
    seed_data()
