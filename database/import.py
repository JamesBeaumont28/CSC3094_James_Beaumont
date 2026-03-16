import json
import time
from sre_constants import error

import mysql.connector
import subprocess

DB_CONFIG = {
    "host":     "localhost",
    "port":     3306,
    "db_name":   "survey_data_db",
    "user":     "admin",
    "password": "adminpass",
}

def db_connect():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["db_name"]
    )


def innit_db(cursor):

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS good_responses (
        domain_rank INT PRIMARY KEY,
        ip VARCHAR(45),
        region VARCHAR(255),
        domain VARCHAR(255) NOT NULL,
        sector VARCHAR(255),
        status VARCHAR(50) NOT NULL,
        cipher_suite VARCHAR(100),
        tls_version VARCHAR(20),
        has_pqc BOOLEAN
        )""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bad_responses (
        domain_rank INT PRIMARY KEY,
        ip VARCHAR(45),
        domain VARCHAR(255) NOT NULL,
        status VARCHAR(50) NOT NULL,
        status_detail TEXT
        )""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS protocols (
        id INT AUTO_INCREMENT PRIMARY KEY,
        protocol_name VARCHAR(255) NOT NULL,
        key_size INT,
        Protocol_Type ENUM('pure','hybrid','classical')
        )""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_protocols (
        domain_rank INT,
        protocol_id INT,
        PRIMARY KEY (domain_rank, protocol_id),
        FOREIGN KEY (domain_rank) REFERENCES good_responses(domain_rank),
        FOREIGN KEY (protocol_id) REFERENCES protocols(id)
        )""")

    print("Database initialised.")

def start_docker():
    print("Starting Docker container.")
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd="..",
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[ERROR] docker compose up failed:\n{result.stderr}")
        exit(1)

    print("Waiting for db to respond...", end="", flush=True)
    for _ in range(30):
        try:
            test = mysql.connector.connect(
                host=DB_CONFIG["host"],
                port=DB_CONFIG["port"],
                user=DB_CONFIG["user"],
                password=DB_CONFIG["password"],
            )
            test.close()
            print(" success!")
            return
        except mysql.connector.Error:
            print(".", end="", flush=True)
            time.sleep(1)


def main(
        input_file = "../pqc_results_1",
):
    start_docker()

    try:
        db_conn = db_connect()
        db_cursor = db_conn.cursor(dictionary=True)
    except mysql.connector.Error:
        print("Could not connect to database")
        exit(0)


    required_schema = {
        "good_responses" : {"rank","ip","region", "domain", "sector", "status",
                            "cipher_suite", "tls_version", "has_pqc", "pqc_groups_supported"},

        "bad_responses": {"rank", "ip", "domain", "status", "status_detail"},

        "protocols" : {"id", "protocol_name", "key_size", "Protocol_Type"},

        "response_protocols" : {"rank", "protocol_id"}
    }

    db_cursor.execute("SHOW TABLES")
    existing_tables = {row[f"Tables_in_{DB_CONFIG['db_name']}"] for row in db_cursor.fetchall()}

    if not required_schema.keys() <= existing_tables:
        print("One or more tables missing, creating database.")
        db_cursor.execute("DROP TABLE IF EXISTS response_protocols")
        db_cursor.execute("DROP TABLE IF EXISTS good_responses")
        db_cursor.execute("DROP TABLE IF EXISTS bad_responses")
        db_cursor.execute("DROP TABLE IF EXISTS protocols")
        innit_db(db_cursor)

    print("all checks sucsesfull")
    exit(1)

    with open(input_file,'r', encoding="utf-8") as file:
        for line in file:
            data = json.loads(line)
            print(data)

    pass



if __name__ == "__main__":
    main()