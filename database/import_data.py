import json
import time
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
        status VARCHAR(50) NOT NULL
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
        input_file = "../results/pqc_results_1.jsonl",
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

    print("all checks successful, database ready.")
    #exit(1)

    # variables to count rows inserted into each table in the DB
    good_count = 0
    bad_count = 0
    skip_count = 0

    good_rows = []
    bad_rows = []
    proto_links = []

    failed_file = f"failed_imports.csv"
    failed_rows = []

    def commit(force=False):
        # commits batch to db
        nonlocal good_count, bad_count, skip_count

        # only runs if there are 10000 results or if force is true
        if len(good_rows) + len(bad_rows) < 10000 and not force:
            return

        # if no good rows where found so good_rows is empty it will not run
        if good_rows:
            try:
                db_cursor.executemany("""
                        INSERT INTO good_responses
                            (domain_rank, ip, domain, status, cipher_suite, tls_version, has_pqc)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, good_rows)
                good_count += db_cursor.rowcount
            except mysql.connector.Error as err:
                print(f"  [WARN] Could not connect to database, failed to commit - {err}")
                exit(0)
            good_rows.clear()

        if bad_rows:
            try:
                db_cursor.executemany("""
                        INSERT INTO bad_responses
                            (domain_rank, ip, domain, status)
                        VALUES (%s, %s, %s, %s)
                    """, bad_rows)
                bad_count += db_cursor.rowcount
            except mysql.connector.Error as err:
                print(f"  [WARN] Could not connect to database, failed to commit - {err}")
                exit(0)
            bad_rows.clear()

        if proto_links:
            for domain_rank, protocol_name in proto_links:
                try:
                    # look up protocol, insert if it's new
                    db_cursor.execute(
                        "SELECT id FROM protocols WHERE protocol_name = %s", (protocol_name,)
                    )
                    row = db_cursor.fetchone()
                    if row:
                        proto_id = row["id"]
                    else:
                        db_cursor.execute(
                            "INSERT INTO protocols (protocol_name, key_size) VALUES (%s, NULL)",
                            (protocol_name,)
                        )
                        proto_id = db_cursor.lastrowid

                    db_cursor.execute(
                        "INSERT INTO response_protocols (domain_rank, protocol_id) VALUES (%s, %s)",
                        (domain_rank, proto_id))

                except mysql.connector.Error as err:
                    print(f"  [WARN] Could not connect to database, failed to commit - {err}")
                    exit(0)
            proto_links.clear()

        db_conn.commit()
        print(f"  committed batch - good_responses: {good_count:,}  bad_responses: {bad_count:,}")


    print(f"Reading {input_file} ...")
    with open(input_file, 'r', encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [WARN] Line {line_num}: invalid JSON - {e}")
                exit(0)

            rank = data.get("rank", "?")
            domain = data.get("domain", "?")

            # check key data for classification is present otherwise would cause error in code or db
            if not all(k in data for k in ("rank", "domain", "status")):
                failed_rows.append((rank, domain))
                skip_count += 1
                continue

            if data["status"] == "ok":
                good_rows.append((
                    data["rank"],
                    data.get("ip"),
                    data["domain"],
                    data["status"],
                    data.get("cipher_suite"),
                    data.get("tls_version"),

                    data.get("has_pqc"),
                ))
                for proto_name in data.get("pqc_groups_supported") or []:
                    proto_links.append((data["rank"], proto_name))
            else:
                bad_rows.append((
                    data["rank"],
                    data.get("ip"),
                    data["domain"],
                    data["status"],
                ))
            # only runs at 10000 records
            commit()
    # flushes remaining results
    commit(force=True)

    # writes all the rows that were incorrectly formated to a csv to be rescanned
    if failed_rows:
        with open(failed_file, "w", encoding="utf-8") as f:
            for rank, domain in failed_rows:
                f.write(f"{rank} {domain}\n")
        print(f"\n  {len(failed_rows):,} failed records written to {failed_file}")
    else:
        print("\n  No failed records.")

    print(f"\nImport complete:")
    print(f"  good_responses : {good_count:,}")
    print(f"  bad_responses  : {bad_count:,}")
    print(f"  skipped        : {skip_count:,}")

    db_cursor.close()
    db_conn.close()


if __name__ == "__main__":
    main()