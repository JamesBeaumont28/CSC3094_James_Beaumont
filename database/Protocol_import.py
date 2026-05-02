import time
import mysql.connector
import subprocess

DB_CONFIG = {
    "host":     "localhost",
    "port":     3306,
    "db_name":  "survey_data_db",
    "user":     "admin",
    "password": "adminpass",
}

# PQC protocol definitions
# TLS code points included as a reference comment
PROTOCOLS = [
    # name                        key_size  type       # TLS code
    ("X25519MLKEM768",            768,      "hybrid"), # 0x11EC - NIST FIPS 203 hybrid
    ("SecP256r1MLKEM768",         768,      "hybrid"), # 0x11EB - NIST FIPS 203 hybrid
    ("SecP384r1MLKEM1024",        1024,     "hybrid"), # 0x11ED - newer hybrid, rarely implemented
    ("MLKEM512",                  512,      "pure"),   # 0x0200 - pure ML-KEM
    ("MLKEM768",                  768,      "pure"),   # 0x0201 - pure ML-KEM
    ("MLKEM1024",                 1024,     "pure"),   # 0x0202 - pure ML-KEM
    ("X25519Kyber768Draft00",     768,      "hybrid"), # 0x6399 - legacy Cloudflare/Google draft
    ("SecP256r1Kyber768Draft00",  768,      "hybrid"), # 0x639A - legacy Cloudflare/Google draft
    ("curveSM2MLKEM768",          768,      "hybrid"), # 0x11EE - Chinese hybrid protocol
]


def db_connect():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        port=DB_CONFIG["port"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["db_name"],
    )


def start_docker():
    print("Starting Docker container...")
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd="..",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[ERROR] docker compose up failed:\n{result.stderr}")
        exit(1)

    print("Waiting for DB to respond...", end="", flush=True)
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

    print("\n[ERROR] DB did not become ready in time.")
    exit(1)


def seed_protocols(cursor):
    inserted = 0
    skipped = 0

    for name, key_size, proto_type in PROTOCOLS:
        cursor.execute(
            "SELECT id FROM protocols WHERE protocol_name = %s", (name,)
        )
        row = cursor.fetchone()

        if row:
            cursor.execute(
                """
                UPDATE protocols
                SET key_size = %s, Protocol_Type = %s
                WHERE protocol_name = %s
                """,
                (key_size, proto_type, name),
            )
            print(f"  [UPDATE] '{name}' -> key_size={key_size}, type={proto_type}")
            skipped += 1
        else:
            cursor.execute(
                """
                INSERT INTO protocols (protocol_name, key_size, Protocol_Type)
                VALUES (%s, %s, %s)
                """,
                (name, key_size, proto_type),
            )
            print(f"  [INSERT] '{name}' (key_size={key_size}, type={proto_type})")
            inserted += 1

    return inserted, skipped


def main():
    start_docker()

    try:
        conn = db_connect()
        cursor = conn.cursor(dictionary=True)
    except mysql.connector.Error as err:
        print(f"[ERROR] Could not connect to database: {err}")
        exit(1)

    print(f"\nSeeding {len(PROTOCOLS)} protocols into `protocols` table...")
    inserted, skipped = seed_protocols(cursor)
    conn.commit()

    print(f"\nDone.")
    print(f"  Inserted : {inserted}")
    print(f"  Updated  : {skipped}")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()