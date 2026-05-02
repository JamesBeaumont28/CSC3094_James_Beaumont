from import_data import start_docker, db_connect
import mysql.connector

TABLES_IN_ORDER = [
    "response_protocols",
    "good_responses",
    "bad_responses",
    "protocols",
]


def wipe_db():
    start_docker()

    try:
        conn = db_connect()
        cursor = conn.cursor()
    except mysql.connector.Error:
        print("Could not connect to database.")
        exit(1)

    print("Wiping database...")
    for table in TABLES_IN_ORDER:
        cursor.execute(f"DROP TABLE IF EXISTS {table}")
        print(f"  Dropped table: {table}")

    conn.commit()
    cursor.close()
    conn.close()
    print("Database wiped successfully.")


if __name__ == "__main__":
    wipe_db()