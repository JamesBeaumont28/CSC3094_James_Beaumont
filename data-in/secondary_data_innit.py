import os
import sys
import csv
import tarfile
import requests
import tldextract

CURLIE_RAW_FILE = "../data-in/curlie_raw.csv"
CURLIE_FILE     = "../ingested-data/curlie_domains.csv"
UT1_DIR         = "../ingested-data/ut1"
UT1_URL         = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"

# maps curlie top level category to DIT sector
CURLIE_TOP_LEVEL_MAP = {
    "arts":           "Leisure & Entertainment",
    "business":       "Project Management, Marketing and Admin",
    "computers":      "IT",
    "games":          "Leisure & Entertainment",
    "health":         "Healthcare",
    "home":           "Personal Services",
    "kids_and_teens": "Education",
    "news":           "Publishing, Printing and Photography",
    "recreation":     "Leisure & Entertainment",
    "reference":      "Education",
    "science":        "Science and Engineering",
    "shopping":       "Trade",
    "society":        "Community Groups, Social, Political and Religious",
    "sports":         "Leisure & Entertainment",
}

def process_curlie():
    print("\nCurlie/DMOZ")

    if not os.path.exists(CURLIE_RAW_FILE):
        print(f"  [ERROR] {CURLIE_RAW_FILE} not found.")
        print("  1. Go to: https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/OMV93V")
        print("  2. Download parsed-domain.csv.7z")
        print("  3. Extract and rename the file to curlie_raw.csv in this directory")
        return False

    if os.path.exists(CURLIE_FILE):
        print(f"{CURLIE_FILE} already exists.")
        print("  Skipping Curlie processing.")
        return True

    print(f"  Processing {CURLIE_RAW_FILE}...", end=" ", flush=True)
    count   = 0
    skipped = 0

    with open(CURLIE_RAW_FILE, newline="", encoding="utf-8", errors="replace") as fin, \
         open(CURLIE_FILE, "w", newline="", encoding="utf-8") as fout:

        writer = csv.writer(fout)
        writer.writerow(["domain", "raw_category", "sector"])

        for row in csv.reader(fin):
            if len(row) < 2:
                skipped += 1
                continue

            url      = row[0].strip().lower()
            category = row[1].strip()

            if not url or not category:
                skipped += 1
                continue

            ext    = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
            if not domain or domain.startswith("."):
                skipped += 1
                continue

            # category format is Top/Section/SubSection/... — take element after Top/
            parts  = category.split("/")
            top    = parts[1].lower() if len(parts) > 1 else ""
            sector = CURLIE_TOP_LEVEL_MAP.get(top)

            if not sector:
                skipped += 1
                continue

            writer.writerow([domain, category, sector])
            count += 1

    print(f"done — {count:,} entries written ({skipped:,} skipped)")
    return True

def download_ut1():
    print("\nUT1 Blacklist:")

    if os.path.exists(UT1_DIR):
        if input(f"{UT1_DIR}/ already exists. Re-download and overwrite? [y/n]: ").strip().lower() == "n":
            print("  Skipping UT1 download.")
            return True
        import shutil
        shutil.rmtree(UT1_DIR)

    tar_path = "ut1_blacklists.tar.gz"

    print(f"Downloading from {UT1_URL}...")
    try:
        r = requests.get(UT1_URL, stream=True, timeout=120)
        total_bytes = 0
        with open(tar_path, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk)
                total_bytes += len(chunk)
                print(f"Downloaded {total_bytes/1_000_000:.1f} MB...", end="\r", flush=True)
        print()
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        return False

    print("Extracting...", end=" ", flush=True)
    try:
        # UT1 extracts to blacklists/ and rename to ut1/
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(".")
        os.remove(tar_path)
        if os.path.exists("blacklists"):
            os.rename("blacklists", UT1_DIR)
        print("done")
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}")
        return False

    return True

def check_geolite2():
    print("\nGeoLite2...")

    mmdb_files = [f for f in os.listdir("../ingested-data") if f.endswith(".mmdb")]

    # will detect if file has been miss-named if so secondary_import_data wont work
    if mmdb_files:
        print(f"Found: {mmdb_files[0]}")
        if mmdb_files[0] != "GeoLite2-Country.mmdb":
            print(f"[WARN] File is named '{mmdb_files[0]}' but enrich_data.py expects "
                  f"'GeoLite2-Country.mmdb'")
    else:
        print("[ERROR] GeoLite2-Country.mmdb not found.")
        print("1. Register at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print("2. Download GeoLite2-Country.mmdb")
        print("3. Place it in directory")
        return False

    return True

def main():
    print("beggining secondary data ingest...\n")

    results = {
        "Curlie":   process_curlie(),
        "UT1":      download_ut1(),
        "GeoLite2": check_geolite2(),
    }

    print("\nSummary:")
    all_ok = True
    for name, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {name:<12} : {status}")
        if not ok:
            all_ok = False

    if all_ok:
        print("\nAll datasets ready. You can now run:")
        print("  python enrich_data.py --dry-run")
    else:
        print("\nSome datasets are missing or failed — resolve the errors above before running enrich_data.py.")


if __name__ == "__main__":
    main()