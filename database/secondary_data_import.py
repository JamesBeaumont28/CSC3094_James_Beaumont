import argparse
import csv
import os
import sys
import time
from collections import Counter
from import_data import db_connect, start_docker
import tldextract
import geoip2.database
import mysql.connector

# ── config ────────────────────────────────────────────────────────────────────

GEOLITE2_DB_PATH = "../ingested-data/GeoLite2-Country.mmdb"
CURLIE_FILE      = "../ingested-data/curlie_domains.csv"
UT1_DIR          = "../ingested-data/ut1"

# number of rows to update in a single db commit
BATCH_SIZE = 10_000

# ccTLDs that are used commercially and carry no geographic signal
COMMERCIAL_CCTLDS = {"tv", "io", "ai", "co", "fm", "am", "me", "ly",
                     "gg", "gl", "sh", "to", "tk", "la", "so"}

# .uk is not an ISO 3166 code, GB is the correct code for the uk
CCTLD_OVERRIDES = {"uk": "GB"}

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

# maps UT1 blocklist folder name to DIT sector
# source: https://dsi.ut-capitole.fr/blacklists/index_en.php
UT1_MAP = {
    # Leisure & Entertainment
    "adult":                "Leisure & Entertainment",
    "arjel":                "Leisure & Entertainment",
    "audio-video":          "Leisure & Entertainment",
    "celebrity":            "Leisure & Entertainment",
    "educational_games":    "Leisure & Entertainment",
    "gambling":             "Leisure & Entertainment",
    "games":                "Leisure & Entertainment",
    "manga":                "Leisure & Entertainment",
    "mixed_adult":          "Leisure & Entertainment",
    "radio":                "Leisure & Entertainment",
    "sports":               "Leisure & Entertainment",

    # IT
    "ai":                   "IT",
    "bitcoin":              "IT",
    "doh":                  "IT",
    "download":             "IT",
    "dynamic-dns":          "IT",
    "filehosting":          "IT",
    "forums":               "IT",
    "remote-control":       "IT",
    "update":               "IT",
    "vpn":                  "IT",
    "webhosting":           "IT",
    "webmail":              "IT",

    # Financial Services and Insurance
    "bank":                 "Financial Services and Insurance",
    "financial":            "Financial Services and Insurance",

    # Publishing, Printing and Photography
    "blog":                 "Publishing, Printing and Photography",
    "fakenews":             "Publishing, Printing and Photography",
    "press":                "Publishing, Printing and Photography",

    # Trade
    "lingerie":             "Trade",
    "shopping":             "Trade",

    # Restaurants, Bars, Cafes, Catering
    "cooking":              "Restaurants, Bars, Cafes, Catering",

    # Employment, Recruitment, HR
    "jobsearch":            "Employment, Recruitment, HR",

    # Project Management, Marketing and Admin
    "marketingware":        "Project Management, Marketing and Admin",
    "publicite":            "Project Management, Marketing and Admin",
    "translation":          "Project Management, Marketing and Admin",

    # Education
    "child":                "Education",
    "liste_bu":             "Education",

    # Healthcare
    # UT1 notes this category may contain misclassified pornography sites
    "sexual_education":     "Healthcare",

    # Community Groups, Social, Political and Religious
    "social_networks":      "Community Groups, Social, Political and Religious",
    "chat":                 "Community Groups, Social, Political and Religious",
    "associations_religieuses": "Community Groups, Social, Political and Religious",
    "sect":                 "Community Groups, Social, Political and Religious",

    # Personal Services
    "dating":               "Personal Services",
}

# maps new gTLDs to DIT sector
HEURISTIC_GTLD_MAP = {
    "tech": "IT", "software": "IT", "app": "IT", "cloud": "IT",
    "digital": "IT", "hosting": "IT", "website": "IT", "online": "IT",
    "email": "IT", "domains": "IT", "dev": "IT",
    "shop": "Trade", "store": "Trade", "market": "Trade", "shopping": "Trade",
    "sale": "Trade", "deals": "Trade", "buy": "Trade", "auction": "Trade",
    "bank": "Financial Services and Insurance",
    "finance": "Financial Services and Insurance",
    "insurance": "Financial Services and Insurance",
    "capital": "Financial Services and Insurance",
    "investments": "Financial Services and Insurance",
    "money": "Financial Services and Insurance",
    "fund": "Financial Services and Insurance",
    "edu": "Education", "school": "Education", "university": "Education",
    "academy": "Education", "college": "Education", "training": "Education",
    "courses": "Education",
    "gov": "Community Groups, Social, Political and Religious",
    "ngo": "Community Groups, Social, Political and Religious",
    "charity": "Community Groups, Social, Political and Religious",
    "foundation": "Community Groups, Social, Political and Religious",
    "health": "Healthcare", "clinic": "Healthcare", "dental": "Healthcare",
    "healthcare": "Healthcare", "hospital": "Healthcare", "care": "Healthcare",
    "doctor": "Healthcare", "pharmacy": "Healthcare",
    "news": "Publishing, Printing and Photography",
    "press": "Publishing, Printing and Photography",
    "media": "Publishing, Printing and Photography",
    "blog": "Publishing, Printing and Photography",
    "photo": "Publishing, Printing and Photography",
    "photography": "Publishing, Printing and Photography",
    "radio": "Leisure & Entertainment",
    "tv": "Leisure & Entertainment",
    "travel": "Tourism and Accommodation",
    "tours": "Tourism and Accommodation",
    "holiday": "Tourism and Accommodation",
    "flights": "Tourism and Accommodation",
    "law": "Legal, Public Order, Security",
    "legal": "Legal, Public Order, Security",
    "attorney": "Legal, Public Order, Security",
    "security": "Legal, Public Order, Security",
    "realestate": "Real Estate", "property": "Real Estate",
    "properties": "Real Estate", "rentals": "Real Estate",
    "house": "Real Estate", "homes": "Real Estate",
    "sport": "Leisure & Entertainment",
    "fitness": "Leisure & Entertainment", "yoga": "Leisure & Entertainment",
    "football": "Leisure & Entertainment", "casino": "Leisure & Entertainment",
    "bet": "Leisure & Entertainment", "poker": "Leisure & Entertainment",
    "racing": "Leisure & Entertainment", "golf": "Leisure & Entertainment",
    "restaurant": "Restaurants, Bars, Cafes, Catering",
    "cafe": "Restaurants, Bars, Cafes, Catering",
    "catering": "Restaurants, Bars, Cafes, Catering",
    "bar": "Restaurants, Bars, Cafes, Catering",
    "pub": "Restaurants, Bars, Cafes, Catering",
    "construction": "Construction", "build": "Construction",
    "builders": "Construction",
    "energy": "Energy and Utility Suppliers",
    "solar": "Energy and Utility Suppliers",
    "engineering": "Science and Engineering",
    "science": "Science and Engineering",
    "industries": "Manufacturing",
    "car": "Automotive", "cars": "Automotive", "auto": "Automotive",
    "beauty": "Beauty and Perfume", "salon": "Beauty and Perfume",
    "cleaning": "Cleaning and Facility Management Services",
    "jobs": "Employment, Recruitment, HR",
    "careers": "Employment, Recruitment, HR",
    "farm": "Agriculture, Forestry, Fishing",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    start_docker()
    try:
        conn = db_connect()
        cursor = conn.cursor(dictionary=True)
        write_cursor = conn.cursor()
        print("Connected to database.")
    except mysql.connector.Error as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # flush=True forces the print to display immediately rather than buffering
    print(f"Loading GeoLite2 from {GEOLITE2_DB_PATH}...", end=" ", flush=True)
    try:
        geo_reader = geoip2.database.Reader(GEOLITE2_DB_PATH)
        print("done")
    except FileNotFoundError:
        print(f"\n[ERROR] GeoLite2 database not found at '{GEOLITE2_DB_PATH}' — exiting.")
        sys.exit(1)

    print("Loading Curlie...", end=" ", flush=True)
    if not os.path.exists(CURLIE_FILE):
        print(f"\n[ERROR] Curlie dataset not found at '{CURLIE_FILE}' — exiting.")
        sys.exit(1)

    curlie_map = {}

    with open(CURLIE_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = row.get("domain", "").lower().strip()
            s = row.get("sector", "").strip()
            if d and s:
                curlie_map[d] = s
    print("Done\n")
    print("Loading UT1...", end=" ", flush=True)

    if not os.path.exists(UT1_DIR):
        print(f"\n[ERROR] UT1 dataset not found at '{UT1_DIR}/' — exiting.")
        sys.exit(1)

    ut1_map = {}
    # loads the map by ban category
    for category in os.listdir(UT1_DIR):
        cat_path     = os.path.join(UT1_DIR, category)
        domains_file = os.path.join(cat_path, "domains")
        if not os.path.isfile(domains_file):
            continue
        sector = UT1_MAP.get(category.lower())

        # skip folders not in UT1_MAP as they dont fit a sector category
        # so dont need to be loaded
        if not sector:
            continue

        try:
            with open(domains_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    domain = line.strip().lower()
                    if not domain or domain.startswith("#"):
                        continue
                    ext  = tldextract.extract(domain)
                    root = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
                    # first match wins — dont overwrite if already classified by another category
                    if root and root not in ut1_map:
                        ut1_map[root] = sector
        except Exception:
            pass

    print("\nFetching rows from good_responses...")
    cursor.execute("SELECT domain_rank, domain, ip FROM good_responses")
    rows  = cursor.fetchall()
    total = len(rows)
    print(f"Success!  {total:,} rows fetched.\n")

    # counters for summary stats at the end
    ip_cache      = {}  # stored by ip so doesnt need to scan the same IP again
    update_batch  = []
    region_counts = Counter()
    sector_counts = Counter()
    start         = time.time()

    for i, row in enumerate(rows, start=1):
        rank   = row["domain_rank"]
        domain = row["domain"]
        ip     = row.get("ip")

        # extract tld and root domain once and reuse for both region and sector
        ext = tldextract.extract(domain)
        tld = ext.suffix.split(".")[-1].lower() if ext.suffix else ""

        # region scan order: ccTLD, GeoIP
        # ccTLD is preferred as it reflects organisational geography not server location
        region = None
        if len(tld) == 2 and tld not in COMMERCIAL_CCTLDS:
            region = CCTLD_OVERRIDES.get(tld, tld.upper())
        if not region and ip:
            if ip in ip_cache:
                region = ip_cache[ip]
            else:
                try:
                    region       = geo_reader.country(ip).country.iso_code
                    ip_cache[ip] = region
                except Exception:
                    ip_cache[ip] = None

        # sector scan order: Curlie, UT1, heuristic gTLD
        root   = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
        sector = (curlie_map.get(root)
                  or ut1_map.get(root)
                  or HEURISTIC_GTLD_MAP.get(tld))

        region_counts[region or "NULL"] += 1
        sector_counts[sector or "NULL"] += 1
        update_batch.append((region, sector, rank))

        # only commit when batch is full or on the last row
        if len(update_batch) >= BATCH_SIZE or i == total:
            if not args.dry_run:
                write_cursor.executemany(
                    "UPDATE good_responses SET region=%s, sector=%s WHERE domain_rank=%s",
                    update_batch
                )
                conn.commit()
            update_batch.clear()

            elapsed   = time.time() - start
            rate      = i / elapsed if elapsed > 0 else 0
            remaining = (total - i) / rate if rate > 0 else 0
            pct       = i / total * 100
            bar_len   = 30
            filled    = int(bar_len * i / total)
            bar       = "█" * filled + "-" * (bar_len - filled)
            r_done    = total - region_counts["NULL"]
            s_done    = total - sector_counts["NULL"]
            print(
                f"\r[{bar}] {i:,}/{total:,} ({pct:.1f}%) --- "
                f"Rate={rate:.0f}/s --- "
                f"ETA={remaining/60:.1f}min --- "
                f"Region={r_done:,} --- "
                f"Sector={s_done:,}",
                end="", flush=True
            )

    print()

    elapsed = time.time() - start
    print(f"\nEnrichment complete ({total:,} rows in {elapsed:.1f}s)")
    if args.dry_run:
        print("  DRY RUN — no changes written to database")

    classified = total - region_counts["NULL"]
    print(f"\nRegion")
    print(f"  Classified        : {classified:,}  ({classified/total*100:.1f}%)")
    print(f"  NULL              : {region_counts['NULL']:,}  ({region_counts['NULL']/total*100:.1f}%)")
    print(f"\n  Top 10 regions:")
    for k, n in sorted(((k, v) for k, v in region_counts.items()
                         if k != "NULL"), key=lambda x: -x[1])[:10]:
        print(f"    {k:<25} {n:>7,}  ({n/total*100:.1f}%)")

    classified = total - sector_counts["NULL"]
    print(f"\nSector")
    print(f"  Classified        : {classified:,}  ({classified/total*100:.1f}%)")
    print(f"  NULL              : {sector_counts['NULL']:,}  ({sector_counts['NULL']/total*100:.1f}%)")
    print(f"\n  Top 10 sectors:")
    for k, n in sorted(((k, v) for k, v in sector_counts.items()
                         if k != "NULL"), key=lambda x: -x[1])[:10]:
        print(f"    {k:<55} {n:>7,}  ({n/total*100:.1f}%)")

    write_cursor.close()
    cursor.close()
    conn.close()
    geo_reader.close()


if __name__ == "__main__":
    main()