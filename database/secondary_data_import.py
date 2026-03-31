import argparse
import csv
import ipaddress
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

# known CDN IP ranges — if the IP falls in one of these the site is CDN-hosted
# source: each provider's published IP list (Cloudflare, AWS, Fastly, Akamai, Google, Azure)
CDN_IP_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "54.230.0.0/16", "64.252.64.0/18", "64.252.128.0/18",
        "99.84.0.0/16", "205.251.192.0/19", "216.137.32.0/19",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "104.156.80.0/20",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ],
    "Akamai": [
        "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
        "72.246.0.0/15", "95.100.0.0/15", "184.24.0.0/13", "184.84.0.0/14",
    ],
    "Google": [
        "8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "35.186.0.0/16",
        "35.190.0.0/17", "66.102.0.0/20", "74.125.0.0/16",
        "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
    ],
    "Azure": [
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/11",
        "40.64.0.0/10", "52.96.0.0/12", "52.224.0.0/11",
        "104.40.0.0/13", "104.208.0.0/13",
    ],
}

# maps ISO 3166-1 alpha-2 country code to continent name
# used to derive continent from ccTLD-based region codes
ISO_TO_CONTINENT = {
    # Europe
    "AD": "Europe", "AL": "Europe", "AT": "Europe", "BA": "Europe",
    "BE": "Europe", "BG": "Europe", "BY": "Europe", "CH": "Europe",
    "CY": "Europe", "CZ": "Europe", "DE": "Europe", "DK": "Europe",
    "EE": "Europe", "ES": "Europe", "FI": "Europe", "FR": "Europe",
    "GB": "Europe", "GR": "Europe", "HR": "Europe", "HU": "Europe",
    "IE": "Europe", "IS": "Europe", "IT": "Europe", "LI": "Europe",
    "LT": "Europe", "LU": "Europe", "LV": "Europe", "MC": "Europe",
    "MD": "Europe", "ME": "Europe", "MK": "Europe", "MT": "Europe",
    "NL": "Europe", "NO": "Europe", "PL": "Europe", "PT": "Europe",
    "RO": "Europe", "RS": "Europe", "RU": "Europe", "SE": "Europe",
    "SI": "Europe", "SK": "Europe", "SM": "Europe", "UA": "Europe",
    "VA": "Europe", "XK": "Europe",
    # North America
    "AG": "North America", "BB": "North America", "BL": "North America",
    "BM": "North America", "BS": "North America", "BZ": "North America",
    "CA": "North America", "CR": "North America", "CU": "North America",
    "DM": "North America", "DO": "North America", "GD": "North America",
    "GL": "North America", "GP": "North America", "GT": "North America",
    "HN": "North America", "HT": "North America", "JM": "North America",
    "KN": "North America", "KY": "North America", "LC": "North America",
    "MF": "North America", "MQ": "North America", "MS": "North America",
    "MX": "North America", "NI": "North America", "PA": "North America",
    "PM": "North America", "PR": "North America", "SV": "North America",
    "TC": "North America", "TT": "North America", "US": "North America",
    "VC": "North America", "VG": "North America", "VI": "North America",
    # South America
    "AR": "South America", "BO": "South America", "BR": "South America",
    "CL": "South America", "CO": "South America", "EC": "South America",
    "FK": "South America", "GF": "South America", "GY": "South America",
    "PE": "South America", "PY": "South America", "SR": "South America",
    "UY": "South America", "VE": "South America",
    # Asia
    "AE": "Asia", "AF": "Asia", "AM": "Asia", "AZ": "Asia",
    "BD": "Asia", "BH": "Asia", "BN": "Asia", "BT": "Asia",
    "CN": "Asia", "CY": "Asia", "GE": "Asia", "HK": "Asia",
    "ID": "Asia", "IL": "Asia", "IN": "Asia", "IQ": "Asia",
    "IR": "Asia", "JO": "Asia", "JP": "Asia", "KG": "Asia",
    "KH": "Asia", "KP": "Asia", "KR": "Asia", "KW": "Asia",
    "KZ": "Asia", "LA": "Asia", "LB": "Asia", "LK": "Asia",
    "MM": "Asia", "MN": "Asia", "MO": "Asia", "MV": "Asia",
    "MY": "Asia", "NP": "Asia", "OM": "Asia", "PH": "Asia",
    "PK": "Asia", "PS": "Asia", "QA": "Asia", "SA": "Asia",
    "SG": "Asia", "SY": "Asia", "TH": "Asia", "TJ": "Asia",
    "TL": "Asia", "TM": "Asia", "TR": "Asia", "TW": "Asia",
    "UZ": "Asia", "VN": "Asia", "YE": "Asia",
    # Africa
    "AO": "Africa", "BF": "Africa", "BI": "Africa", "BJ": "Africa",
    "BW": "Africa", "CD": "Africa", "CF": "Africa", "CG": "Africa",
    "CI": "Africa", "CM": "Africa", "CV": "Africa", "DJ": "Africa",
    "DZ": "Africa", "EG": "Africa", "EH": "Africa", "ER": "Africa",
    "ET": "Africa", "GA": "Africa", "GH": "Africa", "GM": "Africa",
    "GN": "Africa", "GQ": "Africa", "GW": "Africa", "KE": "Africa",
    "KM": "Africa", "LR": "Africa", "LS": "Africa", "LY": "Africa",
    "MA": "Africa", "MG": "Africa", "ML": "Africa", "MR": "Africa",
    "MU": "Africa", "MW": "Africa", "MZ": "Africa", "NA": "Africa",
    "NE": "Africa", "NG": "Africa", "RW": "Africa", "SC": "Africa",
    "SD": "Africa", "SL": "Africa", "SN": "Africa", "SO": "Africa",
    "SS": "Africa", "ST": "Africa", "SZ": "Africa", "TD": "Africa",
    "TG": "Africa", "TN": "Africa", "TZ": "Africa", "UG": "Africa",
    "ZA": "Africa", "ZM": "Africa", "ZW": "Africa",
    # Oceania
    "AU": "Oceania", "FJ": "Oceania", "FM": "Oceania", "GU": "Oceania",
    "KI": "Oceania", "MH": "Oceania", "MP": "Oceania", "NC": "Oceania",
    "NR": "Oceania", "NZ": "Oceania", "PF": "Oceania", "PG": "Oceania",
    "PW": "Oceania", "SB": "Oceania", "TK": "Oceania", "TO": "Oceania",
    "TV": "Oceania", "VU": "Oceania", "WF": "Oceania", "WS": "Oceania",
}

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

    print("Building CDN IP lookup...", end=" ", flush=True)
    cdn_networks = [
        (ipaddress.ip_network(prefix), cdn_name)
        for cdn_name, prefixes in CDN_IP_RANGES.items()
        for prefix in prefixes
    ]
    print("done")

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
    for category in os.listdir(UT1_DIR):
        cat_path     = os.path.join(UT1_DIR, category)
        domains_file = os.path.join(cat_path, "domains")
        if not os.path.isfile(domains_file):
            continue
        sector = UT1_MAP.get(category.lower())
        # skip folders not in UT1_MAP as they dont fit a sector category
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
    print("Done\n")

    print("\nFetching rows from good_responses...")
    cursor.execute("SELECT domain_rank, domain, ip FROM good_responses")
    rows  = cursor.fetchall()
    total = len(rows)
    print(f"Success!  {total:,} rows fetched.\n")

    # counters for summary stats at the end
    ip_cache = {}  # cached by ip so doesnt need to scan the same IP again
    update_batch = []
    region_counts = Counter()
    sector_counts = Counter()
    continent_counts = Counter()
    cdn_counts = Counter()
    start = time.time()

    for i, row in enumerate(rows, start=1):
        rank   = row["domain_rank"]
        domain = row["domain"]
        ip     = row.get("ip")

        # extract tld and root domain once and reuse for both region and sector
        ext = tldextract.extract(domain)
        tld = ext.suffix.split(".")[-1].lower() if ext.suffix else ""

        cdn_provider = None
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
                cdn_provider = next(
                    (name for network, name in cdn_networks if addr in network), None
                )
            except ValueError:
                pass

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

        # derive continent from the resolved region ISO code
        continent = ISO_TO_CONTINENT.get(region) if region else None

        # sector scan order: Curlie, UT1, heuristic gTLD
        root   = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
        sector = (curlie_map.get(root)
                  or ut1_map.get(root)
                  or HEURISTIC_GTLD_MAP.get(tld))

        region_counts[region or "NULL"]  += 1
        sector_counts[sector or "NULL"]  += 1
        continent_counts[continent or "NULL"] += 1
        cdn_counts[cdn_provider or "NULL"] += 1
        update_batch.append((region, sector, continent, cdn_provider, rank))

        # only commit when batch is full or on the last row
        if len(update_batch) >= BATCH_SIZE or i == total:
            if not args.dry_run:
                write_cursor.executemany(
                    "UPDATE good_responses SET region=%s, sector=%s, continent=%s, cdn_provider=%s WHERE domain_rank=%s",
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

    classified = total - continent_counts["NULL"]
    print(f"\nContinent")
    print(f"  Classified        : {classified:,}  ({classified/total*100:.1f}%)")
    print(f"  NULL              : {continent_counts['NULL']:,}  ({continent_counts['NULL']/total*100:.1f}%)")
    for k, n in sorted(((k, v) for k, v in continent_counts.items()
                         if k != "NULL"), key=lambda x: -x[1]):
        print(f"    {k:<25} {n:>7,}  ({n/total*100:.1f}%)")

    cdn_detected = total - cdn_counts["NULL"]
    print(f"\nCDN")
    print(f"  CDN-hosted        : {cdn_detected:,}  ({cdn_detected/total*100:.1f}%)")
    for k, n in sorted(((k, v) for k, v in cdn_counts.items()
                         if k != "NULL"), key=lambda x: -x[1]):
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