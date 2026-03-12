import csv
import math
import random
from wipe import wipe_ingested_files
import os

#varales to change how the ranking is split
files = 1
total_domains = 1000000
randomize = True

input_csv = "tranco_QW8X4.csv"

#clears all previsouly ingested files
wipe_ingested_files()

#added to store split files is separate directory
output_dir = "../ingested-data"
os.makedirs(output_dir, exist_ok=True)

#added so i could more easly run wipe.py to wipe files
if not files or files == 0:
    exit(0)

domains_per_file = math.ceil(total_domains / files)

for file_index in range(files):

    start = file_index * domains_per_file
    end = min(start + domains_per_file, total_domains)

    rows = []

    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)

        for i, row in enumerate(reader):
            if i < start:
                continue
            if i >= end:
                break
            rows.append(row)

    if randomize:
        random.shuffle(rows)

    output_file = f"{output_dir}/domains_{file_index+1}.csv"

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_file}")