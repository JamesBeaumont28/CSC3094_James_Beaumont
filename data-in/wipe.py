#made with chatGPT to wipe created files
import os
import glob

def wipe_ingested_files():
    # folder where your split files are stored
    folder = "ingested-data"

    # pattern of files to remove
    pattern = "domains_*.csv"

    files = glob.glob(os.path.join(folder, pattern))

    if not files:
        print("No generated files found.")
    else:
        for file in files:
            os.remove(file)
            print(f"Deleted {file}")

    print(f"\nRemoved {len(files)} files.")
