import os
import sys
import pandas as pd

NUM_USERS = 75
START_DATE = "2010-01-01"
END_DATE = "2010-03-31"

print("\n=== REDUCING CERT r5.2 DATASET ===\n")

# Determine data directory:
#   1. dataset/r5.2  (new organized layout)
#   2. r5.2          (legacy layout next to script)
#   3. current working dir
script_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
for candidate in [
    os.path.join(script_dir, "dataset", "r5.2"),
    os.path.join(script_dir, "r5.2"),
]:
    if os.path.isdir(candidate):
        DATA_DIR = candidate
        break
else:
    DATA_DIR = script_dir

def _read_csv(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"CSV not found: {path}")
    return pd.read_csv(path)

# Parse date bounds as timestamps
START_TS = pd.to_datetime(START_DATE)
END_TS = pd.to_datetime(END_DATE)

# ---------------- LOGON ----------------
logon_path = os.path.join(DATA_DIR, "logon.csv")
print(f"Loading {logon_path}...")
logon = _read_csv(logon_path)
if "date" in logon.columns:
    logon["date"] = pd.to_datetime(logon["date"])

if "user" not in logon.columns:
    raise Exception("`logon.csv` must contain a `user` column")

unique_users = logon["user"].unique()
selected_users = list(unique_users[:NUM_USERS])
print(f"Selected {len(selected_users)} users.")

logon_small = logon[logon["user"].isin(selected_users)].copy()
if "date" in logon_small.columns:
    logon_small = logon_small[(logon_small["date"] >= START_TS) & (logon_small["date"] <= END_TS)]

print(f"Filtered logon rows: {len(logon_small)}")

# ---------------- DEVICE ----------------
device_path = os.path.join(DATA_DIR, "device.csv")
print(f"Loading {device_path}...")
device = _read_csv(device_path)
if "date" in device.columns:
    device["date"] = pd.to_datetime(device["date"])

if "user" not in device.columns:
    raise Exception("`device.csv` must contain a `user` column")

device_small = device[device["user"].isin(selected_users)].copy()
if "date" in device_small.columns:
    device_small = device_small[(device_small["date"] >= START_TS) & (device_small["date"] <= END_TS)]

print(f"Filtered device rows: {len(device_small)}")

# ---------------- FILE ----------------
file_path = os.path.join(DATA_DIR, "file.csv")
print(f"Loading {file_path}...")
file_df = _read_csv(file_path)
if "date" in file_df.columns:
    file_df["date"] = pd.to_datetime(file_df["date"])

if "user" not in file_df.columns:
    raise Exception("`file.csv` must contain a `user` column")

file_small = file_df[file_df["user"].isin(selected_users)].copy()
if "date" in file_small.columns:
    file_small = file_small[(file_small["date"] >= START_TS) & (file_small["date"] <= END_TS)]

print(f"Filtered file rows: {len(file_small)}")

# ---------------- LDAP (FOLDER) ----------------
ldap_folder = os.path.join(DATA_DIR, "LDAP")
print(f"Loading LDAP folder at {ldap_folder}...")
if not os.path.isdir(ldap_folder):
    raise FileNotFoundError(f"LDAP folder not found: {ldap_folder}")

ldap_files = [f for f in os.listdir(ldap_folder) if f.endswith(".csv")]
if not ldap_files:
    raise FileNotFoundError(f"No .csv files found in LDAP folder: {ldap_folder}")

ldap_data = []
for f in ldap_files:
    full_path = os.path.join(ldap_folder, f)
    df = pd.read_csv(full_path)
    ldap_data.append(df)

ldap = pd.concat(ldap_data, ignore_index=True)

# Normalize user column types to string for safe comparison
selected_users_str = [str(u) for u in selected_users]

if "user_id" in ldap.columns:
    ldap["user_id"] = ldap["user_id"].astype(str)
    ldap_small = ldap[ldap["user_id"].isin(selected_users_str)].copy()
elif "user" in ldap.columns:
    ldap["user"] = ldap["user"].astype(str)
    ldap_small = ldap[ldap["user"].isin(selected_users_str)].copy()
else:
    raise Exception("No user column found in LDAP files")

# Optionally filter LDAP by date if present
if "date" in ldap_small.columns:
    ldap_small["date"] = pd.to_datetime(ldap_small["date"])
    ldap_small = ldap_small[(ldap_small["date"] >= START_TS) & (ldap_small["date"] <= END_TS)]

print(f"Filtered ldap rows: {len(ldap_small)}")

# ---------------- HTTP (chunked — file is ~30 GB) ----------------
http_path = os.path.join(DATA_DIR, "http.csv")
if os.path.exists(http_path):
    print(f"Loading {http_path} in chunks (large file, please wait)...")
    selected_users_set = set(selected_users)
    http_chunks = []
    chunk_size = 200_000
    total_rows = 0
    for chunk in pd.read_csv(http_path, chunksize=chunk_size):
        if "user" not in chunk.columns:
            raise Exception("`http.csv` must contain a `user` column")
        filtered = chunk[chunk["user"].isin(selected_users_set)].copy()
        if "date" in filtered.columns:
            filtered["date"] = pd.to_datetime(filtered["date"])
            filtered = filtered[(filtered["date"] >= START_TS) & (filtered["date"] <= END_TS)]
        if len(filtered):
            http_chunks.append(filtered)
        total_rows += len(chunk)
        print(f"  Processed {total_rows:,} rows...", end="\r")
    print()
    http_small = pd.concat(http_chunks, ignore_index=True) if http_chunks else pd.DataFrame()
    print(f"Filtered http rows (before cap): {len(http_small)}")

    # Cap to 10 rows per user per day so file size matches the other CSVs
    if len(http_small) and "date" in http_small.columns:
        http_small["_day"] = pd.to_datetime(http_small["date"]).dt.date
        http_small = (
            http_small
            .groupby(["user", "_day"], group_keys=False)
            .apply(lambda g: g.head(10))
            .reset_index(drop=True)
        )
        if "_day" in http_small.columns:
            http_small = http_small.drop(columns=["_day"])
    print(f"Filtered http rows (after cap):  {len(http_small)}")
else:
    print("http.csv not found — skipping.")
    http_small = None

# ---------------- SAVE ----------------
# Save to dataset/ folder if it exists, else next to script
dataset_dir = os.path.join(script_dir, "dataset")
out_dir = dataset_dir if os.path.isdir(dataset_dir) else script_dir

logon_small.to_csv(os.path.join(out_dir, "logon_small.csv"), index=False)
device_small.to_csv(os.path.join(out_dir, "device_small.csv"), index=False)
file_small.to_csv(os.path.join(out_dir, "file_small.csv"), index=False)
ldap_small.to_csv(os.path.join(out_dir, "ldap_small.csv"), index=False)
if http_small is not None and len(http_small):
    http_small.to_csv(os.path.join(out_dir, "http_small.csv"), index=False)
    print(f"Saved: http_small.csv ({len(http_small):,} rows)")

print(f"\nDONE ✅ Smaller dataset created successfully! Files written to {out_dir}")
print("\nFiles created:")
for fname in ["logon_small.csv", "device_small.csv", "file_small.csv", "ldap_small.csv", "http_small.csv"]:
    fpath = os.path.join(out_dir, fname)
    if os.path.exists(fpath):
        size_kb = os.path.getsize(fpath) // 1024
        print(f"  ✅ {fname} ({size_kb:,} KB)")
    else:
        print(f"  ⚠️  {fname} — not created")
