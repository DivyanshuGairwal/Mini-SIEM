import pandas as pd
import numpy as np
import os

RAW = "data/raw/"
CLEAN = "data/cleaned/"
os.makedirs(CLEAN, exist_ok=True)

# ── helper ──────────────────────────────────────────────
def standardise(df):
    df.columns = (df.columns
                  .str.strip()
                  .str.lower()
                  .str.replace(" ", "_")
                  .str.replace("/", "_per_")
                  .str.replace("-", "_"))
    df = df.dropna(how="all")
    df = df.drop_duplicates()
    return df

def sample(df, n=8000):
    return df.sample(min(n, len(df)), random_state=42)

# ── 1. CICIDS 2017 ──────────────────────────────────────
print("Cleaning CICIDS 2017 files...")

files_17 = {
    "cicids17_bruteforce.csv"  : "brute_force",
    "cicids17_webattacks.csv"  : "web_attacks",
    "cicids17_ddos.csv"        : "ddos",
    "cicids17_portscan.csv"    : "port_scan",
}

frames_17 = []
for fname, label in files_17.items():
    path = RAW + fname
    if not os.path.exists(path):
        print(f"  MISSING: {fname} — skipping")
        continue
    df = pd.read_csv(path, encoding="utf-8", low_memory=False)
    df = standardise(df)
    df = sample(df)
    df["source_dataset"] = "cicids17"
    df["attack_category"] = label
    frames_17.append(df)
    print(f"  {fname}: {len(df)} rows loaded")

if frames_17:
    cicids17 = pd.concat(frames_17, ignore_index=True)
    cicids17.to_csv(CLEAN + "cicids17_cleaned.csv", index=False)
    print(f"  Saved cicids17_cleaned.csv — {len(cicids17)} total rows\n")

# ── 2. CICIDS 2018 ──────────────────────────────────────
print("Cleaning CICIDS 2018...")

path18 = RAW + "cicids18_main.csv"
if os.path.exists(path18):
    df18 = pd.read_csv(path18, encoding="utf-8", low_memory=False)
    df18 = standardise(df18)
    df18 = sample(df18, n=8000)
    df18["source_dataset"] = "cicids18"
    df18.to_csv(CLEAN + "cicids18_cleaned.csv", index=False)
    print(f"  Saved cicids18_cleaned.csv — {len(df18)} rows\n")
else:
    print("  MISSING: cicids18_main.csv — skipping\n")

# ── 3. MalMem 2022 ──────────────────────────────────────
print("Cleaning MalMem 2022...")

path_mal = RAW + "malmem.csv"
if os.path.exists(path_mal):
    dfmal = pd.read_csv(path_mal, encoding="utf-8", low_memory=False)
    dfmal = standardise(dfmal)
    dfmal = sample(dfmal, n=6000)
    dfmal["source_dataset"] = "malmem"
    dfmal.to_csv(CLEAN + "malmem_cleaned.csv", index=False)
    print(f"  Saved malmem_cleaned.csv — {len(dfmal)} rows\n")
else:
    print("  MISSING: malmem.csv — skipping\n")

# ── 4. CSIC HTTP 2010 ───────────────────────────────────
print("Cleaning CSIC HTTP 2010...")

def parse_csic(filepath, label):
    rows = []
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    requests = content.strip().split("\n\n")
    for req in requests:
        lines = req.strip().split("\n")
        if not lines:
            continue
        row = {"raw_request": req[:300], "label": label}
        if lines:
            first = lines[0]
            parts = first.split(" ")
            row["method"]  = parts[0] if len(parts) > 0 else ""
            row["url"]     = parts[1] if len(parts) > 1 else ""
            row["protocol"]= parts[2] if len(parts) > 2 else ""
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                row[k.lower().replace("-", "_")] = v
        rows.append(row)
    return pd.DataFrame(rows)

normal_path   = RAW + "csic_normal.txt"
anomalous_path= RAW + "csic_anomalous.txt"

csic_frames = []
for fpath, lbl in [(normal_path, "normal"), (anomalous_path, "attack")]:
    df_c = parse_csic(fpath, lbl)
    if df_c is not None:
        df_c = sample(df_c, n=4000)
        csic_frames.append(df_c)
        print(f"  Parsed {fpath}: {len(df_c)} requests")

if csic_frames:
    csic = pd.concat(csic_frames, ignore_index=True)
    csic["source_dataset"] = "csic"
    csic.to_csv(CLEAN + "csic_cleaned.csv", index=False)
    print(f"  Saved csic_cleaned.csv — {len(csic)} rows\n")

# ── Final summary ────────────────────────────────────────
print("=" * 45)
print("CLEANING COMPLETE — files in data/cleaned/:")
for f in os.listdir(CLEAN):
    path = CLEAN + f
    size = os.path.getsize(path) // 1024
    print(f"  {f}  ({size} KB)")
print("=" * 45)