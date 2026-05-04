"""
pipeline.py — Master pipeline for Mini SIEM
Runs the complete detection pipeline in one command:
    python pipeline.py

Stages:
    1. clean.py     — load + clean all 4 datasets
    2. detect.py    — run 10+ rule-based threat detections
    3. ml.py        — train IF + LOF + SHAP anomaly detection
    4. db.py        — build 3-table SQLite database

Usage:
    python pipeline.py              # run all stages
    python pipeline.py --stage 2    # run from stage 2 onwards
    python pipeline.py --clean      # wipe DB and restart fresh
"""

import subprocess
import sys
import os
import time
import argparse
from datetime import datetime

# ── Config ────────────────────────────────────────────────
STAGES = [
    (1, "src/clean.py",   "Data cleaning + normalisation"),
    (2, "src/detect.py",  "Rule-based threat detection"),
    (3, "src/ml.py",      "ML anomaly detection (IF + LOF + SHAP)"),
    (4, "src/db.py",      "SQLite database build"),
]

DB_PATH = "outputs/threat_alerts.db"
PYTHON  = sys.executable

def banner(text, char="="):
    line = char * 55
    print(f"\n{line}")
    print(f"  {text}")
    print(f"{line}")

def run_stage(stage_num, script, description):
    banner(f"STAGE {stage_num}: {description}")
    print(f"  Script  : {script}")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 55)

    start = time.time()
    result = subprocess.run(
        [PYTHON, script],
        capture_output=False,   # print output live
        text=True
    )
    elapsed = time.time() - start

    print("-" * 55)
    if result.returncode == 0:
        print(f"  PASSED in {elapsed:.1f}s")
        return True
    else:
        print(f"  FAILED after {elapsed:.1f}s")
        print(f"  Return code: {result.returncode}")
        return False

def check_outputs():
    banner("OUTPUT VERIFICATION", "-")
    checks = [
        ("data/cleaned/cicids17_cleaned.csv",  "CICIDS 2017 cleaned"),
        ("data/cleaned/cicids18_cleaned.csv",  "CICIDS 2018 cleaned"),
        ("data/cleaned/csic_cleaned.csv",      "CSIC HTTP cleaned"),
        ("data/cleaned/malmem_cleaned.csv",    "MalMem cleaned"),
        ("data/ml/raw_alerts.csv",             "Raw alerts"),
        ("data/ml/ml_results.csv",             "ML results"),
        ("data/ml/iso_model.pkl",              "Isolation Forest model"),
        ("data/ml/scaler.pkl",                 "Feature scaler"),
        ("data/ml/shap_importance.csv",        "SHAP importance"),
        ("outputs/threat_alerts.db",           "SQLite database"),
    ]

    all_ok = True
    for path, label in checks:
        exists = os.path.exists(path)
        size   = os.path.getsize(path) // 1024 if exists else 0
        status = "OK" if exists else "MISSING"
        mark   = "+" if exists else "X"
        print(f"  [{mark}] {label:<30} {status}  ({size} KB)")
        if not exists:
            all_ok = False

    return all_ok

def show_summary():
    banner("PIPELINE SUMMARY", "-")
    import sqlite3
    if not os.path.exists(DB_PATH):
        print("  Database not found — pipeline may have failed")
        return

    conn = sqlite3.connect(DB_PATH)

    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    high  = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity='High'").fetchone()[0]
    crit  = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE status='Critical'").fetchone()[0]
    ml    = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE ml_anomaly=1").fetchone()[0]
    ips   = conn.execute("SELECT COUNT(*) FROM ip_risk").fetchone()[0]
    notes = conn.execute("SELECT COUNT(*) FROM analyst_notes").fetchone()[0]

    print(f"  Total alerts        : {total:,}")
    print(f"  High severity       : {high:,}")
    print(f"  Critical (ML+High)  : {crit:,}")
    print(f"  ML anomalies        : {ml:,}")
    print(f"  Unique IPs profiled : {ips:,}")
    print(f"  Analyst notes       : {notes:,}")

    print("\n  Threat breakdown:")
    for row in conn.execute("""
        SELECT threat, severity, COUNT(*) as cnt
        FROM alerts GROUP BY threat
        ORDER BY cnt DESC
    """):
        print(f"    {row[0]:<25} {row[1]:<8} {row[2]:>5}")

    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Mini SIEM Pipeline")
    parser.add_argument("--stage", type=int, default=1,
                        help="Start from stage N (1-4)")
    parser.add_argument("--clean", action="store_true",
                        help="Delete existing database before running")
    args = parser.parse_args()

    banner("MINI SIEM — DETECTION PIPELINE")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  From stage: {args.stage}")
    print(f"  Python   : {PYTHON}")

    # clean run
    if args.clean and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"\n  Deleted existing database: {DB_PATH}")

    # run stages
    pipeline_start = time.time()
    failed_at = None

    for stage_num, script, description in STAGES:
        if stage_num < args.stage:
            print(f"\n  Skipping stage {stage_num}: {description}")
            continue

        success = run_stage(stage_num, script, description)
        if not success:
            failed_at = stage_num
            break

    total_time = time.time() - pipeline_start

    # verify outputs
    all_ok = check_outputs()

    # summary
    show_summary()

    # final result
    banner("PIPELINE COMPLETE" if not failed_at else f"PIPELINE FAILED AT STAGE {failed_at}")
    print(f"  Total time : {total_time:.1f}s")

    if not failed_at and all_ok:
        print(f"\n  All stages passed. Launch dashboard with:")
        print(f"  streamlit run dashboard/app.py")
        print(f"\n  Or re-run pipeline with:")
        print(f"  python pipeline.py --clean")
    else:
        print(f"\n  Fix the error above then re-run:")
        print(f"  python pipeline.py --stage {failed_at}")

if __name__ == "__main__":
    main()

