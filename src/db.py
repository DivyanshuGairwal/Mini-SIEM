import pandas as pd
import sqlite3
import os
from datetime import datetime, timedelta
import random

DB_PATH = "outputs/threat_alerts.db"
ML_PATH = "data/ml/ml_results.csv"
os.makedirs("outputs", exist_ok=True)

print("Building SQLite database...")

# ── Connect and create 3-table schema ────────────────────
conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()

# Table 1: alerts (main table)
cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    threat            TEXT NOT NULL,
    severity          TEXT NOT NULL,
    source_ip         TEXT,
    destination_ip    TEXT,
    timestamp         TEXT,
    mitre_technique   TEXT,
    mitre_tactic      TEXT,
    detection_type    TEXT,
    source_dataset    TEXT,
    ml_anomaly        INTEGER DEFAULT 0,
    shap_top_feature  TEXT,
    iso_score         REAL,
    status            TEXT DEFAULT 'Open',
    risk_score        REAL DEFAULT 0.0
)
""")

# Table 2: analyst_notes
cur.execute("""
CREATE TABLE IF NOT EXISTS analyst_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER REFERENCES alerts(id),
    analyst     TEXT DEFAULT 'SOC Analyst',
    note        TEXT,
    action      TEXT,
    created_at  TEXT
)
""")

# Table 3: ip_risk (aggregated per source IP)
cur.execute("""
CREATE TABLE IF NOT EXISTS ip_risk (
    source_ip     TEXT PRIMARY KEY,
    risk_score    REAL,
    alert_count   INTEGER,
    high_count    INTEGER,
    last_seen     TEXT,
    top_threat    TEXT
)
""")

conn.commit()
print("  3-table schema created: alerts, analyst_notes, ip_risk")

# ── Load ML results ───────────────────────────────────────
print("\nLoading ML results...")
df = pd.read_csv(ML_PATH)
print(f"  Loaded {len(df)} rows")

# ── Generate realistic timestamps ─────────────────────────
base_time = datetime.now() - timedelta(hours=48)
timestamps = []
for i in range(len(df)):
    offset = timedelta(
        hours=random.randint(0, 47),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    timestamps.append((base_time + offset).strftime("%Y-%m-%d %H:%M:%S"))

df["timestamp"] = timestamps

# ── Risk score formula ────────────────────────────────────
# severity weight + ml_anomaly bonus + iso_score penalty
sev_weight = {"High": 8, "Medium": 5, "Low": 2}
df["risk_score"] = (
    df["severity"].map(sev_weight).fillna(2) +
    df["ml_anomaly"] * 3 +
    df["iso_score"].apply(lambda x: max(0, -x * 2))
).round(2)

# ── Status logic ──────────────────────────────────────────
def assign_status(row):
    if row["severity"] == "High" and row["ml_anomaly"] == 1:
        return "Critical"
    elif row["severity"] == "High":
        return "High Priority"
    elif row["severity"] == "Medium":
        return "Investigate"
    else:
        return "Open"

df["status"] = df.apply(assign_status, axis=1)

# ── Insert into alerts table ──────────────────────────────
print("\nInserting alerts into database...")

insert_cols = [
    "threat", "severity", "source_ip", "destination_ip",
    "timestamp", "mitre_technique", "mitre_tactic",
    "detection_type", "source_dataset", "ml_anomaly",
    "shap_top_feature", "iso_score", "status", "risk_score"
]

# ensure all columns exist
for col in insert_cols:
    if col not in df.columns:
        df[col] = "unknown"

records = df[insert_cols].values.tolist()
cur.executemany("""
    INSERT INTO alerts (
        threat, severity, source_ip, destination_ip,
        timestamp, mitre_technique, mitre_tactic,
        detection_type, source_dataset, ml_anomaly,
        shap_top_feature, iso_score, status, risk_score
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
""", records)
conn.commit()
print(f"  Inserted {len(records)} alerts")

# ── Seed analyst_notes with 5 example notes ──────────────
print("\nSeeding analyst notes...")
sample_ids = [1, 5, 10, 25, 50]
notes = [
    ("SOC Analyst 1", "Confirmed malicious. Source IP blacklisted.", "Blocked"),
    ("SOC Analyst 2", "Under investigation. Correlating with other events.", "Investigating"),
    ("SOC Analyst 1", "False positive — internal scanner activity.", "Closed"),
    ("SOC Analyst 3", "Escalated to IR team. High confidence attack.", "Escalated"),
    ("SOC Analyst 2", "Monitoring. No immediate action required.", "Watching"),
]
for alert_id, (analyst, note, action) in zip(sample_ids, notes):
    cur.execute("""
        INSERT INTO analyst_notes (alert_id, analyst, note, action, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_id, analyst, note, action,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
conn.commit()
print("  5 analyst notes seeded")

# ── Build ip_risk table ───────────────────────────────────
print("\nBuilding IP risk table...")
ip_stats = df.groupby("source_ip").agg(
    alert_count = ("threat",      "count"),
    high_count  = ("severity",    lambda x: (x == "High").sum()),
    last_seen   = ("timestamp",   "max"),
    top_threat  = ("threat",      lambda x: x.value_counts().index[0]),
    risk_score  = ("risk_score",  "sum")
).reset_index()

ip_stats["risk_score"] = ip_stats["risk_score"].round(2)

for _, row in ip_stats.iterrows():
    cur.execute("""
        INSERT OR REPLACE INTO ip_risk
        (source_ip, risk_score, alert_count, high_count, last_seen, top_threat)
        VALUES (?,?,?,?,?,?)
    """, (str(row["source_ip"]), float(row["risk_score"]),
          int(row["alert_count"]), int(row["high_count"]),
          str(row["last_seen"]), str(row["top_threat"])))
conn.commit()
print(f"  {len(ip_stats)} unique IPs profiled")

# ── Verification queries ──────────────────────────────────
print("\n" + "="*50)
print("DATABASE VERIFICATION")
print("="*50)

print("\nAlert counts by severity:")
for row in cur.execute("""
    SELECT severity, status, COUNT(*) as cnt
    FROM alerts GROUP BY severity, status
    ORDER BY cnt DESC
"""):
    print(f"  {row[0]:<8} {row[1]:<15} {row[2]}")

print("\nTop 5 riskiest IPs:")
for row in cur.execute("""
    SELECT source_ip, risk_score, alert_count, top_threat
    FROM ip_risk ORDER BY risk_score DESC LIMIT 5
"""):
    print(f"  {str(row[0])[:18]:<20} score={row[1]:<8} "
          f"alerts={row[2]:<5} {row[3]}")

print("\nTable row counts:")
for tbl in ["alerts", "analyst_notes", "ip_risk"]:
    count = cur.execute(
        f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
    print(f"  {tbl:<20} {count} rows")

conn.close()
print(f"\nDatabase saved: {DB_PATH}")
print("="*50)
