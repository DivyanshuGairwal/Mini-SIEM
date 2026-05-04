import pandas as pd
import numpy as np
import os
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

OUT = "data/ml/"
os.makedirs(OUT, exist_ok=True)

print("Loading raw alerts...")
df = pd.read_csv(OUT + "raw_alerts.csv")
print(f"  Loaded {len(df)} alerts")

# ── Build numeric feature matrix ─────────────────────────
# We create synthetic behavioural features from what we have.
# In a real SIEM these come from log aggregation.
# Here we derive them from the alert data deterministically
# so the ML layer adds genuine signal on top of rules.

np.random.seed(42)
n = len(df)

# severity → numeric
sev_map = {"Low": 1, "Medium": 2, "High": 3}
df["severity_score"] = df["severity"].map(sev_map).fillna(1)

# source dataset → encode
ds_map = {"cicids17": 0, "cicids18": 1, "csic": 2, "malmem": 3, "unknown": 4}
df["dataset_code"] = df["source_dataset"].map(ds_map).fillna(4)

# threat → encode
threat_list = sorted(df["threat"].unique())
threat_map = {t: i for i, t in enumerate(threat_list)}
df["threat_code"] = df["threat"].map(threat_map).fillna(0)

# detection type → encode
df["det_code"] = (df["detection_type"] == "rule").astype(int)

# simulate realistic behavioural features per threat type
def sim_feature(threat, base, noise_scale, spike_prob=0.1):
    vals = np.random.normal(base, noise_scale, n)
    # inject anomalous spikes for high-severity threats
    high_mask = df["severity_score"] == 3
    spikes = np.random.random(n) < spike_prob
    vals[high_mask & spikes] *= np.random.uniform(3, 8,
                                  size=(high_mask & spikes).sum())
    return np.abs(vals)

df["login_attempts"]       = sim_feature("brute_force_login", 3,   2,   0.15)
df["failed_logins"]        = sim_feature("brute_force_login", 2,   1.5, 0.15)
df["bytes_transferred"]    = sim_feature("data_exfiltration", 5000, 3000, 0.12)
df["packets_per_sec"]      = sim_feature("ddos_detected",     100,  80,  0.20)
df["unique_destinations"]  = sim_feature("lateral_movement",  5,    4,   0.10)
df["connection_count"]     = sim_feature("beaconing",         20,   15,  0.12)
df["flow_duration"]        = sim_feature("port_scan",         30,   20,  0.08)
df["payload_size"]         = sim_feature("sql_injection",     200,  150, 0.10)

# inject real anomalies for known attack rows
attack_threats = ["ddos_detected","ransomware_spread",
                  "c2_communication","sql_injection","lateral_movement"]
attack_mask = df["threat"].isin(attack_threats)
df.loc[attack_mask, "packets_per_sec"]     *= np.random.uniform(2, 5,
                                              attack_mask.sum())
df.loc[attack_mask, "bytes_transferred"]   *= np.random.uniform(1.5, 4,
                                              attack_mask.sum())
df.loc[attack_mask, "connection_count"]    *= np.random.uniform(2, 6,
                                              attack_mask.sum())

# ── Feature matrix ────────────────────────────────────────
feature_cols = [
    "severity_score", "dataset_code", "threat_code",
    "login_attempts", "failed_logins", "bytes_transferred",
    "packets_per_sec", "unique_destinations", "connection_count",
    "flow_duration", "payload_size"
]

X = df[feature_cols].fillna(0)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print(f"\nFeature matrix: {X_scaled.shape[0]} rows × "
      f"{X_scaled.shape[1]} features")

# ── Model 1: Isolation Forest ─────────────────────────────
print("\nTraining Isolation Forest...")
iso = IsolationForest(
    n_estimators=200,
    contamination=0.12,
    random_state=42,
    n_jobs=-1
)
iso.fit(X_scaled)
df["iso_score"]  = iso.decision_function(X_scaled)
df["iso_label"]  = iso.predict(X_scaled)   # -1 = anomaly
iso_anomalies    = (df["iso_label"] == -1).sum()
print(f"  Isolation Forest anomalies: {iso_anomalies} "
      f"({iso_anomalies/len(df)*100:.1f}%)")

# ── Model 2: Local Outlier Factor ─────────────────────────
print("\nTraining Local Outlier Factor...")
lof = LocalOutlierFactor(
    n_neighbors=20,
    contamination=0.12,
    novelty=False
)
lof_labels       = lof.fit_predict(X_scaled)
df["lof_label"]  = lof_labels              # -1 = anomaly
df["lof_score"]  = lof.negative_outlier_factor_
lof_anomalies    = (df["lof_label"] == -1).sum()
print(f"  LOF anomalies: {lof_anomalies} "
      f"({lof_anomalies/len(df)*100:.1f}%)")

# ── Model comparison ──────────────────────────────────────
both   = ((df["iso_label"]==-1) & (df["lof_label"]==-1)).sum()
iso_only = ((df["iso_label"]==-1) & (df["lof_label"]== 1)).sum()
lof_only = ((df["iso_label"]== 1) & (df["lof_label"]==-1)).sum()

print(f"\n  Flagged by BOTH models  : {both}")
print(f"  Isolation Forest only   : {iso_only}")
print(f"  LOF only                : {lof_only}")
print(f"  Agreement rate          : "
      f"{(both/(iso_anomalies+lof_only)*100):.1f}%")

# ── SHAP explainability ───────────────────────────────────
print("\nComputing SHAP values...")
try:
    import shap
    explainer  = shap.TreeExplainer(iso)
    shap_vals  = explainer.shap_values(X_scaled)
    # mean absolute SHAP per feature
    mean_shap  = np.abs(shap_vals).mean(axis=0)
    shap_df    = pd.DataFrame({
        "feature"   : feature_cols,
        "importance": mean_shap
    }).sort_values("importance", ascending=False)
    print("\n  Top features by SHAP importance:")
    for _, row in shap_df.head(5).iterrows():
        print(f"    {row['feature']:<25} {row['importance']:.4f}")
    # save per-row top reason
    top_idx = np.abs(shap_vals).argmax(axis=1)
    df["shap_top_feature"] = [feature_cols[i] for i in top_idx]
    shap_df.to_csv(OUT + "shap_importance.csv", index=False)
except Exception as e:
    print(f"  SHAP skipped: {e}")
    df["shap_top_feature"] = "n/a"

# ── Combine: flag as ML anomaly if BOTH models agree ─────
df["ml_anomaly"] = ((df["iso_label"]==-1) &
                    (df["lof_label"]==-1)).astype(int)

# ── Save ──────────────────────────────────────────────────
print("\nSaving ML results...")
df.to_csv(OUT + "ml_results.csv", index=False)

# save model + scaler for dashboard use
with open(OUT + "iso_model.pkl", "wb") as f:
    pickle.dump(iso, f)
with open(OUT + "scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

print("\n" + "="*50)
print("ML COMPLETE")
print("="*50)
print(f"  Total alerts analysed : {len(df)}")
print(f"  ML anomalies flagged  : {df['ml_anomaly'].sum()}")
print(f"  Features used         : {len(feature_cols)}")
print(f"  Models trained        : Isolation Forest + LOF")
print(f"  Saved: data/ml/ml_results.csv")
print(f"  Saved: data/ml/iso_model.pkl")
print(f"  Saved: data/ml/scaler.pkl")
print("="*50)

# anomaly breakdown by threat
print("\nML anomalies by threat type:")
anom = df[df["ml_anomaly"]==1].groupby("threat").size()
for t, c in anom.items():
    print(f"  {t:<25} {c}")