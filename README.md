# Mini SIEM — Security Information and Event Management System

A lightweight SOC (Security Operations Centre) tool that detects 
cyber threats from multiple log sources using rule-based detection 
and machine learning anomaly detection.

---

## Project Architecture
```
Raw Datasets → Data Cleaning → Rule-Based Detection → 
ML Feature Engineering → Dual-Model Training (IF + LOF) → 
SHAP Explainability → Alert Integration → SQLite Storage → 
3-Page SOC Dashboard
```

---

## Datasets Used

| Dataset | Source | Threats Detected |
|---|---|---|
| CICIDS 2017 | Canadian Institute for Cybersecurity | Brute Force, SQLi, XSS, DDoS, Port Scan |
| CICIDS 2018 | Canadian Institute for Cybersecurity | Botnet, Infiltration, Web Attacks |
| CSIC 2010 | Spanish National Research Council | HTTP Web Attacks |
| CIC-MalMem 2022 | Canadian Institute for Cybersecurity | Malware, Ransomware, Trojans |

---

## Threat Detection Rules (10 threat types)

| Threat | Severity | MITRE Technique | MITRE Tactic |
|---|---|---|---|
| Brute Force Login | Medium | T1110.001 | TA0006 - Credential Access |
| SQL Injection | High | T1190 | TA0001 - Initial Access |
| XSS Attack | Medium | T1059.007 | TA0002 - Execution |
| DDoS Detected | High | T1498 | TA0040 - Impact |
| Port Scan | Low | T1046 | TA0007 - Discovery |
| Data Exfiltration | Medium | T1041 | TA0010 - Exfiltration |
| Web Brute Force | Medium | T1110.001 | TA0001 - Initial Access |
| C2 Communication | High | T1071 | TA0011 - C2 |
| Malware Detected | High | T1204 | TA0002 - Execution |
| Ransomware Spread | High | T1486 | TA0040 - Impact |

---

## Machine Learning

- **Algorithm 1**: Isolation Forest (unsupervised anomaly detection)
- **Algorithm 2**: Local Outlier Factor (unsupervised anomaly detection)
- **Consensus**: Alert flagged as ML anomaly only when BOTH models agree
- **Explainability**: SHAP values computed per anomaly — shows which 
  feature drove the detection
- **Why unsupervised**: No ground truth attack labels available across 
  all datasets. Unsupervised detection mirrors production SIEM 
  behaviour (Splunk UBA, Darktrace)

---

## Database Schema (SQLite — 3 tables)

**alerts** — all detected threats with MITRE tags, severity, 
risk score, status

**analyst_notes** — analyst investigation notes per alert 
(INSERT + SELECT)

**ip_risk** — aggregated risk profile per source IP with 
cumulative score and top threat

---

## Dashboard Pages

**Page 1 — SOC Overview**: KPI cards, threat volume chart, 
severity distribution, 48-hour timeline, live incident feed

**Page 2 — Threat Intelligence**: MITRE ATT&CK treemap, 
ML anomaly breakdown, SHAP feature importance, IP risk 
leaderboard, dataset contribution

**Page 3 — Analyst Workbench**: Alert triage table, 
add investigation notes, update alert status, CSV + TXT export

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.13 |
| Data processing | Pandas, NumPy |
| Machine learning | Scikit-learn |
| Explainability | SHAP |
| Database | SQLite3 |
| Dashboard | Streamlit |
| Visualisation | Plotly |
| Report export | fpdf2 |

---

## How to Run

**Full pipeline (fresh run):**
```bash
python pipeline.py --clean
streamlit run dashboard/app.py
```

**Run from specific stage:**
```bash
python pipeline.py --stage 3
```

**Dashboard only (database already built):**
```bash
streamlit run dashboard/app.py
```

---

## Project Structure
```
mini-siem/
├── data/
│   ├── raw/          # original dataset files
│   ├── cleaned/      # standardised CSVs
│   └── ml/           # alerts, ML results, model files
├── src/
│   ├── clean.py      # data cleaning pipeline
│   ├── detect.py     # rule-based detection engine
│   ├── ml.py         # ML training + SHAP
│   └── db.py         # SQLite database builder
├── dashboard/
│   └── app.py        # 3-page Streamlit dashboard
├── outputs/
│   └── threat_alerts.db  # SQLite database
├── pipeline.py       # master orchestration script
├── requirements.txt
└── README.md
```