import pandas as pd
import numpy as np
import os
import re
import hashlib

CLEAN = "data/cleaned/"
OUT   = "data/ml/"
os.makedirs(OUT, exist_ok=True)

def generate_ip(identifier):
    # generates a consistent fake IP from any string identifier
    # same input always gives same IP — realistic and reproducible
    h = int(hashlib.md5(str(identifier).encode()).hexdigest(), 16)
    return f"{(h % 200) + 10}.{(h >> 8) % 256}.{(h >> 16) % 256}.{(h >> 24) % 254 + 1}"

MITRE = {
    "brute_force_login"  : ("T1110.001", "TA0006 - Credential Access"),
    "credential_stuffing": ("T1110.004", "TA0006 - Credential Access"),
    "password_spray"     : ("T1110.003", "TA0006 - Credential Access"),
    "suspicious_access"  : ("T1078.001", "TA0001 - Initial Access"),
    "port_scan"          : ("T1046",     "TA0007 - Discovery"),
    "network_discovery"  : ("T1018",     "TA0007 - Discovery"),
    "ddos_detected"      : ("T1498",     "TA0040 - Impact"),
    "lateral_movement"   : ("T1021",     "TA0008 - Lateral Movement"),
    "dns_tunneling"      : ("T1048.003", "TA0010 - Exfiltration"),
    "data_exfiltration"  : ("T1041",     "TA0010 - Exfiltration"),
    "beaconing"          : ("T1071.001", "TA0011 - C2"),
    "web_brute_force"    : ("T1110.001", "TA0001 - Initial Access"),
    "sql_injection"      : ("T1190",     "TA0001 - Initial Access"),
    "xss_attack"         : ("T1059.007", "TA0002 - Execution"),
    "ransomware_spread"  : ("T1486",     "TA0040 - Impact"),
    "c2_communication"   : ("T1071",     "TA0011 - C2"),
    "malware_detected"   : ("T1204",     "TA0002 - Execution"),
}

def severity(threat):
    high = ["ddos_detected","ransomware_spread","sql_injection",
            "lateral_movement","c2_communication","malware_detected"]
    med  = ["brute_force_login","credential_stuffing","data_exfiltration",
            "dns_tunneling","xss_attack","beaconing","web_brute_force"]
    if threat in high: return "High"
    if threat in med:  return "Medium"
    return "Low"

def find_label_col(df):
    for c in df.columns:
        if c.strip().lower() in ["label", "attack_category", "category",
                                  "class", "type", "attack"]:
            return c
    return None

def make_alert(threat, row):
    tech, tactic = MITRE.get(threat, ("T0000", "Unknown"))
    
    # generate varied IPs based on row index for realism
    raw_src = str(row.get("source_ip", row.get("src_ip", "")))
    raw_dst = str(row.get("destination_ip", row.get("dst_ip", "")))
    
    # if IP is missing or generic, generate one from threat+dataset combo
    if raw_src in ["unknown", "10.0.0.1", "nan", ""]:
        raw_src = generate_ip(f"{threat}_{row.get('source_dataset','x')}_"
                              f"{row.name if hasattr(row, 'name') else id(row)}")
    if raw_dst in ["unknown", "192.168.1.1", "nan", ""]:
        raw_dst = generate_ip(f"dst_{threat}_{id(row)}")

    return {
        "threat"          : threat,
        "severity"        : severity(threat),
        "source_ip"       : raw_src[:20],
        "destination_ip"  : raw_dst[:20],
        "mitre_technique" : tech,
        "mitre_tactic"    : tactic,
        "detection_type"  : "rule",
        "source_dataset"  : str(row.get("source_dataset", "unknown")),
    }

alerts = []

# ════════════════════════════════════════════════════════
# BLOCK A — CICIDS 2017
# ════════════════════════════════════════════════════════
print("Running CICIDS 2017 rules...")
c17 = pd.read_csv(CLEAN + "cicids17_cleaned.csv", low_memory=False)
lc = find_label_col(c17)
print(f"  Label column found: '{lc}'")
print(f"  Columns sample: {list(c17.columns[:8])}")

if lc:
    c17[lc] = c17[lc].astype(str).str.strip().str.upper()
    print(f"  Unique labels: {c17[lc].unique()[:10]}")

    bf   = c17[c17[lc].str.contains("BRUTE", na=False)]
    sqli = c17[c17[lc].str.contains("SQL", na=False)]
    xss  = c17[c17[lc].str.contains("XSS", na=False)]
    ddos = c17[c17[lc].str.contains("DDOS|DOS", na=False)]
    ps   = c17[c17[lc].str.contains("PORTSCAN|PORT", na=False)]

    for _, r in bf.iterrows():   alerts.append(make_alert("brute_force_login", r))
    for _, r in sqli.iterrows(): alerts.append(make_alert("sql_injection", r))
    for _, r in xss.iterrows():  alerts.append(make_alert("xss_attack", r))
    for _, r in ddos.iterrows(): alerts.append(make_alert("ddos_detected", r))
    for _, r in ps.iterrows():   alerts.append(make_alert("port_scan", r))

    print(f"  BruteForce:{len(bf)}  SQLi:{len(sqli)}  "
          f"XSS:{len(xss)}  DDoS:{len(ddos)}  PortScan:{len(ps)}")

# numeric threshold rules on 2017
num17 = c17.select_dtypes(include=[np.number]).columns.tolist()
if "total_fwd_packets" in num17:
    exfil = c17[c17["total_fwd_packets"] > 500]
    for _, r in exfil.iterrows():
        alerts.append(make_alert("data_exfiltration", r))
    print(f"  Data exfiltration (threshold): {len(exfil)}")

# ════════════════════════════════════════════════════════
# BLOCK B — CICIDS 2018  (FIX: print all columns first)
# ════════════════════════════════════════════════════════
print("\nRunning CICIDS 2018 rules...")
c18 = pd.read_csv(CLEAN + "cicids18_cleaned.csv", low_memory=False)
lc18 = find_label_col(c18)
print(f"  Label column found: '{lc18}'")
print(f"  Columns sample: {list(c18.columns[:8])}")

if lc18:
    c18[lc18] = c18[lc18].astype(str).str.strip().str.upper()
    print(f"  Unique labels: {c18[lc18].unique()[:10]}")

    bf18   = c18[c18[lc18].str.contains("BRUTE|FTP|SSH", na=False)]
    bot18  = c18[c18[lc18].str.contains("BOT|BOTNET", na=False)]
    lat18  = c18[c18[lc18].str.contains("INFILTRAT|LATERAL", na=False)]
    ddos18 = c18[c18[lc18].str.contains("DDOS|DOS", na=False)]
    web18  = c18[c18[lc18].str.contains("WEB|HTTP", na=False)]

    for _, r in bf18.iterrows():   alerts.append(make_alert("brute_force_login", r))
    for _, r in bot18.iterrows():  alerts.append(make_alert("beaconing", r))
    for _, r in lat18.iterrows():  alerts.append(make_alert("lateral_movement", r))
    for _, r in ddos18.iterrows(): alerts.append(make_alert("ddos_detected", r))
    for _, r in web18.iterrows():  alerts.append(make_alert("web_brute_force", r))

    print(f"  BruteForce:{len(bf18)}  Botnet:{len(bot18)}  "
          f"Lateral:{len(lat18)}  DDoS:{len(ddos18)}  Web:{len(web18)}")

    # show benign vs attack split
    benign18 = c18[c18[lc18].str.contains("BENIGN", na=False)]
    attack18 = c18[~c18[lc18].str.contains("BENIGN", na=False)]
    print(f"  Benign rows: {len(benign18)}  Attack rows: {len(attack18)}")

# ════════════════════════════════════════════════════════
# BLOCK C — CSIC HTTP (FIX: raw strings for regex)
# ════════════════════════════════════════════════════════
print("\nRunning CSIC HTTP rules...")
csic = pd.read_csv(CLEAN + "csic_cleaned.csv", low_memory=False)
print(f"  Columns: {list(csic.columns[:8])}")

if "url" in csic.columns:
    csic["url"] = csic["url"].astype(str).fillna("")

    # use raw strings (r"...") to fix escape warning
    sqli_pat = r"select|union|insert|drop|delete|--|exec|cast\("
    xss_pat  = r"<script|alert\(|onerror|javascript:|onload="

    sqli_c = csic[csic["url"].str.contains(sqli_pat, case=False, na=False)]
    xss_c  = csic[csic["url"].str.contains(xss_pat,  case=False, na=False)]

    for _, r in sqli_c.iterrows(): alerts.append(make_alert("sql_injection", r))
    for _, r in xss_c.iterrows():  alerts.append(make_alert("xss_attack", r))
    print(f"  SQLi URL patterns: {len(sqli_c)}")
    print(f"  XSS  URL patterns: {len(xss_c)}")

if "label" in csic.columns:
    atk = csic[csic["label"].astype(str).str.lower() == "attack"]
    for _, r in atk.iterrows():
        alerts.append(make_alert("web_brute_force", r))
    print(f"  Web attack (label): {len(atk)}")

# also check raw_request column for patterns
if "raw_request" in csic.columns:
    csic["raw_request"] = csic["raw_request"].astype(str).fillna("")
    sqli_raw = csic[csic["raw_request"].str.contains(
        r"select|union|insert|drop", case=False, na=False)]
    for _, r in sqli_raw.iterrows():
        alerts.append(make_alert("sql_injection", r))
    print(f"  SQLi raw_request patterns: {len(sqli_raw)}")

# ════════════════════════════════════════════════════════
# BLOCK D — MalMem
# ════════════════════════════════════════════════════════
print("\nRunning MalMem rules...")
mal = pd.read_csv(CLEAN + "malmem_cleaned.csv", low_memory=False)
lm = find_label_col(mal)
print(f"  Label column: '{lm}'")

if lm:
    mal[lm] = mal[lm].astype(str).str.strip().str.upper()
    print(f"  Unique labels: {mal[lm].unique()[:10]}")

    malware   = mal[~mal[lm].str.contains("BENIGN", na=False)]
    ransomware= mal[mal[lm].str.contains("RANSOM", na=False)]
    trojan    = mal[mal[lm].str.contains("TROJAN|BACKDOOR|SPYWARE", na=False)]

    for _, r in malware.iterrows():    alerts.append(make_alert("malware_detected", r))
    for _, r in ransomware.iterrows(): alerts.append(make_alert("ransomware_spread", r))
    for _, r in trojan.iterrows():     alerts.append(make_alert("c2_communication", r))

    print(f"  Malware:{len(malware)}  Ransomware:{len(ransomware)}  "
          f"Trojan:{len(trojan)}")

# ════════════════════════════════════════════════════════
# Save — keep 500 per threat, preserve variety
# ════════════════════════════════════════════════════════
print("\nSaving results...")
df = pd.DataFrame(alerts)
print(f"  Raw alerts before cap: {len(df)}")

capped = []
for threat_name in df["threat"].unique():
    group = df[df["threat"] == threat_name]
    sampled = group.sample(min(len(group), 500), random_state=42)
    capped.append(sampled)
df = pd.concat(capped, ignore_index=True)
df.to_csv(OUT + "raw_alerts.csv", index=False)


print("\n" + "="*50)
print("DETECTION COMPLETE")
print("="*50)
for t in sorted(df["threat"].unique()):
    sev = df[df["threat"]==t]["severity"].iloc[0]
    cnt = len(df[df["threat"]==t])
    print(f"  {t:<25} {sev:<8} {cnt}")
print(f"\nTotal alerts: {len(df)}")
print("Output: data/ml/raw_alerts.csv")
print("="*50)