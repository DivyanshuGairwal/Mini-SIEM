import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os

# ── Page config ───────────────────────────────────────────
st.set_page_config(
    page_title="Mini SIEM — SOC Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

import os
import streamlit as st

if not os.path.exists(DB):
    st.error("Database not found🚫")
    st.info("run the pipeline locally to generate alerts database.")
    st.stop()

DB = "outputs/threat_alerts.db"

# ── Custom CSS — dark SOC theme ───────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #0d1117; }
[data-testid="stSidebar"]          { background-color: #161b22; }
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}
.metric-value { font-size: 2.2rem; font-weight: 700; color: #58a6ff; }
.metric-label { font-size: 0.85rem; color: #8b949e; margin-top: 4px; }
.high-badge   { background:#3d1a1a; color:#f85149;
                padding:3px 10px; border-radius:12px; font-size:12px; }
.med-badge    { background:#2d2208; color:#e3b341;
                padding:3px 10px; border-radius:12px; font-size:12px; }
.low-badge    { background:#0d2119; color:#3fb950;
                padding:3px 10px; border-radius:12px; font-size:12px; }
.threat-card  {
    background:#161b22; border:1px solid #30363d;
    border-radius:8px; padding:14px; margin-bottom:10px;
}
h1,h2,h3     { color: #c9d1d9 !important; }
.stMetric    { background:#161b22; border-radius:8px; padding:12px; }
</style>
""", unsafe_allow_html=True)

# ── DB helper ─────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_alerts():
    conn = sqlite3.connect(DB)
    df = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
    conn.close()
    return df

@st.cache_data(ttl=30)
def load_ip_risk():
    conn = sqlite3.connect(DB)
    df = pd.read_sql("SELECT * FROM ip_risk ORDER BY risk_score DESC", conn)
    conn.close()
    return df

def load_notes(alert_id):
    conn = sqlite3.connect(DB)
    df = pd.read_sql(
        f"SELECT * FROM analyst_notes WHERE alert_id={alert_id}", conn)
    conn.close()
    return df

def save_note(alert_id, analyst, note, action):
    conn = sqlite3.connect(DB)
    conn.execute("""
        INSERT INTO analyst_notes (alert_id, analyst, note, action, created_at)
        VALUES (?,?,?,?,?)
    """, (alert_id, analyst, note, action,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def update_status(alert_id, new_status):
    conn = sqlite3.connect(DB)
    conn.execute("UPDATE alerts SET status=? WHERE id=?",
                 (new_status, alert_id))
    conn.commit()
    conn.close()

# ── Sidebar navigation ────────────────────────────────────
st.sidebar.markdown("## 🛡 Mini SIEM")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate",
    ["SOC Overview", "Threat Intelligence", "Analyst Workbench"])

st.sidebar.markdown("---")
st.sidebar.markdown("### Filters")
df_all = load_alerts()

sev_filter = st.sidebar.multiselect(
    "Severity",
    options=["High", "Medium", "Low"],
    default=["High", "Medium", "Low"]
)
threat_filter = st.sidebar.multiselect(
    "Threat type",
    options=sorted(df_all["threat"].unique()),
    default=sorted(df_all["threat"].unique())
)
status_filter = st.sidebar.multiselect(
    "Status",
    options=sorted(df_all["status"].unique()),
    default=sorted(df_all["status"].unique())
)

# apply filters
df = df_all[
    df_all["severity"].isin(sev_filter) &
    df_all["threat"].isin(threat_filter) &
    df_all["status"].isin(status_filter)
].copy()

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Showing:** {len(df):,} / {len(df_all):,} alerts")
st.sidebar.markdown("**Analyst:** SOC Operator")
st.sidebar.markdown(f"**Updated:** {datetime.now().strftime('%H:%M:%S')}")

# ════════════════════════════════════════════════════════
# PAGE 1 — SOC OVERVIEW
# ════════════════════════════════════════════════════════
if page == "SOC Overview":
    st.markdown("# 🛡 SOC Operations Dashboard")
    st.markdown(f"*Live threat monitoring — {datetime.now().strftime('%A, %d %B %Y %H:%M')}*")
    st.markdown("---")

    # KPI cards
    total    = len(df)
    critical = len(df[df["status"] == "Critical"])
    high_p   = len(df[df["severity"] == "High"])
    ml_anom  = len(df[df["ml_anomaly"] == 1])
    invest   = len(df[df["status"] == "Investigate"])

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value">{total:,}</div>
            <div class="metric-label">Total Alerts</div></div>""",
            unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#f85149">{critical:,}</div>
            <div class="metric-label">Critical</div></div>""",
            unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#e3b341">{high_p:,}</div>
            <div class="metric-label">High Priority</div></div>""",
            unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#a371f7">{ml_anom:,}</div>
            <div class="metric-label">ML Anomalies</div></div>""",
            unsafe_allow_html=True)
    with c5:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#58a6ff">{invest:,}</div>
            <div class="metric-label">Investigating</div></div>""",
            unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Row 2 — charts
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Threat volume by type")
        threat_counts = df["threat"].value_counts().reset_index()
        threat_counts.columns = ["threat", "count"]
        fig = px.bar(threat_counts, x="count", y="threat",
                     orientation="h", color="count",
                     color_continuous_scale="Reds",
                     template="plotly_dark")
        fig.update_layout(
            plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
            showlegend=False, coloraxis_showscale=False,
            margin=dict(l=10, r=10, t=10, b=10), height=320)
        st.plotly_chart(fig, use_container_width="stretch", config={"displayModeBar": False})

    with col2:
        st.markdown("### Severity distribution")
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        colors = {"High": "#f85149", "Medium": "#e3b341", "Low": "#3fb950"}
        fig2 = px.pie(sev_counts, names="severity", values="count",
                      color="severity", color_discrete_map=colors,
                      template="plotly_dark", hole=0.45)
        fig2.update_layout(
            plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
            margin=dict(l=10, r=10, t=10, b=10), height=320)
        st.plotly_chart(fig2, use_container_width="stretch", config={"displayModeBar": False})

    # Row 3 — timeline
    st.markdown("### Alert timeline (last 48 hours)")
    if "timestamp" in df.columns:
        df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["ts"].dt.floor("h")
        timeline = df.groupby(["hour","severity"]).size().reset_index(name="count")
        fig3 = px.line(timeline, x="hour", y="count", color="severity",
                       color_discrete_map=colors, template="plotly_dark")
        fig3.update_layout(
            plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
            margin=dict(l=10, r=10, t=10, b=10), height=280)
        st.plotly_chart(fig3, use_container_width="stretch", config={"displayModeBar": False})

    # Row 4 — live incident feed
    st.markdown("### Live incident feed")
    recent = df[df["severity"].isin(["High"])].head(8)
    for _, row in recent.iterrows():
        badge = f'<span class="high-badge">HIGH</span>'
        st.markdown(f"""<div class="threat-card">
            {badge} &nbsp; <strong>{row['threat'].replace('_',' ').upper()}</strong>
            &nbsp;|&nbsp; {row['mitre_technique']}
            &nbsp;|&nbsp; Src: <code>{row['source_ip']}</code>
            &nbsp;→&nbsp; Dst: <code>{row['destination_ip']}</code>
            &nbsp;|&nbsp; {row['timestamp']}
        </div>""", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════
# PAGE 2 — THREAT INTELLIGENCE
# ════════════════════════════════════════════════════════
elif page == "Threat Intelligence":
    st.markdown("# Threat Intelligence")
    st.markdown("---")

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown("### MITRE ATT&CK coverage")
        mitre_data = df.groupby(
            ["mitre_tactic","threat"]).size().reset_index(name="count")
        fig_m = px.treemap(mitre_data,
                           path=["mitre_tactic","threat"],
                           values="count",
                           color="count",
                           color_continuous_scale="Reds",
                           template="plotly_dark")
        fig_m.update_layout(
            plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
            margin=dict(l=5, r=5, t=5, b=5), height=380)
        st.plotly_chart(fig_m, use_container_width="stretch", config={"displayModeBar": False})

    with col2:
        st.markdown("### ML anomaly breakdown")
        anom_df = df[df["ml_anomaly"]==1]
        if len(anom_df) > 0:
            anom_counts = anom_df["threat"].value_counts().reset_index()
            anom_counts.columns = ["threat","count"]
            fig_a = px.bar(anom_counts, x="threat", y="count",
                           color="count", color_continuous_scale="Purples",
                           template="plotly_dark")
            fig_a.update_layout(
                plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                showlegend=False, coloraxis_showscale=False,
                margin=dict(l=5, r=5, t=5, b=5), height=380,
                xaxis_tickangle=-30)
            st.plotly_chart(fig_a, use_container_width="stretch", config={"displayModeBar": False})
        else:
            st.info("No ML anomalies in current filter")

    # SHAP feature importance
    shap_path = "data/ml/shap_importance.csv"
    if os.path.exists(shap_path):
        st.markdown("### SHAP feature importance (why ML flagged anomalies)")
        shap_df = pd.read_csv(shap_path)
        fig_s = px.bar(shap_df, x="importance", y="feature",
                       orientation="h", color="importance",
                       color_continuous_scale="Viridis",
                       template="plotly_dark")
        fig_s.update_layout(
            plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
            coloraxis_showscale=False,
            margin=dict(l=5, r=5, t=5, b=5), height=300)
        st.plotly_chart(fig_s, use_container_width="stretch", config={"displayModeBar": False})

    # IP risk leaderboard
    st.markdown("### Top 20 riskiest source IPs")
    ip_df = load_ip_risk().head(20)
    fig_ip = px.bar(ip_df, x="source_ip", y="risk_score",
                    color="risk_score", color_continuous_scale="Reds",
                    hover_data=["alert_count","top_threat"],
                    template="plotly_dark")
    fig_ip.update_layout(
        plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
        coloraxis_showscale=False, xaxis_tickangle=-45,
        margin=dict(l=5, r=5, t=5, b=5), height=320)
    st.plotly_chart(fig_ip, use_container_width="stretch", config={"displayModeBar": False})

    # Detection source breakdown
    st.markdown("### Dataset contribution")
    ds_counts = df["source_dataset"].value_counts().reset_index()
    ds_counts.columns = ["dataset","count"]
    fig_ds = px.pie(ds_counts, names="dataset", values="count",
                    template="plotly_dark", hole=0.4)
    fig_ds.update_layout(
        plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
        margin=dict(l=5, r=5, t=5, b=5), height=300)
    st.plotly_chart(fig_ds, use_container_width="stretch", config={"displayModeBar": False})

# ════════════════════════════════════════════════════════
# PAGE 3 — ANALYST WORKBENCH
# ════════════════════════════════════════════════════════
elif page == "Analyst Workbench":
    st.markdown("# Analyst Workbench")
    st.markdown("---")

    # Filterable alert table
    st.markdown("### Alert triage table")
    show_cols = ["id","threat","severity","status","source_ip",
                 "mitre_technique","timestamp","ml_anomaly","risk_score"]
    st.dataframe(
        df[show_cols].head(200),
        use_container_width="stretch",
        height=320
    )

    st.markdown("---")
    col1, col2 = st.columns(2)

    # Add analyst note
    with col1:
        st.markdown("### Add analyst note")
        alert_id  = st.number_input("Alert ID", min_value=1,
                                    max_value=int(df_all["id"].max()),
                                    value=1)
        analyst   = st.text_input("Analyst name", value="SOC Analyst")
        note_text = st.text_area("Note", placeholder="Enter investigation notes...")
        action    = st.selectbox("Action taken",
                                 ["Investigating","Blocked","Escalated",
                                  "False Positive","Closed","Watching"])
        if st.button("Save note"):
            save_note(alert_id, analyst, note_text, action)
            st.success(f"Note saved for Alert #{alert_id}")
            st.cache_data.clear()

    # Update alert status
    with col2:
        st.markdown("### Update alert status")
        upd_id  = st.number_input("Alert ID to update", min_value=1,
                                   max_value=int(df_all["id"].max()),
                                   value=1, key="upd")
        new_status = st.selectbox("New status",
                                  ["Open","Investigate","High Priority",
                                   "Critical","Closed"])
        if st.button("Update status"):
            update_status(upd_id, new_status)
            st.success(f"Alert #{upd_id} updated to '{new_status}'")
            st.cache_data.clear()

        # Show existing notes
        st.markdown("### Existing notes for alert")
        view_id = st.number_input("View notes for Alert ID",
                                   min_value=1, value=1, key="view")
        notes_df = load_notes(view_id)
        if len(notes_df) > 0:
            for _, n in notes_df.iterrows():
                st.markdown(f"""<div class="threat-card">
                    <strong>{n['analyst']}</strong> — {n['action']}<br>
                    {n['note']}<br>
                    <small style="color:#8b949e">{n['created_at']}</small>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("No notes for this alert yet")

    # Export section
    st.markdown("---")
    st.markdown("### Export")
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        csv = df[show_cols].to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download alerts as CSV",
            data=csv,
            file_name=f"siem_alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )
    with col_e2:
        summary = f"""SIEM ALERT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Total Alerts: {len(df)}
Critical: {len(df[df['status']=='Critical'])}
High Priority: {len(df[df['severity']=='High'])}
ML Anomalies: {len(df[df['ml_anomaly']==1])}

THREAT BREAKDOWN:
{df['threat'].value_counts().to_string()}

TOP 10 RISKIEST IPs:
{load_ip_risk().head(10)[['source_ip','risk_score','top_threat']].to_string()}
"""
        st.download_button(
            label="Download summary report (TXT)",
            data=summary.encode("utf-8"),
            file_name=f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain"
        )