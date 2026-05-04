# 🛡 Mini SIEM — Security Information and Event Management System

A lightweight Security Operations Centre (SOC) platform that detects, analyzes, and visualizes cyber threats using a combination of rule-based detection and machine learning.

---

## 🚀 Overview

Mini SIEM simulates a real-world SOC environment where security analysts monitor logs, detect anomalies, and investigate threats.

The system processes multiple cybersecurity datasets, applies detection logic, and presents insights through an interactive dashboard.

---

## ⚙️ Features

* 🔍 Rule-based threat detection (SQLi, XSS, DDoS, etc.)
* 🤖 Machine learning anomaly detection (Isolation Forest + LOF)
* 🧠 SHAP-based explainability for model decisions
* 🗂 SQLite database for alert storage
* 📊 Interactive Streamlit dashboard (SOC-style UI)
* 🧑‍💻 Analyst workbench for investigation and alert management

---

## 🧱 Architecture

Raw Data → Cleaning → Rule Detection → ML Models → Explainability → Database → Dashboard

---

## 🛠 Tech Stack

* **Language:** Python
* **Data Processing:** Pandas, NumPy
* **Machine Learning:** Scikit-learn
* **Explainability:** SHAP
* **Database:** SQLite
* **Frontend:** Streamlit
* **Visualization:** Plotly

---

## 📂 Project Structure

```
mini-siem/
├── dashboard/        # Streamlit dashboard
├── src/              # Core logic (cleaning, detection, ML, DB)
├── pipeline.py       # Main pipeline
├── requirements.txt
└── README.md
```

---

## ▶️ How to Run Locally

```bash
# Create virtual environment
python -m venv .venv

# Activate
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run pipeline
python pipeline.py --clean

# Launch dashboard
streamlit run dashboard/app.py
```

---

## ⚠️ Note on Data

Due to large dataset sizes, raw and processed data files are not included in this repository.

---

## 🎯 My Contribution

* Designed and developed the SOC dashboard using Streamlit
* Implemented alert visualization and filtering system
* Integrated SQLite database with frontend
* Built analyst workflow interface for alert investigation

---

## 📌 Future Improvements

* Real-time log ingestion (Kafka / APIs)
* User authentication system
* Cloud deployment with scalable backend

---

## 🌐 Deployment

This project can be deployed using **Streamlit Cloud**:

1. Push code to GitHub
2. Go to [https://share.streamlit.io](https://share.streamlit.io)
3. Connect your repository
4. Set entry point: `dashboard/app.py`
5. Deploy

---

## 📣 About

A practical implementation of a SIEM system demonstrating cybersecurity analytics, anomaly detection, and SOC workflows.

---
