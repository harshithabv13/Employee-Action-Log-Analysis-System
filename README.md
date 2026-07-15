# 🛡️ SOC CyberShield: Employee Action Log Analysis System

A modern, production-grade Security Operations Center (SOC) web application that ingests system audit logs to monitor employee actions in real-time. The platform utilizes hardcoded heuristic security constraints alongside unsupervised Machine Learning (`IsolationForest`) to isolate insider threats, flag data exfiltration risks, and maximize organizational infrastructure security.

---

## 🚀 Key Features

* **Live Data Ingestion:** Drag-and-drop CSV log parsing directly through an active web interface.
* **Interactive Control Hub:** Live adjustments for shift-hour thresholds and maximum allowable data transfer sizes.
* **Dynamic KPI Telemetry Row:** Instant metric counters displaying total volume, auth failures, schedule drifts, and data leaks.
* **Rule-Based Security Alerts Engine:** Automatic contextual flag generation for policy violations (e.g., failed logins, off-hours access, huge file sizes).
* **AI Anomaly Suite:** Unsupervised machine learning models utilizing multi-dimensional feature mapping to identify hidden threat vectors.
* **Interactive Spatial Mapping:** Beautifully integrated visual scatter plots plotting activity hours against data packet sizes.
* **High-Contrast Dark Theme:** Sleek Cyberpunk-inspired design engineered for rapid structural readability.

---

## 🛠️ Technologies Used

* **Python** (Core application engine logic)
* **Streamlit** (Production-grade frontend web application framework)
* **Pandas** (Data matrix ingestion, feature extraction, and manipulation)
* **Scikit-learn** (Isolation Forest outlier detection model matrix)
* **Matplotlib** (Spatial feature map generation and rendering graphs)

---

## 📦 Installation & Setup

Before running the application, make sure you install the complete updated project dependencies:

```bash
python -m pip install pandas scikit-learn streamlit matplotlib

## Run Project
python -m streamlit run app.py
