import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# ---------------------------------------------------------
# Page Configurations & Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="SOC CyberShield Dashboard", 
    page_icon="🛡️", 
    layout="wide"
)

# Custom CSS Injection to handle light-on-dark and dark-on-light color pairing perfectly
st.markdown("""
    <style>
        /* Global App Background & Text */
        .stApp {
            background-color: #0b0f19;
            color: #ffffff !important;
        }
        
        /* Default: Force standard text inside dark areas to light gray/white */
        .stApp p, .stApp span, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
            color: #f8fafc !important;
        }
        
        /* ---------------------------------------------------------
           LIGHT BACKGROUNDS -> FORCING BLACK TEXT
           --------------------------------------------------------- */
        
        /* 1. File Uploader Box (White background, black text) */
        div[data-testid="stFileUploader"] section {
            background-color: #ffffff !important;
            border: 2px dashed #3b82f6 !important;
            border-radius: 8px !important;
            padding: 15px !important;
        }
        /* Targets all nested label, header, and instruction text inside the white file uploader */
        div[data-testid="stFileUploader"] section *, 
        div[data-testid="stFileUploader"] section p, 
        div[data-testid="stFileUploader"] section span, 
        div[data-testid="stFileUploader"] section small {
            color: #0f172a !important; 
            font-weight: 500;
        }
        /* Style the target button inside the white file uploader */
        div[data-testid="stFileUploader"] section button {
            background-color: #3b82f6 !important;
            color: #ffffff !important;
            border-radius: 5px !important;
        }

        /* 2. Text/Search Input Field Box (White background, black text) */
        div[data-testid="stTextInput"] input {
            background-color: #ffffff !important;
            color: #0f172a !important;
            font-weight: 500;
            border: 1px solid #cbd5e1 !important;
        }
        
        /* 3. Number Input Component Box (White background, black text) */
        div[data-testid="stNumberInput"] input {
            background-color: #ffffff !important;
            color: #0f172a !important;
            font-weight: 500;
            border: 1px solid #cbd5e1 !important;
        }

        /* ---------------------------------------------------------
           DARK BACKGROUNDS -> FORCING LIGHT TEXT
           --------------------------------------------------------- */
        
        /* Metric Card Configuration */
        div[data-testid="stMetric"] {
            background-color: #111827;
            border: 1px solid #1f2937;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
        }
        
        /* Metric Value Title */
        div[data-testid="stMetricLabel"] > div {
            color: #94a3b8 !important;
            font-weight: 600;
        }
        
        /* Metric Numeric Output */
        div[data-testid="stMetricSimpleValue"] {
            color: #00f2fe !important;
            font-size: 2.2rem !important;
            font-weight: 700;
        }
        
        /* Sidebar Configuration */
        section[data-testid="stSidebar"] {
            background-color: #0f172a;
        }
        section[data-testid="stSidebar"] label p {
            color: #ffffff !important;
        }
        
        /* Header Banner Box */
        .security-banner {
            background: linear-gradient(90deg, #1e3a8a 0%, #0f172a 100%);
            border-left: 5px solid #3b82f6;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .security-banner h1 {
            color: #ffffff !important;
        }
        .security-banner p {
            color: #38bdf8 !important;
        }

        /* Interactive Tabs Styling */
        button[data-baseweb="tab"] {
            font-size: 16px !important;
            font-weight: 600 !important;
            color: #94a3b8 !important;
        }
        button[data-baseweb="tab"][aria-selected="true"] {
            color: #00f2fe !important;
            border-bottom-color: #00f2fe !important;
        }
        
        .stMarkdown h3 {
            color: #00f2fe !important;
        }
        
        /* Empty State Landing Box Styling */
        .landing-box {
            text-align: center; 
            margin-top: 50px; 
            padding: 50px; 
            border: 3px dashed #1e3a8a; 
            border-radius: 12px; 
            background-color: #111827;
        }
    </style>
""", unsafe_allow_html=True)

# App Title Header Banner
st.markdown("""
    <div class="security-banner">
        <h1>🛡️ SOC CyberShield: Activity Monitor</h1>
        <p>Real-Time Insider Threat Detection Engine & Machine Learning Core</p>
    </div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Sidebar Panel Configuration
# ---------------------------------------------------------
st.sidebar.markdown("<h1 style='text-align: center; margin: 0;'>🛡️</h1>", unsafe_allow_html=True)
st.sidebar.markdown("<h2 style='text-align: center; color: #00f2fe; margin-top: 0;'>Control Hub</h2>", unsafe_allow_html=True)
st.sidebar.write("---")

uploaded_file = st.sidebar.file_uploader("📂 Ingest System Logs (.csv)", type=["csv"])

st.sidebar.markdown("### ⚙️ Threshold Configurations")
hour_low = st.sidebar.slider("Start of Safe Shift Hours", 0, 12, 6)
hour_high = st.sidebar.slider("End of Safe Shift Hours", 13, 24, 21)
max_file = st.sidebar.number_input("Max Allowable File Size (MB)", value=500, step=50)

# ---------------------------------------------------------
# Main Application Dashboard Flow
# ---------------------------------------------------------
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    
    # Preprocessing
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Hour'] = df['Timestamp'].dt.hour
    
    alerts = []
    failed_logins = 0
    off_hours = 0
    huge_transfers = 0
    
    for index, row in df.iterrows():
        if row['Status'] == 'Failed':
            alerts.append(f"❌ **Failed login** attempt tracked for employee: `{row['Name']}`")
            failed_logins += 1
        if row['Hour'] < hour_low or row['Hour'] > hour_high:
            alerts.append(f"🌙 **Off-Hours access** detected by `{row['Name']}` at **{row['Hour']}:00**")
            off_hours += 1
        if row['File_Size_MB'] > max_file:
            alerts.append(f"⚠️ **Exfiltration Alert:** Massive payload `{row['File_Size_MB']} MB` moved by `{row['Name']}`")
            huge_transfers += 1

    # ---------------------------------------------------------
    # Visual KPI Matrix Row
    # ---------------------------------------------------------
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Telemetry Volume", f"{len(df)} Records", help="Total historical rows processed")
    m2.metric("Authentication Anomalies", f"{failed_logins} Failures", delta="Risk Warning", delta_color="inverse")
    m3.metric("Out-of-Shift Flags", f"{off_hours} Accesses", delta="Schedule Drift", delta_color="off")
    m4.metric("Data Leak Risks", f"{huge_transfers} Events", delta="Exfiltration Guard", delta_color="inverse")
    
    st.markdown("<br>", unsafe_allow_html=True)

    # UI Tab System creation
    tab1, tab2, tab3 = st.tabs(["📊 Data Stream Inspector", "🚨 Rule Violation Log", "🧠 AI Anomaly Matrix"])
    
    # ---------------------------------------------------------
    # TAB 1: Data Stream Inspector
    # ---------------------------------------------------------
    with tab1:
        st.markdown("### 🔍 Live Data Stream Ingestion Overview")
        st.write("Review complete user activity attributes using real-time search queries below.")
        
        search_user = st.text_input("🎯 Filter stream database records by target employee name:")
        display_df = df.copy()
        if search_user:
            display_df = display_df[display_df['Name'].str.contains(search_user, case=False, na=False)]
            
        st.dataframe(display_df, use_container_width=True)
        
    # ---------------------------------------------------------
    # TAB 2: Rule Violation Log
    # ---------------------------------------------------------
    with tab2:
        st.markdown("### 🚨 Policy Violations (Hardcoded System Safeguards)")
        
        if alerts:
            c1, c2 = st.columns([3, 1])
            with c1:
                for alert in alerts:
                    border_color = "#ef4444" if "Massive" in alert or "Failed" in alert else "#eab308"
                    st.markdown(f"""
                        <div style='background-color:#111827; padding:12px; border-left:5px solid {border_color}; 
                        margin-bottom:10px; border-radius:5px; box-shadow: 0 2px 4px rgba(0,0,0,0.2); color:#ffffff !important;'>
                            <span style='color: #ffffff !important;'>{alert}</span>
                        </div>
                    """, unsafe_allow_html=True)
            with c2:
                st.markdown("### 📈 Incident Report")
                st.markdown("""
                    **Recommended Action Protocol:**
                    1. Notify on-duty SOC manager.
                    2. Cross-reference high file volumes against approved network cloud windows.
                    3. Terminate sessions generating concurrent multi-vector triggers.
                """)
                st.markdown("### ⚠️")
        else:
            st.button("Popups / Success Test Trigger")
            st.balloons()
            st.success("✨ Flawless Run: zero heuristic rules breached across active operations data files.")

    # ---------------------------------------------------------
    # TAB 3: Machine Learning Anomaly Core Engine
    # ---------------------------------------------------------
    with tab3:
        st.markdown("### 🧠 Unsupervised Outlier Identification Core")
        
        col_slider, col_summary = st.columns([3, 2])
        with col_slider:
            contamination = st.slider("🎯 Adjust Machine Learning Sensitivity (Model Contamination Factor)", 0.01, 0.40, 0.15)
        
        # Isolation Forest Calculations
        features = df[['Hour', 'File_Size_MB']]
        model = IsolationForest(contamination=contamination, random_state=42)
        df['Anomaly'] = model.fit_predict(features)
        df['Anomaly'] = df['Anomaly'].map({1: 'Normal', -1: 'Suspicious'})
        
        suspicious_df = df[df['Anomaly'] == 'Suspicious']
        
        with col_summary:
            st.metric("ML Identified Exceptions", f"{len(suspicious_df)} Vectors", f"{round((len(suspicious_df)/len(df))*100, 1)}% of pool")

        st.markdown("#### Classified Behavioral Profiles Output")
        
        def color_rows(val):
            if val == 'Suspicious':
                return 'background-color: #7f1d1d; color: #ffffff; font-weight: bold;'
            return 'background-color: #065f46; color: #ffffff;'
            
        styled_ml_df = df[['Name', 'Action', 'Hour', 'File_Size_MB', 'Anomaly']].style.map(color_rows, subset=['Anomaly'])
        st.dataframe(styled_ml_df, use_container_width=True)
        
        # Professional Scatter Plot Visual Rendering
        st.markdown("#### 📈 Threat Multi-Dimensional Spatial Mapping Matrix")
        
        fig, ax = plt.subplots(figsize=(10, 4.5))
        fig.patch.set_facecolor('#0b0f19')  
        ax.set_facecolor('#111827')
        
        colors = {'Normal': '#00f2fe', 'Suspicious': '#ff007f'}
        
        for label, group in df.groupby('Anomaly'):
            ax.scatter(
                group['Hour'], 
                group['File_Size_MB'], 
                c=colors[label], 
                label=label, 
                alpha=0.9, 
                edgecolors='#ffffff', 
                s=110, 
                linewidths=1.0
            )
            
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#374151')
        ax.spines['bottom'].set_color('#374151')
        ax.tick_params(colors='#9ca3af')
        ax.grid(True, linestyle=':', alpha=0.3, color='#9ca3af')
        
        ax.set_xlabel("Hour of Day (24h Activity Scale)", fontsize=11, color='#9ca3af', fontweight='bold')
        ax.set_ylabel("Data Package Volume Metric (MB)", fontsize=11, color='#9ca3af', fontweight='bold')
        
        leg = ax.legend(loc='upper right', frameon=True, facecolor='#111827', edgecolor='#374151')
        for text in leg.get_texts():
            text.set_color('#ffffff')
            
        st.pyplot(fig)

else:
    st.markdown("""
        <div class="landing-box">
            <h1 style="font-size: 4rem; margin: 0;">☁️</h1>
            <h2 style="color: #ffffff; margin-bottom: 10px;">Awaiting Operational Telemetry Input...</h2>
            <p style="color: #9ca3af; max-width: 550px; margin: 0 auto; font-size: 1.1rem;">
                Please drag and drop your target organization transaction tracking log spreadsheet sheet (.csv) inside the left configuration sidebar panel to initialize active telemetry parsing.
            </p>
        </div>
    """, unsafe_allow_html=True)
