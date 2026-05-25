import pandas as pd
from sklearn.ensemble import IsolationForest

# Load Dataset
df = pd.read_csv("dataset/employee_logs.csv")

# Convert Timestamp
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Extract Hour
df['Hour'] = df['Timestamp'].dt.hour

print("\n===== Employee Log Dataset =====")
print(df.head())

# -----------------------------------------
# Rule-Based Security Alerts
# -----------------------------------------

alerts = []

for index, row in df.iterrows():

    # Failed Login Detection
    if row['Status'] == 'Failed':
        alerts.append(
            f"ALERT: Failed login detected for {row['Name']}"
        )

    # Unusual Access Time Detection
    if row['Hour'] < 6 or row['Hour'] > 21:
        alerts.append(
            f"ALERT: Unusual access time by {row['Name']}"
        )

    # Large File Transfer Detection
    if row['File_Size_MB'] > 500:
        alerts.append(
            f"ALERT: Large file transfer by {row['Name']}"
        )

# Display Alerts
print("\n===== SECURITY ALERTS =====")

for alert in alerts:
    print(alert)

# -----------------------------------------
# Machine Learning Anomaly Detection
# -----------------------------------------

# Select Features
features = df[['Hour', 'File_Size_MB']]

# Train Model
model = IsolationForest(
    contamination=0.2,
    random_state=42
)

df['Anomaly'] = model.fit_predict(features)

# Convert Results
df['Anomaly'] = df['Anomaly'].map({
    1: 'Normal',
    -1: 'Suspicious'
})

print("\n===== ANOMALY DETECTION RESULTS =====")
print(df[['Name', 'Action', 'Hour', 'File_Size_MB', 'Anomaly']])