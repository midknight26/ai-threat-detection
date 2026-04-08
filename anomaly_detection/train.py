import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib, os

# ── Load data ────────────────────────────────────────────────────────────────
df = pd.read_csv("data/cicids_sample.csv")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "SYN Flag Count", "RST Flag Count", "ACK Flag Count",
    "Average Packet Size"
]

X = df[FEATURES]
y = df["Label"]

# ── Isolation Forest (unsupervised — detects anomalies) ──────────────────────
print("Training Isolation Forest...")
iso = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
iso.fit(X)

# ── Random Forest Classifier (supervised — labels attack type) ───────────────
print("Training Random Forest Classifier...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42
)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)
print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── Save models ───────────────────────────────────────────────────────────────
os.makedirs("anomaly_detection/model", exist_ok=True)
joblib.dump(iso, "anomaly_detection/model/isolation_forest.pkl")
joblib.dump(rf,  "anomaly_detection/model/random_forest.pkl")
joblib.dump(le,  "anomaly_detection/model/label_encoder.pkl")
joblib.dump(FEATURES, "anomaly_detection/model/features.pkl")

print("\n✅ Models saved to anomaly_detection/model/")
