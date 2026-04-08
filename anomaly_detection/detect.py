import pandas as pd
import numpy as np
import joblib, json, uuid
from datetime import datetime, timedelta
import random

# ── Load models ───────────────────────────────────────────────────────────────
iso      = joblib.load("anomaly_detection/model/isolation_forest.pkl")
rf       = joblib.load("anomaly_detection/model/random_forest.pkl")
le       = joblib.load("anomaly_detection/model/label_encoder.pkl")
FEATURES = joblib.load("anomaly_detection/model/features.pkl")

FAKE_IPS = [f"192.168.1.{i}" for i in range(1, 50)] + \
           [f"10.0.0.{i}"    for i in range(1, 20)] + \
           ["45.33.32.156", "185.220.101.45", "198.51.100.23"]

def generate_alert(row, anomaly_score, attack_type, confidence):
    severity = (
        "CRITICAL" if confidence > 0.90 else
        "HIGH"     if confidence > 0.75 else
        "MEDIUM"   if confidence > 0.55 else
        "LOW"
    )
    return {
        "alert_id":      str(uuid.uuid4()),
        "timestamp":     (datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))).isoformat(),
        "src_ip":        random.choice(FAKE_IPS),
        "dst_ip":        f"10.0.0.{random.randint(1, 10)}",
        "attack_type":   attack_type,
        "anomaly_score": round(float(anomaly_score), 4),
        "confidence":    round(float(confidence),    4),
        "severity":      severity,
        "flow_stats": {
            "duration_ms":      row["Flow Duration"],
            "fwd_packets":      row["Total Fwd Packets"],
            "bytes_per_sec":    round(row["Flow Bytes/s"], 2),
            "packets_per_sec":  round(row["Flow Packets/s"], 2),
            "syn_count":        row["SYN Flag Count"],
        }
    }

def run_detection(csv_path="data/cicids_sample.csv", output_path="data/sample_alerts.json"):
    df = pd.read_csv(csv_path)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    X = df[FEATURES]

    iso_scores  = iso.decision_function(X)   # lower = more anomalous
    iso_preds   = iso.predict(X)             # -1 = anomaly, 1 = normal

    rf_preds    = rf.predict(X)
    rf_proba    = rf.predict_proba(X)
    rf_labels   = le.inverse_transform(rf_preds)
    rf_confs    = rf_proba.max(axis=1)

    alerts = []
    for i, row in df.iterrows():
        if iso_preds[i] == -1 and rf_labels[i] != "BENIGN":
            alert = generate_alert(
                row        = row,
                anomaly_score = iso_scores[i],
                attack_type   = rf_labels[i],
                confidence    = rf_confs[i]
            )
            alerts.append(alert)

    with open(output_path, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"✅ {len(alerts)} alerts written to {output_path}")
    return alerts

if __name__ == "__main__":
    alerts = run_detection()
    print("\nSample alert:")
    print(json.dumps(alerts[0], indent=2))
