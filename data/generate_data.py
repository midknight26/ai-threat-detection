import pandas as pd
import numpy as np

np.random.seed(42)
n_normal = 8000
n_attack = 2000
n = n_normal + n_attack

def generate_traffic(attack=False):
    if not attack:
        return {
            "Flow Duration":        np.random.randint(1000, 50000),
            "Total Fwd Packets":    np.random.randint(1, 20),
            "Total Bwd Packets":    np.random.randint(1, 20),
            "Flow Bytes/s":         np.random.uniform(100, 5000),
            "Flow Packets/s":       np.random.uniform(0.1, 50),
            "Flow IAT Mean":        np.random.uniform(100, 10000),
            "Fwd PSH Flags":        0,
            "Bwd PSH Flags":        0,
            "Fwd URG Flags":        0,
            "SYN Flag Count":       np.random.randint(0, 2),
            "RST Flag Count":       0,
            "ACK Flag Count":       np.random.randint(0, 5),
            "Average Packet Size":  np.random.uniform(40, 800),
            "Label":                "BENIGN"
        }
    else:
        attack_type = np.random.choice(["DDoS", "PortScan", "BruteForce"])
        return {
            "Flow Duration":        np.random.randint(1, 500),
            "Total Fwd Packets":    np.random.randint(100, 5000),
            "Total Bwd Packets":    np.random.randint(0, 10),
            "Flow Bytes/s":         np.random.uniform(50000, 1000000),
            "Flow Packets/s":       np.random.uniform(500, 10000),
            "Flow IAT Mean":        np.random.uniform(1, 100),
            "Fwd PSH Flags":        np.random.randint(0, 3),
            "Bwd PSH Flags":        np.random.randint(0, 2),
            "Fwd URG Flags":        np.random.randint(0, 2),
            "SYN Flag Count":       np.random.randint(50, 500),
            "RST Flag Count":       np.random.randint(0, 50),
            "ACK Flag Count":       np.random.randint(0, 100),
            "Average Packet Size":  np.random.uniform(40, 100),
            "Label":                attack_type
        }

rows = [generate_traffic(attack=False) for _ in range(n_normal)] + \
       [generate_traffic(attack=True)  for _ in range(n_attack)]

np.random.shuffle(rows)
df = pd.DataFrame(rows)
df.to_csv("data/cicids_sample.csv", index=False)
print(f"✅ Generated {len(df)} rows → data/cicids_sample.csv")
print(df["Label"].value_counts())
