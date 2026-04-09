import pandas as pd
import numpy as np

np.random.seed(42)
n_normal    = 8000
n_per_attack = 700  # 700 x 3 = 2100 attack samples

def generate_normal():
    return {
        "Flow Duration":        np.random.randint(10000, 50000),
        "Total Fwd Packets":    np.random.randint(2, 15),
        "Total Bwd Packets":    np.random.randint(2, 15),
        "Flow Bytes/s":         np.random.uniform(200, 4000),
        "Flow Packets/s":       np.random.uniform(1, 30),
        "Flow IAT Mean":        np.random.uniform(2000, 10000),
        "Fwd PSH Flags":        0,
        "Bwd PSH Flags":        0,
        "Fwd URG Flags":        0,
        "SYN Flag Count":       np.random.randint(0, 2),
        "RST Flag Count":       0,
        "ACK Flag Count":       np.random.randint(1, 5),
        "Average Packet Size":  np.random.uniform(300, 800),
        "Label": "BENIGN"
    }

def generate_ddos():
    # Hallmarks: massive packet rate, tiny duration, huge SYN count, small packets
    return {
        "Flow Duration":        np.random.randint(1, 300),
        "Total Fwd Packets":    np.random.randint(5000, 20000),
        "Total Bwd Packets":    np.random.randint(0, 5),
        "Flow Bytes/s":         np.random.uniform(500000, 2000000),
        "Flow Packets/s":       np.random.uniform(5000, 20000),
        "Flow IAT Mean":        np.random.uniform(1, 20),
        "Fwd PSH Flags":        0,
        "Bwd PSH Flags":        0,
        "Fwd URG Flags":        0,
        "SYN Flag Count":       np.random.randint(3000, 15000),
        "RST Flag Count":       np.random.randint(0, 10),
        "ACK Flag Count":       np.random.randint(0, 20),
        "Average Packet Size":  np.random.uniform(40, 80),   # tiny packets
        "Label": "DDoS"
    }

def generate_portscan():
    # Hallmarks: many short flows, RST flags high, very few packets per flow, many SYNs
    return {
        "Flow Duration":        np.random.randint(50, 800),
        "Total Fwd Packets":    np.random.randint(1, 4),     # just 1-3 packets
        "Total Bwd Packets":    np.random.randint(0, 2),
        "Flow Bytes/s":         np.random.uniform(50, 500),
        "Flow Packets/s":       np.random.uniform(1, 10),
        "Flow IAT Mean":        np.random.uniform(10, 200),
        "Fwd PSH Flags":        0,
        "Bwd PSH Flags":        0,
        "Fwd URG Flags":        0,
        "SYN Flag Count":       np.random.randint(1, 3),
        "RST Flag Count":       np.random.randint(5, 50),    # high RST = port closed
        "ACK Flag Count":       np.random.randint(0, 3),
        "Average Packet Size":  np.random.uniform(40, 80),
        "Label": "PortScan"
    }

def generate_bruteforce():
    # Hallmarks: medium duration, repeated attempts, PSH flags, medium packet size
    return {
        "Flow Duration":        np.random.randint(5000, 20000),
        "Total Fwd Packets":    np.random.randint(50, 300),
        "Total Bwd Packets":    np.random.randint(50, 300),
        "Flow Bytes/s":         np.random.uniform(3000, 15000),
        "Flow Packets/s":       np.random.uniform(20, 100),
        "Flow IAT Mean":        np.random.uniform(100, 800),
        "Fwd PSH Flags":        np.random.randint(10, 80),   # PSH = data push (login attempts)
        "Bwd PSH Flags":        np.random.randint(10, 80),
        "Fwd URG Flags":        np.random.randint(0, 5),
        "SYN Flag Count":       np.random.randint(1, 5),
        "RST Flag Count":       np.random.randint(0, 5),
        "ACK Flag Count":       np.random.randint(40, 200),
        "Average Packet Size":  np.random.uniform(150, 400), # medium — login payloads
        "Label": "BruteForce"
    }

rows = (
    [generate_normal()     for _ in range(n_normal)]     +
    [generate_ddos()       for _ in range(n_per_attack)] +
    [generate_portscan()   for _ in range(n_per_attack)] +
    [generate_bruteforce() for _ in range(n_per_attack)]
)

np.random.shuffle(rows)
df = pd.DataFrame(rows)
df.to_csv("data/cicids_sample.csv", index=False)
print(f"✅ Generated {len(df)} rows → data/cicids_sample.csv")
print(df["Label"].value_counts())
