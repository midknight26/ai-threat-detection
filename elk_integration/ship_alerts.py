import json
import sys
import os
from elasticsearch import Elasticsearch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

es = Elasticsearch("http://localhost:9200")
INDEX = "threat-alerts"

def create_index():
    if es.indices.exists(index=INDEX):
        es.indices.delete(index=INDEX)
        print(f"🗑️  Deleted existing index '{INDEX}'")

    es.indices.create(index=INDEX, mappings={
        "properties": {
            "alert_id":      {"type": "keyword"},
            "timestamp":     {"type": "date"},
            "src_ip":        {"type": "keyword"},
            "dst_ip":        {"type": "keyword"},
            "attack_type":   {"type": "keyword"},
            "anomaly_score": {"type": "float"},
            "confidence":    {"type": "float"},
            "severity":      {"type": "keyword"},
            "flow_stats":    {"type": "object"}
        }
    })
    print(f"✅ Created index '{INDEX}'")

def ship_alerts(path="data/sample_alerts.json"):
    with open(path) as f:
        alerts = json.load(f)

    success = 0
    for alert in alerts:
        try:
            es.index(index=INDEX, id=alert["alert_id"], document=alert)
            success += 1
        except Exception as e:
            print(f"❌ Failed: {alert['alert_id']}: {e}")

    print(f"✅ Shipped {success}/{len(alerts)} alerts → '{INDEX}'")

if __name__ == "__main__":
    create_index()
    ship_alerts()
