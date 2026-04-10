import json
import numpy as np
import os
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from cve_fetcher import fetch_all_cves

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_CACHE = "data/cve_embeddings.npy"
CVE_INDEX_CACHE = "data/cve_index.json"

_model = None
_cve_embeddings = None
_cves = None

def get_model():
    global _model
    if _model is None:
        print(f"[INFO] Loading sentence transformer: {MODEL_NAME}")
        _model = SentenceTransformer(MODEL_NAME)
    return _model

def build_cve_corpus_text(cve: dict) -> str:
    """Combine CVE fields into a single string for embedding."""
    return f"{cve['cve_id']}: {cve['description']} [attack hint: {cve.get('attack_type_hint', '')}]"

def load_or_build_embeddings(force_rebuild: bool = False):
    global _cve_embeddings, _cves

    cves = fetch_all_cves()
    _cves = cves

    if not force_rebuild and os.path.exists(EMBEDDING_CACHE) and os.path.exists(CVE_INDEX_CACHE):
        print("[INFO] Loading cached CVE embeddings...")
        _cve_embeddings = np.load(EMBEDDING_CACHE)
        return

    print(f"[INFO] Building embeddings for {len(cves)} CVEs...")
    model = get_model()
    corpus = [build_cve_corpus_text(c) for c in cves]
    _cve_embeddings = model.encode(corpus, show_progress_bar=True, batch_size=32)
    np.save(EMBEDDING_CACHE, _cve_embeddings)
    with open(CVE_INDEX_CACHE, "w") as f:
        json.dump(cves, f, indent=2)
    print(f"[INFO] Embeddings saved -> {EMBEDDING_CACHE}")

def build_alert_query(alert: dict) -> str:
    """Convert an alert into a natural language query for semantic matching."""
    attack = alert.get("attack_type", "unknown")
    flow = alert.get("flow_stats", {})
    severity = alert.get("severity", "")
    
    query_parts = [f"{severity} severity {attack} attack detected."]
    
    if attack == "DDoS":
        query_parts.append(
            f"High volume SYN flood with {flow.get('syn_count', 0)} SYN packets, "
            f"{flow.get('packets_per_sec', 0):.0f} packets/sec, "
            f"{flow.get('bytes_per_sec', 0):.0f} bytes/sec."
        )
    elif attack == "PortScan":
        query_parts.append(
            f"Network reconnaissance with {flow.get('fwd_packets', 0)} forward packets "
            f"over {flow.get('duration_ms', 0)}ms duration."
        )
    elif attack == "BruteForce":
        query_parts.append(
            f"Repeated authentication attempts, sustained traffic at "
            f"{flow.get('packets_per_sec', 0):.0f} packets/sec."
        )
    
    return " ".join(query_parts)

def find_top_cves(alert: dict, top_k: int = 3) -> list[dict]:
    """Given an alert, return top-k semantically similar CVEs."""
    global _cve_embeddings, _cves

    if _cve_embeddings is None:
        load_or_build_embeddings()

    model = get_model()
    query = build_alert_query(alert)
    query_embedding = model.encode([query])

    similarities = cosine_similarity(query_embedding, _cve_embeddings)[0]
    top_indices = np.argsort(similarities)[::-1][:top_k]

    results = []
    for idx in top_indices:
        cve = _cves[idx].copy()
        cve["similarity_score"] = float(similarities[idx])
        cve["matched_query"] = query
        results.append(cve)

    return results

def enrich_alerts_with_cves(alerts: list[dict], top_k: int = 3) -> list[dict]:
    """Enrich a list of alerts with their top matching CVEs."""
    load_or_build_embeddings()
    enriched = []
    for alert in alerts:
        top_cves = find_top_cves(alert, top_k=top_k)
        alert_copy = alert.copy()
        alert_copy["matched_cves"] = top_cves
        enriched.append(alert_copy)
    return enriched

if __name__ == "__main__":
    # Quick test: load a few alerts and find matching CVEs
    with open("data/sample_alerts.json") as f:
        alerts = json.load(f)

    load_or_build_embeddings()

    print("\n=== Semantic CVE Matching Demo ===\n")
    for alert in alerts[:3]:
        print(f"Alert: {alert['attack_type']} | {alert['severity']} | {alert['src_ip']}")
        print(f"Query: {build_alert_query(alert)}")
        top_cves = find_top_cves(alert, top_k=3)
        for i, cve in enumerate(top_cves, 1):
            score = cve['base_score'] or 'N/A'
            sim = cve['similarity_score']
            print(f"  [{i}] {cve['cve_id']} (CVSS: {score}, similarity: {sim:.3f})")
            print(f"       {cve['description'][:120]}...")
        print()
