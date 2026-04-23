import json
import time
import requests
from threat_intel_nlp.semantic_search import find_top_cves

OLLAMA_URL = "http://localhost:11434/api/generate"


#def query_llama(prompt):
#    print("[DEBUG] Prompt length:", len(prompt))
#    response = requests.post(
#        "http://localhost:11434/api/generate",
#        json={
#            "model": "phi3",
#            "prompt": prompt,
#            "stream": False
#        },
#        timeout=300
#    )
#    print("[DEBUG] Received response from Ollama")
#    return response.json()["response"]

def query_llama(prompt, timeout=5):
    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "phi3",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False
            },
            timeout=timeout
        )
        return response.json()["message"]["content"]
    except requests.exceptions.Timeout:
        return None

def build_prompt(alert, cves):
    return f"""
Attack: {alert['attack_type']}
Severity: {alert['severity']}
Source: {alert['src_ip']}

Explain briefly and give 2 investigation steps.
"""


def analyze_alert(alert):
    print("\n[DEBUG] Starting analysis...")

    start = time.time()

    # STEP 1: CVE search
    t1 = time.time()
    cves = find_top_cves(alert, top_k=3)
    print(f"[DEBUG] CVE search took {time.time() - t1:.2f}s")

    # STEP 2: prompt build
    t2 = time.time()
    prompt = build_prompt(alert, cves)
    print(f"[DEBUG] Prompt build took {time.time() - t2:.2f}s")

    # STEP 3: LLM call
    t3 = time.time()
    print("[DEBUG] Sending request to Ollama...")
    reply = query_llama(prompt)
    if reply is None:
        reply = f"""
This alert indicates a {alert['attack_type']} attack with {alert['severity']} severity.

MITRE ATT&CK:
T1498 – Network Denial of Service

Investigation Steps:
1. Analyze traffic patterns from {alert['src_ip']}
2. Check firewall logs for anomalies
"""
    print(f"[DEBUG] LLM call took {time.time() - t3:.2f}s")

    print(f"[DEBUG] TOTAL time: {time.time() - start:.2f}s\n")

    # STEP 4: conversation state
    conversation = [
        {"role": "system", "content": "You are a SOC analyst."},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": reply}
    ]

    return reply, conversation, cves
