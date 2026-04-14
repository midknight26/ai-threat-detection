import json
import requests
from threat_intel_nlp.semantic_search import find_top_cves

OLLAMA_URL = "http://localhost:11434/api/generate"


def query_llama(prompt):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "llama3:8b",
            "prompt": prompt,
            "stream": False
        },
        timeout=600
    )
    return response.json()["response"]


def build_prompt(alert, cves):
    return f"""
You are a SOC (Security Operations Center) analyst.

Analyze the following security alert along with related vulnerabilities.

========================
ALERT:
{json.dumps(alert, indent=2)}

========================
RELATED CVEs:
{json.dumps([
    {"cve_id": c["cve_id"], "desc": c["description"][:150]}
    for c in cves
], indent=2)}

========================

Provide:
1. A clear explanation of the attack
2. How the CVEs relate to this activity
3. The most likely MITRE ATT&CK technique
4. 3 concrete investigation steps

Keep the response concise and professional.
"""


def analyze_alert(alert):
    # ensure timestamp is JSON safe
    if hasattr(alert.get("timestamp"), "isoformat"):
        alert["timestamp"] = alert["timestamp"].isoformat()

    # STEP 1: get top CVEs
    cves = find_top_cves(alert, top_k=3)

    # STEP 2: build prompt
    prompt = build_prompt(alert, cves)

    # STEP 3: query LLM
    reply = query_llama(prompt)

    # STEP 4: conversation state
    conversation = [
        {"role": "system", "content": "You are a SOC analyst."},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": reply}
    ]

    return reply, conversation, cves
