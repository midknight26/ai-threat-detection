import streamlit as st
import json
import os
import sys
import pandas as pd
import plotly.express as px
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_assistant.soc_assistant import analyze_alert

# ── CONFIG ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

# ── LOAD DATA ──────────────────────────────────────────────────────────
@st.cache_data
def load_alerts():
    path = "data/sample_alerts.json"
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)

alerts = load_alerts()
df = pd.DataFrame(alerts)

if not df.empty:
    df["timestamp"] = pd.to_datetime(df["timestamp"])

# ── SIDEBAR ───────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ AI Threat Detection")

    severity_filter = st.multiselect(
        "Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    attack_filter = st.multiselect(
        "Attack Type",
        ["DDoS", "PortScan", "BruteForce"],
        default=["DDoS", "PortScan", "BruteForce"]
    )

    page = st.radio(
        "Navigation",
        ["📊 Overview", "🔍 Alert Feed", "🤖 SOC Assistant"]
    )

    st.markdown("---")
    st.markdown("STACK: Isolation Forest · Random Forest · MiniLM · phi3 (Ollama) · ELK")

# ── FILTER DATA ───────────────────────────────────────────────────────
fdf = df.copy()
if not fdf.empty:
    fdf = fdf[
        fdf["severity"].isin(severity_filter) &
        fdf["attack_type"].isin(attack_filter)
    ]

# ══════════════════════════════════════════════════════════════════════
# OVERVIEW
# ══════════════════════════════════════════════════════════════════════
if page == "📊 Overview":
    st.title("Threat Detection Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", len(fdf))
    col2.metric("Critical Alerts", len(fdf[fdf["severity"] == "CRITICAL"]))
    col3.metric("High Alerts", len(fdf[fdf["severity"] == "HIGH"]))

    if not fdf.empty:
        timeline = fdf.groupby(fdf["timestamp"].dt.floor("min")).size().reset_index(name="count")
        fig = px.line(timeline, x="timestamp", y="count", title="Alerts Over Time")
        st.plotly_chart(fig, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════
# ALERT FEED
# ══════════════════════════════════════════════════════════════════════
elif page == "🔍 Alert Feed":
    st.title("Live Alert Feed")

    if not fdf.empty:
        for _, row in fdf.head(50).iterrows():
            st.write(
                f"{row['timestamp']} | {row['attack_type']} | "
                f"{row['severity']} | {row['src_ip']} → {row['dst_ip']}"
            )
    else:
        st.info("No alerts available")

# ══════════════════════════════════════════════════════════════════════
# SOC ASSISTANT (FINAL VERSION 🔥)
# ══════════════════════════════════════════════════════════════════════
elif page == "🤖 SOC Assistant":
    st.title("SOC Assistant")

    if not df.empty:
        selected_alert = df.iloc[0].to_dict()

        # Severity 
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "gold",
            "LOW": "green"
        }

        st.markdown(
            f"<span style='color:{severity_color[selected_alert['severity']]}; font-weight:bold;'>"
            f"{selected_alert['severity']} ALERT</span>",
            unsafe_allow_html=True
        )

        st.subheader("Selected Alert")
        st.json(selected_alert)

        if st.button("🔍 Analyze Alert"):
            with st.spinner("Running CVE correlation + LLM analysis..."):
                reply, conversation, cves = analyze_alert(selected_alert)

            # 🔗 CVEs
            st.subheader("🔗 Matched CVEs")
            for cve in cves:
                with st.container():
                    st.markdown(
                        "<div style='background-color:#111; padding:10px; border-radius:8px;'>",
                        unsafe_allow_html=True 
                    )
                    st.markdown(f"### {cve['cve_id']}")
                    st.markdown(f"**Similarity:** {cve['similarity_score']:.3f}")
        
                    st.markdown(
                        f"<div style='font-size:14px; color:#ccc;'>"
                        f"{cve['description'][:180]}..."
                        f"</div>",
                        unsafe_allow_html=True
                    )
        
                    st.markdown("</div>")

            # 🧠 LLM
            st.subheader("🧠 SOC Analysis")
            st.write(reply)
            if "timed out" in reply:
                st.warning("LLM response timed out - showing fallback analysis")

            st.session_state["conversation"] = conversation

        # FOLLOW-UP CHAT
        if "conversation" in st.session_state:
            st.subheader("Follow-up Chat")

            follow_up = st.text_input("Ask a follow-up question:")

            if st.button("Send") and follow_up:
                conv = st.session_state["conversation"]
                conv.append({"role": "user", "content": follow_up})

                prompt = "\n".join([f"{m['role']}: {m['content']}" for m in conv])

                response = requests.post(
                    "http://localhost:11434/api/generate",
                    json={"model": "phi3", "prompt": prompt, "stream": False}
                )

                reply = response.json()["response"]

                conv.append({"role": "assistant", "content": reply})
                st.session_state["conversation"] = conv

                st.write(reply)

    else:
        st.warning("No alert data found. Run detection first.")
