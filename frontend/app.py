"""
SIEM Assistant — Streamlit Frontend

Run with:
    streamlit run frontend/app.py
(from the project root, with backend running on localhost:8000)
"""

import json
from datetime import datetime

import requests
import streamlit as st

BACKEND_URL = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SIEM Assistant",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SIEM Assistant")
st.caption("Ask natural-language questions about your web server logs.")

# ---------------------------------------------------------------------------
# Health check sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Status")
    try:
        r = requests.get(f"{BACKEND_URL}/health", timeout=3)
        h = r.json()
        if h["elasticsearch"] == "up":
            st.success("✅ Elasticsearch: up")
        else:
            st.error("❌ Elasticsearch: unreachable")
        if h["status"] == "ok":
            st.success("✅ Backend: up")
        else:
            st.warning("⚠️ Backend: degraded")
    except Exception:
        st.error("❌ Backend: unreachable")
        st.caption(f"Is the backend running at {BACKEND_URL}?")

    st.divider()
    st.caption("**Tip:** Ask things like:")
    st.markdown(
        "- *Which IPs are hitting us the most today?*\n"
        "- *Show me 4xx errors in the last hour*\n"
        "- *Any scanner user agents in the last 24 hours?*\n"
        "- *Failed login attempts from a single IP?*"
    )

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

if "history" not in st.session_state:
    st.session_state.history = []  # list of {"question", "summary", "query_used", "raw_results", "ts"}

# ---------------------------------------------------------------------------
# Chat history (above the input)
# ---------------------------------------------------------------------------

for item in reversed(st.session_state.history):
    with st.chat_message("user"):
        st.markdown(f"**{item['question']}**")
        st.caption(item["ts"])

    with st.chat_message("assistant"):
        st.markdown(item["summary"])

        with st.expander("🔍 Query used (ES DSL)", expanded=False):
            st.code(json.dumps(item["query_used"], indent=2), language="json")

        raw = item["raw_results"]
        with st.expander("📋 Raw results", expanded=False):
            if "error" in raw:
                st.error(raw["error"])
            elif "hits" in raw and raw["hits"]:
                st.dataframe(raw["hits"], use_container_width=True)
                st.caption(f"Total matching: {raw.get('total', '?')}")
            elif "aggregations" in raw:
                # Render each aggregation as a table
                for agg_name, agg_data in raw["aggregations"].items():
                    buckets = agg_data.get("buckets", [])
                    if buckets:
                        st.subheader(agg_name)
                        st.dataframe(buckets, use_container_width=True)
                st.caption(f"Total matching: {raw.get('total', '?')}")
            else:
                st.info("No results returned.")

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

st.divider()
with st.form("ask_form", clear_on_submit=True):
    col1, col2 = st.columns([5, 1])
    with col1:
        question = st.text_input(
            "Ask a question about your logs",
            placeholder="e.g. Which IPs are hitting us the most today?",
            label_visibility="collapsed",
        )
    with col2:
        submitted = st.form_submit_button("Ask 🔍", use_container_width=True)

if submitted and question.strip():
    with st.spinner("Thinking..."):
        try:
            resp = requests.post(
                f"{BACKEND_URL}/ask",
                json={"question": question.strip()},
                timeout=60,
            )
            if resp.status_code == 200:
                data = resp.json()
                st.session_state.history.append({
                    "question": data["question"],
                    "summary": data["summary"],
                    "query_used": data["query_used"],
                    "raw_results": data["raw_results"],
                    "ts": datetime.now().strftime("%H:%M:%S"),
                })
                st.rerun()
            else:
                detail = resp.json().get("detail", resp.text)
                st.error(f"Backend error ({resp.status_code}): {detail}")
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot reach backend at {BACKEND_URL}. Is it running?")
        except Exception as e:
            st.error(f"Unexpected error: {e}")

elif submitted and not question.strip():
    st.warning("Please enter a question first.")
