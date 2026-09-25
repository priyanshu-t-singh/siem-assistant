"""
Result → analyst-style summary via LiteLLM.

Provider and model are controlled by the LLM_MODEL env var (same as llm_query_gen).

Public API:
    summarize(user_question: str, query_used: dict, results: dict) -> str
"""

import json
import logging
import os

import litellm

logger = logging.getLogger(__name__)

MODEL = os.environ.get("LLM_MODEL", "gemini/gemini-2.0-flash")

litellm.suppress_debug_info = True
if os.environ.get("LITELLM_DEBUG"):
    litellm.set_verbose = True

SYSTEM_PROMPT = """\
You are a senior security analyst assistant for a SIEM (Security Information and Event Management) system.
Your job is to interpret Elasticsearch query results and produce a concise, factual summary.

Guidelines:
- State clearly what was found: counts, top offenders, notable patterns.
- Call out obvious anomalies: repeated auth failures, unusual paths (e.g. /.env, /wp-login.php), \
scanner user agents (sqlmap, Nikto, curl), IP addresses generating disproportionate traffic.
- If the result set is empty or contains fewer than 3 events, say "no notable findings" or \
"insufficient data to draw conclusions" — do NOT fabricate patterns.
- Keep the summary under 200 words.
- Use bullet points for multiple findings, plain prose for single findings.
- Do NOT repeat raw JSON or the query itself in the summary.
- Do NOT say "based on the data provided" or similar filler phrases — just state the findings.
"""


def summarize(user_question: str, query_used: dict, results: dict) -> str:
    """
    Produce a natural-language analyst summary of ES query results.

    Args:
        user_question: The original user question.
        query_used:    The ES query body that was executed.
        results:       The trimmed result dict from es_client.run_query().

    Returns:
        A plain-text summary string.
    """
    results_text = json.dumps(results, indent=2, default=str)
    if len(results_text) > 8000:
        results_text = results_text[:8000] + "\n... [truncated for brevity]"

    user_message = f"""\
User question: {user_question}

Query results:
{results_text}

Total matching documents: {results.get('total', 'unknown')}

Please summarize these findings for a security analyst.
"""

    response = litellm.completion(
        model=MODEL,
        max_tokens=512,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )

    return response.choices[0].message.content.strip()


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(f"Using model: {MODEL}\n")

    sample_agg_result = {
        "aggregations": {
            "top_ips": {
                "buckets": [
                    {"key": "185.220.101.5", "doc_count": 847},
                    {"key": "10.0.45.23", "doc_count": 62},
                    {"key": "10.0.12.8", "doc_count": 41},
                    {"key": "91.108.4.213", "doc_count": 39},
                    {"key": "10.0.7.99", "doc_count": 18},
                ]
            }
        },
        "total": 1007,
    }

    sample_hits_result = {
        "hits": [
            {"@timestamp": "2026-09-25T17:22:01Z", "source.ip": "185.220.101.5",
             "http.response.status_code": 401, "url.path": "/login",
             "user_agent.original": "python-requests/2.31.0"},
            {"@timestamp": "2026-09-25T17:22:03Z", "source.ip": "185.220.101.5",
             "http.response.status_code": 401, "url.path": "/login",
             "user_agent.original": "python-requests/2.31.0"},
            {"@timestamp": "2026-09-25T17:22:05Z", "source.ip": "185.220.101.5",
             "http.response.status_code": 403, "url.path": "/admin",
             "user_agent.original": "sqlmap/1.7.11"},
        ],
        "total": 3,
    }

    empty_result = {"hits": [], "total": 0}

    tests = [
        ("Which IPs are hitting us the most today?", {}, sample_agg_result),
        ("Show me failed logins in the last hour", {}, sample_hits_result),
        ("Any 500 errors in the last 5 minutes?", {}, empty_result),
    ]

    for question, query, result in tests:
        print(f"\n{'='*60}")
        print(f"Q: {question}")
        summary = summarize(question, query, result)
        print(f"Summary:\n{summary}")
