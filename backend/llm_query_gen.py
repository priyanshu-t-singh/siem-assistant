"""
NL → Elasticsearch Query DSL via Claude.

Public API:
    generate_query(user_question: str) -> dict
        Returns a validated ES query body dict ready to pass to es_client.run_query().
        Raises ValueError on unrecoverable failure.
"""

import json
import os
import re
from datetime import datetime, timezone

import anthropic

from schema import ALLOWED_FIELDS, INDEX_NAME, schema_as_prompt_text

# ---------------------------------------------------------------------------
# Claude client
# ---------------------------------------------------------------------------

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL = "claude-sonnet-4-5"

# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

FEW_SHOT_EXAMPLES = """
--- FEW-SHOT EXAMPLES ---

Q: Show me all 4xx errors in the last 2 hours
A:
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now-2h", "lte": "now"}}},
        {"range": {"http.response.status_code": {"gte": 400, "lt": 500}}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}],
  "size": 50
}

Q: Which IPs are hitting us the most today?
A:
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now/d", "lte": "now"}}}
      ]
    }
  },
  "aggs": {
    "top_ips": {
      "terms": {
        "field": "source.ip",
        "size": 10
      }
    }
  },
  "size": 0
}

Q: Show me failed login attempts (401 or 403) in the last hour
A:
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
        {"terms": {"http.response.status_code": [401, 403]}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}],
  "size": 50
}

Q: Any spike in 404s in the last 30 minutes, grouped by path?
A:
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now-30m", "lte": "now"}}},
        {"term": {"http.response.status_code": 404}}
      ]
    }
  },
  "aggs": {
    "top_paths": {
      "terms": {
        "field": "url.path",
        "size": 10
      }
    }
  },
  "size": 0
}

--- END EXAMPLES ---
"""

SYSTEM_TEMPLATE = """\
You are an Elasticsearch query generation assistant for a SIEM system.
Your ONLY job is to produce a valid Elasticsearch Query DSL JSON object.

Current date/time (UTC): {now_utc}
Target index: {index}

{schema}

{examples}

RULES — follow strictly:
1. Always include a time range filter on "@timestamp" in the "query.bool.filter" array.
   Use Elasticsearch date math (e.g. "now-1h", "now-24h", "now/d") — never hardcode timestamps.
2. Only use field names from the schema above. Do NOT invent fields.
3. Allowed top-level keys: "query", "aggs", "sort", "size". Nothing else.
4. For aggregation-only queries set "size": 0.
5. For hit searches cap "size" at 50 maximum.
6. Do NOT include scripts, _delete_by_query, _update_by_query, or any write operations.
7. Return ONLY the JSON object — no explanation, no markdown fences, no extra text.
"""


def _build_system_prompt() -> str:
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return SYSTEM_TEMPLATE.format(
        now_utc=now_utc,
        index=INDEX_NAME,
        schema=schema_as_prompt_text(),
        examples=FEW_SHOT_EXAMPLES,
    )


# ---------------------------------------------------------------------------
# Tool / structured output definition
# ---------------------------------------------------------------------------

QUERY_TOOL = {
    "name": "elasticsearch_query",
    "description": "Return a valid Elasticsearch Query DSL body.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query_body": {
                "type": "object",
                "description": "The complete ES query body (query, aggs, sort, size).",
            }
        },
        "required": ["query_body"],
    },
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _extract_field_names(obj, results: set):
    """Recursively walk the query body and collect all string keys that look like field names."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            # These are ES DSL structural keys, not field names
            if k not in {
                "query", "bool", "filter", "must", "must_not", "should",
                "range", "term", "terms", "match", "match_phrase", "prefix",
                "wildcard", "exists", "aggs", "aggregations", "sort", "size",
                "field", "value", "gte", "lte", "gt", "lt", "order",
                "nested", "boost", "minimum_should_match",
            }:
                # Heuristic: if the key contains a dot or starts with lowercase, treat as field
                if "." in k or (k and k[0].islower() and k not in ("desc", "asc")):
                    results.add(k)
            _extract_field_names(v, results)
    elif isinstance(obj, list):
        for item in obj:
            _extract_field_names(item, results)


def _validate_and_repair(query_body: dict, error_context: str = "") -> tuple[dict, list[str]]:
    """
    Validate field names against ALLOWED_FIELDS.
    Returns (repaired_body, list_of_warnings).
    Does a best-effort strip of unknown top-level keys.
    """
    warnings = []

    # 1. Strip disallowed top-level keys
    allowed_top = {"query", "aggs", "sort", "size"}
    bad_top = set(query_body.keys()) - allowed_top
    for key in bad_top:
        del query_body[key]
        warnings.append(f"Stripped disallowed top-level key: {key!r}")

    # 2. Check referenced field names
    referenced = set()
    _extract_field_names(query_body, referenced)
    unknown = referenced - ALLOWED_FIELDS
    if unknown:
        warnings.append(f"Unknown fields referenced (may cause ES errors): {unknown}")

    # 3. Cap size
    if "size" in query_body:
        if query_body["size"] > 50:
            query_body["size"] = 50
            warnings.append("Capped size to 50")

    # 4. Ensure a time range filter is present
    try:
        filters = query_body["query"]["bool"]["filter"]
        has_time_filter = any(
            isinstance(f, dict) and "range" in f and "@timestamp" in f["range"]
            for f in filters
        )
        if not has_time_filter:
            warnings.append("No @timestamp range filter found — adding default 24h window")
            filters.insert(0, {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}})
    except (KeyError, TypeError):
        warnings.append("Could not locate bool.filter — wrapping in default 24h bool query")
        original_query = query_body.get("query", {"match_all": {}})
        query_body["query"] = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    original_query,
                ]
            }
        }

    return query_body, warnings


# ---------------------------------------------------------------------------
# Core call
# ---------------------------------------------------------------------------

def _call_llm(user_question: str, extra_context: str = "") -> dict:
    """Call Claude and return the raw query_body dict from the tool call."""
    messages = [{"role": "user", "content": user_question}]
    if extra_context:
        messages[0]["content"] += f"\n\nAdditional context / previous error:\n{extra_context}"

    response = _client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=_build_system_prompt(),
        tools=[QUERY_TOOL],
        tool_choice={"type": "tool", "name": "elasticsearch_query"},
        messages=messages,
    )

    # Extract tool use block
    for block in response.content:
        if block.type == "tool_use" and block.name == "elasticsearch_query":
            return block.input.get("query_body", {})

    raise ValueError("LLM did not return a tool_use block — unexpected response format")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_query(user_question: str) -> dict:
    """
    Convert a natural-language security question into a validated ES Query DSL body.

    Retries once if validation surfaces unknown fields, feeding the error back to the model.
    Raises ValueError on unrecoverable failure.
    """
    # Attempt 1
    raw = _call_llm(user_question)
    query, warnings = _validate_and_repair(raw)

    # If we got unknown-field warnings, retry once with error context
    unknown_warnings = [w for w in warnings if "Unknown fields" in w]
    if unknown_warnings:
        error_ctx = "; ".join(unknown_warnings)
        raw2 = _call_llm(user_question, extra_context=f"Your previous attempt used invalid fields: {error_ctx}. Use ONLY the fields listed in the schema.")
        query, warnings2 = _validate_and_repair(raw2)
        warnings.extend(["[retry] " + w for w in warnings2])

    if warnings:
        import logging
        logging.getLogger(__name__).warning("Query generation warnings: %s", warnings)

    return query


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    test_questions = [
        "Show me failed logins in the last hour",
        "Which IPs are hitting us the most today?",
        "Any spike in 404s in the last 30 minutes?",
        "List all POST requests to /login in the last 6 hours",
        "Show me traffic from scanner user agents in the last 24 hours",
    ]

    for q in test_questions:
        print(f"\n{'='*60}")
        print(f"Q: {q}")
        try:
            result = generate_query(q)
            print(f"Generated query:\n{json.dumps(result, indent=2)}")
        except Exception as e:
            print(f"ERROR: {e}")
