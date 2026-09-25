"""
NL → Elasticsearch Query DSL via LiteLLM.

LiteLLM is a unified interface for 100+ LLM providers. Swap the model with
a single env var — no code changes needed.

Supported providers (examples):
    gemini/gemini-2.0-flash          → needs GEMINI_API_KEY
    gemini/gemini-1.5-pro            → needs GEMINI_API_KEY
    openai/gpt-4o                    → needs OPENAI_API_KEY
    openai/gpt-4o-mini               → needs OPENAI_API_KEY
    anthropic/claude-sonnet-4-5      → needs ANTHROPIC_API_KEY
    azure/gpt-4o                     → needs AZURE_API_KEY + AZURE_API_BASE
    cohere/command-r-plus            → needs COHERE_API_KEY

Set LLM_MODEL env var to change provider. Default: gemini/gemini-2.0-flash

Public API:
    generate_query(user_question: str) -> dict
"""

import json
import logging
import os
from datetime import datetime, timezone

import litellm

from schema import ALLOWED_FIELDS, INDEX_NAME, schema_as_prompt_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model configuration — change provider here or via env var
# ---------------------------------------------------------------------------

MODEL = os.environ.get("LLM_MODEL", "gemini/gemini-2.0-flash")

# Silence litellm's verbose output unless DEBUG is set
litellm.suppress_debug_info = True
if os.environ.get("LITELLM_DEBUG"):
    litellm.set_verbose = True

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
# Tool definition (OpenAI function-calling format — LiteLLM normalises this
# across all providers that support tool/function calling)
# ---------------------------------------------------------------------------

QUERY_TOOL = {
    "type": "function",
    "function": {
        "name": "elasticsearch_query",
        "description": "Return a valid Elasticsearch Query DSL body.",
        "parameters": {
            "type": "object",
            "properties": {
                "query_body": {
                    "type": "object",
                    "description": "The complete ES query body (query, aggs, sort, size).",
                }
            },
            "required": ["query_body"],
        },
    },
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _extract_field_names(obj, results: set):
    """Recursively walk the query body and collect string keys that look like field names."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in {
                "query", "bool", "filter", "must", "must_not", "should",
                "range", "term", "terms", "match", "match_phrase", "prefix",
                "wildcard", "exists", "aggs", "aggregations", "sort", "size",
                "field", "value", "gte", "lte", "gt", "lt", "order",
                "nested", "boost", "minimum_should_match",
            }:
                if "." in k or (k and k[0].islower() and k not in ("desc", "asc")):
                    results.add(k)
            _extract_field_names(v, results)
    elif isinstance(obj, list):
        for item in obj:
            _extract_field_names(item, results)


def _validate_and_repair(query_body: dict) -> tuple[dict, list[str]]:
    """
    Validate field names against ALLOWED_FIELDS, strip bad top-level keys,
    cap size, and inject a default time filter if missing.
    Returns (repaired_body, warnings).
    """
    warnings = []

    # 1. Strip disallowed top-level keys
    allowed_top = {"query", "aggs", "sort", "size"}
    for key in list(query_body.keys() - allowed_top):
        del query_body[key]
        warnings.append(f"Stripped disallowed top-level key: {key!r}")

    # 2. Check field names
    referenced: set[str] = set()
    _extract_field_names(query_body, referenced)
    unknown = referenced - ALLOWED_FIELDS
    if unknown:
        warnings.append(f"Unknown fields referenced (may cause ES errors): {unknown}")

    # 3. Cap size
    if query_body.get("size", 0) > 50:
        query_body["size"] = 50
        warnings.append("Capped size to 50")

    # 4. Ensure @timestamp range filter exists
    try:
        filters = query_body["query"]["bool"]["filter"]
        has_time = any(
            isinstance(f, dict) and "range" in f and "@timestamp" in f["range"]
            for f in filters
        )
        if not has_time:
            filters.insert(0, {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}})
            warnings.append("Injected default 24h @timestamp filter")
    except (KeyError, TypeError):
        original_query = query_body.get("query", {"match_all": {}})
        query_body["query"] = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    original_query,
                ]
            }
        }
        warnings.append("Wrapped query in default 24h bool filter")

    return query_body, warnings


# ---------------------------------------------------------------------------
# Core LLM call
# ---------------------------------------------------------------------------

def _call_llm(user_question: str, extra_context: str = "") -> dict:
    """
    Call the configured LLM via LiteLLM and extract the query_body from the
    tool call response.

    Falls back to JSON parsing from the text content if the model does not
    support tool calling (e.g. some smaller models).
    """
    content = user_question
    if extra_context:
        content += f"\n\nAdditional context / previous error:\n{extra_context}"

    messages = [
        {"role": "system", "content": _build_system_prompt()},
        {"role": "user", "content": content},
    ]

    # Try tool calling first
    try:
        response = litellm.completion(
            model=MODEL,
            messages=messages,
            tools=[QUERY_TOOL],
            tool_choice={"type": "function", "function": {"name": "elasticsearch_query"}},
            max_tokens=1024,
        )
        msg = response.choices[0].message
        if msg.tool_calls:
            args = msg.tool_calls[0].function.arguments
            parsed = json.loads(args) if isinstance(args, str) else args
            return parsed.get("query_body", parsed)
    except Exception as tool_err:
        logger.warning("Tool calling failed (%s), falling back to text parsing: %s", MODEL, tool_err)

    # Fallback: ask for raw JSON in the text
    fallback_messages = [
        {"role": "system", "content": _build_system_prompt()},
        {"role": "user", "content": content + "\n\nRespond with ONLY a raw JSON object, no markdown."},
    ]
    response = litellm.completion(
        model=MODEL,
        messages=fallback_messages,
        max_tokens=1024,
    )
    raw_text = response.choices[0].message.content.strip()
    # Strip accidental markdown fences
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
    return json.loads(raw_text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_query(user_question: str) -> dict:
    """
    Convert a natural-language security question into a validated ES Query DSL body.

    Retries once if field validation fails, feeding the error back to the model.
    Raises ValueError on unrecoverable failure.
    """
    raw = _call_llm(user_question)
    query, warnings = _validate_and_repair(raw)

    unknown_warnings = [w for w in warnings if "Unknown fields" in w]
    if unknown_warnings:
        error_ctx = "; ".join(unknown_warnings)
        logger.warning("Retrying query generation due to unknown fields: %s", error_ctx)
        raw2 = _call_llm(
            user_question,
            extra_context=f"Your previous attempt used invalid fields: {error_ctx}. Use ONLY the fields listed in the schema.",
        )
        query, warnings2 = _validate_and_repair(raw2)
        warnings.extend(["[retry] " + w for w in warnings2])

    if warnings:
        logger.warning("Query generation warnings: %s", warnings)

    return query


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(f"Using model: {MODEL}\n")

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
