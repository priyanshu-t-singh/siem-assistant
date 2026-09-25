"""
Elasticsearch query execution client.

Public API:
    run_query(query_body: dict, index: str = INDEX_NAME) -> dict
        Executes the query and returns a trimmed, LLM-friendly result dict.
        On ES error, returns {"error": "<message>"} rather than raising.
"""

import os

from elasticsearch import Elasticsearch, BadRequestError, NotFoundError

from schema import ALLOWED_FIELDS, INDEX_NAME, SCHEMA_FIELDS

# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")

_es: Elasticsearch | None = None


def get_client() -> Elasticsearch:
    global _es
    if _es is None:
        _es = Elasticsearch(ES_HOST)
    return _es


# ---------------------------------------------------------------------------
# Result trimming
# ---------------------------------------------------------------------------

_SCHEMA_FIELD_NAMES = {f["name"] for f in SCHEMA_FIELDS}


def _trim_hit(hit: dict) -> dict:
    """Strip ES metadata; keep only schema fields from _source."""
    source = hit.get("_source", {})
    trimmed = {}
    for field in _SCHEMA_FIELD_NAMES:
        # Support dot-notation fields stored nested or flat
        parts = field.split(".")
        val = source
        try:
            for p in parts:
                val = val[p]
            trimmed[field] = val
        except (KeyError, TypeError):
            # Also try flat key (some Filebeat versions flatten ECS fields)
            flat_key = field.replace(".", "_")
            if flat_key in source:
                trimmed[field] = source[flat_key]
    return trimmed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_query(query_body: dict, index: str = INDEX_NAME) -> dict:
    """
    Execute an ES query and return a trimmed result dict.

    Returns one of:
        {"hits": [...], "total": N}              — for plain searches
        {"aggregations": {...}, "total": 0}      — for agg-only queries (size=0)
        {"error": "..."}                          — on ES error
    """
    es = get_client()

    # Server-side cap: never return more than 50 raw hits
    if "size" in query_body and query_body["size"] > 50:
        query_body = {**query_body, "size": 50}

    try:
        response = es.search(index=index, body=query_body)
    except BadRequestError as e:
        return {"error": f"Elasticsearch bad request: {e.message}"}
    except NotFoundError:
        return {"error": f"Index '{index}' not found. Has Filebeat shipped any logs yet?"}
    except Exception as e:
        return {"error": f"Elasticsearch error: {str(e)}"}

    has_aggs = bool(response.get("aggregations"))
    total = response["hits"]["total"]["value"]

    if has_aggs:
        # Return aggregation buckets directly — already compact
        return {
            "aggregations": dict(response["aggregations"]),
            "total": total,
        }
    else:
        hits = [_trim_hit(h) for h in response["hits"]["hits"]]
        return {
            "hits": hits,
            "total": total,
        }


def ping() -> bool:
    """
    Return True if Elasticsearch is reachable.

    Uses info() (GET /) instead of ping() (HEAD /) because ES 8.x returns
    HTTP 400 on HEAD requests even when fully healthy, causing ping() to
    always report the cluster as unreachable.
    """
    try:
        get_client().info()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print(f"Connecting to {ES_HOST} ...")
    if not ping():
        print("ERROR: Cannot reach Elasticsearch. Is it running?")
        raise SystemExit(1)

    test_queries = [
        # 1. Recent hits (plain search)
        {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 5,
        },
        # 2. Top IPs (aggregation)
        {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "top_ips": {
                    "terms": {"field": "source.ip", "size": 5}
                }
            },
            "size": 0,
        },
        # 3. 4xx errors
        {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                        {"range": {"http.response.status_code": {"gte": 400, "lt": 500}}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 10,
        },
    ]

    labels = ["Recent hits (5)", "Top IPs by request count", "4xx errors (10)"]
    for label, qb in zip(labels, test_queries):
        print(f"\n{'='*60}")
        print(f"TEST: {label}")
        result = run_query(qb)
        print(json.dumps(result, indent=2, default=str)[:2000])
