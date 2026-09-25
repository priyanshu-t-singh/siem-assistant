"""
Curated schema for the SIEM LLM assistant.

This is the *only* set of fields the LLM is permitted to reference in queries.
It is intentionally small — do NOT replace this with a raw Elasticsearch mapping dump.
"""

SCHEMA_FIELDS = [
    {
        "name": "@timestamp",
        "type": "date",
        "example": "2026-09-25T10:15:30.000Z",
        "description": "When the log event was recorded (ISO-8601, UTC). Use this for all time-range filters.",
    },
    {
        "name": "source.ip",
        "type": "ip",
        "example": "185.220.101.5",
        "description": "IP address of the client making the HTTP request.",
    },
    {
        "name": "http.response.status_code",
        "type": "integer",
        "example": 404,
        "description": "HTTP response status code returned by the server (e.g. 200, 301, 400, 401, 403, 404, 500).",
    },
    {
        "name": "http.request.method",
        "type": "keyword",
        "example": "GET",
        "description": "HTTP method used (GET, POST, PUT, DELETE, etc.).",
    },
    {
        "name": "url.path",
        "type": "keyword",
        "example": "/api/v1/users",
        "description": "The URL path portion of the request (without query string).",
    },
    {
        "name": "url.original",
        "type": "keyword",
        "example": "/login?redirect=/dashboard",
        "description": "Full original URL as received by the server, including any query string.",
    },
    {
        "name": "user_agent.original",
        "type": "keyword",
        "example": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "description": "Raw User-Agent string sent by the client. Look here for scanners (sqlmap, Nikto, curl, etc.).",
    },
    {
        "name": "user_agent.name",
        "type": "keyword",
        "example": "Chrome",
        "description": "Parsed browser/client name extracted from the User-Agent string.",
    },
    {
        "name": "http.response.body.bytes",
        "type": "long",
        "example": 12543,
        "description": "Size of the HTTP response body in bytes.",
    },
    {
        "name": "http.version",
        "type": "keyword",
        "example": "1.1",
        "description": "HTTP protocol version used for the request (1.0, 1.1, 2.0).",
    },
    {
        "name": "event.duration",
        "type": "long",
        "example": 145230000,
        "description": "Request processing duration in nanoseconds (if present in logs).",
    },
    {
        "name": "http.request.referrer",
        "type": "keyword",
        "example": "https://google.com",
        "description": "HTTP Referer header value — where the user came from. '-' means no referrer.",
    },
]

# Flat set of allowed field names for fast validation
ALLOWED_FIELDS: set[str] = {f["name"] for f in SCHEMA_FIELDS}

# The target Elasticsearch index
INDEX_NAME = "logs-nginx-access"


def schema_as_prompt_text() -> str:
    """Return a compact, human-readable schema string for use in LLM system prompts."""
    lines = ["Available Elasticsearch fields (ONLY use these in your queries):"]
    lines.append("")
    for f in SCHEMA_FIELDS:
        lines.append(f"  • {f['name']} ({f['type']}) — {f['description']}")
        lines.append(f"    Example value: {f['example']!r}")
    return "\n".join(lines)
