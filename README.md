# SIEM Assistant

A minimal GenAI-powered SIEM assistant. Ask natural-language questions about your web server logs — the assistant converts them to Elasticsearch queries, executes them, and returns an analyst-style summary.

```
User question → LLM (Claude) → ES Query DSL → Elasticsearch → LLM (Claude) → Summary
```

## Architecture

```
siem-assistant/
├── docker-compose.yml       # Elasticsearch + Kibana + Filebeat
├── filebeat/
│   └── filebeat.yml         # Nginx module → logs-nginx-access index
├── sample-logs/
│   ├── access.log           # written by generate_logs.py
│   └── generate_logs.py     # synthetic NGINX log generator
├── backend/
│   ├── main.py              # FastAPI: POST /ask, GET /health
│   ├── es_client.py         # ES query execution + result trimming
│   ├── llm_query_gen.py     # NL → ES Query DSL via Claude tool-calling
│   ├── llm_summarize.py     # ES results → analyst summary via Claude
│   ├── schema.py            # Curated ECS field schema (12 fields)
│   └── requirements.txt
└── frontend/
    └── app.py               # Streamlit UI
```

---

## Running Instructions

### Prerequisites

- Docker + Docker Compose
- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com/)

---

### Terminal 1 — Start Elasticsearch, Kibana & Filebeat

```bash
docker compose up -d
```

Wait ~30 seconds, then confirm Elasticsearch is healthy:

```bash
curl -s http://localhost:9200/_cluster/health | python -m json.tool
# "status" should be "green" or "yellow"
```

Kibana will be available at **http://localhost:5601** (may take another 30–60 s to fully load).

---

### Terminal 2 — Generate synthetic log data

```bash
cd sample-logs

# Stream logs continuously (recommended — keep running while you use the app)
python generate_logs.py

# Or write a fixed batch and exit:
python generate_logs.py --count 1000
```

Wait ~30 seconds for Filebeat to pick up and ship the first batch.

**Verify in Kibana Dev Tools** (`http://localhost:5601` → Menu → Dev Tools):

```
GET logs-nginx-access*/_search?size=1
```

You should see documents with fields like `source.ip`, `http.response.status_code`, `url.path`, `@timestamp`, `user_agent.original`.

---

### Terminal 3 — Start the backend

```bash
cd backend

pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...    # paste your key here

uvicorn main:app --reload --port 8000
```

Confirm it's up:

```bash
curl -s http://localhost:8000/health | python -m json.tool
# {"status": "ok", "elasticsearch": "up"}
```

> **Troubleshooting:** if `elasticsearch` shows `"unreachable"`, make sure the docker stack is running and `localhost:9200` is accessible.

---

### Terminal 4 — Start the frontend

```bash
pip install streamlit requests    # skip if already installed

streamlit run frontend/app.py
```

Open **http://localhost:8501** in your browser.

---

## Standalone verification (optional but recommended)

Run these before the full stack to verify each layer in isolation.

```bash
cd backend
export ANTHROPIC_API_KEY=sk-ant-...

# Step 3 — NL → ES query generation (calls Claude, no ES needed)
python llm_query_gen.py
# Expected: 5 generated query DSL objects printed to stdout

# Step 4 — ES query execution (needs Elasticsearch running)
python es_client.py
# Expected: trimmed JSON results for 3 hand-written queries

# Step 5 — Result summarization (calls Claude, no ES needed)
python llm_summarize.py
# Expected: 3 analyst-style summaries printed to stdout
```

---

## End-to-end API test

```bash
curl -s -X POST localhost:8000/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "top 5 IPs in the last hour"}' | python -m json.tool
```

Expected response shape:

```json
{
  "question": "top 5 IPs in the last hour",
  "query_used": { ... },
  "raw_results": { ... },
  "summary": "..."
}
```

---

## Sample questions to try

| Question | What it demonstrates |
|---|---|
| Which IPs are hitting us the most today? | Terms aggregation |
| Show me all 4xx errors in the last hour | Range filter on status code |
| Any failed login attempts in the last 30 minutes? | 401/403 filter |
| Are there any scanner user agents? | Keyword match on `user_agent.original` |
| What paths are getting the most 404s? | Compound query + terms agg |
| Show me traffic from 185.220.101.5 | IP filter |

---

## Out of scope (Phase 2)

- Elasticsearch security / API key scoping
- Authentication / multi-user
- ES ML anomaly detection
- Real web server integration
- Query result caching / audit logging
- Containerised backend/frontend
