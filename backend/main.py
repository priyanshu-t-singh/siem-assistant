"""
FastAPI backend — SIEM Assistant

Endpoints:
    GET  /health   — liveness + ES connectivity check
    POST /ask      — full NL → query → execute → summarize loop
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from es_client import ping, run_query
from llm_query_gen import generate_query
from llm_summarize import summarize
from schema import INDEX_NAME

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    if ping():
        logger.info("Elasticsearch reachable at startup.")
    else:
        logger.warning("Elasticsearch NOT reachable at startup — queries will fail until it is up.")
    yield


app = FastAPI(
    title="SIEM Assistant",
    description="GenAI-powered SIEM log analysis assistant",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AskRequest(BaseModel):
    question: str


class AskResponse(BaseModel):
    question: str
    query_used: dict
    raw_results: dict
    summary: str


class HealthResponse(BaseModel):
    status: str
    elasticsearch: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["ops"])
def health():
    es_ok = ping()
    return HealthResponse(
        status="ok" if es_ok else "degraded",
        elasticsearch="up" if es_ok else "unreachable",
    )


@app.post("/ask", response_model=AskResponse, tags=["siem"])
def ask(request: AskRequest):
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=422, detail="Question cannot be empty.")

    logger.info("Processing question: %r", question)

    try:
        # Step 1: Generate ES query
        query_body = generate_query(question)
        logger.info("Generated query: %s", query_body)
    except Exception as e:
        logger.exception("Query generation failed")
        raise HTTPException(status_code=502, detail=f"Query generation failed: {str(e)}")

    try:
        # Step 2: Execute query — handle ES errors inline with one retry
        raw_results = run_query(query_body, index=INDEX_NAME)

        if "error" in raw_results:
            # Attempt one repair: re-generate with the ES error as context
            logger.warning("ES error on first attempt: %s — retrying query generation", raw_results["error"])
            try:
                query_body = generate_query(question + f"\n\nNote: previous query failed with: {raw_results['error']}")
                raw_results = run_query(query_body, index=INDEX_NAME)
            except Exception:
                pass  # fall through to summarize with the error dict

        logger.info("Query returned total=%s", raw_results.get("total", "n/a"))
    except Exception as e:
        logger.exception("Query execution failed")
        raise HTTPException(status_code=502, detail=f"Query execution failed: {str(e)}")

    try:
        # Step 3: Summarize
        summary_text = summarize(question, query_body, raw_results)
        logger.info("Summary generated (%d chars)", len(summary_text))
    except Exception as e:
        logger.exception("Summarization failed")
        summary_text = f"[Summarization failed: {str(e)}]"

    return AskResponse(
        question=question,
        query_used=query_body,
        raw_results=raw_results,
        summary=summary_text,
    )
