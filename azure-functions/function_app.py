"""
Byte Me — Azure Functions v2 (Python 3.11, Flex Consumption).

Routes
  POST /api/analyze          Judge quick-paste (subject, body, sender, headers)
  GET  /api/queue            Ranked Cosmos (or memory) triage queue
  POST /api/graph/poll       Pull report-phishing mailbox via Graph (or simulated)
  GET  /api/health

Timer
  graph_mailbox_timer        Every 5 minutes — same ingest path as POST /api/graph/poll
"""

from __future__ import annotations

import json
import logging
import azure.functions as func

from azure_ai_orchestrator import analyze_payload
from cosmos_store import list_reports, upsert_report
from graph_ingest import fetch_mailbox

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _json(payload: dict | list, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(payload, default=str), status_code=status, mimetype="application/json")


def _ingest_one(subject: str, body: str, sender: str, headers: str, source: str, graph_id: str | None = None) -> dict:
    result = analyze_payload(subject=subject, body=body, sender=sender, headers=headers)
    result["source"] = source
    if graph_id:
        result["graph_message_id"] = graph_id
        result["id"] = result.get("id") or graph_id
    stored = upsert_report(result)
    result["store"] = stored.get("store")
    return result


@app.route(route="analyze", methods=["POST"])
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Byte Me analyze invoked")
    try:
        body = req.get_json()
    except ValueError:
        return _json({"error": "Request body must be JSON."}, 400)

    subject = str(body.get("subject") or "")
    email_body = str(body.get("body") or "")
    sender = str(body.get("sender") or "")
    headers = str(body.get("headers") or "")
    if not (subject or email_body or sender):
        return _json({"error": "Provide at least subject, body, or sender."}, 400)

    return _json(_ingest_one(subject, email_body, sender, headers, source="quick-paste"))


@app.route(route="queue", methods=["GET"])
def queue(req: func.HttpRequest) -> func.HttpResponse:
    limit = int(req.params.get("limit") or 50)
    return _json({"items": list_reports(limit=limit)})


@app.route(route="graph/poll", methods=["POST", "GET"])
def graph_poll_http(req: func.HttpRequest) -> func.HttpResponse:
    try:
        messages, source = fetch_mailbox(top=int(req.params.get("top") or 8))
    except Exception as exc:
        logging.exception("Graph poll failed")
        return _json({"error": type(exc).__name__, "detail": str(exc)}, 502)

    ingested = []
    for msg in messages:
        ingested.append(
            _ingest_one(
                subject=msg.get("subject") or "",
                body=msg.get("body") or "",
                sender=msg.get("sender") or "",
                headers=msg.get("headers") or "",
                source=source,
                graph_id=msg.get("id"),
            )
        )
    return _json({"source": source, "count": len(ingested), "items": ingested})


@app.schedule(schedule="0 */5 * * * *", arg_name="timer", run_on_startup=False)
def graph_mailbox_timer(timer: func.TimerRequest) -> None:
    """Simulated Microsoft Graph mailbox poll (Office 365 report-phishing inbox)."""
    if timer.past_due:
        logging.warning("Byte Me Graph timer is past due")
    try:
        messages, source = fetch_mailbox(top=8)
        for msg in messages:
            _ingest_one(
                subject=msg.get("subject") or "",
                body=msg.get("body") or "",
                sender=msg.get("sender") or "",
                headers=msg.get("headers") or "",
                source=source,
                graph_id=msg.get("id"),
            )
        logging.info("Timer ingest complete source=%s n=%s", source, len(messages))
    except Exception:
        logging.exception("Timer Graph ingest failed")


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return _json(
        {
            "status": "ok",
            "service": "byteme",
            "runtime": "python3.11",
            "functions": ["analyze", "queue", "graph/poll", "graph_mailbox_timer"],
        }
    )
