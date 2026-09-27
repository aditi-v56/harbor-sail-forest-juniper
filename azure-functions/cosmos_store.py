"""Byte Me — Cosmos DB queue persistence with an in-memory fallback.

When COSMOS_DB_URL + COSMOS_DB_KEY are set, reports land in the
`byteme` / `triage-queue` container (partition key /label). Otherwise the
same interface writes to a process-local list so judges can demo without
an Azure account.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

_lock = threading.Lock()
_memory: list[dict[str, Any]] = []

DATABASE = os.environ.get("COSMOS_DB_DATABASE", "byteme")
CONTAINER = os.environ.get("COSMOS_DB_CONTAINER", "triage-queue")


def _live() -> bool:
    return bool(os.environ.get("COSMOS_DB_URL") and os.environ.get("COSMOS_DB_KEY"))


def _container():
    from azure.cosmos import CosmosClient, PartitionKey  # type: ignore

    client = CosmosClient(os.environ["COSMOS_DB_URL"], os.environ["COSMOS_DB_KEY"])
    db = client.create_database_if_not_exists(id=DATABASE)
    return db.create_container_if_not_exists(
        id=CONTAINER,
        partition_key=PartitionKey(path="/label"),
        offer_throughput=400,
    )


def upsert_report(doc: dict[str, Any]) -> dict[str, Any]:
    """Persist a triage document. Never raises to the HTTP path."""
    payload = {**doc, "id": doc.get("id") or doc.get("ts")}
    try:
        if _live():
            _container().upsert_item(payload)
            payload["store"] = "cosmos"
            return payload
    except Exception as exc:
        logging.exception("Cosmos upsert failed; falling back to memory: %s", exc)
    with _lock:
        _memory[:] = [d for d in _memory if d.get("id") != payload["id"]]
        _memory.append(payload)
    payload["store"] = "memory"
    return payload


def list_reports(limit: int = 50) -> list[dict[str, Any]]:
    try:
        if _live():
            items = list(
                _container().query_items(
                    query="SELECT TOP @n * FROM c ORDER BY c.risk DESC",
                    parameters=[{"name": "@n", "value": int(limit)}],
                    enable_cross_partition_query=True,
                )
            )
            return items
    except Exception as exc:
        logging.exception("Cosmos query failed: %s", exc)
    with _lock:
        ranked = sorted(_memory, key=lambda d: int(d.get("risk") or 0), reverse=True)
        return ranked[:limit]
