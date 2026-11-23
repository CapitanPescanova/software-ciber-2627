import copy
import json
import logging
import os
import time
from pathlib import Path

import requests


logger = logging.getLogger(__name__)

PUBLISH_SENT = "sent"
PUBLISH_PERMANENT_REJECT = "permanent_reject"
PUBLISH_TEMPORARY_FAILURE = "temporary_failure"


def get_siem_url():
    return os.getenv("SIEM_URL", "http://siem:80/events").strip()


def get_pending_path():
    return Path(__file__).resolve().parents[2] / "output" / "pending_events.json"


def load_pending(path=None):
    path = Path(path) if path is not None else get_pending_path()
    try:
        with path.open(encoding="utf-8") as file:
            pending = json.load(file)
        return pending if isinstance(pending, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def save_pending(pending, path=None):
    path = Path(path) if path is not None else get_pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(pending, file, ensure_ascii=False, indent=2)


def publish_event(event, siem_url=None, timeout=5, session=None):
    payload = copy.deepcopy(event)
    url = siem_url or get_siem_url()
    http = session or requests

    try:
        response = http.post(url, json=payload, timeout=timeout)
    except requests.RequestException as error:
        logger.warning("No se pudo publicar el evento %s: %s", payload["event_id"], error)
        return PUBLISH_TEMPORARY_FAILURE
    except (TimeoutError, ConnectionError) as error:
        logger.warning("No se pudo publicar el evento %s: %s", payload["event_id"], error)
        return PUBLISH_TEMPORARY_FAILURE

    if response.status_code == 200:
        try:
            acknowledged_id = response.json().get("event_id")
        except (ValueError, AttributeError):
            acknowledged_id = None
        if acknowledged_id != payload["event_id"]:
            logger.error(
                "El SIEM respondió 200 sin confirmar el event_id enviado: "
                "enviado=%s, recibido=%s",
                payload["event_id"],
                acknowledged_id,
            )
            return PUBLISH_TEMPORARY_FAILURE
        return PUBLISH_SENT

    detail = getattr(response, "text", "") or ""
    if response.status_code == 409:
        logger.error(
            "Rechazo definitivo del evento %s: HTTP 409 EVENT_ID_CONFLICT. Detalle: %s",
            payload["event_id"],
            detail[:500],
        )
        return PUBLISH_PERMANENT_REJECT

    logger.warning(
        "El SIEM rechazó el evento %s con HTTP %s: %s",
        payload["event_id"],
        response.status_code,
        detail[:500],
    )
    if 500 <= response.status_code <= 599:
        return PUBLISH_TEMPORARY_FAILURE
    return PUBLISH_PERMANENT_REJECT


def publish_and_queue_status(event, siem_url=None, timeout=5, session=None,
                             pending_path=None, retries=2, retry_delay=1):
    pending_path = Path(pending_path) if pending_path is not None else get_pending_path()

    pending = load_pending(pending_path)
    payload = copy.deepcopy(event)

    for attempt in range(retries + 1):
        result = publish_event(payload, siem_url=siem_url, timeout=timeout, session=session)
        if result == PUBLISH_SENT:
            remaining = [
                pending_event
                for pending_event in pending
                if not (
                    isinstance(pending_event, dict)
                    and pending_event.get("event_id") == payload["event_id"]
                )
            ]
            save_pending(remaining, pending_path)
            return PUBLISH_SENT
        if result == PUBLISH_PERMANENT_REJECT:
            remaining = [
                pending_event
                for pending_event in pending
                if not (
                    isinstance(pending_event, dict)
                    and pending_event.get("event_id") == payload["event_id"]
                )
            ]
            save_pending(remaining, pending_path)
            return PUBLISH_PERMANENT_REJECT
        if attempt < retries:
            time.sleep(retry_delay)

    existing_ids = {
        pending_event.get("event_id")
        for pending_event in pending
        if isinstance(pending_event, dict)
    }
    if payload["event_id"] not in existing_ids:
        pending.append(copy.deepcopy(payload))
        save_pending(pending, pending_path)

    return PUBLISH_TEMPORARY_FAILURE


def publish_and_queue(event, siem_url=None, timeout=5, session=None,
                      pending_path=None, retries=2, retry_delay=1):
    result = publish_and_queue_status(
        event,
        siem_url=siem_url,
        timeout=timeout,
        session=session,
        pending_path=pending_path,
        retries=retries,
        retry_delay=retry_delay,
    )
    return result == PUBLISH_SENT


def retry_pending(siem_url=None, timeout=5, session=None, pending_path=None,
                  retries=0, retry_delay=1):
    pending_path = Path(pending_path) if pending_path is not None else get_pending_path()
    pending = load_pending(pending_path)
    remaining = []

    for event in pending:
        if not isinstance(event, dict):
            continue
        result = publish_and_queue_status(
            event,
            siem_url=siem_url,
            timeout=timeout,
            session=session,
            pending_path=pending_path,
            retries=retries,
            retry_delay=retry_delay,
        )
        if result == PUBLISH_TEMPORARY_FAILURE:
            remaining.append(copy.deepcopy(event))

    save_pending(remaining, pending_path)
