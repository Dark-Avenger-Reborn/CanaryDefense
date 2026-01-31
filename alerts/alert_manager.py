"""
Lightweight alert orchestration for honeypot events.

- Suspicious activity: first event starts a short timer (default 5 minutes).
  When the timer elapses, the collected logs are emailed once.
- Honeypot down: immediate email when a honeypot is marked inactive.

This module keeps in-memory state only; a process restart resets timers.
"""

import os
import threading
import time
from typing import Dict, List, Tuple

from database.database_communicator import DatabaseCommunicator
from .send_email import send_email

# Delay before emailing suspicious activity (seconds). Default 5 minutes.
ALERT_DELAY_SECONDS = int(os.getenv("ALERT_DELAY_SECONDS", "300"))

_db = DatabaseCommunicator()

# Structure: {(uid, honeypot_id): {"started_at": ts, "logs": [..], "timer": Timer}}
_pending: Dict[Tuple[str, str], Dict[str, object]] = {}
_pending_lock = threading.Lock()


def _build_activity_body(uid: str, honeypot_id: str, logs: List[dict]) -> str:
    user = _db.get_user_entry(uid)
    user_email = user.get("data", {}).get("email") if user.get("success") else "unknown"
    lines = [
        f"Honeypot activity detected for {honeypot_id}",
        f"Account: {user_email}",
        "",
        f"Total events collected: {len(logs)}",
        ""
    ]
    for log in logs:
        lines.append(
            " - "
            + " | ".join(
                [
                    f"timestamp={log.get('timestamp', 'n/a')}",
                    f"src_ip={log.get('src_ip', log.get('source_ip', 'n/a'))}",
                    f"dest_ip={log.get('dest_ip', log.get('destination_ip', 'n/a'))}",
                    f"protocol={log.get('protocol', log.get('server', 'n/a'))}",
                    f"status={log.get('status', 'n/a')}",
                ]
            )
        )
    return "\n".join(lines)


def _send_activity_email(uid: str, honeypot_id: str, logs: List[dict]):
    user_data = _db.get_user_entry(uid)
    if not user_data.get("success"):
        return

    alerts = user_data.get("data", {}).get("alerts", {})
    preferences = alerts.get("preferences", {})
    if not preferences.get("alert_on_suspicious_activity", False):
        return

    recipients = alerts.get("emails", [])
    subject = f"Honeypot activity detected: {honeypot_id}"
    body = _build_activity_body(uid, honeypot_id, logs)
    send_email(recipients, subject, body)


def _finalize_pending(key: Tuple[str, str]):
    with _pending_lock:
        entry = _pending.pop(key, None)
    if not entry:
        return
    _send_activity_email(key[0], key[1], entry.get("logs", []))


def record_suspicious_activity(uid: str, honeypot_id: str, log_entry: dict):
    """Queue an activity alert if preferences allow it."""
    user_data = _db.get_user_entry(uid)
    if not user_data.get("success"):
        return

    alerts = user_data.get("data", {}).get("alerts", {})
    preferences = alerts.get("preferences", {})
    if not preferences.get("alert_on_suspicious_activity", False):
        return

    key = (uid, honeypot_id)
    with _pending_lock:
        if key not in _pending:
            timer = threading.Timer(ALERT_DELAY_SECONDS, _finalize_pending, args=(key,))
            _pending[key] = {"started_at": time.time(), "logs": [log_entry], "timer": timer}
            timer.daemon = True
            timer.start()
        else:
            _pending[key]["logs"].append(log_entry)


def notify_honeypot_down(uid: str, honeypot_id: str):
    """Immediately send a honeypot-down alert if enabled."""
    user_data = _db.get_user_entry(uid)
    if not user_data.get("success"):
        return

    alerts = user_data.get("data", {}).get("alerts", {})
    preferences = alerts.get("preferences", {})
    if not preferences.get("alert_on_honeypot_down", False):
        return

    recipients = alerts.get("emails", [])
    honeypot_result = _db.get_honeypot(uid, honeypot_id)
    honeypot_name = honeypot_result.get("honeypot", {}).get("name", honeypot_id) if honeypot_result.get("success") else honeypot_id

    subject = f"Honeypot down: {honeypot_name}"
    body = (
        f"The honeypot '{honeypot_name}' (ID: {honeypot_id}) was marked inactive.\n"
        "Please check the honeypot or restart it if this is unexpected."
    )
    send_email(recipients, subject, body)
