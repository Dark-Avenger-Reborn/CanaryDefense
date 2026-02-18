"""
Lightweight alert orchestration for honeypot events.

- Suspicious activity: first event starts a short timer (default 5 minutes).
  When the timer elapses, the collected logs are emailed once.
- Honeypot down: immediate email when a honeypot is marked inactive.

This module keeps in-memory state only; a process restart resets timers.
"""

import html
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Tuple

from database.database_communicator import DatabaseCommunicator
from .send_email import send_email

# Delay before emailing suspicious activity (seconds). Default 5 minutes.
ALERT_DELAY_SECONDS = int(os.getenv("ALERT_DELAY_SECONDS", "300"))

_db = DatabaseCommunicator()

# Structure: {(uid, honeypot_id): {"started_at": ts, "logs": [..], "timer": Timer}}
_pending: Dict[Tuple[str, str], Dict[str, object]] = {}
_pending_lock = threading.Lock()


def _format_timestamp(iso_timestamp: str) -> str:
    """
    Convert ISO timestamp to human-readable local time format.
    
    Args:
        iso_timestamp: Timestamp in ISO format
        
    Returns:
        Formatted timestamp string in local time (e.g., "Feb 16, 2026 14:30:45")
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        # Convert to local time if timestamp has timezone info
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%b %d, %Y %H:%M:%S")
    except (ValueError, AttributeError):
        return iso_timestamp  # Return original if parsing fails


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
        timestamp_raw = log.get('timestamp', 'n/a')
        timestamp_formatted = _format_timestamp(timestamp_raw) if timestamp_raw != 'n/a' else 'n/a'
        lines.append(
            " - "
            + " | ".join(
                [
                    f"timestamp={timestamp_formatted}",
                    f"src_ip={log.get('src_ip', log.get('source_ip', 'n/a'))}",
                    f"dest_ip={log.get('dest_ip', log.get('destination_ip', 'n/a'))}",
                    f"protocol={log.get('protocol', log.get('server', 'n/a'))}",
                    f"status={log.get('status', 'n/a')}",
                ]
            )
        )
    return "\n".join(lines)


def _build_activity_html(uid: str, honeypot_id: str, logs: List[dict]) -> str:
    user = _db.get_user_entry(uid)
    user_email = user.get("data", {}).get("email") if user.get("success") else "unknown"

    safe_honeypot_id = html.escape(str(honeypot_id))
    safe_user_email = html.escape(str(user_email))
    safe_total = html.escape(str(len(logs)))

    rows = []
    for log in logs:
        timestamp_raw = log.get('timestamp', 'n/a')
        timestamp_formatted = _format_timestamp(timestamp_raw) if timestamp_raw != 'n/a' else 'n/a'
        rows.append(
            "".join(
                [
                    "<tr>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(timestamp_formatted))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('src_ip', log.get('source_ip', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('dest_ip', log.get('destination_ip', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('protocol', log.get('server', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('status', 'n/a')))}</td>",
                    "</tr>",
                ]
            )
        )

    rows_html = "".join(rows) if rows else (
        "<tr><td colspan=\"5\" style=\"padding:10px;color:#6b7280;\">No events recorded.</td></tr>"
    )

    return (
        "<div style=\"margin:0;padding:0;background-color:#f3f4f6;\">"
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"background-color:#f3f4f6;padding:24px 0;\">"
        "<tr><td align=\"center\">"
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"680\" style=\"width:680px;max-width:92vw;background-color:#ffffff;border-radius:12px;overflow:hidden;font-family:Arial,Helvetica,sans-serif;color:#111827;\">"
        "<tr><td style=\"background:linear-gradient(120deg,#0f172a,#1f2937);padding:20px 24px;\">"
        "<div style=\"font-size:18px;font-weight:600;color:#ffffff;\">Honeypot activity detected</div>"
        "<div style=\"font-size:13px;color:#e5e7eb;margin-top:6px;\">Immediate review recommended</div>"
        "</td></tr>"
        "<tr><td style=\"padding:20px 24px;\">"
        f"<div style=\"font-size:14px;margin-bottom:6px;\"><strong>Honeypot:</strong> {safe_honeypot_id}</div>"
        f"<div style=\"font-size:14px;margin-bottom:6px;\"><strong>Account:</strong> {safe_user_email}</div>"
        f"<div style=\"font-size:14px;color:#374151;\"><strong>Total events collected:</strong> {safe_total}</div>"
        "</td></tr>"
        "<tr><td style=\"padding:0 24px 24px 24px;\">"
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"border-collapse:collapse;font-size:12px;\">"
        "<thead>"
        "<tr style=\"background-color:#f9fafb;color:#6b7280;text-transform:uppercase;letter-spacing:0.04em;\">"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Timestamp</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Source IP</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Dest IP</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Protocol</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Status</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        "</td></tr>"
        "<tr><td style=\"padding:16px 24px 24px 24px;color:#6b7280;font-size:12px;\">"
        "You are receiving this alert because suspicious activity alerts are enabled in your settings."
        "</td></tr>"
        "</table>"
        "</td></tr>"
        "</table>"
        "</div>"
    )


def _get_honeypot_alert_recipients(owner_uid: str, honeypot_id: str) -> dict:
    """
    Get all users who should receive alerts for a honeypot.
    Returns a dict of {uid: {emails: [...], preferences: {...}}}
    """
    recipients = {}
    
    # Get owner's alert settings
    owner_data = _db.get_user_entry(owner_uid)
    if owner_data.get("success"):
        owner_alerts = owner_data.get("data", {}).get("alerts", {})
        owner_prefs = owner_alerts.get("preferences", {})
        if owner_prefs.get("alert_on_suspicious_activity", False) or owner_prefs.get("alert_on_honeypot_down", False):
            recipients[owner_uid] = {
                "emails": owner_alerts.get("emails", []),
                "preferences": owner_prefs
            }
    
    # Get collaborators' alert settings
    honeypot_data = _db.get_honeypot(owner_uid, honeypot_id)
    if honeypot_data.get("success"):
        collaborators = honeypot_data.get("honeypot", {}).get("collaborators", {})
        for collab_uid in collaborators:
            collab_data = _db.get_user_entry(collab_uid)
            if collab_data.get("success"):
                collab_alerts = collab_data.get("data", {}).get("alerts", {})
                collab_prefs = collab_alerts.get("preferences", {})
                # Check if collaborator has enabled alerts for shared honeypots
                if collab_prefs.get("alert_on_suspicious_activity", False) or collab_prefs.get("alert_on_honeypot_down", False):
                    recipients[collab_uid] = {
                        "emails": collab_alerts.get("emails", []),
                        "preferences": collab_prefs
                    }
    
    return recipients


def _send_activity_email(uid: str, honeypot_id: str, logs: List[dict]):
    """Send activity emails to owner and all collaborators who have alerts enabled."""
    recipients_info = _get_honeypot_alert_recipients(uid, honeypot_id)
    
    for recipient_uid, recipient_data in recipients_info.items():
        prefs = recipient_data.get("preferences", {})
        if not prefs.get("alert_on_suspicious_activity", False):
            continue
        
        # Get the timestamp of the last email sent for this honeypot
        last_email_time = _db.get_last_alert_email_time(recipient_uid, honeypot_id)
        
        # Filter logs to only include those after the last email timestamp
        if last_email_time:
            filtered_logs = [
                log for log in logs
                if log.get("timestamp", "") > last_email_time
            ]
        else:
            filtered_logs = logs
        
        # Only send email if there are new logs
        if not filtered_logs:
            continue

        recipients = recipient_data.get("emails", [])
        if not recipients:
            continue
        
        subject = f"Honeypot activity detected: {honeypot_id}"
        body = _build_activity_body(recipient_uid, honeypot_id, filtered_logs)
        html_body = _build_activity_html(recipient_uid, honeypot_id, filtered_logs)
        success, message = send_email(recipients, subject, body, html_body)
        
        # Update the last email timestamp only if the email was sent successfully
        if success:
            _db.update_last_alert_email_time(recipient_uid, honeypot_id)


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
    """Immediately send a honeypot-down alert to owner and collaborators if enabled."""
    recipients_info = _get_honeypot_alert_recipients(uid, honeypot_id)
    
    honeypot_result = _db.get_honeypot(uid, honeypot_id)
    honeypot_name = honeypot_result.get("honeypot", {}).get("name", honeypot_id) if honeypot_result.get("success") else honeypot_id

    for recipient_uid, recipient_data in recipients_info.items():
        prefs = recipient_data.get("preferences", {})
        if not prefs.get("alert_on_honeypot_down", False):
            continue
        
        recipients = recipient_data.get("emails", [])
        if not recipients:
            continue

        subject = f"Honeypot down: {honeypot_name}"
        body = (
            f"The honeypot '{honeypot_name}' (ID: {honeypot_id}) was marked inactive.\n"
            "Please check the honeypot or restart it if this is unexpected."
        )
        html_body = (
            "<div style=\"margin:0;padding:0;background-color:#f3f4f6;\">"
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"background-color:#f3f4f6;padding:24px 0;\">"
            "<tr><td align=\"center\">"
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"640\" style=\"width:640px;max-width:92vw;background-color:#ffffff;border-radius:12px;overflow:hidden;font-family:Arial,Helvetica,sans-serif;color:#111827;\">"
            "<tr><td style=\"background:linear-gradient(120deg,#991b1b,#dc2626);padding:18px 24px;\">"
            "<div style=\"font-size:18px;font-weight:600;color:#ffffff;\">Honeypot down</div>"
            "<div style=\"font-size:13px;color:#fee2e2;margin-top:6px;\">Immediate attention required</div>"
            "</td></tr>"
            "<tr><td style=\"padding:20px 24px;\">"
            f"<div style=\"font-size:14px;margin-bottom:10px;\"><strong>Honeypot:</strong> {html.escape(str(honeypot_name))}</div>"
            f"<div style=\"font-size:14px;margin-bottom:16px;\"><strong>ID:</strong> {html.escape(str(honeypot_id))}</div>"
            "<div style=\"font-size:14px;color:#374151;\">The honeypot was marked inactive. Please check the honeypot or restart it if this is unexpected.</div>"
            "</td></tr>"
            "<tr><td style=\"padding:16px 24px 24px 24px;color:#6b7280;font-size:12px;\">"
            "You are receiving this alert because honeypot-down alerts are enabled in your settings."
            "</td></tr>"
            "</table>"
            "</td></tr>"
            "</table>"
            "</div>"
        )
        send_email(recipients, subject, body, html_body)


