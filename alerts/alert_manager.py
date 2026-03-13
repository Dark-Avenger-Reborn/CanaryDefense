"""
Lightweight alert orchestration for honeypot events.

- Suspicious activity: first event starts a short timer (default 5 minutes).
    When the timer elapses, the collected logs are emailed once.
- Honeypot down: delayed email with reconnect-aware suppression and cooldown.

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

# Wait before sending a down alert so short network blips don't notify.
HONEYPOT_DOWN_ALERT_GRACE_SECONDS = int(os.getenv("HONEYPOT_DOWN_ALERT_GRACE_SECONDS", "120"))

# Minimum time between down alerts for the same honeypot.
HONEYPOT_DOWN_ALERT_COOLDOWN_SECONDS = int(os.getenv("HONEYPOT_DOWN_ALERT_COOLDOWN_SECONDS", "1800"))

_db = DatabaseCommunicator()

# Structure: {(uid, honeypot_id): {"started_at": ts, "logs": [..], "timer": Timer}}
_pending: Dict[Tuple[str, str], Dict[str, object]] = {}
_pending_lock = threading.Lock()

# Structure: {(uid, honeypot_id): {"started_at": ts, "timer": Timer}}
_pending_honeypot_down: Dict[Tuple[str, str], Dict[str, object]] = {}
_pending_honeypot_down_lock = threading.Lock()

# Structure: {(uid, honeypot_id): sent_at_unix_ts}
_last_honeypot_down_sent: Dict[Tuple[str, str], float] = {}


def _format_location(log: dict, intel: dict) -> str:
    city = intel.get("city") or log.get("city") or "Unknown"
    region = intel.get("region") or log.get("region") or "Unknown"
    country = intel.get("country") or log.get("country") or "Unknown"
    parts = [str(city).strip(), str(region).strip(), str(country).strip()]
    return ", ".join(part if part else "Unknown" for part in parts)


def _build_activity_summary(logs: List[dict]) -> dict:
    summary = {
        "total": len(logs),
        "infiltration": 0,
        "brute_force": 0,
        "reconnaissance": 0,
        "scan": 0,
        "failed": 0,
        "error": 0,
        "high_risk": 0,
        "unknown": 0,
        "unique_sources": set(),
    }

    for log in logs:
        status = str(log.get("status", "")).lower()
        risk_level = str(log.get("risk_level", "")).lower()
        source_ip = log.get("src_ip", log.get("source_ip"))

        if status in summary:
            summary[status] += 1
        if risk_level in {"high", "critical"}:
            summary["high_risk"] += 1
        if source_ip:
            summary["unique_sources"].add(source_ip)

    summary["unique_sources"] = len(summary["unique_sources"])
    return summary


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
    summary = _build_activity_summary(logs)
    lines = [
        f"Honeypot activity detected for {honeypot_id}",
        f"Account: {user_email}",
        "",
        f"Total events collected: {summary['total']}",
        f"Unique source IPs: {summary['unique_sources']}",
        f"Infiltration: {summary['infiltration']} | Brute Force: {summary['brute_force']} | Recon: {summary['reconnaissance']} | Scan: {summary['scan']} | Failed: {summary['failed']} | Error: {summary['error']}",
        f"High/Critical risk events: {summary['high_risk']}",
        ""
    ]
    for log in logs:
        timestamp_raw = log.get('timestamp', 'n/a')
        timestamp_formatted = _format_timestamp(timestamp_raw) if timestamp_raw != 'n/a' else 'n/a'
        intel = log.get("source_intel") or {}
        intel_tags = intel.get("tags") or []
        tags_text = ",".join(str(tag) for tag in intel_tags) if intel_tags else "none"
        location_text = _format_location(log, intel)
        lines.append(
            " - "
            + " | ".join(
                [
                    f"timestamp={timestamp_formatted}",
                    f"action={log.get('action', 'n/a')}",
                    f"src_ip={log.get('src_ip', log.get('source_ip', 'n/a'))}",
                    f"dest_ip={log.get('dest_ip', log.get('destination_ip', 'n/a'))}",
                    f"protocol={log.get('protocol', log.get('server', 'n/a'))}",
                    f"status={log.get('status', 'n/a')}",
                    f"reason={log.get('status_reason', 'n/a')}",
                    f"risk={log.get('risk_score', 'n/a')} ({log.get('risk_level', 'n/a')})",
                    f"location={location_text}",
                    f"intel={intel.get('category', 'n/a')} / rdns={intel.get('reverse_dns', 'Unknown')} / tags={tags_text}",
                ]
            )
        )
    return "\n".join(lines)


def _build_activity_html(uid: str, honeypot_id: str, logs: List[dict]) -> str:
    user = _db.get_user_entry(uid)
    user_email = user.get("data", {}).get("email") if user.get("success") else "unknown"
    summary = _build_activity_summary(logs)

    safe_honeypot_id = html.escape(str(honeypot_id))
    safe_user_email = html.escape(str(user_email))
    safe_total = html.escape(str(len(logs)))
    safe_unique_sources = html.escape(str(summary["unique_sources"]))
    safe_high_risk = html.escape(str(summary["high_risk"]))
    safe_infiltration = html.escape(str(summary["infiltration"]))
    safe_brute_force = html.escape(str(summary["brute_force"]))
    safe_reconnaissance = html.escape(str(summary["reconnaissance"]))
    safe_scan = html.escape(str(summary["scan"]))
    safe_failed = html.escape(str(summary["failed"]))
    safe_error = html.escape(str(summary["error"]))

    rows = []
    for log in logs:
        timestamp_raw = log.get('timestamp', 'n/a')
        timestamp_formatted = _format_timestamp(timestamp_raw) if timestamp_raw != 'n/a' else 'n/a'
        intel = log.get("source_intel") or {}
        intel_tags = intel.get("tags") or []
        tags_text = ", ".join(str(tag) for tag in intel_tags) if intel_tags else "none"
        location_text = _format_location(log, intel)
        risk_value = f"{log.get('risk_score', 'n/a')} ({log.get('risk_level', 'n/a')})"
        intel_value = (
            f"{intel.get('category', 'n/a')}"
            f" | location: {location_text}"
            f" | rdns: {intel.get('reverse_dns', 'Unknown')}"
            f" | tags: {tags_text}"
        )
        rows.append(
            "".join(
                [
                    "<tr>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(timestamp_formatted))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('action', 'n/a')))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('src_ip', log.get('source_ip', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('dest_ip', log.get('destination_ip', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('protocol', log.get('server', 'n/a'))))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('status', 'n/a')))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(str(log.get('status_reason', 'n/a')))}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(risk_value)}</td>",
                    f"<td style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">{html.escape(intel_value)}</td>",
                    "</tr>",
                ]
            )
        )

    rows_html = "".join(rows) if rows else (
        "<tr><td colspan=\"9\" style=\"padding:10px;color:#6b7280;\">No events recorded.</td></tr>"
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
        f"<div style=\"font-size:14px;color:#374151;margin-top:4px;\"><strong>Unique source IPs:</strong> {safe_unique_sources}</div>"
        f"<div style=\"font-size:14px;color:#374151;margin-top:4px;\"><strong>Infiltration:</strong> {safe_infiltration} &nbsp;|&nbsp; <strong>Brute Force:</strong> {safe_brute_force} &nbsp;|&nbsp; <strong>Recon:</strong> {safe_reconnaissance} &nbsp;|&nbsp; <strong>Scan:</strong> {safe_scan} &nbsp;|&nbsp; <strong>Failed:</strong> {safe_failed} &nbsp;|&nbsp; <strong>Error:</strong> {safe_error}</div>"
        f"<div style=\"font-size:14px;color:#374151;margin-top:4px;\"><strong>High/Critical risk events:</strong> {safe_high_risk}</div>"
        "</td></tr>"
        "<tr><td style=\"padding:0 24px 24px 24px;\">"
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"border-collapse:collapse;font-size:12px;\">"
        "<thead>"
        "<tr style=\"background-color:#f9fafb;color:#6b7280;text-transform:uppercase;letter-spacing:0.04em;\">"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Timestamp</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Action</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Source IP</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Dest IP</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Protocol</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Status</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Reason</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Risk</th>"
        "<th align=\"left\" style=\"padding:8px 10px;border-bottom:1px solid #e5e7eb;\">Source Intel</th>"
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


def _send_honeypot_down_email(uid: str, honeypot_id: str):
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


def _finalize_honeypot_down_alert(key: Tuple[str, str]):
    with _pending_honeypot_down_lock:
        _pending_honeypot_down.pop(key, None)

        last_sent = _last_honeypot_down_sent.get(key)
        if last_sent is not None and (time.time() - last_sent) < HONEYPOT_DOWN_ALERT_COOLDOWN_SECONDS:
            return

    uid, honeypot_id = key
    honeypot_result = _db.get_honeypot(uid, honeypot_id)
    if honeypot_result.get("success") and honeypot_result.get("honeypot", {}).get("is_active", False):
        return

    _send_honeypot_down_email(uid, honeypot_id)
    with _pending_honeypot_down_lock:
        _last_honeypot_down_sent[key] = time.time()


def clear_pending_honeypot_down_alert(uid: str, honeypot_id: str):
    """Cancel a pending down alert if a honeypot reconnects in time."""
    key = (uid, honeypot_id)
    with _pending_honeypot_down_lock:
        entry = _pending_honeypot_down.pop(key, None)

    if entry and entry.get("timer"):
        entry["timer"].cancel()


def notify_honeypot_down(uid: str, honeypot_id: str):
    """Queue a down alert with grace period and cooldown throttling."""
    key = (uid, honeypot_id)
    with _pending_honeypot_down_lock:
        if key in _pending_honeypot_down:
            return

        timer = threading.Timer(HONEYPOT_DOWN_ALERT_GRACE_SECONDS, _finalize_honeypot_down_alert, args=(key,))
        timer.daemon = True
        _pending_honeypot_down[key] = {
            "started_at": time.time(),
            "timer": timer,
        }
        timer.start()


