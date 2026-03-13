"""
Socket.IO routes for honeypot-to-server communication.
Handles honeypot connections, disconnections, log streaming, and status updates.
No dashboard communication - this is purely for honeypot instances to communicate with the server.
"""

from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from collections import deque
from pathlib import Path
import ipaddress
import socket
import time
import logging
from functools import wraps
from typing import Any, Dict
from database.database_communicator import DatabaseCommunicator
from alerts import (
    clear_pending_honeypot_down_alert,
    record_suspicious_activity,
    notify_honeypot_down,
)

logger = logging.getLogger(__name__)
db = DatabaseCommunicator()

# Initialize Socket.IO (will be properly initialized in main.py)
socketio = SocketIO()

# Track authenticated honeypots by their socket SID
# Key: request.sid, Value: {'uid': str, 'honeypot_id': str}
authenticated_honeypots = {}

SCAN_WINDOW_SECONDS = 60
SCAN_EVENT_THRESHOLD = 8
SCAN_PORT_THRESHOLD = 4
SCAN_PROTOCOL_THRESHOLD = 3

_recent_activity_by_src = {}
SERVER_TIME_MARKER_FILE = Path("honeypot/state/server_time.txt")


def _mark_server_time_now():
    """Persist the latest known server time for abrupt-shutdown recovery."""
    try:
        SERVER_TIME_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
        SERVER_TIME_MARKER_FILE.write_text(datetime.now().isoformat(), encoding="utf-8")
    except Exception as e:
        logger.warning("Unable to write server time marker: %s", str(e))


def _read_server_time_marker():
    try:
        if not SERVER_TIME_MARKER_FILE.exists():
            return None
        value = SERVER_TIME_MARKER_FILE.read_text(encoding="utf-8").strip()
        return value or None
    except Exception as e:
        logger.warning("Unable to read server time marker: %s", str(e))
        return None


def recover_honeypots_after_abrupt_shutdown():
    """
    On startup, mark stale active honeypots as inactive and set their
    last_active to the most recently persisted server time.
    """
    recovery_time = _read_server_time_marker() or datetime.now().isoformat()
    result = db.recover_active_honeypots_after_restart(recovery_time)
    if not result.get("success"):
        logger.error("Failed to recover stale honeypots after restart: %s", result.get("error"))
        return result

    recovered = result.get("recovered", 0)
    if recovered:
        logger.warning(
            "Recovered %s stale active honeypot(s) after abrupt restart; set last_active=%s",
            recovered,
            recovery_time,
        )
    _mark_server_time_now()
    return result


def _parse_iso_timestamp(value):
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _coerce_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _risk_level_from_score(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _local_intel(ip: str) -> Dict[str, Any]:
    intel: Dict[str, Any] = {
        "source_ip": ip,
        "category": "invalid",
        "ip_version": "unknown",
        "is_private": False,
        "is_loopback": False,
        "is_multicast": False,
        "is_reserved": False,
        "is_global": False,
        "is_link_local": False,
        "is_unspecified": False,
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "asn": "Unknown",
        "org": "Unknown",
        "reverse_dns": "Unknown",
        "provider": "local",
        "abuse_confidence": None,
        "tags": [],
        "risk_score": 0,
        "risk_level": "low",
        "summary": "Invalid source IP",
    }

    if not ip:
        return intel

    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return intel

    tags = []
    intel.update(
        {
            "ip_version": f"ipv{ip_obj.version}",
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved": ip_obj.is_reserved,
            "is_global": ip_obj.is_global,
            "is_link_local": ip_obj.is_link_local,
            "is_unspecified": ip_obj.is_unspecified,
        }
    )

    if ip_obj.is_loopback:
        intel["category"] = "loopback"
        intel["summary"] = "Local loopback traffic"
        tags.extend(["local", "loopback"])
        intel["risk_score"] = 5
    elif ip_obj.is_private:
        intel["category"] = "private"
        intel["summary"] = "Private network source"
        tags.extend(["internal", "rfc1918"])
        intel["risk_score"] = 12
    elif ip_obj.is_link_local:
        intel["category"] = "link_local"
        intel["summary"] = "Link-local source"
        tags.extend(["link_local"])
        intel["risk_score"] = 15
    elif ip_obj.is_multicast:
        intel["category"] = "multicast"
        intel["summary"] = "Multicast source address"
        tags.extend(["multicast", "suspicious"])
        intel["risk_score"] = 35
    elif ip_obj.is_reserved:
        intel["category"] = "reserved"
        intel["summary"] = "Reserved/bogon source range"
        tags.extend(["bogon", "reserved"])
        intel["risk_score"] = 45
    elif ip_obj.is_unspecified:
        intel["category"] = "unspecified"
        intel["summary"] = "Unspecified source address"
        tags.extend(["invalid_source"])
        intel["risk_score"] = 55
    elif ip_obj.is_global:
        intel["category"] = "global"
        intel["summary"] = "Public routable source"
        tags.extend(["internet", "external"])
        intel["risk_score"] = 40
    else:
        intel["category"] = "other"
        intel["summary"] = "Unclassified source address"
        tags.append("unclassified")
        intel["risk_score"] = 25

    try:
        reverse_dns = socket.gethostbyaddr(str(ip_obj))[0]
        intel["reverse_dns"] = reverse_dns
        tags.append("rdns_present")
    except Exception:
        if intel["is_global"]:
            intel["risk_score"] += 5
        tags.append("rdns_missing")

    intel["tags"] = sorted(set(tags))
    intel["risk_score"] = max(0, min(int(intel["risk_score"]), 100))
    intel["risk_level"] = _risk_level_from_score(intel["risk_score"])
    return intel


def _apply_risk_scoring(log_entry):
    intel = log_entry.get("source_intel") or {}
    score = _coerce_int(intel.get("risk_score")) or 0

    status = str(log_entry.get("status") or "").lower()
    action = str(log_entry.get("action") or "").lower()
    details = str(log_entry.get("details") or "").lower()

    if status == "infiltration":
        score += 35
    elif status == "brute_force":
        score += 22
    elif status == "scan":
        score += 18
    elif status == "reconnaissance":
        score += 12
    elif status == "failed":
        score += 8
    elif status == "error":
        score += 8

    if "credential" in details or "password" in details:
        score += 8
    if action in {"command", "shell", "exec"}:
        score += 10
    if status == "unknown" and action in {"connection", "probe", "get", "request"}:
        score += 6

    score = max(0, min(int(score), 100))
    level = _risk_level_from_score(score)

    log_entry["risk_score"] = score
    log_entry["risk_level"] = level

    if isinstance(intel, dict):
        intel["risk_score"] = score
        intel["risk_level"] = level
        log_entry["source_intel"] = intel


def _infer_status_from_context(log_entry):
    action = str(log_entry.get("action") or "").lower()
    status = str(log_entry.get("status") or "").lower()
    details_lower = str(log_entry.get("details") or "").lower()
    intel = log_entry.get("source_intel") or {}

    if status != "unknown":
        return status, "status reported directly by the honeypot"

    if action in {"process", "heartbeat", "startup", "start"}:
        return "success", "service lifecycle event"

    if action in {"connection", "probe", "get", "request"}:
        if intel.get("is_global"):
            return "reconnaissance", "external connection/probe from public IP"
        return "success", "local/internal connection observed"

    if action in {"login", "auth", "authentication"}:
        if any(token in details_lower for token in ("fail", "denied", "invalid")):
            return "brute_force", "failed authentication attempt"
        if any(token in details_lower for token in ("accepted", "success", "authenticated")):
            return "success", "authentication accepted"
        return "brute_force", "authentication attempt with no success indicator"

    if action in {"command", "exec", "shell"}:
        return "infiltration", "command execution attempt"

    return "unknown", "insufficient evidence for confident classification"


def _normalize_status(raw_status, details_text=""):
    if raw_status is None:
        raw_status = ""
    status = str(raw_status).strip().lower()
    mapping = {
        "ok": "success",
        "accepted": "success",
        "success": "success",
        "fail": "failed",
        "failed": "failed",
        "denied": "failed",
        "invalid": "failed",
        "error": "error",
        "scan": "scan",
        "infiltration": "infiltration",
        "reconnaissance": "reconnaissance",
        "brute_force": "brute_force",
        "unknown": "unknown",
    }
    if status in mapping:
        return mapping[status]

    details_lower = details_text.lower()
    if "error" in details_lower:
        return "error"
    if any(token in details_lower for token in ("fail", "denied", "invalid")):
        return "failed"
    if any(token in details_lower for token in ("success", "accepted", "authenticated")):
        return "success"
    return "unknown"


def _normalize_action(log_entry):
    action = log_entry.get("action") or log_entry.get("event") or log_entry.get("type")
    if action:
        return str(action).strip().lower()

    if log_entry.get("command") or log_entry.get("cmd"):
        return "command"
    if log_entry.get("query"):
        return "query"

    details = str(log_entry.get("details") or log_entry.get("data") or log_entry.get("message") or "")
    details_lower = details.lower()
    if "login" in details_lower or "auth" in details_lower:
        return "login"
    if "query" in details_lower:
        return "query"
    if "command" in details_lower:
        return "command"
    return "connection"


def _normalize_log_entry(log_entry):
    normalized = dict(log_entry or {})

    details = normalized.get("details") or normalized.get("data") or normalized.get("message")
    if details and "details" not in normalized:
        normalized["details"] = details

    normalized["action"] = _normalize_action(normalized)

    src_ip = normalized.get("src_ip") or normalized.get("source_ip") or normalized.get("client_ip")
    if not src_ip:
        src_ip = normalized.get("ip")
    if src_ip:
        normalized["src_ip"] = src_ip

    normalized["source_intel"] = _local_intel(str(src_ip or ""))

    source_intel = normalized.get("source_intel") or {}
    geo = normalized.get("geo") or {}
    if isinstance(geo, dict):
        country = normalized.get("country") or geo.get("country")
        region = normalized.get("region") or geo.get("region") or geo.get("state")
        city = normalized.get("city") or geo.get("city")
        if country:
            source_intel["country"] = country
        if region:
            source_intel["region"] = region
        if city:
            source_intel["city"] = city
    else:
        country = normalized.get("country")
        region = normalized.get("region")
        city = normalized.get("city")
        if country:
            source_intel["country"] = country
        if region:
            source_intel["region"] = region
        if city:
            source_intel["city"] = city
    normalized["source_intel"] = source_intel

    src_port = normalized.get("src_port") or normalized.get("client_port")
    if src_port is not None:
        normalized["src_port"] = _coerce_int(src_port) or src_port

    dest_ip = normalized.get("dest_ip") or normalized.get("destination_ip") or normalized.get("server_ip")
    if dest_ip:
        normalized["dest_ip"] = dest_ip

    dest_port = normalized.get("dest_port") or normalized.get("port")
    if dest_port is not None:
        normalized["dest_port"] = _coerce_int(dest_port) or dest_port

    server = normalized.get("server") or normalized.get("protocol")
    if server:
        normalized["server"] = server
        if "protocol" not in normalized and isinstance(server, str):
            normalized["protocol"] = server.replace("_server", "") if server.endswith("_server") else server

    details_text = str(normalized.get("details") or "")
    normalized["status"] = _normalize_status(normalized.get("status"), details_text)

    return normalized


def _detect_scan(log_entry):
    src_ip = log_entry.get("src_ip")
    if not src_ip:
        return False

    action = (log_entry.get("action") or "").lower()
    if action not in {"connection", "scan", "probe"}:
        return False

    timestamp = _parse_iso_timestamp(log_entry.get("timestamp"))
    now_ts = timestamp.timestamp() if timestamp else time.time()

    activity = _recent_activity_by_src.setdefault(src_ip, deque())
    activity.append((now_ts, log_entry.get("dest_port"), log_entry.get("protocol")))

    cutoff = now_ts - SCAN_WINDOW_SECONDS
    while activity and activity[0][0] < cutoff:
        activity.popleft()

    ports = {item[1] for item in activity if item[1]}
    protocols = {item[2] for item in activity if item[2]}
    total_events = len(activity)

    if total_events >= SCAN_EVENT_THRESHOLD:
        return True
    if len(ports) >= SCAN_PORT_THRESHOLD:
        return True
    if len(protocols) >= SCAN_PROTOCOL_THRESHOLD:
        return True
    return False


def _classify_log_entry(log_entry):
    normalized = _normalize_log_entry(log_entry)
    action = normalized.get("action")
    status = normalized.get("status")

    inferred_status, reason = _infer_status_from_context(normalized)
    normalized["status"] = inferred_status
    normalized["status_reason"] = reason
    status = normalized["status"]

    if action in {"login", "auth", "authentication", "command"} and status == "success":
        normalized["status"] = "infiltration"
        normalized["status_reason"] = "authenticated or command-level interaction"
        _apply_risk_scoring(normalized)
        return normalized

    # Promote plain "failed" on auth actions to brute_force
    if action in {"login", "auth", "authentication"} and status == "failed":
        normalized["status"] = "brute_force"
        normalized["status_reason"] = "failed authentication attempt"

    if _detect_scan(normalized) and status not in {"infiltration", "brute_force", "error"}:
        normalized["status"] = "scan"
        normalized["action"] = "scan"
        normalized["status_reason"] = "high-frequency multi-target sweep"

    _apply_risk_scoring(normalized)
    return normalized


def _find_authenticated_sid_by_honeypot_id(honeypot_id):
    for sid, info in authenticated_honeypots.items():
        if info.get('honeypot_id') == honeypot_id:
            return sid
    return None


def honeypot_authenticated_only(f):
    """Decorator to ensure Socket.IO events have a honeypot_id set (authenticated via honeypot_connect)"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if request.sid not in authenticated_honeypots:
            logger.warning(f"Unauthorized honeypot Socket.IO access attempt from {request.sid}")
            try:
                emit('error', {'message': 'Unauthorized: Please authenticate via honeypot_connect first'})
            except Exception as e:
                logger.error(f"Error emitting unauthorized response: {str(e)}")
            return False
        return f(*args, **kwargs)
    return wrapped


def validate_honeypot_ownership(uid, honeypot_id):
    """Verify that the user owns the specified honeypot"""
    result = db.get_honeypot(uid, honeypot_id)
    if not result.get('success'):
        logger.warning(f"User {uid} attempted access to non-existent honeypot {honeypot_id}")
        return False
    return True

# ==================== Connection Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle honeypot client initial WebSocket connection to Socket.IO server"""
    try:
        logger.info(f"Honeypot client connected: {request.sid}")
        _mark_server_time_now()
        # Don't require authentication on connection—let honeypot authenticate via honeypot_connect event
        emit('connection_response', {
            'success': True,
            'message': 'Connected to server. Send honeypot_connect to authenticate.',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in handle_connect: {str(e)}")
        # Don't re-raise, just log the error


@socketio.on('disconnect')
def handle_disconnect():
    """Handle honeypot client disconnection"""
    try:
        _mark_server_time_now()
        if request.sid in authenticated_honeypots:
            auth_info = authenticated_honeypots.pop(request.sid)
            honeypot_id = auth_info['honeypot_id']
            uid = auth_info['uid']
            logger.info(f"Honeypot {honeypot_id} (user {uid}) disconnected: {request.sid}")
            
            # Clean up the honeypot status
            try:
                db.update_honeypot(
                    uid,
                    honeypot_id,
                    is_active=False,
                    last_active=datetime.now().isoformat()
                )
            except Exception as e:
                logger.error(f"Error updating honeypot status on disconnect: {str(e)}")
            
            # Trigger alert if configured
            notify_honeypot_down(uid, honeypot_id)
        else:
            logger.info(f"Unauthenticated client disconnected: {request.sid}")
    except Exception as e:
        logger.error(f"Error in handle_disconnect: {str(e)}")


# ==================== Honeypot Connection Lifecycle ====================

@socketio.on('honeypot_connect')
def handle_honeypot_connect(data):
    """
    Handle honeypot instance connecting to the server using honeypot_id.
    Expected data: {'honeypot_id': str, 'protocols': list, 'metadata': dict}
    This handler authenticates the honeypot by looking up its owner and storing the uid/honeypot_id in authenticated_honeypots.
    Prevents duplicate connections with the same honeypot_id.
    """
    try:
        _mark_server_time_now()
        honeypot_id = data.get('honeypot_id')
        metadata = data.get('metadata', {})
        
        if not honeypot_id:
            emit('error', {'message': 'honeypot_id is required'})
            return
        
        # Find which user owns this honeypot
        uid = db.find_honeypot_owner(honeypot_id)
        if not uid:
            logger.warning(f"Connection attempt for non-existent or unowned honeypot {honeypot_id}")
            emit('error', {'message': 'Honeypot ID not found or not owned by user'})
            return
        
        current_state = db.get_honeypot(uid, honeypot_id)
        current_honeypot = current_state.get('honeypot', {}) if current_state.get('success') else {}
        current_active = current_honeypot.get('is_active', False)
        configured_protocols = current_honeypot.get('active_protocols', [])

        # Block duplicate live connections for the same honeypot_id
        existing_sid = _find_authenticated_sid_by_honeypot_id(honeypot_id)
        if existing_sid:
            logger.warning(f"Duplicate connection attempt for active honeypot {honeypot_id}")
            emit('error', {'message': 'Honeypot already connected. Disconnect the existing connection first.'})
            return

        # Clear stale active flag when there is no live socket tracked
        if current_active:
            logger.warning(f"Stale active flag for honeypot {honeypot_id}. Resetting to allow reconnect.")
            try:
                db.update_honeypot(uid, honeypot_id, is_active=False)
            except Exception as e:
                logger.error(f"Failed to reset stale active flag for {honeypot_id}: {str(e)}")
        
        # Store authentication info by socket SID
        authenticated_honeypots[request.sid] = {'uid': uid, 'honeypot_id': honeypot_id}
        
        # Update honeypot status to active
        result = db.update_honeypot(
            uid,
            honeypot_id,
            protocols=configured_protocols,
            is_active=True,
            last_active=datetime.now().isoformat()
        )
        
        if result['success']:
            # Suppress transient down alerts when the honeypot reconnects quickly.
            clear_pending_honeypot_down_alert(uid, honeypot_id)

            # Join honeypot-specific room for receiving commands
            room_name = f"honeypot_{honeypot_id}"
            join_room(room_name)
            
            logger.info(
                "Honeypot %s connected for user %s with protocols: %s",
                honeypot_id,
                uid,
                configured_protocols,
            )
            
            # Confirm to the connecting honeypot
            emit('honeypot_connect_ack', {
                'success': True,
                'honeypot_id': honeypot_id,
                'message': 'Honeypot connected successfully',
                'timestamp': datetime.now().isoformat()
            })

            send_stop_command(honeypot_id)
            if configured_protocols:
                send_start_command(honeypot_id, configured_protocols)
        else:
            # Remove from authenticated_honeypots if update failed
            authenticated_honeypots.pop(request.sid, None)
            emit('error', {'message': result.get('error', 'Failed to connect honeypot')})
    
    except Exception as e:
        logger.error(f"Error in honeypot_connect: {str(e)}")
        authenticated_honeypots.pop(request.sid, None)
        emit('error', {'message': f'Internal error: {str(e)}'})


@socketio.on('honeypot_disconnect')
@honeypot_authenticated_only
def handle_honeypot_disconnect(data):
    """
    Handle honeypot instance disconnecting from the server.
    Expected data: {'reason': str} (uid and honeypot_id come from authenticated_honeypots)
    """
    try:
        _mark_server_time_now()
        auth_info = authenticated_honeypots.get(request.sid)
        if not auth_info:
            emit('error', {'message': 'Not authenticated'})
            return
            
        uid = auth_info['uid']
        honeypot_id = auth_info['honeypot_id']
        reason = data.get('reason', 'Manual disconnect')
        
        # Remove from authenticated honeypots
        authenticated_honeypots.pop(request.sid, None)
        
        # Update honeypot status to inactive
        result = db.update_honeypot(
            uid,
            honeypot_id,
            is_active=False,
            last_active=datetime.now().isoformat()
        )
        
        if result['success']:
            # Leave honeypot-specific room
            room_name = f"honeypot_{honeypot_id}"
            leave_room(room_name)
            
            logger.info(f"Honeypot {honeypot_id} disconnected for user {uid}. Reason: {reason}")
            
            # Trigger alert if configured
            notify_honeypot_down(uid, honeypot_id)
            
            # Confirm to the disconnecting honeypot (may fail if connection closing)
            try:
                emit('honeypot_disconnect_ack', {
                    'success': True,
                    'honeypot_id': honeypot_id,
                    'message': 'Honeypot disconnected successfully',
                    'timestamp': datetime.now().isoformat()
                })
            except Exception:
                pass
        else:
            try:
                emit('error', {'message': result.get('error', 'Failed to disconnect honeypot')})
            except Exception:
                pass
    
    except Exception as e:
        logger.error(f"Error in honeypot_disconnect: {str(e)}")


# ==================== Server Commands to Honeypot ====================
# These functions can be called from other parts of the application
# to send commands to connected honeypot instances

def send_start_command(honeypot_id, protocols=None):
    """
    Send start command to a honeypot instance (if connected).
    This is called from other parts of the application, not a Socket.IO event.
    """
    try:
        logger.info(f"Sending start command to honeypot {honeypot_id}")
        socketio.emit('start_command', {
            'honeypot_id': honeypot_id,
            'protocols': protocols or [],
            'timestamp': datetime.now().isoformat()
        }, room=f"honeypot_{honeypot_id}")
    except Exception as e:
        logger.error(f"Error sending start command: {str(e)}")


def send_stop_command(honeypot_id, protocols=None):
    """
    Send stop command to a honeypot instance (if connected).
    This is called from other parts of the application, not a Socket.IO event.
    """
    try:
        logger.info(f"Sending stop command to honeypot {honeypot_id}")
        payload = {
            'honeypot_id': honeypot_id,
            'timestamp': datetime.now().isoformat()
        }
        if protocols is not None:
            payload['protocols'] = protocols
        socketio.emit('stop_command', payload, room=f"honeypot_{honeypot_id}")
    except Exception as e:
        logger.error(f"Error sending stop command: {str(e)}")


# ==================== Log Management ====================

@socketio.on('honeypot_log')
@honeypot_authenticated_only
def handle_honeypot_log(data):
    """
    Receive and store a log entry from a honeypot.
    Expected data: {
        'log_entry': {
            'timestamp': str,
            'src_ip': str,
            'src_port': int,
            'dest_ip': str,
            'dest_port': int,
            'protocol': str,
            'action': str,
            'status': str,
            'details': str (optional)
        }
    }
    uid and honeypot_id come from authenticated_honeypots
    """
    try:
        _mark_server_time_now()
        auth_info = authenticated_honeypots.get(request.sid)
        if not auth_info:
            emit('error', {'message': 'Not authenticated'})
            return
            
        uid = auth_info['uid']
        honeypot_id = auth_info['honeypot_id']
        log_entry = data.get('log_entry', {})
        
        if not log_entry:
            emit('error', {'message': 'log_entry is required'})
            return
        
        # Add timestamp if not provided
        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()

        log_entry = _classify_log_entry(log_entry)
        
        # Add log to database
        result = db.add_log(uid, honeypot_id, log_entry)
        
        if result['success']:
            logger.debug(f"Log added for honeypot {honeypot_id} from user {uid}: {log_entry.get('src_ip')} -> {log_entry.get('protocol')}")

            if not result.get('ignored'):
                record_suspicious_activity(uid, honeypot_id, log_entry)
            
            # Acknowledge receipt to honeypot
            emit('log_ack', {
                'success': True,
                'honeypot_id': honeypot_id,
                'timestamp': log_entry['timestamp'],
                'ignored': bool(result.get('ignored'))
            })
        else:
            emit('error', {'message': result.get('error', 'Failed to add log')})
    
    except Exception as e:
        logger.error(f"Error in honeypot_log: {str(e)}")
        emit('error', {'message': f'Internal error: {str(e)}'})


@socketio.on('batch_honeypot_logs')
@honeypot_authenticated_only
def handle_batch_honeypot_logs(data):
    """
    Receive and store multiple log entries at once (bulk insert).
    Expected data: {
        'logs': [log_entry1, log_entry2, ...]
    }
    uid and honeypot_id come from authenticated_honeypots
    """
    try:
        _mark_server_time_now()
        auth_info = authenticated_honeypots.get(request.sid)
        if not auth_info:
            emit('error', {'message': 'Not authenticated'})
            return
            
        uid = auth_info['uid']
        honeypot_id = auth_info['honeypot_id']
        logs = data.get('logs', [])
        
        if not logs:
            emit('error', {'message': 'logs array is required'})
            return
        
        successful_logs = 0
        failed_logs = 0
        ignored_logs = 0
        
        for log_entry in logs:
            # Add timestamp if not provided
            if 'timestamp' not in log_entry:
                log_entry['timestamp'] = datetime.now().isoformat()

            log_entry = _classify_log_entry(log_entry)

            result = db.add_log(uid, honeypot_id, log_entry)
            
            if result['success']:
                if result.get('ignored'):
                    ignored_logs += 1
                else:
                    successful_logs += 1
                    record_suspicious_activity(uid, honeypot_id, log_entry)
            else:
                failed_logs += 1
                logger.warning(f"Failed to add batch log: {result.get('error')}")
        
        logger.info(f"Batch logs for honeypot {honeypot_id}: {successful_logs} successful, {failed_logs} failed out of {len(logs)} total")
        
        # Acknowledge batch processing complete
        emit('batch_logs_ack', {
            'success': True,
            'honeypot_id': honeypot_id,
            'successful': successful_logs,
            'ignored': ignored_logs,
            'failed': failed_logs,
            'total': len(logs),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error in batch_honeypot_logs: {str(e)}")
        emit('error', {'message': f'Internal error: {str(e)}'})


# ==================== Status and Health Monitoring ====================

@socketio.on('honeypot_heartbeat')
@honeypot_authenticated_only
def handle_honeypot_heartbeat(data):
    """
    Receive heartbeat from honeypot to confirm it's still alive.
    Expected data: {'status': dict}
    uid and honeypot_id come from authenticated_honeypots
    """
    try:
        _mark_server_time_now()
        auth_info = authenticated_honeypots.get(request.sid)
        if not auth_info:
            emit('error', {'message': 'Not authenticated'})
            return
            
        uid = auth_info['uid']
        honeypot_id = auth_info['honeypot_id']
        status = data.get('status', {})
        
        # Update last active timestamp in database
        result = db.update_honeypot(
            uid,
            honeypot_id,
            last_active=datetime.now().isoformat()
        )
        
        if result['success']:
            logger.debug(f"Heartbeat received from honeypot {honeypot_id} - Status: {status}")
            
            # Acknowledge heartbeat
            emit('heartbeat_ack', {
                'success': True,
                'honeypot_id': honeypot_id,
                'timestamp': datetime.now().isoformat()
            })
        else:
            emit('error', {'message': result.get('error', 'Failed to process heartbeat')})
    
    except Exception as e:
        logger.error(f"Error in honeypot_heartbeat: {str(e)}")
        emit('error', {'message': f'Internal error: {str(e)}'})


# ==================== Error Handling ====================

@socketio.on_error()
def error_handler(e):
    """Global error handler for Socket.IO events"""
    logger.error(f"Socket.IO error: {str(e)}")
    try:
        emit('error', {'message': 'An unexpected error occurred'})
    except Exception as emit_error:
        logger.error(f"Failed to emit error response: {str(emit_error)}")


@socketio.on_error_default
def default_error_handler(e):
    """Default error handler for unhandled Socket.IO errors"""
    logger.error(f"Unhandled Socket.IO error: {str(e)}")
    try:
        emit('error', {'message': 'An unexpected error occurred'})
    except Exception as emit_error:
        logger.error(f"Failed to emit error response: {str(emit_error)}")
