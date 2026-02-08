"""
Socket.IO routes for honeypot-to-server communication.
Handles honeypot connections, disconnections, log streaming, and status updates.
No dashboard communication - this is purely for honeypot instances to communicate with the server.
"""

from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
import logging
from functools import wraps
from database.database_communicator import DatabaseCommunicator
from alerts import record_suspicious_activity, notify_honeypot_down

logger = logging.getLogger(__name__)
db = DatabaseCommunicator()

# Initialize Socket.IO (will be properly initialized in main.py)
socketio = SocketIO()

# Track authenticated honeypots by their socket SID
# Key: request.sid, Value: {'uid': str, 'honeypot_id': str}
authenticated_honeypots = {}


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
        
        # Add log to database
        result = db.add_log(uid, honeypot_id, log_entry)
        
        if result['success']:
            logger.debug(f"Log added for honeypot {honeypot_id} from user {uid}: {log_entry.get('src_ip')} -> {log_entry.get('protocol')}")
            
            # Record suspicious activity for alerting
            record_suspicious_activity(uid, honeypot_id, log_entry)
            
            # Acknowledge receipt to honeypot
            emit('log_ack', {
                'success': True,
                'honeypot_id': honeypot_id,
                'timestamp': log_entry['timestamp']
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
        
        for log_entry in logs:
            # Add timestamp if not provided
            if 'timestamp' not in log_entry:
                log_entry['timestamp'] = datetime.now().isoformat()
            
            result = db.add_log(uid, honeypot_id, log_entry)
            
            if result['success']:
                successful_logs += 1
                # Record suspicious activity
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
