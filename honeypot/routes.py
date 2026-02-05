"""
Honeypot routes - API endpoints for honeypot operations
"""

from flask import Blueprint, render_template, request, jsonify, session, send_file, Response
from auth.routes import is_logged_in
import os
import uuid
import logging
from datetime import datetime
from database.database_communicator import DatabaseCommunicator

logger = logging.getLogger(__name__)
honeypot_bp = Blueprint('honeypot', __name__, url_prefix='/honeypot')
db = DatabaseCommunicator()


@honeypot_bp.route('/create', methods=['POST'])
def create_honeypot():
    """
    Create a new honeypot instance
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        data = request.get_json()
        
        name = data.get('name', 'Honeypot Instance')
        description = data.get('description', '')
        
        honeypot_id = str(uuid.uuid4())[:12]
        result = db.create_honeypot(uid, name, honeypot_id)
        
        if not result['success']:
            return jsonify({'error': result.get('error', 'Failed to create honeypot')}), 400
        
        # Update with description
        db_data = db._load_db()
        db_data[uid]['honeypots'][honeypot_id]['description'] = description
        db._save_db(db_data)
        
        return jsonify({
            'success': True,
            'honeypot_id': honeypot_id,
            'name': name,
            'description': description
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _download_file(filename: str, mimetype: str):
    """Helper function to download files from the honeypot directory"""
    try:
        script_path = os.path.join(os.path.dirname(__file__), filename)
        
        if not os.path.exists(script_path):
            return jsonify({'error': f'File {filename} not found'}), 404
        
        with open(script_path, 'r') as f:
            content = f.read()
        
        return Response(content, mimetype=mimetype)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/install.sh', methods=['GET'])
def download_install_script():
    """Download the installation script"""
    return _download_file('install.sh', 'text/x-shellscript')


@honeypot_bp.route('/honeypot_client.py', methods=['GET'])
def download_honeypot_client_script():
    """Download the honeypot client Python script"""
    return _download_file('honeypot_client.py', 'text/x-python')


@honeypot_bp.route('/api/register', methods=['POST'])
def register_honeypot():
    """Register a honeypot client with the server"""
    try:
        data = request.get_json()
        honeypot_id = data.get('honeypot_id')
        
        if not honeypot_id:
            return jsonify({'error': 'honeypot_id is required'}), 400
        
        # Note: In production, validate honeypot ownership and store registration info
        logger.info(f"Honeypot {honeypot_id} registered from {request.remote_addr}")
        
        return jsonify({
            'success': True,
            'message': 'Honeypot registered successfully',
            'honeypot_id': honeypot_id
        }), 200
    
    except Exception as e:
        logger.error(f"Error registering honeypot: {e}")
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/heartbeat', methods=['POST'])
def honeypot_heartbeat():
    """Receive heartbeat from honeypot client"""
    try:
        data = request.get_json()
        honeypot_id = data.get('honeypot_id')
        
        if not honeypot_id:
            return jsonify({'error': 'honeypot_id is required'}), 400
        
        # Note: In production, update last_active timestamp in database
        logger.debug(f"Heartbeat received from {honeypot_id}")
        
        return '', 204
    
    except Exception as e:
        logger.error(f"Error processing heartbeat: {e}")
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/logs', methods=['POST'])
def receive_honeypot_log():
    """Receive attack logs from honeypot client"""
    try:
        data = request.get_json()
        honeypot_id = data.get('honeypot_id')
        log_entry = data.get('log')
        
        if not honeypot_id or not log_entry:
            return jsonify({'error': 'honeypot_id and log are required'}), 400
        
        # Note: In production, store logs in database
        # For now, just log it
        logger.info(f"Log received from {honeypot_id}: {log_entry.get('attack_type', 'unknown')} from {log_entry.get('source_ip', 'unknown')}")
        
        return jsonify({
            'success': True,
            'message': 'Log received successfully'
        }), 201
    
    except Exception as e:
        logger.error(f"Error receiving log: {e}")
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/config', methods=['GET'])
def get_honeypot_config():
    """Get configuration updates for honeypot client"""
    try:
        honeypot_id = request.headers.get('X-Honeypot-ID')
        
        if not honeypot_id:
            return jsonify({'error': 'X-Honeypot-ID header is required'}), 400
        
        # Note: In production, retrieve honeypot-specific configuration from database
        config = {
            'start_honeypots': [],
            'stop_honeypots': [],
            'update_interval': 300
        }
        
        return jsonify(config), 200
    
    except Exception as e:
        logger.error(f"Error retrieving config: {e}")
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/list', methods=['GET'])
def list_honeypots():
    """
    List all honeypots for the logged-in user
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        result = db.list_honeypots(uid)
        
        if result['success']:
            honeypots = result.get('honeypots', {})
            honeypot_list = []
            
            for hp_id, hp_data in honeypots.items():
                honeypot_list.append({
                    'id': hp_id,
                    'name': hp_data.get('name', 'Unknown'),
                    'is_active': hp_data.get('is_active', False),
                    'created_at': hp_data.get('created_at'),
                    'last_active': hp_data.get('last_active'),
                    'description': hp_data.get('description', '')
                })
            
            return jsonify({
                'success': True,
                'honeypots': honeypot_list,
                'total': len(honeypot_list)
            }), 200
        else:
            return jsonify({'error': 'Failed to retrieve honeypots'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/<honeypot_id>/delete', methods=['DELETE'])
def delete_honeypot(honeypot_id):
    """
    Delete a honeypot instance
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        result = db.delete_honeypot(uid, honeypot_id)
        
        if result['success']:
            return jsonify({'success': True, 'message': 'Honeypot deleted'}), 200
        else:
            return jsonify({'error': 'Failed to delete honeypot'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/<honeypot_id>/logs', methods=['GET'])
def get_honeypot_logs(honeypot_id):
    """
    Get logs for a specific honeypot
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        result = db.get_honeypot(uid, honeypot_id)
        
        if result['success']:
            honeypot = result.get('honeypot', {})
            logs = honeypot.get('logs', [])
            
            # Paginate logs
            paginated_logs = logs[offset:offset + limit]
            
            return jsonify({
                'success': True,
                'honeypot_id': honeypot_id,
                'logs': paginated_logs,
                'total': len(logs),
                'limit': limit,
                'offset': offset
            }), 200
        else:
            return jsonify({'error': 'Honeypot not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
