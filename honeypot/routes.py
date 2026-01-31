"""
Honeypot routes - API endpoints for honeypot operations
"""

from flask import Blueprint, render_template, request, jsonify, session, send_file, Response
from auth.routes import is_logged_in
import os
import uuid
from datetime import datetime
from database.database_communicator import DatabaseCommunicator

honeypot_bp = Blueprint('honeypot', __name__, url_prefix='/honeypot')
db = DatabaseCommunicator()


@honeypot_bp.route('/create', methods=['POST'])
def create_honeypot():
    """
    Create a new honeypot instance
    Returns installation URL and credentials
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        data = request.get_json()
        
        honeypot_name = data.get('name', 'Honeypot Instance')
        honeypot_type = data.get('type', 'default')
        description = data.get('description', '')
        
        # Generate unique honeypot ID
        honeypot_id = str(uuid.uuid4())[:12]
        
        # Generate API key
        api_key = str(uuid.uuid4())
        
        # Create honeypot entry in database
        honeypot_data = {
            'id': honeypot_id,
            'name': honeypot_name,
            'type': honeypot_type,
            'description': description,
            'api_key': api_key,
            'created_at': datetime.now().isoformat(),
            'is_active': False,
            'logs': [],
            'active_protocols': [],
            'last_seen': None,
            'events_count': 0
        }
        
        result = db.create_honeypot(uid, honeypot_id, honeypot_data)
        
        if not result['success']:
            return jsonify({'error': 'Failed to create honeypot'}), 400
        
        # Get the domain from request
        domain = request.host.split(':')[0]
        server_url = f"{'https' if request.is_secure else 'http'}://{domain}"
        
        # Generate installation URL and script
        install_url = f"{server_url}/honeypot/install.sh?id={honeypot_id}&key={api_key}"
        install_command = f"wget {server_url}/honeypot/install.sh -O /tmp/install.sh && bash /tmp/install.sh --server-url {server_url} --honeypot-id {honeypot_id} --api-key {api_key}"
        
        return jsonify({
            'success': True,
            'honeypot_id': honeypot_id,
            'api_key': api_key,
            'install_url': install_url,
            'install_command': install_command,
            'server_url': server_url
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/install.sh', methods=['GET'])
def download_install_script():
    """
    Download the installation script
    The script can be used with: wget <url> | bash
    """
    try:
        honeypot_id = request.args.get('id')
        api_key = request.args.get('key')
        
        if not honeypot_id or not api_key:
            return "Error: Missing required parameters\n", 400
        
        # Verify the honeypot and API key exist
        # You might want to validate this against your database
        
        script_path = os.path.join(
            os.path.dirname(__file__),
            'install.sh'
        )
        
        with open(script_path, 'r') as f:
            script_content = f.read()
        
        # The script will use the parameters passed in the command line
        return Response(script_content, mimetype='text/x-shellscript')
    
    except Exception as e:
        return f"Error: {str(e)}\n", 500


@honeypot_bp.route('/api/register', methods=['POST'])
def register_honeypot():
    """
    Register a honeypot client with the server
    Authentication: Bearer token in Authorization header
    """
    try:
        # Get headers
        auth_header = request.headers.get('Authorization', '')
        honeypot_id = request.headers.get('X-Honeypot-ID', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        api_key = auth_header.replace('Bearer ', '')
        data = request.get_json()
        
        # Verify the API key and honeypot ID
        # This should be validated against your database
        
        # Mark honeypot as active
        update_data = {
            'is_active': True,
            'last_seen': datetime.now().isoformat(),
            'hostname': data.get('hostname'),
            'platform': data.get('platform')
        }
        
        # You would update this in the database
        # For now, we'll just return success
        
        return jsonify({
            'success': True,
            'message': 'Honeypot registered successfully',
            'honeypot_id': honeypot_id
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/heartbeat', methods=['POST'])
def honeypot_heartbeat():
    """
    Receive heartbeat from honeypot client
    Indicates the honeypot is still alive
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        honeypot_id = request.headers.get('X-Honeypot-ID', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        data = request.get_json()
        
        # Update last_seen in database
        # This indicates the honeypot is online
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat()
        }), 204
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/logs', methods=['POST'])
def receive_honeypot_log():
    """
    Receive attack logs from honeypot client
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        honeypot_id = request.headers.get('X-Honeypot-ID', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        api_key = auth_header.replace('Bearer ', '')
        data = request.get_json()
        
        log_entry = data.get('log', {})
        
        # Parse and store the log
        formatted_log = {
            'timestamp': log_entry.get('timestamp', datetime.now().isoformat()),
            'source_ip': log_entry.get('source_ip', 'unknown'),
            'source_port': log_entry.get('source_port', 'unknown'),
            'destination_port': log_entry.get('destination_port', 'unknown'),
            'protocol': log_entry.get('protocol', 'unknown'),
            'attack_type': log_entry.get('attack_type', 'unknown'),
            'status': 'infiltration' if log_entry.get('payload') else 'scan',
            'payload': log_entry.get('payload', ''),
            'raw_data': log_entry.get('raw_data', {})
        }
        
        # Add log to the honeypot in the database
        # db.add_honeypot_log(uid, honeypot_id, formatted_log)
        
        return jsonify({
            'success': True,
            'message': 'Log received successfully'
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/config', methods=['GET'])
def get_honeypot_config():
    """
    Get configuration updates for honeypot client
    """
    try:
        auth_header = request.headers.get('Authorization', '')
        honeypot_id = request.headers.get('X-Honeypot-ID', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        # Return configuration for the honeypot
        config = {
            'start_honeypots': [],
            'stop_honeypots': [],
            'update_interval': 300
        }
        
        return jsonify(config), 200
    
    except Exception as e:
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
                    'type': hp_data.get('type', 'unknown'),
                    'is_active': hp_data.get('is_active', False),
                    'created_at': hp_data.get('created_at'),
                    'last_seen': hp_data.get('last_seen'),
                    'events_count': hp_data.get('events_count', 0),
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
