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


@honeypot_bp.route('/install.sh', methods=['GET'])
def download_install_script():
    """
    Download the installation script
    """
    try:
        script_path = os.path.join(
            os.path.dirname(__file__),
            'install.sh'
        )
        
        with open(script_path, 'r') as f:
            script_content = f.read()
        
        return Response(script_content, mimetype='text/x-shellscript')
    
    except Exception as e:
        return f"Error: {str(e)}\n", 500

@honeypot_bp.route('/honeypot_client.py', methods=['GET'])
def download_honeypot_client_script():
    """
    Download the installation script
    """
    try:
        script_path = os.path.join(
            os.path.dirname(__file__),
            'honeypot_client.py'
        )
        
        with open(script_path, 'r') as f:
            script_content = f.read()
        
        return Response(script_content, mimetype='text/x-python')
    
    except Exception as e:
        return f"Error: {str(e)}\n", 500


@honeypot_bp.route('/api/register', methods=['POST'])
def register_honeypot():
    """
    Register a honeypot client with the server
    """
    try:
        # TODO: Implement honeypot registration
        return jsonify({
            'success': True,
            'message': 'Honeypot registered successfully'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@honeypot_bp.route('/api/heartbeat', methods=['POST'])
def honeypot_heartbeat():
    """
    Receive heartbeat from honeypot client
    """
    try:
        # TODO: Implement heartbeat handling
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
        # TODO: Implement log receiving and storage
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
        # TODO: Implement config retrieval
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
