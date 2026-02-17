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
honeypot_api_bp = Blueprint('honeypot_api', __name__, url_prefix='/api/honeypot')
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
        result = db.create_honeypot(uid, name, honeypot_id, extra_data={"description": description})
        
        if not result['success']:
            return jsonify({'error': result.get('error', 'Failed to create honeypot')}), 400

        actor_profile = db.get_user_basic(uid)
        actor_username = None
        if actor_profile.get("success"):
            actor_username = actor_profile.get("username") or actor_profile.get("email")
        db.record_activity(
            uid,
            "honeypot_created",
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username
        )
        
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
def download_honeypot_client():
    """Download the honeypot client"""
    return _download_file('honeypot_client.py', 'text/x-python')



@honeypot_bp.route('/list', methods=['GET'])
def list_honeypots():
    """
    List all honeypots for the logged-in user
    """
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        uid = session.get('uid')
        result = db.list_accessible_honeypots(uid)
        
        if result['success']:
            honeypots = result.get('honeypots', {})
            honeypot_list = []
            
            for hp_id, hp_data in honeypots.items():
                owner_label = None
                if hp_data.get("shared"):
                    owner_profile = db.get_user_basic(hp_data.get("owner_uid"))
                    if owner_profile.get("success"):
                        owner_label = owner_profile.get("username") or owner_profile.get("email")
                honeypot_list.append({
                    'id': hp_id,
                    'name': hp_data.get('name', 'Unknown'),
                    'is_active': hp_data.get('is_active', False),
                    'created_at': hp_data.get('created_at'),
                    'last_active': hp_data.get('last_active'),
                    'description': hp_data.get('description', ''),
                    'shared': bool(hp_data.get('shared')),
                    'owner_uid': hp_data.get('owner_uid'),
                    'owner': owner_label
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
        access = db.resolve_honeypot_access(uid, honeypot_id)
        if not access.get("success"):
            return jsonify({'error': access.get('error')}), 403

        if access.get("owner_uid") != uid and not access.get("can_delete"):
            return jsonify({'error': 'Delete permission denied'}), 403

        owner_uid = access.get("owner_uid")
        result = db.delete_honeypot(owner_uid, honeypot_id)
        
        if result['success']:
            actor_profile = db.get_user_basic(uid)
            actor_username = None
            if actor_profile.get("success"):
                actor_username = actor_profile.get("username") or actor_profile.get("email")
            db.record_activity(
                owner_uid,
                "honeypot_deleted",
                honeypot_id=honeypot_id,
                actor_uid=uid,
                actor_username=actor_username
            )
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
        
        access = db.get_honeypot_with_access(uid, honeypot_id)
        if not access.get('success'):
            return jsonify({'error': access.get('error')}), 403

        owner_uid = access.get('owner_uid')
        result = db.get_honeypot(owner_uid, honeypot_id)
        
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
