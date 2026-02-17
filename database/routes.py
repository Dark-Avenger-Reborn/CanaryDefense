from flask import Blueprint, render_template, session, request, redirect, url_for, jsonify
from database.database_communicator import DatabaseCommunicator
from auth.extensions import limiter
from alerts import record_suspicious_activity, notify_honeypot_down
from honeypot.honeypot_to_db_routes import send_start_command, send_stop_command

database_bp = Blueprint('database', __name__)
db = DatabaseCommunicator()

def is_logged_in():
    return 'uid' in session

def _has_manage_access(role):
    return role in {"owner", "manage"}

def _get_actor_username(uid):
    profile = db.get_user_basic(uid)
    if not profile.get("success"):
        return None
    return profile.get("username") or profile.get("email")

# Honeypot Management Routes
@database_bp.route('/honeypots')
def honeypots():
    if not is_logged_in():
        # Show the explore/informational page for non-logged-in users
        counts = db.get_global_counts()
        return render_template(
            'explore_honeypots.html',
            total_accounts=counts.get('total_users', 0),
            total_honeypots=counts.get('total_honeypots', 0),
            total_logs=counts.get('total_logs', 0)
        )
    
    # Show management page for logged-in users
    uid = session.get('uid')
    result = db.list_accessible_honeypots(uid)

    honeypots_data = result.get('honeypots', {}) if result['success'] else {}
    for hp_id, hp in honeypots_data.items():
        if hp.get("shared"):
            owner_profile = db.get_user_basic(hp.get("owner_uid"))
            if owner_profile.get("success"):
                hp["owner_username"] = owner_profile.get("username") or owner_profile.get("email")
            else:
                hp["owner_username"] = "Unknown"
    
    return render_template(
        'honeypots.html',
        honeypots=honeypots_data,
        error=request.args.get('error'),
        success=request.args.get('success')
    )

@database_bp.route('/honeypots/create', methods=['POST'])
@limiter.limit("10 per minute")
def create_honeypot():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    name = request.form.get('name')
    
    if not name:
        return redirect(url_for('database.honeypots', error='Name is required'))
    
    result = db.create_honeypot(uid, name)
    
    if result['success']:
        actor_username = _get_actor_username(uid)
        db.record_activity(
            uid,
            "honeypot_created",
            honeypot_id=None,
            actor_uid=uid,
            actor_username=actor_username,
            details={"name": name}
        )
        return redirect(url_for('database.honeypots', success='Honeypot created successfully'))
    else:
        return redirect(url_for('database.honeypots', error=result['error']))

@database_bp.route('/honeypots/<honeypot_id>/delete', methods=['POST'])
@limiter.limit("10 per minute")
def delete_honeypot(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    access = db.resolve_honeypot_access(uid, honeypot_id)
    if not access.get("success"):
        return redirect(url_for('database.honeypots', error=access.get('error')))

    if access.get("owner_uid") != uid and not access.get("can_delete"):
        return redirect(url_for('database.honeypots', error='Delete permission denied'))

    owner_uid = access.get("owner_uid")
    result = db.delete_honeypot(owner_uid, honeypot_id)

    if result['success']:
        actor_username = _get_actor_username(uid)
        db.record_activity(
            owner_uid,
            "honeypot_deleted",
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username
        )
        return redirect(url_for('database.honeypots', success='Honeypot deleted successfully'))
    else:
        return redirect(url_for('database.honeypots', error=result['error']))

@database_bp.route('/honeypots/<honeypot_id>/update', methods=['POST'])
def update_honeypot(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    access = db.resolve_honeypot_access(uid, honeypot_id)
    if not access.get("success"):
        return redirect(url_for('database.honeypots', error=access.get('error')))

    if not _has_manage_access(access.get("role")):
        return redirect(url_for('database.honeypots', error='Manage permission denied'))

    owner_uid = access.get("owner_uid")
    payload = request.get_json() if request.is_json else None

    name = payload.get('name') if payload else request.form.get('name')
    description = payload.get('description') if payload else request.form.get('description')
    protocols = payload.get('protocols') if payload else request.form.getlist('protocols')
    is_active_raw = payload.get('is_active') if payload else request.form.get('is_active')

    is_active_value = None
    if is_active_raw is not None:
        if isinstance(is_active_raw, bool):
            is_active_value = is_active_raw
        else:
            is_active_value = str(is_active_raw).lower() in ['true', '1', 'yes', 'on']

    current_state = db.get_honeypot(owner_uid, honeypot_id)
    current_honeypot = current_state.get('honeypot', {}) if current_state.get('success') else {}
    was_active = current_honeypot.get('is_active')
    current_protocols = current_honeypot.get('active_protocols', [])
    protocols_provided = protocols is not None

    result = db.update_honeypot(owner_uid, honeypot_id, name=name, description=description, protocols=protocols, is_active=is_active_value)
    
    if result['success']:
        actor_username = _get_actor_username(uid)
        db.record_activity(
            owner_uid,
            "honeypot_updated",
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username,
            details={"name": name, "description": description}
        )
        if was_active and is_active_value is False:
            notify_honeypot_down(owner_uid, honeypot_id)
            send_stop_command(honeypot_id)
        elif was_active and protocols_provided:
            new_protocols = set(protocols)
            previous_protocols = set(current_protocols or [])
            protocols_to_start = sorted(new_protocols - previous_protocols)
            protocols_to_stop = sorted(previous_protocols - new_protocols)

            if protocols_to_start:
                send_start_command(honeypot_id, protocols_to_start)
            if protocols_to_stop:
                send_stop_command(honeypot_id, protocols_to_stop)
        return redirect(url_for('database.honeypots', success='Honeypot updated successfully'))
    else:
        return redirect(url_for('database.honeypots', error=result['error']))

# Logs Management Routes
@database_bp.route('/logs')
def logs():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    honeypot_id = request.args.get('honeypot_id')
    
    # Get all honeypots for the dropdown
    honeypots_result = db.list_accessible_honeypots(uid)
    honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
    for hp_id, hp in honeypots_data.items():
        if hp.get("shared"):
            owner_profile = db.get_user_basic(hp.get("owner_uid"))
            if owner_profile.get("success"):
                hp["owner_username"] = owner_profile.get("username") or owner_profile.get("email")
            else:
                hp["owner_username"] = "Unknown"
    
    logs_data = []
    selected_honeypot = None
    selected_can_manage = False
    
    if honeypot_id:
        access = db.get_honeypot_with_access(uid, honeypot_id)
        if access.get('success'):
            owner_uid = access.get('owner_uid')
            selected_can_manage = _has_manage_access(access.get('role'))
            logs_result = db.get_logs(owner_uid, honeypot_id)
            if logs_result['success']:
                logs_data = logs_result['logs']
                selected_honeypot = access.get('honeypot')
    
    return render_template(
        'logs.html',
        logs=logs_data,
        honeypots=honeypots_data,
        selected_honeypot_id=honeypot_id,
        selected_honeypot=selected_honeypot,
        selected_can_manage=selected_can_manage,
        error=request.args.get('error'),
        success=request.args.get('success')
    )

@database_bp.route('/api/honeypots')
def honeypots_live():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session.get('uid')
    result = db.list_accessible_honeypots(uid)
    if not result.get('success'):
        return jsonify({"success": False, "error": result.get("error", "Failed to load honeypots")}), 400

    honeypots_payload = {}
    for hp_id, hp in result.get('honeypots', {}).items():
        owner_label = None
        if hp.get("shared"):
            owner_profile = db.get_user_basic(hp.get("owner_uid"))
            if owner_profile.get("success"):
                owner_label = owner_profile.get("username") or owner_profile.get("email")
        honeypots_payload[hp_id] = {
            "name": hp.get('name', hp_id),
            "description": hp.get('description'),
            "is_active": bool(hp.get('is_active')),
            "active_protocols": hp.get('active_protocols', []),
            "logs_count": len(hp.get('logs', [])),
            "last_active": hp.get('last_active'),
            "created_at": hp.get('created_at'),
            "shared": bool(hp.get("shared")),
            "owner_uid": hp.get("owner_uid"),
            "owner": owner_label
        }

    return jsonify({"success": True, "honeypots": honeypots_payload})

@database_bp.route('/logs/<honeypot_id>/clear', methods=['POST'])
def clear_logs(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    access = db.resolve_honeypot_access(uid, honeypot_id)
    if not access.get("success"):
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error=access.get('error')))
    if not _has_manage_access(access.get("role")):
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error='Manage permission denied'))

    owner_uid = access.get("owner_uid")
    result = db.clear_logs(owner_uid, honeypot_id)
    
    if result['success']:
        actor_username = _get_actor_username(uid)
        db.record_activity(
            owner_uid,
            "logs_cleared",
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username
        )
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, success='Logs cleared successfully'))
    else:
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error=result['error']))

@database_bp.route('/api/logs')
def logs_live():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session.get('uid')
    honeypot_id = request.args.get('honeypot_id')
    if not honeypot_id:
        return jsonify({"success": False, "error": "Honeypot id is required"}), 400

    access = db.resolve_honeypot_access(uid, honeypot_id)
    if not access.get("success"):
        return jsonify({"success": False, "error": access.get('error')}), 403

    owner_uid = access.get("owner_uid")
    logs_result = db.get_logs(owner_uid, honeypot_id)
    if not logs_result.get('success'):
        return jsonify({"success": False, "error": logs_result.get('error', 'Failed to load logs')}), 400

    honeypot_result = db.get_honeypot(owner_uid, honeypot_id)
    honeypot_data = honeypot_result.get('honeypot') if honeypot_result.get('success') else None

    return jsonify({
        "success": True,
        "logs": logs_result.get('logs', []),
        "honeypot": honeypot_data
    })

@database_bp.route('/logs/<honeypot_id>/add', methods=['POST'])
def add_log(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    access = db.resolve_honeypot_access(uid, honeypot_id)
    if not access.get("success"):
        if request.is_json:
            return {"success": False, "error": access.get('error')}, 400
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error=access.get('error')))
    if not _has_manage_access(access.get("role")):
        if request.is_json:
            return {"success": False, "error": "Manage permission denied"}, 403
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error='Manage permission denied'))

    owner_uid = access.get("owner_uid")
    
    # Get log data from form or JSON
    if request.is_json:
        log_entry = request.get_json()
    else:
        log_entry = {
            "action": request.form.get('action'),
            "dest_ip": request.form.get('dest_ip'),
            "dest_port": request.form.get('dest_port'),
            "server": request.form.get('server'),
            "src_ip": request.form.get('src_ip'),
            "src_port": request.form.get('src_port'),
            "status": request.form.get('status'),
            "timestamp": request.form.get('timestamp')
        }
    
    result = db.add_log(owner_uid, honeypot_id, log_entry)
    
    if result['success']:
        if not result.get('ignored'):
            record_suspicious_activity(owner_uid, honeypot_id, log_entry)
        if request.is_json:
            return {"success": True, "message": "Log added successfully"}
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, success='Log added successfully'))
    else:
        if request.is_json:
            return {"success": False, "error": result['error']}, 400
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error=result['error']))

@database_bp.route('/alerts/config', methods=['GET', 'POST'])
def alert_config():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    
    if request.method == 'POST':
        emails = request.form.get('emails', '').split(',')
        emails = [email.strip() for email in emails if email.strip()]
        
        alert_on_honeypot_down = request.form.get('alert_on_honeypot_down') == 'on'
        alert_on_suspicious_activity = request.form.get('alert_on_suspicious_activity') == 'on'
        
        preferences = {
            "alert_on_honeypot_down": alert_on_honeypot_down,
            "alert_on_suspicious_activity": alert_on_suspicious_activity
        }
        
        result = db.update_user_alerts(uid, emails, preferences)
        user_data = db.get_user_entry(uid)
        
        if result['success']:
            return redirect(url_for('database.alert_config', success='Alert settings updated'))
        else:
            return redirect(url_for('database.alert_config', error=result['error']))
    
    # GET request - show form
    user_data = db.get_user_entry(uid)
    alerts = user_data.get('data', {}).get('alerts', {}) if user_data['success'] else {}

    return render_template(
        'alert_config.html',
        alerts=alerts,
        error=request.args.get('error'),
        success=request.args.get('success'),
        preferences=user_data.get('data', {}).get('alerts', {}).get('preferences', {}) if user_data['success'] else {}
    )

@database_bp.route('/collaboration', methods=['GET'])
def collaboration():
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    owned_result = db.list_honeypots(uid)
    owned_honeypots = owned_result.get('honeypots', {}) if owned_result.get('success') else {}

    collaborator_map = {}
    for hp_id, hp in owned_honeypots.items():
        collaborators = []
        for collab_uid, access in (hp.get('collaborators', {}) or {}).items():
            profile = db.get_user_basic(collab_uid)
            collaborators.append({
                "uid": collab_uid,
                "username": profile.get("username") if profile.get("success") else None,
                "email": profile.get("email") if profile.get("success") else None,
                "role": access.get("role", "read"),
                "can_delete": bool(access.get("can_delete"))
            })
        collaborator_map[hp_id] = collaborators

    invites_result = db.list_invites(uid)
    invite_rows = []
    if invites_result.get('success'):
        for invite in invites_result.get('invites', []):
            owner_uid = invite.get('owner_uid')
            honeypot_id = invite.get('honeypot_id')
            owner_profile = db.get_user_basic(owner_uid)
            owner_label = None
            if owner_profile.get('success'):
                owner_label = owner_profile.get('username') or owner_profile.get('email')
            hp_result = db.get_honeypot(owner_uid, honeypot_id)
            honeypot_name = hp_result.get('honeypot', {}).get('name') if hp_result.get('success') else honeypot_id
            invite_rows.append({
                "owner_uid": owner_uid,
                "owner_label": owner_label,
                "honeypot_id": honeypot_id,
                "honeypot_name": honeypot_name,
                "role": invite.get('role', 'read'),
                "can_delete": bool(invite.get('can_delete')),
                "invited_at": invite.get('invited_at')
            })

    return render_template(
        'collaboration.html',
        honeypots=owned_honeypots,
        collaborators=collaborator_map,
        invites=invite_rows,
        error=request.args.get('error'),
        success=request.args.get('success')
    )

@database_bp.route('/collaboration/invite', methods=['POST'])
def send_invite():
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    username = request.form.get('username', '').strip()
    role = request.form.get('role', 'read')
    if role not in {'read', 'manage'}:
        role = 'read'
    can_delete = request.form.get('can_delete') == 'on'
    honeypot_ids = request.form.getlist('honeypot_ids')

    if not username or not honeypot_ids:
        return redirect(url_for('database.collaboration', error='Username and honeypot selection are required'))

    invitee_uid = db.find_uid_by_username(username)
    if invitee_uid is None:
        return redirect(url_for('database.collaboration', error='Username not found'))
    if invitee_uid == uid:
        return redirect(url_for('database.collaboration', error='You cannot invite yourself'))

    actor_username = _get_actor_username(uid)
    errors = []
    for honeypot_id in honeypot_ids:
        owner_check = db.get_honeypot(uid, honeypot_id)
        if not owner_check.get('success'):
            errors.append(f"Honeypot {honeypot_id} not found")
            continue

        result = db.add_invite(uid, honeypot_id, invitee_uid, role, can_delete, uid)
        if not result.get('success'):
            errors.append(result.get('error'))
            continue

        db.record_activity(
            uid,
            'invite_sent',
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username,
            details={"invitee": username, "role": role, "can_delete": can_delete}
        )

    if errors:
        return redirect(url_for('database.collaboration', error='; '.join(errors)))

    return redirect(url_for('database.collaboration', success='Invite sent successfully'))

@database_bp.route('/collaboration/invites/accept', methods=['POST'])
def accept_invite():
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    owner_uid = request.form.get('owner_uid')
    honeypot_id = request.form.get('honeypot_id')
    if not owner_uid or not honeypot_id:
        return redirect(url_for('database.collaboration', error='Invalid invite'))

    result = db.accept_invite(uid, owner_uid, honeypot_id)
    if result.get('success'):
        actor_username = _get_actor_username(uid)
        db.record_activity(
            owner_uid,
            'collaborator_added',
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username
        )
        return redirect(url_for('database.collaboration', success='Invite accepted'))
    return redirect(url_for('database.collaboration', error=result.get('error')))

@database_bp.route('/collaboration/invites/decline', methods=['POST'])
def decline_invite():
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    owner_uid = request.form.get('owner_uid')
    honeypot_id = request.form.get('honeypot_id')
    if not owner_uid or not honeypot_id:
        return redirect(url_for('database.collaboration', error='Invalid invite'))

    result = db.decline_invite(uid, owner_uid, honeypot_id)
    if result.get('success'):
        return redirect(url_for('database.collaboration', success='Invite declined'))
    return redirect(url_for('database.collaboration', error=result.get('error')))

@database_bp.route('/collaboration/honeypots/<honeypot_id>/collaborators/<collab_uid>/update', methods=['POST'])
def update_collaborator(honeypot_id, collab_uid):
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    owner_check = db.get_honeypot(uid, honeypot_id)
    if not owner_check.get('success'):
        return redirect(url_for('database.collaboration', error='Honeypot not found'))

    role = request.form.get('role', 'read')
    if role not in {'read', 'manage'}:
        role = 'read'
    can_delete = request.form.get('can_delete') == 'on'

    result = db.update_collaborator(uid, honeypot_id, collab_uid, role, can_delete)
    if result.get('success'):
        actor_username = _get_actor_username(uid)
        db.record_activity(
            uid,
            'collaborator_updated',
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username,
            details={"collaborator_uid": collab_uid, "role": role, "can_delete": can_delete}
        )
        return redirect(url_for('database.collaboration', success='Collaborator updated'))
    return redirect(url_for('database.collaboration', error=result.get('error')))

@database_bp.route('/collaboration/honeypots/<honeypot_id>/collaborators/<collab_uid>/remove', methods=['POST'])
def remove_collaborator(honeypot_id, collab_uid):
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    uid = session.get('uid')
    owner_check = db.get_honeypot(uid, honeypot_id)
    if not owner_check.get('success'):
        return redirect(url_for('database.collaboration', error='Honeypot not found'))

    result = db.remove_collaborator(uid, honeypot_id, collab_uid)
    if result.get('success'):
        actor_username = _get_actor_username(uid)
        db.record_activity(
            uid,
            'collaborator_removed',
            honeypot_id=honeypot_id,
            actor_uid=uid,
            actor_username=actor_username,
            details={"collaborator_uid": collab_uid}
        )
        return redirect(url_for('database.collaboration', success='Collaborator removed'))
    return redirect(url_for('database.collaboration', error=result.get('error')))
