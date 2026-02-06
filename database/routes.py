from flask import Blueprint, render_template, session, request, redirect, url_for
from database.database_communicator import DatabaseCommunicator
from auth.extensions import limiter
from alerts import record_suspicious_activity, notify_honeypot_down
from honeypot.honeypot_to_db_routes import send_start_command, send_stop_command

database_bp = Blueprint('database', __name__)
db = DatabaseCommunicator()

def is_logged_in():
    return 'uid' in session

# Honeypot Management Routes
@database_bp.route('/honeypots')
def honeypots():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    result = db.list_honeypots(uid)
    
    honeypots_data = result.get('honeypots', {}) if result['success'] else {}
    
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
        return redirect(url_for('database.honeypots', success='Honeypot created successfully'))
    else:
        return redirect(url_for('database.honeypots', error=result['error']))

@database_bp.route('/honeypots/<honeypot_id>/delete', methods=['POST'])
@limiter.limit("10 per minute")
def delete_honeypot(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    result = db.delete_honeypot(uid, honeypot_id)
    
    if result['success']:
        return redirect(url_for('database.honeypots', success='Honeypot deleted successfully'))
    else:
        return redirect(url_for('database.honeypots', error=result['error']))

@database_bp.route('/honeypots/<honeypot_id>/update', methods=['POST'])
def update_honeypot(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    payload = request.get_json() if request.is_json else None

    name = payload.get('name') if payload else request.form.get('name')
    protocols = payload.get('protocols') if payload else request.form.getlist('protocols')
    is_active_raw = payload.get('is_active') if payload else request.form.get('is_active')

    is_active_value = None
    if is_active_raw is not None:
        if isinstance(is_active_raw, bool):
            is_active_value = is_active_raw
        else:
            is_active_value = str(is_active_raw).lower() in ['true', '1', 'yes', 'on']

    current_state = db.get_honeypot(uid, honeypot_id)
    current_honeypot = current_state.get('honeypot', {}) if current_state.get('success') else {}
    was_active = current_honeypot.get('is_active')
    current_protocols = current_honeypot.get('active_protocols', [])
    protocols_provided = protocols is not None

    result = db.update_honeypot(uid, honeypot_id, name=name, protocols=protocols, is_active=is_active_value)
    
    if result['success']:
        if was_active and is_active_value is False:
            notify_honeypot_down(uid, honeypot_id)
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
    honeypots_result = db.list_honeypots(uid)
    honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
    
    logs_data = []
    selected_honeypot = None
    
    if honeypot_id:
        logs_result = db.get_logs(uid, honeypot_id)
        if logs_result['success']:
            logs_data = logs_result['logs']
            honeypot_result = db.get_honeypot(uid, honeypot_id)
            if honeypot_result['success']:
                selected_honeypot = honeypot_result['honeypot']
    
    return render_template(
        'logs.html',
        logs=logs_data,
        honeypots=honeypots_data,
        selected_honeypot_id=honeypot_id,
        selected_honeypot=selected_honeypot,
        error=request.args.get('error'),
        success=request.args.get('success')
    )

@database_bp.route('/logs/<honeypot_id>/clear', methods=['POST'])
def clear_logs(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    result = db.clear_logs(uid, honeypot_id)
    
    if result['success']:
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, success='Logs cleared successfully'))
    else:
        return redirect(url_for('database.logs', honeypot_id=honeypot_id, error=result['error']))

@database_bp.route('/logs/<honeypot_id>/add', methods=['POST'])
def add_log(honeypot_id):
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    
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
    
    result = db.add_log(uid, honeypot_id, log_entry)
    
    if result['success']:
        record_suspicious_activity(uid, honeypot_id, log_entry)
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
