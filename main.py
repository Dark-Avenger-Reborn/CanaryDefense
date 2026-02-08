from flask import Flask, render_template, session, redirect, url_for, jsonify
from pathlib import Path
from auth.routes import auth_bp, is_logged_in
from auth.extensions import limiter
from database.routes import database_bp
from database.database_communicator import DatabaseCommunicator
from honeypot.routes import honeypot_bp, honeypot_api_bp
from honeypot.honeypot_to_db_routes import socketio
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize extensions
limiter.init_app(app)
socketio.init_app(
    app,
    cors_allowed_origins="*",
    manage_session=False,
    async_mode='eventlet',
    engineio_logger=False,
    socketio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(database_bp)
app.register_blueprint(honeypot_bp)
app.register_blueprint(honeypot_api_bp)

db = DatabaseCommunicator()
BRAND_NAME_FILE = Path("config/brand_name.txt")


def load_brand_name():
    try:
        name = BRAND_NAME_FILE.read_text(encoding="utf-8").strip()
        return name or "Honeypot Control"
    except FileNotFoundError:
        return "Honeypot Control"


@app.context_processor
def inject_brand_name():
    return {"brand_name": load_brand_name()}


@app.route('/')
def index():
    if is_logged_in():
        uid = session.get('uid')
        
        # Get honeypots data
        honeypots_result = db.list_honeypots(uid)
        honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
        
        # Calculate statistics
        stats_result = db.get_user_stats(uid)
        stats = stats_result.get('stats', {}) if stats_result['success'] else {}
        total_honeypots = stats.get('total_honeypots_created', 0)
        active_honeypots = sum(1 for hp in honeypots_data.values() if hp.get('is_active', False))
        total_logs = sum(len(hp.get('logs', [])) for hp in honeypots_data.values())
        
        # Get recent logs across all honeypots
        all_logs = []
        for hp_id, hp in honeypots_data.items():
            for log in hp.get('logs', []):
                log_copy = log.copy()
                log_copy['honeypot_id'] = hp_id
                log_copy['honeypot_name'] = hp.get('name', hp_id)
                all_logs.append(log_copy)
        
        # Sort by timestamp (newest first)
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        recent_logs = all_logs[:10]  # Get 10 most recent
        
        # Protocol distribution
        protocol_count = {}
        for hp in honeypots_data.values():
            for protocol in hp.get('active_protocols', []):
                protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
        
        # Attack type distribution for logs
        scans_count = sum(1 for log in all_logs if log.get('status') == 'scan')
        infiltrations_count = sum(1 for log in all_logs if log.get('status') == 'infiltration')
        
        return render_template('dashboard.html',
                             total_honeypots=total_honeypots,
                             active_honeypots=active_honeypots,
                             total_logs=total_logs,
                             recent_logs=recent_logs,
                             honeypots=honeypots_data,
                             protocol_count=protocol_count,
                             scans_count=scans_count,
                             infiltrations_count=infiltrations_count)
    counts = db.get_global_counts()
    return render_template(
        'index.html',
        total_accounts=counts.get('total_users', 0),
        total_honeypots=counts.get('total_honeypots', 0),
        total_logs=counts.get('total_logs', 0)
    )

@app.route('/api/public_counts')
def public_counts():
    counts = db.get_global_counts()
    if not counts.get('success'):
        return jsonify({"success": False, "error": counts.get("error", "Unknown error")}), 500
    return jsonify({
        "success": True,
        "total_accounts": counts.get('total_users', 0),
        "total_honeypots": counts.get('total_honeypots', 0),
        "total_logs": counts.get('total_logs', 0)
    })

@app.route('/api/dashboard')
def dashboard_data():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session.get('uid')
    honeypots_result = db.list_honeypots(uid)
    honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
    total_honeypots = len(honeypots_data)
    active_honeypots = sum(1 for hp in honeypots_data.values() if hp.get('is_active', False))
    total_logs = sum(len(hp.get('logs', [])) for hp in honeypots_data.values())

    all_logs = []
    protocol_count = {}
    honeypot_cards = []

    for hp_id, hp in honeypots_data.items():
        honeypot_cards.append({
            "honeypot_id": hp_id,
            "name": hp.get('name', hp_id),
            "description": hp.get('description'),
            "is_active": bool(hp.get('is_active')),
            "active_protocols": hp.get('active_protocols', []),
            "logs_count": len(hp.get('logs', [])),
            "last_active": hp.get('last_active')
        })
        for protocol in hp.get('active_protocols', []):
            protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
        for log in hp.get('logs', []):
            log_copy = dict(log)
            log_copy['honeypot_id'] = hp_id
            log_copy['honeypot_name'] = hp.get('name', hp_id)
            all_logs.append(log_copy)

    all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_logs = all_logs[:10]

    scans_count = sum(1 for log in all_logs if log.get('status') == 'scan')
    infiltrations_count = sum(1 for log in all_logs if log.get('status') == 'infiltration')

    return jsonify({
        "success": True,
        "stats": {
            "total_honeypots": total_honeypots,
            "active_honeypots": active_honeypots,
            "total_logs": total_logs,
            "scans_count": scans_count,
            "infiltrations_count": infiltrations_count
        },
        "protocol_count": protocol_count,
        "recent_logs": recent_logs,
        "honeypots": honeypot_cards
    })

@app.route('/settings')
def settings():
    return redirect(url_for('auth.settings'))

if __name__ == '__main__':
    # Use socketio.run() instead of app.run() to enable WebSocket support
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)