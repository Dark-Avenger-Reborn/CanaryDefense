from flask import Flask, render_template, session, redirect, url_for, jsonify, request, Response
from pathlib import Path
from datetime import datetime
from auth.routes import auth_bp, is_logged_in
from auth.extensions import limiter

from database.routes import database_bp
from database.database_communicator import DatabaseCommunicator
from honeypot.routes import honeypot_bp, honeypot_api_bp
from honeypot.honeypot_to_db_routes import (
    socketio,
    authenticated_honeypots,
    recover_honeypots_after_abrupt_shutdown,
)
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


def get_public_base_url():
    configured_base_url = (os.getenv("BASE_URL") or "").strip().rstrip('/')
    if configured_base_url:
        return configured_base_url

    # Prefer reverse-proxy headers so port-forwarded/public hosts are reflected.
    forwarded_host = (request.headers.get('X-Forwarded-Host') or '').split(',')[0].strip()
    forwarded_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip()
    if forwarded_host:
        scheme = forwarded_proto or request.scheme or 'https'
        return f"{scheme}://{forwarded_host}".rstrip('/')

    return request.host_url.rstrip('/')


def load_brand_name():
    try:
        name = BRAND_NAME_FILE.read_text(encoding="utf-8").strip()
        return name or "Honeypot Control"
    except FileNotFoundError:
        return "Honeypot Control"


@app.context_processor
def inject_brand_name():
    return {
        "brand_name": load_brand_name(),
        "public_base_url": get_public_base_url()
    }


@app.route('/')
def index():
    if is_logged_in():
        uid = session.get('uid')
        
        # Get honeypots data
        honeypots_result = db.list_accessible_honeypots(uid)
        honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
        for hp_id, hp in honeypots_data.items():
            if hp.get("shared"):
                owner_profile = db.get_user_basic(hp.get("owner_uid"))
                if owner_profile.get("success"):
                    hp["owner_email"] = owner_profile.get("email")
                else:
                    hp["owner_email"] = "Unknown"
        
        # Calculate statistics
        stats_result = db.get_user_stats(uid)
        stats = stats_result.get('stats', {}) if stats_result['success'] else {}
        total_honeypots = len(honeypots_data)
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
        
        # Get actually connected honeypot IDs
        connected_honeypot_ids = {auth_info['honeypot_id'] for auth_info in authenticated_honeypots.values()}
        for hp_id, hp in honeypots_data.items():
            hp['is_live'] = bool(hp.get('is_active', False) and hp_id in connected_honeypot_ids)
        
        # Protocol distribution (only actually connected honeypots)
        protocol_count = {}
        for hp_id, hp in honeypots_data.items():
            if hp.get('is_active', False) and hp_id in connected_honeypot_ids:
                for protocol in hp.get('active_protocols', []):
                    protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
        
        # Attack type distribution for logs
        scans_count = sum(1 for log in all_logs if log.get('status') == 'scan')
        infiltrations_count = sum(1 for log in all_logs if log.get('status') == 'infiltration')
        
        activity_result = db.list_recent_activity(uid, limit=8)
        recent_activity = activity_result.get("activity", []) if activity_result.get("success") else []
        name_lookup = {hp_id: hp.get("name", hp_id) for hp_id, hp in honeypots_data.items()}
        for item in recent_activity:
            hp_id = item.get("honeypot_id")
            if hp_id:
                item["honeypot_name"] = name_lookup.get(hp_id, hp_id)

        return render_template('dashboard.html',
                             total_honeypots=total_honeypots,
                             active_honeypots=active_honeypots,
                             total_logs=total_logs,
                             recent_logs=recent_logs,
                     recent_activity=recent_activity,
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


@app.route('/robots.txt')
def robots_txt():
    site_root = get_public_base_url()
    robots_content = (
        "User-agent: *\n"
        "Allow: /\n"
        f"Sitemap: {site_root}/sitemap.xml\n"
    )
    return Response(robots_content, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = get_public_base_url()
    now = datetime.utcnow().strftime('%Y-%m-%d')
    pages = [
        {'loc': f'{base_url}/', 'changefreq': 'daily', 'priority': '1.0'},
        {'loc': f'{base_url}/honeypots', 'changefreq': 'weekly', 'priority': '0.8'},
        {'loc': f'{base_url}/login', 'changefreq': 'monthly', 'priority': '0.5'},
        {'loc': f'{base_url}/create_account', 'changefreq': 'monthly', 'priority': '0.5'},
    ]

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for page in pages:
        xml_parts.append(
            "<url>"
            f"<loc>{page['loc']}</loc>"
            f"<lastmod>{now}</lastmod>"
            f"<changefreq>{page['changefreq']}</changefreq>"
            f"<priority>{page['priority']}</priority>"
            "</url>"
        )
    xml_parts.append('</urlset>')

    return Response('\n'.join(xml_parts), mimetype='application/xml')

@app.route('/api/dashboard')
def dashboard_data():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session.get('uid')
    honeypots_result = db.list_accessible_honeypots(uid)
    honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
    total_honeypots = len(honeypots_data)
    active_honeypots = sum(1 for hp in honeypots_data.values() if hp.get('is_active', False))
    total_logs = sum(len(hp.get('logs', [])) for hp in honeypots_data.values())

    # Get actually connected honeypot IDs
    connected_honeypot_ids = {auth_info['honeypot_id'] for auth_info in authenticated_honeypots.values()}

    all_logs = []
    protocol_count = {}
    honeypot_cards = []

    for hp_id, hp in honeypots_data.items():
        is_live = bool(hp.get('is_active', False) and hp_id in connected_honeypot_ids)
        last_active_value = hp.get('last_active')
        owner_label = None
        if hp.get("shared"):
            owner_profile = db.get_user_basic(hp.get("owner_uid"))
            if owner_profile.get("success"):
                owner_label = owner_profile.get("email")
        honeypot_cards.append({
            "honeypot_id": hp_id,
            "name": hp.get('name', hp_id),
            "description": hp.get('description'),
            "is_active": bool(hp.get('is_active')),
            "is_live": is_live,
            "active_protocols": hp.get('active_protocols', []),
            "logs_count": len(hp.get('logs', [])),
            "last_active": last_active_value,
            "shared": bool(hp.get('shared')),
            "owner": owner_label
        })
        if hp.get('is_active', False) and hp_id in connected_honeypot_ids:
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

    activity_result = db.list_recent_activity(uid, limit=8)
    recent_activity = activity_result.get("activity", []) if activity_result.get("success") else []
    name_lookup = {hp_id: hp.get("name", hp_id) for hp_id, hp in honeypots_data.items()}
    for item in recent_activity:
        hp_id = item.get("honeypot_id")
        if hp_id:
            item["honeypot_name"] = name_lookup.get(hp_id, hp_id)

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
        "recent_activity": recent_activity,
        "honeypots": honeypot_cards
    })

@app.route('/settings')
def settings():
    return redirect(url_for('auth.settings'))

@app.route('/activity-history')
def activity_history():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    page = request.args.get('page', 1, type=int)
    action_filter = (request.args.get('action', '', type=str) or '').strip().lower().replace(' ', '_')
    query_filter = (request.args.get('q', '', type=str) or '').strip().lower()
    per_page = request.args.get('per_page', 20, type=int)
    if per_page not in (10, 20, 50):
        per_page = 20
    
    # Get all activity (using higher limit to show full history)
    activity_result = db.list_recent_activity(uid, limit=200)
    raw_activity = activity_result.get("activity", []) if activity_result.get("success") else []
    
    # Get honeypot names for display
    honeypots_result = db.list_accessible_honeypots(uid)
    honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
    name_lookup = {hp_id: hp.get("name", hp_id) for hp_id, hp in honeypots_data.items()}
    
    all_activity = []
    for item in raw_activity:
        entry = dict(item)
        action_key = (entry.get("action") or "unknown").strip().lower().replace(' ', '_')
        entry["action_key"] = action_key
        entry["action_label"] = action_key.replace('_', ' ').title()
        if "delete" in action_key:
            entry["action_style"] = "deleted"
        elif "create" in action_key:
            entry["action_style"] = "created"
        elif "activate" in action_key or "start" in action_key:
            entry["action_style"] = "activated"
        elif "deactivate" in action_key or "stop" in action_key:
            entry["action_style"] = "deactivated"
        elif "update" in action_key:
            entry["action_style"] = "updated"
        else:
            entry["action_style"] = "updated"

        hp_id = item.get("honeypot_id")
        if hp_id:
            entry["honeypot_name"] = name_lookup.get(hp_id, hp_id)
        all_activity.append(entry)

    action_options = sorted({
        (entry.get("action_key", "unknown"), entry.get("action_label", "Unknown"))
        for entry in all_activity
    }, key=lambda pair: pair[1])

    # Filter by normalized action key
    if action_filter:
        all_activity = [a for a in all_activity if a.get("action_key") == action_filter]

    # Filter by free text query
    if query_filter:
        all_activity = [
            a for a in all_activity
            if query_filter in (a.get("honeypot_name") or '').lower()
            or query_filter in (a.get("honeypot_id") or '').lower()
            or query_filter in (a.get("actor_username") or '').lower()
            or query_filter in (a.get("action_label") or '').lower()
        ]
    
    # Pagination
    total_items = len(all_activity)
    total_pages = (total_items + per_page - 1) // per_page
    if page < 1:
        page = 1
    if page > total_pages and total_pages > 0:
        page = total_pages
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_activity = all_activity[start_idx:end_idx]
    
    return render_template('activity_history.html',
                         activity=paginated_activity,
                         page=page,
                         total_pages=total_pages,
                         total_items=total_items,
                         action_filter=action_filter,
                         query_filter=query_filter,
                         action_options=action_options,
                         per_page=per_page)

if __name__ == '__main__':
    recover_honeypots_after_abrupt_shutdown()
    # Use socketio.run() instead of app.run() to enable WebSocket support
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)