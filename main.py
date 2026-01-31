from flask import Flask, render_template, session, redirect, url_for
from auth.routes import auth_bp, is_logged_in
from auth.extensions import limiter
from database.routes import database_bp
from database.database_communicator import DatabaseCommunicator
from honeypot.routes import honeypot_bp

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
limiter.init_app(app)
app.register_blueprint(auth_bp)
app.register_blueprint(database_bp)
app.register_blueprint(honeypot_bp)
db = DatabaseCommunicator()


@app.route('/')
def index():
    if is_logged_in():
        uid = session.get('uid')
        
        # Get honeypots data
        honeypots_result = db.list_honeypots(uid)
        honeypots_data = honeypots_result.get('honeypots', {}) if honeypots_result['success'] else {}
        
        # Calculate statistics
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
    return render_template('index.html')

@app.route('/settings')
def settings():
    return redirect(url_for('auth.settings'))

if __name__ == '__main__':
    app.run(debug=True)