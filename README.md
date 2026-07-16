# Honeypot Control System

Web-based honeypot management platform built with Flask, Socket.IO, and SQLite.

It lets users create and manage honeypots, monitor logs in real time, collaborate with other users, configure alerts, and review full activity history.

## Features

- Account auth flows (create account, login, reset password, settings)
- Honeypot fleet management (create, start, stop, delete)
- Real-time status and telemetry via Socket.IO
- Protocol-level log collection and dashboard summaries
- Alerting system for suspicious activity and honeypot down events
- Collaboration and shared honeypot access
- Activity history page with search, filters, and pagination
- Theme-aware UI with server-rendered templates

## Tech Stack

- Python 3
- Flask
- Flask-SocketIO + Eventlet
- Flask-Limiter
- SQLite (local app data)
- Pyrebase4 (Firebase authentication)

## Project Structure

```text
main.py                     # Flask app entry point
requirements.txt            # Python dependencies
alerts/                     # Alert orchestration and email sender
auth/                       # Authentication routes and Firebase adapter
database/                   # SQLite-backed data layer + API routes
honeypot/                   # Honeypot API routes, install script, client
templates/                  # Jinja2 HTML templates
static/                     # CSS and JavaScript assets
config/                     # Branding and color config files
```

## Prerequisites

- Python 3.10+ (recommended)
- pip
- Linux host for honeypot client installation script
- Firebase project credentials for authentication

## Installation

1. Clone the repository and enter it:

```bash
git clone https://github.com/Dark-Avenger-Reborn/HoneypotSystemToBeNamed.git
cd HoneypotSystemToBeNamed
```

2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the repository root.

## Environment Variables

Set Firebase auth values in `.env`:

```env
API_KEY=
AUTH_DOMAIN=
DATABASE_URL=
PROJECT_ID=
STORAGE_BUCKET=
MESSAGING_SENDER_ID=
APP_ID=
```

Optional SMTP settings for email alerts:

```env
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_SENDER=
```

Optional public URL override (recommended behind reverse proxies and tunnels):

```env
BASE_URL=https://canarydefense.com
```

Optional alert batching delay (seconds):

```env
ALERT_DELAY_SECONDS=300
```

Optional honeypot-down alert noise controls:

```env
# Wait this long before sending a down alert (suppresses short reconnect blips)
HONEYPOT_DOWN_ALERT_GRACE_SECONDS=120

# Minimum seconds between down emails for the same honeypot
HONEYPOT_DOWN_ALERT_COOLDOWN_SECONDS=1800
```

## Running The App

Start the Flask-SocketIO server:

```bash
python main.py
```

Default local URL:

- `http://127.0.0.1:5000`

## Honeypot Client Install (Remote Host)

A helper installer is provided at `honeypot/install.sh`.

Example:

```bash
sudo bash honeypot/install.sh \
  --server-url http://YOUR_SERVER:5000 \
  --honeypot-id YOUR_HONEYPOT_ID \
  --map-ports
```

Notes:

- Native service ports are the default. `--map-ports` creates an iptables redirect script from the native ports to the backup high ports.
- Use `--no-map-ports` to use the backup ports directly when you already manage port mapping or cannot use the native ports.
- The installer fetches `honeypot_client.py` from your server and configures runtime files under `/opt/honeypot`.

## Activity History

The `/activity-history` page provides:

- Full management activity timeline
- Action filtering
- Free-text search
- Pagination and page size controls

## Security

### Built-in security controls

- Firebase-backed authentication is used for account creation, login, password reset, and account operations.
- Sensitive auth operations are rate-limited with `Flask-Limiter` (for example: login, account creation, password reset).
- Session data stores authenticated user context (`uid`, tokens) server-side in Flask session cookies.
- Honeypot and collaboration access checks are enforced in backend routes and database access methods.
- Alert emails support security visibility for suspicious activity and honeypot downtime.

### Production hardening checklist

- Run behind HTTPS only (reverse proxy with TLS) so session cookies and tokens are encrypted in transit.
- Set a stable, strong `SECRET_KEY` via environment variable in production instead of generating a new one on each start.
- Restrict network access to the app (firewall/security groups) and expose only required ports.
- Isolate honeypot client hosts from critical internal systems; treat them as high-risk surfaces.
- Protect `.env` and database files with strict file permissions and do not commit secrets.
- Configure SMTP credentials as secrets and use least-privilege mail accounts for alerting.
- Keep dependencies patched (`pip install -U` as part of maintenance) and monitor vulnerability advisories.

### Operational notes

- Restarting the app currently rotates runtime-generated secret keys, which invalidates existing sessions.
- Honeypot logs may contain attacker-controlled input; avoid rendering unescaped raw log content in custom views.
- For internet-exposed deployments, add a WAF/reverse-proxy rate limit layer in addition to app-level rate limits.

## Development Notes

- App secret keys are generated at runtime in `main.py`.
- Data is stored in `database/db.sqlite` (created automatically).
- Existing legacy JSON data can be migrated to SQLite on startup if `database/db.json` exists.

## License

This project is licensed under the terms in `LICENSE`.
