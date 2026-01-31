# Honeypot System - File Guide

Quick reference for all honeypot-related files and their purposes.

## Core Application Files

### `honeypot_client.py` ⭐ Main Client
Complete Python application that runs on honeypot-enabled systems.

**Key Classes**:
- `HoneypotConfig` - Configuration management
- `ServerCommunicator` - Server communication
- `HoneypotManager` - Honeypot instance management
- `HoneypotClient` - Main application orchestrator

**Entry Point**: Used by client systems running honeypots

---

### `routes.py` ⭐ Server API Endpoints
Flask blueprint providing 9 RESTful API endpoints.

**Key Endpoints**:
- `POST /honeypot/create` - Create new honeypot
- `GET /honeypot/install.sh` - Download install script
- `POST /honeypot/api/register` - Client registration
- `POST /honeypot/api/heartbeat` - Keep-alive signals
- `POST /honeypot/api/logs` - Receive attack logs
- `GET /honeypot/api/config` - Configuration updates

**Usage**: Automatically registered in Flask app

---

### `install.sh` ⭐ Installation Script
Bash script that automates honeypot client deployment.

**Responsibilities**:
- System package installation
- Directory and user creation
- Python environment setup
- Systemd service configuration
- Configuration file creation

**Usage**: `bash install.sh --server-url <url> --honeypot-id <id> --api-key <key>`

---

### `__init__.py`
Package initialization file (mostly empty).

**Purpose**: Makes honeypot a Python package for importing

---

## Documentation Files

### `README_NEW.md` 📖 Comprehensive Overview
Complete architecture and usage documentation.

**Covers**:
- System overview and architecture
- Server-side components
- Client-side components
- Installation methods
- Configuration details
- Supported honeypot types
- Log format specification
- Troubleshooting guide
- Security considerations

**Audience**: Developers and system administrators

---

### `DEPLOYMENT.md` 🚀 Deployment Guide
Step-by-step deployment and operations guide.

**Covers**:
- Quick start for end users
- Installation process breakdown
- Server API endpoint details
- Client architecture
- Network requirements
- Monitoring and logging
- Troubleshooting procedures
- Advanced configuration
- Performance considerations

**Audience**: DevOps engineers and operators

---

### `IMPLEMENTATION.md` 📋 Implementation Summary
Technical implementation details and architecture.

**Covers**:
- What was built (feature summary)
- Files created and their purposes
- Integration points in main app
- How the system works (user flow)
- Key features list
- Default honeypots
- Security safeguards
- Directory structure
- Configuration details
- API authentication
- Next steps for enhancement
- Testing procedures
- Deployment checklist

**Audience**: Developers and architects

---

### `CONFIG_REFERENCE.md` ⚙️ Configuration Reference
Complete configuration documentation.

**Covers**:
- Configuration file location and format
- Required parameters (SERVER_URL, HONEYPOT_ID, API_KEY)
- Optional parameters
- Advanced parameters (client behavior, honeypot config, security)
- Default configuration template
- Safe modification procedures
- Troubleshooting configuration issues
- Environment variables
- Backup and restore procedures
- Security notes
- Performance tuning
- Configuration updates via server

**Audience**: System administrators and operators

---

### `API_TESTING.md` 🧪 Testing Guide
API testing and debugging guide with examples.

**Covers**:
- curl examples for all endpoints
- Session authentication
- Manual API testing procedures
- Expected responses with status codes
- Automated testing script
- Performance testing methods
- Load testing with Apache Bench
- Debugging techniques
- Integration testing examples
- Error responses and handling

**Audience**: QA engineers and developers

---

### `README.md` (original placeholder)
Original placeholder file in the honeypot directory.

---

## Integration Files

### `/main.py` (Modified)
Main Flask application file.

**Changes Made**:
- Added import: `from honeypot.routes import honeypot_bp`
- Added: `app.register_blueprint(honeypot_bp)`

**Effect**: Registers all honeypot routes with Flask app

---

### `/requirements.txt` (Modified)
Python dependencies file.

**Packages Added**:
- `honeypots==0.36` - Honeypot framework
- `requests==2.31.0` - HTTP client library
- `pyyaml==6.0` - YAML parser

**Update Command**: `pip install -r requirements.txt`

---

## File Organization

```
honeypot/
├── Core Application
│   ├── honeypot_client.py          ⭐ Main client application
│   ├── routes.py                   ⭐ Flask API endpoints
│   ├── install.sh                  ⭐ Installation script
│   └── __init__.py                 Package init
│
├── Documentation
│   ├── README_NEW.md               📖 Architecture overview
│   ├── DEPLOYMENT.md               🚀 Deployment guide
│   ├── IMPLEMENTATION.md           📋 Implementation summary
│   ├── CONFIG_REFERENCE.md         ⚙️ Configuration docs
│   ├── API_TESTING.md              🧪 Testing guide
│   └── README.md                   Original placeholder
│
└── Related (at root level)
    ├── main.py                     Main Flask app (modified)
    └── requirements.txt             Python packages (modified)
```

## Quick Navigation

### I want to...

**Deploy a honeypot to a system**
→ See `DEPLOYMENT.md` → "Quick Start" section

**Understand how the system works**
→ See `IMPLEMENTATION.md` → "How It Works" section

**Configure the honeypot client**
→ See `CONFIG_REFERENCE.md` → "Configuration Parameters" section

**Test the API endpoints**
→ See `API_TESTING.md` → "Testing Examples" section

**Debug connection issues**
→ See `CONFIG_REFERENCE.md` → "Troubleshooting Configuration" section

**View honeypot logs on client system**
→ See `DEPLOYMENT.md` → "Monitoring and Logs" section

**Modify client behavior**
→ See `honeypot_client.py` → Modify classes and methods

**Add new API endpoints**
→ See `routes.py` → Add new route functions

**Customize installation process**
→ See `install.sh` → Modify bash script

---

## Development Workflow

### 1. To Start Flask App
```bash
cd /workspaces/FlaskAuthSystem
python main.py
```

### 2. To Test APIs
```bash
# See API_TESTING.md for curl examples
curl https://localhost/honeypot/api/config
```

### 3. To Deploy Client
```bash
# See DEPLOYMENT.md for deployment guide
bash install.sh --server-url <url> --honeypot-id <id> --api-key <key>
```

### 4. To Monitor Client
```bash
sudo journalctl -u honeypot -f
```

---

## Key Statistics

- **Code Files**: 3 (routes.py, honeypot_client.py, install.sh)
- **Documentation**: 6 comprehensive guides
- **API Endpoints**: 9 total
- **Default Honeypots**: 6 protocols (SSH, HTTP, HTTPS, FTP, Telnet, SMTP)
- **Configuration Parameters**: 20+ options
- **Python Classes**: 4 main classes in client
- **Package Dependencies**: 3 new packages added

---

## Support References

### Most Important Files to Read

1. **New to the system?**
   - Start with `IMPLEMENTATION.md`

2. **Want to deploy?**
   - Read `DEPLOYMENT.md`

3. **Need configuration help?**
   - Reference `CONFIG_REFERENCE.md`

4. **Testing APIs?**
   - Use `API_TESTING.md`

5. **Debugging issues?**
   - Check `README_NEW.md` troubleshooting section

6. **Understanding architecture?**
   - Study `honeypot_client.py` source code

---

## Version Info

- **System**: Flask Honeypot Management System
- **Version**: 1.0
- **Date**: January 31, 2026
- **Status**: Complete implementation with full documentation

---

## Next Steps

1. ✅ Code implementation complete
2. ✅ Documentation complete
3. ⏳ Install dependencies: `pip install -r requirements.txt`
4. ⏳ Test Flask app: `python main.py`
5. ⏳ Create honeypot via UI
6. ⏳ Deploy to test system
7. ⏳ Monitor and adjust as needed

See `IMPLEMENTATION.md` → "Deployment Checklist" for full verification steps.
