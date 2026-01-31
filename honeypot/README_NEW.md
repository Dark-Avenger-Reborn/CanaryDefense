# Honeypot Client System

This directory contains the honeypot client code and installation infrastructure for the Flask Authentication System.

## Overview

The honeypot system allows users to deploy lightweight honeypot instances on remote systems. These honeypots detect and log attack attempts, then communicate the results back to the central server.

## Architecture

### Server-Side Components

#### Routes (`routes.py`)
- **`/honeypot/create`** - Create a new honeypot instance and generate credentials
- **`/honeypot/install.sh`** - Download the installation script
- **`/honeypot/api/register`** - Register a honeypot client with the server
- **`/honeypot/api/heartbeat`** - Receive keepalive signals from clients
- **`/honeypot/api/logs`** - Receive attack logs from clients
- **`/honeypot/api/config`** - Push configuration updates to clients

### Client-Side Components

#### Installation Script (`install.sh`)
- Automates the deployment process
- Creates necessary directories and users
- Installs Python dependencies using the honeypots package
- Sets up systemd service for auto-start
- Configures logging

#### Client Application (`honeypot_client.py`)
- **HoneypotConfig** - Manages configuration from files
- **ServerCommunicator** - Handles all server communication
- **HoneypotManager** - Manages multiple honeypot instances
- **HoneypotClient** - Main application orchestrator

## Usage

### Creating a Honeypot

1. User clicks "Create Honeypot" in the dashboard
2. Server generates:
   - Unique honeypot ID
   - API key for authentication
   - Installation URL and command

### Installation on Remote System

Users can install the honeypot client using one of these methods:

#### Method 1: Direct URL (Recommended)
```bash
wget https://your-domain.com/honeypot/install.sh -O /tmp/install.sh && sudo bash /tmp/install.sh --server-url https://your-domain.com --honeypot-id abc123def --api-key your_api_key
```

#### Method 2: Piped Install
```bash
curl https://your-domain.com/honeypot/install.sh | sudo bash -s -- --server-url https://your-domain.com --honeypot-id abc123def --api-key your_api_key
```

### How It Works

1. **Installation Phase**
   - Script runs with root privileges
   - Creates `/opt/honeypot` directory structure
   - Creates dedicated `honeypot` user
   - Installs Python 3 and required packages
   - Copies client code and configuration
   - Creates systemd service

2. **Runtime Phase**
   - Client starts via systemd service
   - Registers with central server
   - Starts default honeypot instances (SSH, HTTP, FTP, etc.)
   - Sends heartbeats every 5 minutes
   - Logs attacks and sends to server
   - Receives configuration updates from server

3. **Communication Protocol**
   - All requests use Bearer token authentication
   - Honeypot ID included in `X-Honeypot-ID` header
   - JSON payloads with ISO 8601 timestamps
   - Retry logic with exponential backoff

## Configuration

The client reads configuration from `/opt/honeypot/config/honeypot.conf`:

```
SERVER_URL=https://your-domain.com
HONEYPOT_ID=abc123def
API_KEY=your_api_key
LOG_DIR=/opt/honeypot/logs
CONFIG_DIR=/opt/honeypot/config
HOSTNAME=system_hostname
PLATFORM=Linux
```

## Honeypot Types Supported

The system uses the `honeypots` package which supports:
- SSH Honeypot (Port 22)
- HTTP Honeypot (Port 80)
- HTTPS Honeypot (Port 443)
- FTP Honeypot (Port 21)
- Telnet Honeypot (Port 23)
- SMTP Honeypot (Port 25)
- And more...

## Log Format

Logs captured by honeypots include:

```json
{
  "timestamp": "2026-01-31T12:00:00.000000",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_port": 22,
  "protocol": "ssh",
  "attack_type": "brute_force_attempt",
  "status": "infiltration",
  "payload": "SSH_VERSION_STRING",
  "raw_data": {...}
}
```

## Logs and Monitoring

### View Client Logs
```bash
# On the honeypot system
journalctl -u honeypot -f  # Follow logs in real-time
journalctl -u honeypot -n 50  # Show last 50 lines
```

### View Stored Logs
```bash
# Logs are stored locally
ls -la /opt/honeypot/logs/
```

## Security Considerations

1. **API Keys**: Treat as sensitive - never commit to version control
2. **HTTPS**: Always use HTTPS for server communication
3. **Firewall**: Honeypots should be on internet-facing systems or test networks
4. **Isolation**: Consider running on isolated VMs or containers
5. **Permissions**: Install script requires root, but client runs as unprivileged user

## Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status honeypot

# View detailed logs
sudo journalctl -u honeypot -n 100

# Restart service
sudo systemctl restart honeypot
```

### Connection Issues
- Verify `SERVER_URL` is reachable and uses HTTPS
- Check firewall rules on both sides
- Verify API key is correct
- Ensure honeypot ID matches server records

### Permission Errors
- Ensure honeypot user owns `/opt/honeypot` directory
- Check systemd service is running as `honeypot` user
- Verify ports are not already in use

## Future Enhancements

- [ ] Support for custom honeypot types
- [ ] Dynamic port assignment
- [ ] Advanced filtering and alerting
- [ ] Machine learning-based attack classification
- [ ] Multi-tier honeypot networks
- [ ] Live attack visualization dashboard

## Package Dependencies

- **honeypots** - Honeypot framework
- **requests** - HTTP client for server communication
- **pyyaml** - Configuration file parsing
- **python3** - Runtime environment

## License

This honeypot system is part of the Flask Authentication System project.
