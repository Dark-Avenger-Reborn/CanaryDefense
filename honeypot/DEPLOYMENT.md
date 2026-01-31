# Honeypot Client Deployment Guide

## Quick Start

### For End Users

1. **In the Dashboard**: Click "Create Honeypot"
2. **Configure**: Enter name, type, and description
3. **Install**: Copy the installation command provided
4. **Deploy**: Run on your target system with `sudo`

Example command:
```bash
sudo bash /tmp/install.sh --server-url https://your-domain.com --honeypot-id abc123def --api-key your_api_key
```

Or using curl:
```bash
curl https://your-domain.com/honeypot/install.sh | sudo bash -s -- --server-url https://your-domain.com --honeypot-id abc123def --api-key your_api_key
```

## Installation Process Breakdown

### Step 1: Initial Setup
```bash
# Script creates directory structure
/opt/honeypot/
├── config/          # Configuration files
├── logs/            # Local honeypot logs
└── venv/            # Python virtual environment
```

### Step 2: Dependencies
- Updates system packages
- Installs Python 3, pip, and venv
- Creates dedicated `honeypot` user
- Installs Python packages in isolated environment

### Step 3: Configuration
- Creates `/opt/honeypot/config/honeypot.conf` with:
  - Server URL
  - Honeypot ID
  - API Key
  - System information

### Step 4: Service Setup
- Creates `/etc/systemd/system/honeypot.service`
- Enables systemd service (auto-start on reboot)
- Starts the honeypot client

## Server-Side Integration

The server provides several endpoints for the honeypot client:

### 1. Create Honeypot
**Endpoint**: `POST /honeypot/create`
**Authentication**: User session

**Request**:
```json
{
  "name": "My Honeypot",
  "type": "default",
  "description": "Testing honeypot deployment"
}
```

**Response**:
```json
{
  "success": true,
  "honeypot_id": "abc123def",
  "api_key": "uuid-token-string",
  "install_url": "https://domain.com/honeypot/install.sh?id=abc123def&key=api-key",
  "install_command": "wget ... | bash"
}
```

### 2. Install Script Download
**Endpoint**: `GET /honeypot/install.sh`
**Parameters**: 
- `id` - Honeypot ID (optional, for validation)
- `key` - API Key (optional, for validation)

### 3. Client Registration
**Endpoint**: `POST /honeypot/api/register`
**Authentication**: Bearer token

**Request**:
```json
{
  "hostname": "production-server-01",
  "platform": "Linux"
}
```

### 4. Heartbeat
**Endpoint**: `POST /honeypot/api/heartbeat`
**Frequency**: Every 5 minutes
**Authentication**: Bearer token

**Purpose**: Confirms honeypot client is still running

### 5. Log Submission
**Endpoint**: `POST /honeypot/api/logs`
**Authentication**: Bearer token

**Request**:
```json
{
  "log": {
    "timestamp": "2026-01-31T12:00:00",
    "source_ip": "192.168.1.100",
    "source_port": 54321,
    "destination_port": 22,
    "protocol": "ssh",
    "attack_type": "brute_force",
    "payload": "SSH-2.0-OpenSSH_7.4",
    "raw_data": {}
  }
}
```

### 6. Config Updates
**Endpoint**: `GET /honeypot/api/config`
**Authentication**: Bearer token

**Purpose**: Retrieve any configuration changes from server

## Client-Side Architecture

### Configuration Manager
Reads from `/opt/honeypot/config/honeypot.conf`
- Simple key=value format
- Loaded on startup
- Can be updated via server

### Server Communicator
Handles all HTTP communication with server
- Uses Bearer token authentication
- Sends honeypot ID in X-Honeypot-ID header
- Implements error handling and retries
- JSON request/response format

### Honeypot Manager
Manages multiple honeypot instances
- Starts/stops honeypots as needed
- Captures events from honeypots
- Routes events to server

### Client Application
Main orchestrator
- Initializes components
- Starts default honeypots
- Runs main event loop
- Handles graceful shutdown

## Network Requirements

### Outbound Connectivity
- Client → Server on HTTPS (port 443 recommended)
- Must support TLS/SSL connections

### Inbound Ports (on honeypot client)
- Port 22 (SSH)
- Port 80 (HTTP)
- Port 443 (HTTPS)
- Port 21 (FTP)
- Port 23 (Telnet)
- Port 25 (SMTP)
- Additional ports as configured

*Note: These ports should be accessible from the internet for effective honeypoting*

## Monitoring and Logs

### Server-Side Monitoring
- Dashboard shows online/offline status
- Displays recent attack logs
- Shows attack statistics
- Lists all deployed honeypots

### Client-Side Logs
View logs on the honeypot system:
```bash
# Real-time log stream
sudo journalctl -u honeypot -f

# Show last 50 lines
sudo journalctl -u honeypot -n 50

# Show logs from last hour
sudo journalctl -u honeypot --since "1 hour ago"

# Export logs
sudo journalctl -u honeypot -o json > honeypot-logs.json
```

### Local Log Files
```bash
# Honeypot-specific logs
ls -la /opt/honeypot/logs/

# Configuration file
cat /opt/honeypot/config/honeypot.conf
```

## Troubleshooting

### Service Won't Start

Check the service status:
```bash
sudo systemctl status honeypot
sudo systemctl start honeypot
```

View detailed logs:
```bash
sudo journalctl -u honeypot -n 100 --no-pager
```

Check configuration:
```bash
cat /opt/honeypot/config/honeypot.conf
```

### Can't Connect to Server

1. **Test connectivity**:
   ```bash
   curl -I https://your-server-domain.com/honeypot/install.sh
   ```

2. **Check firewall**:
   ```bash
   sudo ufw status
   sudo iptables -L -n
   ```

3. **Verify configuration**:
   ```bash
   cat /opt/honeypot/config/honeypot.conf
   ```

4. **Test DNS**:
   ```bash
   nslookup your-server-domain.com
   ```

### Ports Already in Use

Check what's using the ports:
```bash
sudo lsof -i :22
sudo lsof -i :80
sudo lsof -i :443
```

The script will skip ports already in use, but honeypots won't start on those ports.

### Permission Denied

Ensure honeypot directory ownership:
```bash
sudo ls -la /opt/honeypot/
sudo chown -R honeypot:honeypot /opt/honeypot/
```

## Security Best Practices

1. **API Keys**
   - Keep API keys confidential
   - Regenerate if compromised
   - Don't share installation commands publicly

2. **Network Isolation**
   - Deploy honeypots on isolated networks when possible
   - Use VMs or containers for safety
   - Monitor honeypot traffic separately

3. **HTTPS Only**
   - Always use HTTPS to server
   - Verify SSL certificates
   - Use strong TLS versions (1.2+)

4. **Log Review**
   - Regularly review attack logs
   - Look for patterns and trends
   - Alert on suspicious activities

5. **System Hardening**
   - Keep OS patched and updated
   - Use SELinux or AppArmor if available
   - Implement network segmentation

## Advanced Configuration

### Custom Honeypot Types

Modify the client to support custom honeypot types:
```python
# In honeypot_client.py
custom_honeypots = [
    ('custom_protocol', 9999, 'Custom Protocol Honeypot'),
]
```

### Dynamic Port Assignment

Request specific ports via server configuration:
```json
{
  "start_honeypots": [
    {"type": "ssh", "port": 2222, "name": "SSH Alt Port"}
  ]
}
```

### Alert Thresholds

Configure alert triggers in the server API:
```json
{
  "alerts": {
    "attack_rate": 10,  // attacks per minute
    "unique_ips": 5,    // unique IPs per hour
  }
}
```

## Uninstalling

To remove the honeypot client:

```bash
# Stop the service
sudo systemctl stop honeypot
sudo systemctl disable honeypot

# Remove service file
sudo rm /etc/systemd/system/honeypot.service
sudo systemctl daemon-reload

# Remove honeypot directory
sudo rm -rf /opt/honeypot

# Remove honeypot user
sudo userdel -r honeypot

# Remove logs
sudo rm -rf /var/log/honeypot
```

## Performance Considerations

- Honeypots consume minimal resources (50-100MB RAM per instance)
- Network traffic depends on attack volume
- Local logging is efficient and non-blocking
- Remote communication is batched and asynchronous

## Support and Debugging

For issues, check:
1. Service logs: `journalctl -u honeypot`
2. Configuration: `cat /opt/honeypot/config/honeypot.conf`
3. Connectivity: `ping` and `curl` tests
4. Port availability: `lsof -i` command
5. Directory permissions: `ls -la /opt/honeypot`
