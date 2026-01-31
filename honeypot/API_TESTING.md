# Honeypot API Testing Guide

This guide provides examples for testing the honeypot system using `curl`.

## Prerequisites

```bash
# Install curl if needed
sudo apt-get install curl

# Set variables for reusability
API_KEY="your-api-key-here"
HONEYPOT_ID="abc123def"
SERVER="https://your-domain.com"
```

## 1. Create a Honeypot

Create a new honeypot instance (requires user to be logged in via Flask session).

### Using curl with session cookie

First, authenticate and get a session cookie:
```bash
# Login
curl -c cookies.txt \
  -d "email=user@example.com&password=password" \
  -X POST \
  https://your-domain.com/auth/login
```

Then create honeypot:
```bash
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Honeypot",
    "type": "default",
    "description": "Test honeypot deployment"
  }' \
  -X POST \
  https://your-domain.com/honeypot/create
```

**Expected Response** (201 Created):
```json
{
  "success": true,
  "honeypot_id": "abc123def456",
  "api_key": "550e8400-e29b-41d4-a716-446655440000",
  "install_url": "https://your-domain.com/honeypot/install.sh?id=abc123def456&key=550e8400-e29b-41d4-a716-446655440000",
  "install_command": "wget https://your-domain.com/honeypot/install.sh -O /tmp/install.sh && bash /tmp/install.sh --server-url https://your-domain.com --honeypot-id abc123def456 --api-key 550e8400-e29b-41d4-a716-446655440000",
  "server_url": "https://your-domain.com"
}
```

## 2. Download Installation Script

### Using wget
```bash
wget https://your-domain.com/honeypot/install.sh -O /tmp/install.sh
```

### Using curl
```bash
curl https://your-domain.com/honeypot/install.sh -o /tmp/install.sh
```

### With parameters (optional)
```bash
curl "https://your-domain.com/honeypot/install.sh?id=abc123def&key=550e8400" \
  -o /tmp/install.sh
```

## 3. Register Honeypot Client

This is called by the client automatically after installation. You can test it manually:

```bash
curl -X POST \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Honeypot-ID: abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "test-server-01",
    "platform": "Linux"
  }' \
  https://your-domain.com/honeypot/api/register
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "message": "Honeypot registered successfully",
  "honeypot_id": "abc123def456"
}
```

## 4. Send Heartbeat

Simulates the 5-minute keep-alive signal:

```bash
curl -X POST \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Honeypot-ID: abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "honeypot_id": "abc123def456",
    "timestamp": "2026-01-31T12:00:00.000000",
    "status": "online"
  }' \
  https://your-domain.com/honeypot/api/heartbeat
```

**Expected Response** (204 No Content):
```
[empty response body]
```

## 5. Submit Attack Log

Submit an attack event that was detected:

```bash
curl -X POST \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Honeypot-ID: abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "honeypot_id": "abc123def456",
    "log": {
      "timestamp": "2026-01-31T12:00:00.000000",
      "source_ip": "192.168.1.100",
      "source_port": 54321,
      "destination_port": 22,
      "protocol": "ssh",
      "attack_type": "brute_force_attempt",
      "payload": "SSH-2.0-OpenSSH_7.4",
      "raw_data": {
        "username": "admin",
        "password": "password"
      }
    },
    "timestamp": "2026-01-31T12:00:00.000000"
  }' \
  https://your-domain.com/honeypot/api/logs
```

**Expected Response** (201 Created):
```json
{
  "success": true,
  "message": "Log received successfully"
}
```

## 6. Get Configuration Updates

Client requests configuration changes from server:

```bash
curl -X GET \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Honeypot-ID: abc123def456" \
  https://your-domain.com/honeypot/api/config
```

**Expected Response** (200 OK):
```json
{
  "start_honeypots": [],
  "stop_honeypots": [],
  "update_interval": 300
}
```

## 7. List Honeypots

Get all honeypots for logged-in user:

```bash
curl -b cookies.txt \
  -X GET \
  https://your-domain.com/honeypot/list
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "honeypots": [
    {
      "id": "abc123def456",
      "name": "My Honeypot",
      "type": "default",
      "is_active": true,
      "created_at": "2026-01-31T11:00:00.000000",
      "last_seen": "2026-01-31T12:00:00.000000",
      "events_count": 5,
      "description": "Test honeypot deployment"
    }
  ],
  "total": 1
}
```

## 8. Get Honeypot Logs

Retrieve logs for a specific honeypot:

```bash
curl -b cookies.txt \
  -X GET \
  "https://your-domain.com/honeypot/abc123def456/logs?limit=10&offset=0"
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "honeypot_id": "abc123def456",
  "logs": [
    {
      "timestamp": "2026-01-31T12:00:00.000000",
      "source_ip": "192.168.1.100",
      "source_port": 54321,
      "destination_port": 22,
      "protocol": "ssh",
      "attack_type": "brute_force_attempt",
      "status": "infiltration",
      "payload": "SSH-2.0-OpenSSH_7.4",
      "raw_data": {}
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

## 9. Delete Honeypot

Remove a honeypot instance:

```bash
curl -b cookies.txt \
  -X DELETE \
  https://your-domain.com/honeypot/abc123def456/delete
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "message": "Honeypot deleted"
}
```

## Testing Script

Create an automated test script (`test_honeypot.sh`):

```bash
#!/bin/bash

# Configuration
API_KEY="550e8400-e29b-41d4-a716-446655440000"
HONEYPOT_ID="abc123def456"
SERVER="https://your-domain.com"
COOKIES="cookies.txt"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

test_endpoint() {
  local method=$1
  local endpoint=$2
  local data=$3
  local auth=$4
  
  echo "Testing: $method $endpoint"
  
  if [ -z "$auth" ]; then
    # Public endpoint
    curl -s -X "$method" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "$SERVER$endpoint"
  else
    # Authenticated endpoint
    curl -s -X "$method" \
      -H "Authorization: Bearer $API_KEY" \
      -H "X-Honeypot-ID: $HONEYPOT_ID" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "$SERVER$endpoint"
  fi
  
  echo -e "\n"
}

echo "=== Honeypot API Tests ==="

# Test register
echo -e "${GREEN}1. Testing Registration${NC}"
test_endpoint "POST" "/honeypot/api/register" \
  '{"hostname":"test-server","platform":"Linux"}' \
  "auth"

# Test heartbeat
echo -e "${GREEN}2. Testing Heartbeat${NC}"
test_endpoint "POST" "/honeypot/api/heartbeat" \
  '{"status":"online"}' \
  "auth"

# Test log submission
echo -e "${GREEN}3. Testing Log Submission${NC}"
test_endpoint "POST" "/honeypot/api/logs" \
  '{
    "log": {
      "timestamp":"2026-01-31T12:00:00",
      "source_ip":"192.168.1.100",
      "destination_port":22,
      "protocol":"ssh",
      "attack_type":"brute_force"
    }
  }' \
  "auth"

# Test config retrieval
echo -e "${GREEN}4. Testing Config Retrieval${NC}"
test_endpoint "GET" "/honeypot/api/config" "" "auth"

echo "=== Tests Complete ==="
```

Run the test script:
```bash
chmod +x test_honeypot.sh
./test_honeypot.sh
```

## Common HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 204 | No Content | Success with no response body |
| 400 | Bad Request | Invalid parameters |
| 401 | Unauthorized | Missing/invalid authentication |
| 404 | Not Found | Resource not found |
| 500 | Server Error | Internal server error |

## Error Responses

### 401 Unauthorized
```json
{
  "error": "Invalid authorization header"
}
```

### 400 Bad Request
```json
{
  "error": "Failed to create honeypot"
}
```

### 500 Server Error
```json
{
  "error": "Internal server error description"
}
```

## Performance Testing

Test with multiple requests:

```bash
# Send 100 heartbeats
for i in {1..100}; do
  curl -s -X POST \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Honeypot-ID: $HONEYPOT_ID" \
    https://your-domain.com/honeypot/api/heartbeat
done

echo "100 requests sent"
```

## Load Testing with Apache Bench

```bash
# Test with AB tool
ab -n 100 -c 10 \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Honeypot-ID: $HONEYPOT_ID" \
  https://your-domain.com/honeypot/api/heartbeat
```

## Debugging

### Verbose curl output
```bash
curl -v \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Honeypot-ID: $HONEYPOT_ID" \
  https://your-domain.com/honeypot/api/config
```

### Pretty print JSON response
```bash
curl -s \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Honeypot-ID: $HONEYPOT_ID" \
  https://your-domain.com/honeypot/api/config | python3 -m json.tool
```

### Save response to file
```bash
curl -s \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Honeypot-ID: $HONEYPOT_ID" \
  https://your-domain.com/honeypot/api/config \
  > response.json
```

## Integration Testing

### With Docker
```bash
# Run test inside container
docker run --rm curlimages/curl:latest \
  -X POST \
  -H "Authorization: Bearer $API_KEY" \
  https://your-domain.com/honeypot/api/heartbeat
```

### With Python
```python
import requests

api_key = "550e8400-e29b-41d4-a716-446655440000"
honeypot_id = "abc123def456"
server = "https://your-domain.com"

headers = {
    "Authorization": f"Bearer {api_key}",
    "X-Honeypot-ID": honeypot_id
}

# Send heartbeat
response = requests.post(
    f"{server}/honeypot/api/heartbeat",
    headers=headers,
    json={"status": "online"}
)

print(response.status_code)
print(response.json())
```
