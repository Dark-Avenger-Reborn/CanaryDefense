"""
Honeypot Client - Main Application
Manages honeypot instances and communicates with the server
"""

import os
import json
import time
import logging
import threading
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

try:
    from honeypots import run_honeypot
    HONEYPOTS_AVAILABLE = True
except ImportError:
    HONEYPOTS_AVAILABLE = False
    logger.warning("honeypots library not available. Install with: pip install honeypots")

def setup_logging(log_file: str = None):
    """Setup logging configuration"""
    if log_file:
        handlers = [
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    else:
        handlers = [logging.StreamHandler()]
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


class HoneypotConfig:
    """Manages honeypot configuration"""
    
    def __init__(self, config_file: str = '/opt/honeypot/config/honeypot.conf'):
        self.config_file = config_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            logger.warning(f"Config file not found: {self.config_file}, using defaults")
            return False
        
        try:
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        self.config[key.strip()] = value.strip()
            logger.info("Configuration loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return False
    
    def get(self, key: str, default: str = None) -> str:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def get_required(self, key: str) -> str:
        """Get required configuration value"""
        value = self.config.get(key)
        if not value:
            raise ValueError(f"Required config key missing: {key}")
        return value


class ServerCommunicator:
    """Handles communication with the server"""
    
    def __init__(self, server_url: str, honeypot_id: str):
        self.server_url = server_url.rstrip('/')
        self.honeypot_id = honeypot_id
        self.session = requests.Session()
        self.session.headers.update({
            'X-Honeypot-ID': honeypot_id,
            'User-Agent': 'HoneypotClient/1.0'
        })
    
    def register(self, config: Dict) -> bool:
        """Register honeypot with server"""
        try:
            endpoint = f"{self.server_url}/api/honeypot/register"
            payload = {
                'honeypot_id': self.honeypot_id,
                'hostname': config.get('hostname', ''),
                'platform': config.get('platform', ''),
                'status': 'online',
                'timestamp': datetime.now().isoformat()
            }
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("Successfully registered with server")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error registering with server: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to server"""
        try:
            endpoint = f"{self.server_url}/api/honeypot/heartbeat"
            payload = {
                'honeypot_id': self.honeypot_id,
                'timestamp': datetime.now().isoformat(),
                'status': 'online'
            }
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code in [200, 204]:
                logger.debug("Heartbeat sent successfully")
                return True
            else:
                logger.warning(f"Heartbeat failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error sending heartbeat: {e}")
            return False
    
    def send_log(self, log_entry: Dict) -> bool:
        """Send attack log to server"""
        try:
            endpoint = f"{self.server_url}/api/honeypot/logs"
            payload = {
                'honeypot_id': self.honeypot_id,
                'log': log_entry,
                'timestamp': datetime.now().isoformat()
            }
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code in [200, 201]:
                logger.info(f"Log sent successfully: {log_entry.get('attack_type', 'unknown')}")
                return True
            else:
                logger.warning(f"Failed to send log: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error sending log: {e}")
            return False
    
    def get_config_updates(self) -> Optional[Dict]:
        """Get configuration updates from server"""
        try:
            endpoint = f"{self.server_url}/api/honeypot/config"
            response = self.session.get(endpoint, timeout=10)
            
            if response.status_code == 200:
                logger.info("Retrieved config updates from server")
                return response.json()
            else:
                logger.debug(f"No config updates available: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error retrieving config: {e}")
            return None


class HoneypotManager:
    """Manages honeypot instances"""
    
    def __init__(self, config: HoneypotConfig, communicator: ServerCommunicator):
        self.config = config
        self.communicator = communicator
        self.running_honeypots: Dict[str, dict] = {}
        self.log_queue: List[Dict] = []
        self.lock = threading.Lock()
    
    def start_honeypot(self, hp_type: str, port: int, name: str = None) -> bool:
        """Start a honeypot instance"""
        try:
            hp_id = f"{hp_type}_{port}"
            
            if hp_id in self.running_honeypots:
                logger.warning(f"Honeypot {hp_id} is already running")
                return False
            
            logger.info(f"Starting {hp_type} honeypot on port {port}")
            
            # Run honeypot in a separate thread
            thread = threading.Thread(
                target=self._run_honeypot_thread,
                args=(hp_type, port, hp_id, name),
                daemon=True
            )
            thread.start()
            
            with self.lock:
                self.running_honeypots[hp_id] = {
                    'type': hp_type,
                    'port': port,
                    'name': name or hp_type,
                    'thread': thread,
                    'start_time': datetime.now(),
                    'status': 'running'
                }
            
            logger.info(f"Honeypot {hp_id} started successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error starting honeypot: {e}")
            return False
    
    def _run_honeypot_thread(self, hp_type: str, port: int, hp_id: str, name: str):
        """Run honeypot in a thread"""
        try:
            if not HONEYPOTS_AVAILABLE:
                logger.error(f"Cannot start honeypot {hp_id}: honeypots library not available")
                with self.lock:
                    if hp_id in self.running_honeypots:
                        self.running_honeypots[hp_id]['status'] = 'error'
                return
            
            def capture_callback(data):
                """Callback for honeypot events"""
                self.on_honeypot_event(data, hp_id)
            
            # Configure honeypot parameters
            log_dir = self.config.get('LOG_DIR', '/var/log/honeypot')
            honeypot_options = {
                'type': hp_type,
                'port': port,
                'interface': '0.0.0.0',
                'logs': log_dir,
            }
            
            # Run the honeypot (blocking call)
            run_honeypot(honeypot_options)
        
        except Exception as e:
            logger.error(f"Error in honeypot thread {hp_id}: {e}")
            with self.lock:
                if hp_id in self.running_honeypots:
                    self.running_honeypots[hp_id]['status'] = 'error'
    
    def on_honeypot_event(self, data: Dict, hp_id: str):
        """Handle honeypot event (attack detected)"""
        try:
            log_entry = {
                'honeypot_id': hp_id,
                'honeypot_instance': self.running_honeypots.get(hp_id, {}).get('name', hp_id),
                'attack_type': data.get('type', 'unknown'),
                'source_ip': data.get('source_ip', 'unknown'),
                'source_port': data.get('source_port', 'unknown'),
                'destination_port': data.get('destination_port', 'unknown'),
                'protocol': data.get('protocol', 'unknown'),
                'payload': data.get('payload', ''),
                'timestamp': datetime.now().isoformat(),
                'raw_data': data
            }
            
            # Add to queue for batch sending
            with self.lock:
                self.log_queue.append(log_entry)
            
            logger.info(f"Event captured: {log_entry['attack_type']} from {log_entry['source_ip']}")
            
            # Send immediately
            self.communicator.send_log(log_entry)
        
        except Exception as e:
            logger.error(f"Error handling honeypot event: {e}")
    
    def get_status(self) -> Dict:
        """Get status of all running honeypots"""
        with self.lock:
            status = {
                'timestamp': datetime.now().isoformat(),
                'total_honeypots': len(self.running_honeypots),
                'honeypots': {}
            }
            
            for hp_id, hp_info in self.running_honeypots.items():
                status['honeypots'][hp_id] = {
                    'name': hp_info['name'],
                    'type': hp_info['type'],
                    'port': hp_info['port'],
                    'status': hp_info['status'],
                    'uptime': (datetime.now() - hp_info['start_time']).total_seconds()
                }
            
            return status
    
    def stop_honeypot(self, hp_id: str) -> bool:
        """Stop a honeypot instance"""
        try:
            with self.lock:
                if hp_id not in self.running_honeypots:
                    logger.warning(f"Honeypot {hp_id} not found")
                    return False
                
                honeypot_info = self.running_honeypots[hp_id]
                honeypot_info['status'] = 'stopping'
            
            logger.info(f"Stopping honeypot {hp_id}")
            
            # Note: Since honeypot threads are daemon threads, they will stop when the main program exits
            # For immediate stopping, the honeypots library would need to support graceful shutdown
            
            with self.lock:
                del self.running_honeypots[hp_id]
            
            return True
        
        except Exception as e:
            logger.error(f"Error stopping honeypot: {e}")
            return False


class HoneypotClient:
    """Main honeypot client application"""
    
    def __init__(self):
        self.config = HoneypotConfig()
        self.communicator = ServerCommunicator(
            self.config.get_required('SERVER_URL'),
            self.config.get_required('HONEYPOT_ID')
        )
        self.manager = HoneypotManager(self.config, self.communicator)
        self.running = False
    
    def initialize(self) -> bool:
        """Initialize the honeypot client"""
        try:
            logger.info("Initializing honeypot client")
            
            # Setup logging
            log_file = self.config.get('LOG_FILE')
            setup_logging(log_file)
            
            # Create necessary directories
            log_dir = self.config.get('LOG_DIR', '/var/log/honeypot')
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            
            # Register with server
            config_dict = {
                'hostname': self.config.get('HOSTNAME', os.uname().nodename),
                'platform': self.config.get('PLATFORM', os.uname().sysname)
            }
            
            if not self.communicator.register(config_dict):
                logger.warning("Failed to register with server, continuing anyway")
            
            logger.info("Honeypot client initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error initializing honeypot client: {e}")
            return False
    
    def run(self):
        """Run the honeypot client"""
        try:
            logger.info("Starting honeypot client")
            
            if not self.initialize():
                logger.error("Failed to initialize honeypot client")
                return
            
            self.running = True
            
            # Start default honeypots (SSH, HTTP, FTP, etc.)
            self.start_default_honeypots()
            
            # Main loop
            heartbeat_interval = 300  # 5 minutes
            last_heartbeat = 0
            
            while self.running:
                try:
                    # Send heartbeat every 5 minutes
                    current_time = time.time()
                    if current_time - last_heartbeat >= heartbeat_interval:
                        self.communicator.send_heartbeat()
                        last_heartbeat = current_time
                    
                    # Check for configuration updates
                    updates = self.communicator.get_config_updates()
                    if updates:
                        self.apply_config_updates(updates)
                    
                    time.sleep(10)  # Check every 10 seconds
                
                except KeyboardInterrupt:
                    logger.info("Received interrupt signal")
                    break
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    time.sleep(5)
        
        finally:
            self.shutdown()
    
    def start_default_honeypots(self):
        """Start default honeypots"""
        default_honeypots = [
            ('dhcp', 67, 'DHCP Honeypot'),
            ('dns', 53, 'DNS Honeypot'),
            ('elastic', 9200, 'Elastic Honeypot'),
            ('ftp', 21, 'FTP Honeypot'),
            ('http_proxy', 8080, 'HTTP Proxy Honeypot'),
            ('https_proxy', 8443, 'HTTPS Proxy Honeypot'),
            ('http', 80, 'HTTP Honeypot'),
            ('https', 443, 'HTTPS Honeypot'),
            ('imap', 143, 'IMAP Honeypot'),
            ('ipp', 631, 'IPP Honeypot'),
            ('irc', 6667, 'IRC Honeypot'),
            ('ldap', 389, 'LDAP Honeypot'),
            ('memcache', 11211, 'Memcache Honeypot'),
            ('mssql', 1433, 'MSSQL Honeypot'),
            ('mysql', 3306, 'MySQL Honeypot'),
            ('ntp', 123, 'NTP Honeypot'),
            ('oracle', 1521, 'Oracle Honeypot'),
            ('pjl', 9100, 'PJL Honeypot'),
            ('pop3', 110, 'POP3 Honeypot'),
            ('postgres', 5432, 'Postgres Honeypot'),
            ('rdp', 3389, 'RDP Honeypot'),
            ('redis', 6379, 'Redis Honeypot'),
            ('sip', 5060, 'SIP Honeypot'),
            ('smb', 445, 'SMB Honeypot'),
            ('smtp', 25, 'SMTP Honeypot'),
            ('snmp', 161, 'SNMP Honeypot'),
            ('socks5', 1080, 'SOCKS5 Honeypot'),
            ('ssh', 22, 'SSH Honeypot'),
            ('telnet', 23, 'Telnet Honeypot'),
            ('vnc', 5900, 'VNC Honeypot'),
        ]
        
        for hp_type, port, name in default_honeypots:
            try:
                # Try to start honeypot, skip if port is already in use
                self.manager.start_honeypot(hp_type, port, name)
            except Exception as e:
                logger.warning(f"Could not start {hp_type} honeypot on port {port}: {e}")
    
    def apply_config_updates(self, updates: Dict):
        """Apply configuration updates from server"""
        try:
            # Handle new honeypots to start
            new_honeypots = updates.get('start_honeypots', [])
            for hp in new_honeypots:
                self.manager.start_honeypot(
                    hp.get('type'),
                    hp.get('port'),
                    hp.get('name')
                )
            
            # Handle honeypots to stop
            stop_honeypots = updates.get('stop_honeypots', [])
            for hp_id in stop_honeypots:
                self.manager.stop_honeypot(hp_id)
            
            logger.info("Configuration updates applied")
        
        except Exception as e:
            logger.error(f"Error applying config updates: {e}")
    
    def shutdown(self):
        """Shutdown the honeypot client"""
        logger.info("Shutting down honeypot client")
        self.running = False
        
        # Stop all honeypots
        honeypot_ids = list(self.manager.running_honeypots.keys())
        for hp_id in honeypot_ids:
            self.manager.stop_honeypot(hp_id)
        
        logger.info("Honeypot client stopped")


if __name__ == '__main__':
    client = HoneypotClient()
    client.run()
