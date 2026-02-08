import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
from datetime import datetime

import socketio
from honeypots import *

CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
    "server_url": "",
    "honeypot_id": "",
    "protocols": [],
    "auto_start": False,
    "heartbeat_interval": 30,
    "log_poll_interval": 2,
    "log_dir": "logs",
    "protocol_settings": {},
    "honeypots_config_path": "",
}

PROTOCOL_CLASS_MAP = {
    "ssh": ("QSSHServer", 22),
    "telnet": ("QTelnetServer", 23),
    "http": ("QHTTPServer", 80),
    "https": ("QHTTPSServer", 443),
    "ftp": ("QFTPServer", 21),
    "smtp": ("QSMTPServer", 25),
    "pop3": ("QPOP3Server", 110),
    "imap": ("QIMAPServer", 143),
    "ldap": ("QLDAPServer", 389),
    "mysql": ("QMySQLServer", 3306),
    "postgres": ("QPostgresServer", 5432),
    "mssql": ("QMSSQLServer", 1433),
    "oracle": ("QOracleServer", 1521),
    "redis": ("QRedisServer", 6379),
    "memcache": ("QMemcacheServer", 11211),
    "smb": ("QSMBServer", 445),
    "snmp": ("QSNMPServer", 161),
    "ntp": ("QNTPServer", 123),
    "irc": ("QIRCServer", 6667),
    "rdp": ("QRDPServer", 3389),
    "vnc": ("QVNCServer", 5900),
    "socks5": ("QSOCKS5Server", 1080),
    "http_proxy": ("QHTTPProxyServer", 8080),
    "https_proxy": ("QHTTPSProxyServer", 8443),
    "dns": ("QDNSServer", 53),
    "dhcp": ("QDHCPServer", 67),
    "elastic": ("QElasticServer", 9200),
    "ipp": ("QIPPServer", 631),
    "pjl": ("QPJLServer", 9100),
    "sip": ("QSIPServer", 5060),
}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class JsonLogCaptureHandler(logging.Handler):
    def __init__(self, log_dir):
        super().__init__(level=logging.INFO)
        self.log_dir = os.path.join(os.getcwd(), log_dir)
        os.makedirs(self.log_dir, exist_ok=True)

    def emit(self, record):
        try:
            message = record.getMessage()
            if not message or not message.strip().startswith("{"):
                return

            parsed = json.loads(message)
            if not isinstance(parsed, dict):
                return

            server_name = parsed.get("server")
            if not server_name:
                return

            protocol = server_name.replace("_server", "")
            filename = f"{protocol}.log"
            path = os.path.join(self.log_dir, filename)

            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(parsed) + "\n")
        except Exception:
            return


def _merge_defaults(defaults, data):
    merged = {}
    for key, value in defaults.items():
        if isinstance(value, dict):
            if isinstance(data.get(key), dict):
                merged[key] = _merge_defaults(value, data.get(key, {}))
            else:
                merged[key] = value
        else:
            merged[key] = data.get(key, value)
    for key, value in data.items():
        if key not in merged:
            merged[key] = value
    return merged


def load_or_create_config(config_path):
    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, sort_keys=True)
        logger.error(
            "Config file created at %s. Please fill in server_url and honeypot_id.",
            config_path,
        )
        return None

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return _merge_defaults(DEFAULT_CONFIG, data)





def _get_protocol_from_filename(filename):
    base = os.path.basename(filename)
    if "_" in base:
        return base.split("_")[0]
    if "." in base:
        return base.split(".")[0]
    return base


def _build_log_entry(protocol, line):
    line = line.strip()
    if not line:
        return None

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol": protocol,
        "action": "connection",
        "status": "unknown",
        "details": line,
    }

    if line.startswith("{"):
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                log_entry.update(parsed)
                if "timestamp" not in log_entry:
                    log_entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
        except Exception:
            pass

    return log_entry


class HoneypotClient:
    def __init__(self, config):
        self.config = config
        self.honeypot_id = config["honeypot_id"]
        self.server_url = config["server_url"].rstrip("/")
        self.protocols = config.get("protocols", [])
        self.auto_start = config.get("auto_start", False)
        self.log_dir = config.get("log_dir", "logs")
        self.heartbeat_interval = int(config.get("heartbeat_interval", 30))
        self.log_poll_interval = float(config.get("log_poll_interval", 2))
        self.protocol_settings = config.get("protocol_settings", {})
        self.honeypots_config_path = config.get("honeypots_config_path", "")

        self._setup_log_capture()

        self.honeypots = {}
        self.log_offsets = {}
        self.stop_event = threading.Event()
        self.authenticated = threading.Event()

        self.sio = socketio.Client(reconnection=True)
        self._register_socketio_handlers()

    def _setup_log_capture(self):
        root_logger = logging.getLogger()
        if not any(isinstance(handler, JsonLogCaptureHandler) for handler in root_logger.handlers):
            root_logger.addHandler(JsonLogCaptureHandler(self.log_dir))

    def _register_socketio_handlers(self):
        @self.sio.event
        def connect():
            logger.info("Connected to server")
            self.authenticated.clear()
            self._send_honeypot_connect()

        @self.sio.event
        def disconnect():
            logger.warning("Disconnected from server")
            self.authenticated.clear()

        @self.sio.on("start_command")
        def on_start_command(data):
            protocols = data.get("protocols") or self.protocols
            logger.info("Received start command for protocols: %s", protocols)
            self.start_protocols(protocols)

        @self.sio.on("stop_command")
        def on_stop_command(data):
            protocols = data.get("protocols")
            if protocols:
                logger.info("Received stop command for protocols: %s", protocols)
                self.stop_protocols(protocols)
            else:
                logger.info("Received stop command")
                self.stop_all_protocols()

        @self.sio.on("error")
        def on_error(data):
            logger.error("Server error: %s", data)

        @self.sio.on("log_ack")
        def on_log_ack(data):
            logger.debug("Log acknowledged: %s", data)

        @self.sio.on("batch_logs_ack")
        def on_batch_logs_ack(data):
            logger.debug("Batch logs acknowledged: %s", data)

        @self.sio.on("honeypot_connect_ack")
        def on_connect_ack(data):
            logger.info("Connect ack: %s", data)
            self.authenticated.set()
            if self.auto_start:
                self.start_protocols(self.protocols)

        @self.sio.on("honeypot_disconnect_ack")
        def on_disconnect_ack(data):
            logger.info("Disconnect ack: %s", data)

    def connect(self):
        self.sio.connect(self.server_url, transports=["websocket", "polling"])

    def _send_honeypot_connect(self):
        payload = {
            "honeypot_id": self.honeypot_id,
            "protocols": list(self.honeypots.keys()),
            "metadata": {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python": sys.version.split()[0],
            },
        }
        self.sio.emit("honeypot_connect", payload)

    def _send_honeypot_disconnect(self, reason):
        payload = {"honeypot_id": self.honeypot_id, "reason": reason}
        self.sio.emit("honeypot_disconnect", payload)

    def start_protocols(self, protocols):
        for protocol in protocols:
            self.start_protocol(protocol)

    def start_protocol(self, protocol):
        if protocol in self.honeypots:
            return

        class_name, default_port = PROTOCOL_CLASS_MAP.get(protocol, (None, None))
        if not class_name:
            logger.warning("Unsupported protocol: %s", protocol)
            return

        server_class = globals().get(class_name)
        if not server_class:
            logger.warning("Server class not found for protocol: %s", protocol)
            return

        settings = self.protocol_settings.get(protocol, {})
        port = int(settings.get("port", default_port))
        username = settings.get("username", "test")
        password = settings.get("password", "test")

        kwargs = {"port": port}
        if username:
            kwargs["username"] = username
        if password:
            kwargs["password"] = password
        if self.honeypots_config_path:
            kwargs["config"] = self.honeypots_config_path

        try:
            honeypot = server_class(**kwargs)
            honeypot.run_server(process=True)
            self.honeypots[protocol] = honeypot
            logger.info("Started %s honeypot on port %s", protocol, port)
        except Exception as exc:
            logger.error("Failed to start %s honeypot: %s", protocol, exc)

    def stop_protocol(self, protocol):
        honeypot = self.honeypots.get(protocol)
        if not honeypot:
            return
        try:
            honeypot.kill_server()
            logger.info("Stopped %s honeypot", protocol)
        except Exception as exc:
            logger.error("Failed to stop %s honeypot: %s", protocol, exc)
        finally:
            self.honeypots.pop(protocol, None)

    def stop_protocols(self, protocols):
        for protocol in protocols:
            self.stop_protocol(protocol)

    def stop_all_protocols(self):
        for protocol in list(self.honeypots.keys()):
            self.stop_protocol(protocol)

    def start_background_tasks(self):
        log_thread = threading.Thread(target=self._watch_logs, daemon=True)
        heartbeat_thread = threading.Thread(target=self._send_heartbeats, daemon=True)
        log_thread.start()
        heartbeat_thread.start()

    def _watch_logs(self):
        logs_dir = os.path.join(os.getcwd(), self.log_dir)
        os.makedirs(logs_dir, exist_ok=True)

        while not self.stop_event.is_set():
            try:
                if not self.authenticated.is_set():
                    time.sleep(self.log_poll_interval)
                    continue
                for filename in os.listdir(logs_dir):
                    path = os.path.join(logs_dir, filename)
                    if not os.path.isfile(path):
                        continue

                    offset = self.log_offsets.get(path, 0)
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(offset)
                        lines = f.readlines()
                        self.log_offsets[path] = f.tell()

                    if not lines:
                        continue

                    protocol = _get_protocol_from_filename(filename)
                    for line in lines:
                        entry = _build_log_entry(protocol, line)
                        if not entry:
                            continue
                        self.sio.emit(
                            "honeypot_log",
                            {"log_entry": entry},
                        )
                time.sleep(self.log_poll_interval)
            except Exception as exc:
                logger.debug("Log watcher error: %s", exc)
                time.sleep(self.log_poll_interval)

    def _send_heartbeats(self):
        while not self.stop_event.is_set():
            try:
                if not self.authenticated.is_set():
                    time.sleep(self.heartbeat_interval)
                    continue
                self.sio.emit(
                    "honeypot_heartbeat",
                    {
                        "status": {"active_protocols": list(self.honeypots.keys())},
                    },
                )
            except Exception as exc:
                logger.debug("Heartbeat error: %s", exc)
            time.sleep(self.heartbeat_interval)

    def run(self):
        self.connect()
        self.start_background_tasks()
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown("Keyboard interrupt")

    def shutdown(self, reason):
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        try:
            self._send_honeypot_disconnect(reason)
        except Exception:
            pass
        self.stop_all_protocols()
        try:
            self.sio.disconnect()
        except Exception:
            pass


def main():
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    config = load_or_create_config(config_path)
    if not config:
        return

    missing = [
        key for key in ("server_url", "honeypot_id") if not config.get(key)
    ]
    if missing:
        logger.error(
            "Missing required config fields: %s. Please edit %s",
            missing,
            config_path,
        )
        return

    client = HoneypotClient(config)

    def _handle_signal(signum, frame):
        client.shutdown(f"signal {signum}")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    client.run()


if __name__ == "__main__":
    main()
