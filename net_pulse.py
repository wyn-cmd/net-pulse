# NetPulse network monitoring tool

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import psutil

__version__ = "0.1.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("NetPulse")


# Converts raw bytes into a human-readable string with units
def format_bytes(size: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


# Loads config from JSON, falling back to defaults if missing or invalid
def load_config(config_path: str) -> Dict[str, Any]:
    defaults = {
        "check_interval_seconds": 5,
        "alert_on_unknown_ports": True,
        "monitored_ports": [80, 443, 22, 53],
        "log_file": "net_events.json",
    }

    if not os.path.exists(config_path):
        return defaults

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return {**defaults, **json.load(f)}
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load config from %s: %s. Using defaults.", config_path, e)
        return defaults


# Retrieves active network connections with status ESTABLISHED or LISTEN
def get_active_connections() -> List[Dict[str, Any]]:
    connections: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("ESTABLISHED", "LISTEN"):
                continue

            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None

            process_name = "unknown"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            connections.append({
                "timestamp": time.time(),
                "status": conn.status,
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "pid": conn.pid,
                "process": process_name,
            })
    except psutil.AccessDenied:
        logger.error("Insufficient permissions to access network connection information.")
    except Exception as e:
        logger.error("Unexpected error retrieving connections: %s", e)

    return connections


# Appends a network event entry to the JSONL log file
def log_event(log_file: str, event: Dict[str, Any]) -> None:
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        logger.error("Could not write to log file %s: %s", log_file, e)


# Extracts the integer port out of a "host:port" address, or None when the
# address is not in that shape (for example the "unknown" placeholder used
# when a connection has no local address at all).
def _local_port(local_addr: Optional[str]) -> Optional[int]:
    if not local_addr or ":" not in local_addr:
        return None
    try:
        return int(local_addr.rsplit(":", 1)[1])
    except ValueError:
        return None


# Coerces the monitored_ports config value into a set of ports, logging and
# falling back to an empty set when the config carries the wrong JSON type.
def _monitored_ports_set(raw_monitored_ports: Any) -> Set[int]:
    if isinstance(raw_monitored_ports, list):
        return set(raw_monitored_ports)
    logger.error(
        "monitored_ports in the config must be a list, got %s. Using an empty set.",
        type(raw_monitored_ports).__name__,
    )
    return set()


def main() -> None:
    parser = argparse.ArgumentParser(description="NetPulse network connection monitor")
    parser.add_argument("--interval", type=int, help="Check interval in seconds")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--log", type=str, help="Path to JSON log file")
    parser.add_argument("--version", action="version", version=f"NetPulse {__version__}")
    args = parser.parse_args()

    config = load_config(args.config)
    
    interval = args.interval if args.interval is not None else config.get("check_interval_seconds", 5)
    log_file = args.log if args.log is not None else config.get("log_file", "net_events.json")
    alert_on_unknown_ports = config.get("alert_on_unknown_ports", True)
    monitored_ports = _monitored_ports_set(config.get("monitored_ports", []))

    logger.info("Starting NetPulse monitor. Logging to %s...", log_file)
    
    seen_conns: Set[Tuple[str, Optional[str], str, Optional[int]]] = set()

    try:
        while True:
            for c in get_active_connections():
                conn_key = (c["local_addr"], c["remote_addr"], c["status"], c["pid"])
                if conn_key not in seen_conns:
                    seen_conns.add(conn_key)
                    local_port = _local_port(c["local_addr"])
                    is_unknown_port = (
                        alert_on_unknown_ports
                        and local_port is not None
                        and local_port not in monitored_ports
                    )
                    c["unknown_port"] = is_unknown_port
                    log_event(log_file, c)
                    if is_unknown_port:
                        logger.warning(
                            "Unmonitored port: %s (PID %s) %s -> %s [%s]",
                            c["process"],
                            c["pid"],
                            c["local_addr"],
                            c["remote_addr"],
                            c["status"],
                        )
                    else:
                        logger.info(
                            "New connection: %s (PID %s) %s -> %s [%s]",
                            c["process"],
                            c["pid"],
                            c["local_addr"],
                            c["remote_addr"],
                            c["status"],
                        )
            
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Stopping NetPulse.")
        sys.exit(0)
    except Exception as e:
        logger.critical("Fatal error in monitor loop: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()