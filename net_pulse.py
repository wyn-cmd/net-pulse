import argparse
import json
import os
import sys
import time
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
import psutil

__version__ = "0.1.0"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("NetPulse")

def format_bytes(size: float) -> str:
    # Converts a raw byte count into a human-readable string
    # with appropriate units (B, KB, MB, GB).
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def load_config(config_path: str) -> Dict[str, Any]:
    """Loads configuration from a JSON file, falling back to defaults."""
    defaults = {
        "check_interval_seconds": 5,
        "alert_on_unknown_ports": True,
        "monitored_ports": [80, 443, 22, 53],
        "log_file": "net_events.json"
    }

    if not os.path.exists(config_path):
        return defaults

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return {**defaults, **config}
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load config from {config_path}: {e}. Using defaults.")
        return defaults

def get_active_connections() -> List[Dict[str, Any]]:
    """Retrieves active network connections with status 'ESTABLISHED' or 'LISTEN'."""
    connections: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status not in ('ESTABLISHED', 'LISTEN'):
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
                "process": process_name
            })
    except psutil.AccessDenied:
        logger.error("Insufficient permissions to access network connection information.")
    except Exception as e:
        logger.error(f"Unexpected error retrieving connections: {e}")
        
    return connections

def log_event(log_file: str, event: Dict[str, Any]) -> None:
    """Appends a network event to a JSONL log file."""
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        logger.error(f"Could not write to log file {log_file}: {e}")

def main() -> None:
    parser = argparse.ArgumentParser(description="NetPulse network connection monitor")
    parser.add_argument("--interval", type=int, help="Check interval in seconds")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--log", type=str, help="Path to JSON log file")
    parser.add_argument("--version", action="version", version=f"NetPulse {__version__}")
    args = parser.parse_args()

    config = load_config(args.config)
    
    # Priority: CLI argument > Config file > Default
    interval = args.interval if args.interval is not None else config.get("check_interval_seconds", 5)
    log_file = args.log if args.log is not None else config.get("log_file", "net_events.json")

    logger.info(f"Starting NetPulse monitor. Logging to {log_file}...")
    
    # Store unique connection signatures to prevent duplicate logging
    # within the current monitoring session.
    seen_conns: Set[Tuple[str, Optional[str], str, Optional[int]]] = set()

    try:
        while True:
            conns = get_active_connections()
            for c in conns:
                conn_key = (c["local_addr"], c["remote_addr"], c["status"], c["pid"])
                
                if conn_key not in seen_conns:
                    seen_conns.add(conn_key)
                    log_event(log_file, c)
                    logger.info(
                        f"New connection: {c['process']} (PID {c['pid']}) "
                        f"{c['local_addr']} -> {c['remote_addr']} [{c['status']}]"
                    )
            
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Stopping NetPulse.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error in monitor loop: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()