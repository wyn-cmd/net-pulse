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

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Loads the configuration from a JSON file. If the file does not exist 
    or is invalid, returns default settings.

    Args:
        config_path (str): The path to the configuration JSON file.

    Returns:
        Dict[str, Any]: A dictionary containing configuration parameters.
    """
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
            # Merge defaults with loaded config to ensure all keys exist
            return {**defaults, **config}
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load config from {config_path}: {e}. Using defaults.")
        return defaults

def get_active_connections() -> List[Dict[str, Any]]:
    """
    Retrieves a list of all active network connections with status 
    'ESTABLISHED' or 'LISTEN'.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, where each dictionary 
        represents a connection with metadata (timestamp, status, addresses, PID, process).
    """
    connections: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ('ESTABLISHED', 'LISTEN'):
                remote_ip: Optional[str] = conn.raddr.ip if conn.raddr else None
                remote_port: Optional[int] = conn.raddr.port if conn.raddr else None
                local_ip: Optional[str] = conn.laddr.ip if conn.laddr else None
                local_port: Optional[int] = conn.laddr.port if conn.laddr else None
                
                pid: Optional[int] = conn.pid
                process_name: str = "unknown"
                
                if pid:
                    try:
                        process_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "unknown"
                
                connections.append({
                    "timestamp": time.time(),
                    "status": conn.status,
                    "local_addr": f"{local_ip}:{local_port}" if local_ip else "unknown",
                    "remote_addr": f"{remote_ip}:{remote_port}" if remote_ip else None,
                    "pid": pid,
                    "process": process_name
                })
    except psutil.AccessDenied:
        logger.error("Insufficient permissions to access network connection information.")
    except Exception as e:
        logger.error(f"Unexpected error retrieving connections: {e}")
        
    return connections

def log_event(log_file: str, event: Dict[str, Any]) -> None:
    """
    Appends a single network event to a JSONL (JSON Lines) log file.

    Args:
        log_file (str): Path to the log file.
        event (Dict[str, Any]): The event data to log.

    Returns:
        None
    """
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        logger.error(f"Could not write to log file {log_file}: {e}")

def main() -> None:
    """
    Main entry point for NetPulse. Parses arguments, initializes configuration, 
    and monitors network connections in a loop.
    """
    parser = argparse.ArgumentParser(description="NetPulse network connection monitor")
    parser.add_argument("--interval", type=int, default=None, help="Check interval in seconds")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--log", type=str, default=None, help="Path to JSON log file")
    parser.add_argument("--version", action="version", version=f"NetPulse {__version__}")
    args = parser.parse_args()

    config = load_config(args.config)
    
    # Priority: Command line arg > Config file > Default
    interval: int = args.interval if args.interval is not None else config.get("check_interval_seconds", 5)
    log_file: str = args.log if args.log is not None else config.get("log_file", "net_events.json")

    logger.info(f"Starting NetPulse monitor. Logging to {log_file}...")
    
    # Track unique connections to avoid duplicate logging
    seen_conns: Set[Tuple[Optional[str], Optional[str], str, Optional[int]]] = set()

    try:
        while True:
            conns = get_active_connections()
            for c in conns:
                # Create a unique key for the connection
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