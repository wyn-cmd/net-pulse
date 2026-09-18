import argparse
import json
import os
import sys
import time
import psutil

def load_config(config_path):
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {
        "check_interval_seconds": 5,
        "alert_on_unknown_ports": True,
        "monitored_ports": [80, 443, 22, 53],
        "log_file": "net_events.json"
    }

def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
            remote_ip = conn.raddr.ip if conn.raddr else None
            remote_port = conn.raddr.port if conn.raddr else None
            local_ip = conn.laddr.ip if conn.laddr else None
            local_port = conn.laddr.port if conn.laddr else None
            
            pid = conn.pid
            process_name = None
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"
            
            connections.append({
                "timestamp": time.time(),
                "status": conn.status,
                "local_addr": f"{local_ip}:{local_port}",
                "remote_addr": f"{remote_ip}:{remote_port}" if remote_ip else None,
                "pid": pid,
                "process": process_name
            })
    return connections

def log_event(log_file, event):
    with open(log_file, 'a') as f:
        f.write(json.dumps(event) + "\n")

def main():
    parser = argparse.ArgumentParser(description="NetPulse network connection monitor")
    parser.add_argument("--interval", type=int, default=5, help="Check interval in seconds")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--log", type=str, default="net_events.json", help="Path to JSON log file")
    args = parser.parse_args()

    config = load_config(args.config)
    interval = args.interval or config.get("check_interval_seconds", 5)
    log_file = args.log or config.get("log_file", "net_events.json")

    print(f"[*] Starting NetPulse monitor. Logging to {log_file}...")
    seen_conns = set()

    try:
        while True:
            conns = get_active_connections()
            for c in conns:
                conn_key = (c["local_addr"], c["remote_addr"], c["status"], c["pid"])
                if conn_key not in seen_conns:
                    seen_conns.add(conn_key)
                    log_event(log_file, c)
                    print(f"[+] New connection: {c['process']} (PID {c['pid']}) {c['local_addr']} -> {c['remote_addr']} [{c['status']}]")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Stopping NetPulse.")

if __name__ == "__main__":
    main()
