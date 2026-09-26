# NetPulse

NetPulse is a lightweight Python network connection monitor and anomaly alerter designed for local security analysis and DFIR labs. It inspects active TCP and UDP connections using psutil, flags unusual listening ports or suspicious outbound destinations, and logs structured JSON security events locally.

## Features

- Real-time monitoring of active network connections and associated system processes.
- Configurable rule sets for spotting unusual remote ports or non-standard outbound traffic.
- Local JSON event logging for forensic review and integration into SOC monitoring workflows.
- Zero heavy dependencies outside standard library and psutil.

## Requirements

- Python 3.8+
- psutil

## Installation

Clone the repository and install dependencies:

git clone https://github.com/wyn-cmd/net-pulse.git
cd net-pulse
pip install -r requirements.txt

## Usage

Run the monitor with default settings:

python3 net_pulse.py --interval 5 --log net_events.json

Check the installed version:

python3 net_pulse.py --version

## Unknown port alerting

`config.json` sets `monitored_ports` (a list of expected local ports) and `alert_on_unknown_ports` (true by default). A new connection whose local port is not in `monitored_ports` is logged at WARNING level instead of INFO, and every JSON event on disk carries an `unknown_port` boolean so a downstream script can filter for it without re-parsing the log line. A `monitored_ports` value that is not a JSON list (for example a bare number) is logged as a config error and treated as an empty set rather than crashing the monitor.

## Tests

The helper functions are covered by stdlib unittest cases, so no extra dependency is needed:

python3 -m unittest test_net_pulse -v
