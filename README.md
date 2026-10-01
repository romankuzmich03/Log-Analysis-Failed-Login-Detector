# Log Analysis - Failed Login Detector

A Python-based security tool that analyzes authentication logs and detects suspicious SSH failed login activity.

The project simulates a basic SOC Tier 1 workflow by identifying possible brute-force attacks from Linux authentication logs.

## Features

- Parses Linux `auth.log` files
- Detects failed SSH login attempts
- Extracts source IP addresses
- Counts failed attempts per IP
- Identifies suspicious IP addresses
- Assigns severity levels
- Records first and last attack timestamps
- Generates JSON security reports
- Includes basic threat intelligence checking

## Detection Logic

The tool analyzes log entries containing:

Failed password


Example:

Sep 15 20:10:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.55 port 22 ssh2

 
Detected information:

- Source IP address
- Number of failed attempts
- Attack type
- Severity level
- First seen time
- Last seen time

## Severity Levels

| Attempts | Severity |
|----------|----------|
| 5+       | MEDIUM   |
| 10+      | HIGH     |
| 20+      | CRITICAL |

## Project Structure

linux-home-lab-hardening/
├── logs/
│   └── auth.log
├── reports/
│   └── security_report.json
├── scripts/
│   ├── failed_login_detector.py
│   └── threat_intel.py
├── main.py
├── requirements.txt
└── README.md


## Installation

Clone the repository:

```bash
git clone https://github.com/romankuzmich03/Log-Analysis-Failed-Login-Detector.git
```

Go to project directory:

```bash
cd Log-Analysis-Failed-Login-Detector
```

Create virtual environment:

```bash
python3 -m venv .venv
```

Activate environment:

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the security scanner:

```bash
python main.py
```

Example output:

```text
[+] Starting security scan

[+] Failed login detection

192.168.1.55:
5 attempts |
MEDIUM |
SSH brute force
```

## Report Example

The tool generates:

```
reports/security_report.json
```

Example:

```json
{
    "192.168.1.55": {
        "attempts": 5,
        "severity": "MEDIUM",
        "attack_type": "SSH brute force",
        "first_seen": "Sep 15 20:10:01",
        "last_seen": "Sep 15 20:10:20"
    }
}
```
## Technologies

- Python 3
- Regular Expressions
- JSON
- Linux Authentication Logs
- Basic Threat Intelligence

## Security Concepts Demonstrated

This project demonstrates:

- Log analysis
- Brute-force detection
- IOC identification
- Security event monitoring
- Basic SOC analyst workflow

## Future Improvements

Possible improvements:

- Real-time log monitoring
- AbuseIPDB API integration
- Email/Telegram alerts
- Windows Event Log support
- Dashboard visualization

## Author

Roman Kuzmich

Cybersecurity / Python Security Projects