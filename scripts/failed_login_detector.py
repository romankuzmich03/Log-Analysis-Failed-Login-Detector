import re
import os
import json
from datetime import datetime
from collections import Counter
from typing import Dict, Any

from scripts.threat_intel import check_ip_reputation


FAILED_LOGIN_PATTERN = (
    r"(\w+\s+\d+\s+\d+:\d+:\d+)"
    r".*Failed password.*from "
    r"(\d+\.\d+\.\d+\.\d+)"
)


def parse_failed_logins(log_file):

    failed_events = []

    with open(log_file, "r") as log_file_handle:

        for log_line in log_file_handle:

            match = re.search(
                FAILED_LOGIN_PATTERN,
                log_line
            )

            if match:

                login_time = match.group(1)
                detected_ip = match.group(2)

                failed_events.append(
                    {
                        "time": login_time,
                        "ip": detected_ip
                    }
                )

    return failed_events



def get_severity(attempt_count):

    if attempt_count >= 20:
        return "CRITICAL"

    elif attempt_count >= 10:
        return "HIGH"

    elif attempt_count >= 5:
        return "MEDIUM"

    else:
        return "LOW"



def analyze_failed_logins(events, threshold=5):

    detected_ips = [
        event["ip"]
        for event in events
    ]

    ip_counter = Counter(detected_ips)

    suspicious_results = {}


    for current_ip, attempt_count in ip_counter.items():

        if attempt_count >= threshold:

            attack_times = [
                event["time"]
                for event in events
                if event["ip"] == current_ip
            ]


            reputation = check_ip_reputation(current_ip)


            suspicious_results[current_ip] = {

                "attempts": attempt_count,

                "first_seen": attack_times[0],

                "last_seen": attack_times[-1],

                "severity": get_severity(attempt_count),

                "attack_type": "SSH brute force",

                "threat_intel": reputation

            }


    return suspicious_results



def run_failed_login_scan() -> Dict[str, Any]:

    log_path = "logs/auth.log"

    login_events = parse_failed_logins(log_path)

    scan_result = analyze_failed_logins(login_events)

    return scan_result



def generate_report() -> Dict[str, Any]:

    log_path = "logs/auth.log"

    login_events = parse_failed_logins(log_path)

    scan_result = analyze_failed_logins(login_events)


    generated_report = {

        "scan_time": str(datetime.now()),

        "total_failed_attempts": len(login_events),

        "suspicious_ips": scan_result

    }


    os.makedirs("reports", exist_ok=True)


    with open(
        "../reports/failed_login_report.json",
        "w"
    ) as report_file:

        json.dump(
            generated_report,
            report_file,
            indent=4
        )


    return generated_report



if __name__ == "__main__":

    final_report = generate_report()


    print("\nFailed login analysis:")
    print("---------------------")


    suspicious_ips = final_report["suspicious_ips"]


    for detected_address, attack_data in suspicious_ips.items():

        print(
            f"{detected_address}: "
            f"{attack_data['attempts']} attempts | "
            f"{attack_data['severity']} | "
            f"{attack_data['attack_type']} | "
            f"Threat: {attack_data['threat_intel']['status']} | "
            f"First: {attack_data['first_seen']} | "
            f"Last: {attack_data['last_seen']}"
        )