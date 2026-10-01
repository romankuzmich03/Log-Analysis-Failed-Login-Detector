import json
import os
from datetime import datetime

from scripts.failed_login_detector import run_failed_login_scan



def main():

    print("[+] Starting security scan")


    print("\n[+] Failed login detection")


    failed_login_result = run_failed_login_scan()



    if failed_login_result:

        for ip, data in failed_login_result.items():

            print(
                f"{ip}: "
                f"{data['attempts']} attempts | "
                f"{data['severity']} | "
                f"{data['attack_type']} | "
                f"Threat: {data['threat_intel']['status']}"
            )


    else:

        print("No suspicious login attempts detected")



    report = {

        "scan_time": str(datetime.now()),

        "failed_logins": failed_login_result

    }


    os.makedirs(
        "reports",
        exist_ok=True
    )


    with open(
        "reports/security_report.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


    print("\n[+] Security report created")



if __name__ == "__main__":

    main()