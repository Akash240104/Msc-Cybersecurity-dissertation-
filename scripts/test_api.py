import urllib.request
import json

API_KEY = "YOUR_API_KEY_HERE"

body = json.dumps({
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Say hello"}]
}).encode('utf-8')

req = urllib.request.Request(
    "https://api.anthropic.com/v1/messages",
    data=body,
    headers={
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode('utf-8'))
        print(result['content'][0]['text'])
except urllib.error.HTTPError as e:
    print(f"Error: {e.code}")
    print(e.read().decode('utf-8'))
