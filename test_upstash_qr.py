#!/usr/bin/env python3
"""
Simple helper to fetch a QR key from Upstash (or Redis URL) and save to a PNG.
Usage: python test_upstash_qr.py [user_id]
"""
import os
import sys
import requests
import base64


def _clean_env(v):
    if v is None:
        return None
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v

UPSTASH_REST_URL = _clean_env(os.environ.get('UPSTASH_REDIS_REST_URL') or os.environ.get('UPSTASH_REST_URL') or os.environ.get('UPSTASH_URL'))
UPSTASH_REST_TOKEN = _clean_env(os.environ.get('UPSTASH_REDIS_REST_TOKEN') or os.environ.get('UPSTASH_REST_TOKEN') or os.environ.get('UPSTASH_TOKEN'))

if not UPSTASH_REST_URL or not UPSTASH_REST_TOKEN:
    print("Missing Upstash REST URL/token in environment. Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN or UPSTASH_REST_URL/TOKEN.")
    sys.exit(1)

user_id = sys.argv[1] if len(sys.argv) > 1 else '6'
key = f"qr:{user_id}"
url = UPSTASH_REST_URL.rstrip('/') + f"/get/{key}"
headers = {'Authorization': f'Bearer {UPSTASH_REST_TOKEN}'}

print(f"Requesting {url}")
resp = requests.get(url, headers=headers, timeout=10)
if resp.status_code != 200:
    print(f"Unexpected status {resp.status_code}: {resp.text}")
    sys.exit(2)

j = resp.json()
val = j.get('result') or j.get('value') or j.get('result_raw') or j.get('value_raw')
if not val:
    print("No value found for key", key)
    sys.exit(3)

try:
    data = base64.b64decode(val)
except Exception:
    # If it's not base64, try bytes
    data = val.encode()

out = f"qr_user_{user_id}.png"
with open(out, 'wb') as f:
    f.write(data)

print(f"Saved QR to {out}")
