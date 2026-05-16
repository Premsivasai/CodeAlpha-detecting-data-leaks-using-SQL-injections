import json
import time
import redis
import urllib.request
import urllib.error

REDIS_URL = "redis://localhost:6379/0"
CHANNEL = "ws:attacks"


def publish_test_attack():
    try:
        r = redis.from_url(REDIS_URL)
    except Exception:
        r = None
    payload = {
        "id": 999999,
        "user_id": None,
        "ip_address": "127.0.0.1",
        "attack_type": "test_injection",
        "payload": "SELECT * FROM users WHERE id=1; -- test",
        "target": "database",
        "severity": "low",
        "detection_method": "smoke_test",
        "blocked": True,
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S')
    }

    msg = json.dumps(payload)
    print(f"Publishing test message to {CHANNEL}: {msg}")
    if r is not None:
        try:
            r.publish(CHANNEL, msg)
            print('Published via Redis')
            return
        except Exception as e:
            print('Redis publish failed, falling back to HTTP publish:', e)

    # Fallback to internal HTTP publish endpoint
    try:
        data = json.dumps({"channel": CHANNEL, "message": payload}).encode('utf-8')
        req = urllib.request.Request('http://127.0.0.1:8000/api/v1/internal/publish', data=data, headers={'Content-Type':'application/json'})
        resp = urllib.request.urlopen(req, timeout=5)
        print('Published via HTTP fallback, status:', resp.getcode())
    except urllib.error.URLError as e:
        print('HTTP fallback failed:', e)


if __name__ == '__main__':
    publish_test_attack()