from flask import Flask, request, jsonify
import os, time, jwt
from functools import wraps

SECRET = os.environ.get("API_SECRET", "dev-secret-change-me")
ISSUER = "bluebastion-labs"
ALGO = "HS256"

app = Flask(__name__)

# Simple role-based JWT decorator

def requires_role(role):
    def wrapper(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            auth = request.headers.get("Authorization", "").split()
            if len(auth) != 2 or auth[0].lower() != "bearer":
                return jsonify({"error": "missing bearer token"}), 401
            try:
                payload = jwt.decode(auth[1], SECRET, algorithms=[ALGO], options={"require": ["exp", "iat", "iss"]})
                if payload.get("iss") != ISSUER:
                    return jsonify({"error": "bad issuer"}), 401
                roles = payload.get("roles", [])
                if role not in roles:
                    return jsonify({"error": "forbidden"}), 403
            except Exception as e:
                return jsonify({"error": "invalid token"}), 401
            return fn(*args, **kwargs)
        return inner
    return wrapper

@app.get("/health")
def health():
    return jsonify({"status": "ok", "ts": int(time.time())})

@app.get("/admin/metrics")
@requires_role("admin")
def metrics():
    # Example PII-safe payload (no real data). In production use structured logging with PII scrubbing.
    return jsonify({"requests": 123, "errors": 0})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
