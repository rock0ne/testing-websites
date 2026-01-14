import jwt, os, time
from app import ISSUER, ALGO

def make_token(roles):
    return jwt.encode({
        "iss": ISSUER,
        "iat": int(time.time()),
        "exp": int(time.time())+3600,
        "roles": roles
    }, os.environ.get("API_SECRET", "dev-secret-change-me"), algorithm=ALGO)

def test_token_structure():
    t = make_token(["admin"]) 
    assert t
