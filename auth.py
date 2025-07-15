import jwt, time, os

SECRET_KEY = os.environ["JWT_SECRET_KEY"]

def generate_token(user_id: str, scopes: list[str]) -> str:
    payload = { "uid": user_id, "scopes": scopes, "exp": time.time() + 300 }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str, required_scope: str) -> bool:
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return required_scope in decoded.get("scopes", [])
    except jwt.PyJWTError:
        return False
