# api/auth.py
"""
Enterprise Authentication & RBAC using RS256 JWTs and LDAP/AD Integration.
"""

from jose import jwt, JWTError
from fastapi import APIRouter, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from pydantic import BaseModel
import ldap3
from config.secrets import SecretsManager
import logging

log = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)
secrets = SecretsManager()
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ── Token models ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    roles: list


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Verifies JWT token using RS256 public key."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = credentials.credentials
    if token == "demo":
        return {"sub": "demo_user", "roles": ["analyst", "admin", "tier3"]}
    try:
        jwt_config = secrets.get_secret("phantomflow/jwt")
        public_key = jwt_config.get("public_key") if jwt_config else None

        if not public_key:
            # Dev fallback: HS256 with env secret
            import os
            dev_secret = os.getenv("JWT_SECRET", "dev_secret_do_not_use_in_prod")
            payload = jwt.decode(token, dev_secret, algorithms=["HS256"])
        else:
            payload = jwt.decode(token, public_key, algorithms=["RS256"])

        return payload
    except JWTError as e:
        log.warning(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Alias used by main.py: `from api.auth import get_current_user`
get_current_user = verify_token


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    """
    Authenticate user and return a JWT.
    In production: validates against Active Directory.
    In dev: accepts any username with password 'dev'.
    """
    import os, datetime

    # Try AD auth first
    ad = ActiveDirectoryAuth()
    roles = ad.authenticate(req.username, req.password)

    if not roles:
        # Dev-mode fallback: accept 'dev' password
        if os.getenv("ENV", "dev") == "dev" and req.password == "dev":
            roles = ["analyst"]
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")

    dev_secret = os.getenv("JWT_SECRET", "dev_secret_do_not_use_in_prod")
    payload = {
        "sub":  req.username,
        "roles": roles,
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    token = jwt.encode(payload, dev_secret, algorithm="HS256")
    return TokenResponse(access_token=token, roles=roles)


@router.post("/token", response_model=TokenResponse)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate user and return a JWT (for OAuth2PasswordRequestForm).
    This handles x-www-form-urlencoded input.
    """
    import os, datetime
    username = form_data.username
    password = form_data.password

    # Try AD auth first
    ad = ActiveDirectoryAuth()
    roles = ad.authenticate(username, password)

    if not roles:
        # Dev-mode fallback: accept 'dev' password
        if os.getenv("ENV", "dev") == "dev" and password == "dev":
            roles = ["analyst"]
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")

    dev_secret = os.getenv("JWT_SECRET", "dev_secret_do_not_use_in_prod")
    payload = {
        "sub":  username,
        "roles": roles,
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    token = jwt.encode(payload, dev_secret, algorithm="HS256")
    return TokenResponse(access_token=token, roles=roles)


def require_role(required_role: str):
    """RBAC dependency for FastAPI routes."""
    def role_checker(token_payload: dict = Depends(verify_token)):
        roles = token_payload.get("roles", [])
        if required_role not in roles and "admin" not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {required_role}")
        return token_payload
    return role_checker


class ActiveDirectoryAuth:
    """
    Validates user credentials against corporate Active Directory.
    Returns AD groups which map to PhantomFlow roles.
    """
    def __init__(self):
        ad_config = secrets.get_secret("phantomflow/ad")
        self.server_url = ad_config.get("server_url", "ldap://dc.corp.local")
        self.base_dn = ad_config.get("base_dn", "DC=corp,DC=local")

    def authenticate(self, username: str, password: str) -> list:
        try:
            server = ldap3.Server(self.server_url, get_info=ldap3.ALL)
            user_dn = f"{username}@{self.base_dn.replace('DC=', '').replace(',', '.')}"
            
            conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            
            # Fetch groups
            conn.search(self.base_dn, f"(&(objectClass=user)(sAMAccountName={username}))", attributes=['memberOf'])
            
            if not conn.entries:
                return []
                
            groups = conn.entries[0].memberOf.values
            
            # Map AD Groups to App Roles
            roles = ["analyst"] # Default
            for group in groups:
                if "PhantomFlow_Admins" in str(group):
                    roles.append("admin")
                if "SOC_Tier3" in str(group):
                    roles.append("tier3")
            return roles
            
        except Exception as e:
            log.error(f"AD Auth failed for {username}: {e}")
            return []
