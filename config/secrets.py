# config/secrets.py
"""
Secrets management with three providers:
  - "env"  (default for dev): reads from environment variables / .env file
  - "aws"  (production):      AWS Secrets Manager
  - "vault" (production):     HashiCorp Vault

The "env" provider never crashes on startup — it always returns a dict
so the rest of the codebase can use .get() safely.
"""

import os
import json
import logging
from functools import lru_cache

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger(__name__)


class SecretsManager:
    """
    Unified secrets access. Picks provider from SECRETS_PROVIDER env var.
    Cached to avoid repeated network calls.
    """

    def __init__(self, region: str = "us-east-1"):
        self.provider = os.getenv("SECRETS_PROVIDER", "env")
        self._client = None

        if self.provider == "aws":
            try:
                import boto3
                self._client = boto3.client("secretsmanager", region_name=region)
            except Exception as e:
                log.warning(f"AWS Secrets Manager unavailable, falling back to env: {e}")
                self.provider = "env"

        elif self.provider == "vault":
            try:
                import hvac
                self._vault = hvac.Client(url=os.getenv("VAULT_URL", "http://vault:8200"))
                self._vault.token = os.getenv("VAULT_TOKEN", "")
            except Exception as e:
                log.warning(f"Vault unavailable, falling back to env: {e}")
                self.provider = "env"

    @lru_cache(maxsize=20)
    def get_secret(self, secret_name: str) -> dict:
        """
        Fetch secret by name. Returns {} on any failure — never raises.
        Callers must use .get() with defaults.
        """
        try:
            if self.provider == "aws":
                response = self._client.get_secret_value(SecretId=secret_name)
                return json.loads(response["SecretString"])

            elif self.provider == "vault":
                result = self._vault.secrets.kv.read_secret_version(path=secret_name)
                return result["data"]["data"]

            else:
                # "env" provider: map well-known secret names to env var prefixes
                return self._from_env(secret_name)

        except Exception as e:
            log.warning(f"Secret '{secret_name}' unavailable: {e} — using defaults")
            return {}

    def _from_env(self, secret_name: str) -> dict:
        """
        Map secret paths to env var groups.
        e.g. "phantomflow/postgres" → {user: PG_USER, password: PG_PASSWORD, ...}
        """
        mapping = {
            "phantomflow/postgres": {
                "user":     os.getenv("PG_USER", "phantom"),
                "password": os.getenv("PG_PASSWORD", "PhantomSecure2026!"),
                "host":     os.getenv("PG_HOST", "localhost"),
                "port":     os.getenv("PG_PORT", "5432"),
                "db":       os.getenv("PG_DB", "phantomflow"),
            },
            "phantomflow/redis": {
                "password": os.getenv("REDIS_PASSWORD", "PhantomSecure2026!"),
                "host":     os.getenv("REDIS_HOST", "localhost"),
            },
            "phantomflow/jwt": {
                "secret":      os.getenv("JWT_SECRET", "dev_secret_do_not_use_in_prod"),
                "algorithm":   os.getenv("JWT_ALGORITHM", "HS256"),
                "public_key":  os.getenv("JWT_PUBLIC_KEY", ""),     # empty = use HS256
                "private_key": os.getenv("JWT_PRIVATE_KEY", ""),
            },
            "phantomflow/ad": {
                "server_url": os.getenv("AD_SERVER_URL", "ldap://dc.corp.local"),
                "base_dn":    os.getenv("AD_BASE_DN", "DC=corp,DC=local"),
            },
            "phantomflow/threat_intel_keys": {
                "abuseipdb":  os.getenv("ABUSEIPDB_API_KEY", ""),
                "virustotal": os.getenv("VIRUSTOTAL_API_KEY", ""),
            },
        }
        return mapping.get(secret_name, {})

    # ── Convenience helpers ───────────────────────────────────────────────────
    def get_db_credentials(self) -> dict:
        return self.get_secret("phantomflow/postgres")

    def get_redis_password(self) -> str:
        return self.get_secret("phantomflow/redis").get("password", "")

    def get_jwt_config(self) -> dict:
        return self.get_secret("phantomflow/jwt")

    def get_jwt_private_key(self) -> str:
        return self.get_jwt_config().get("private_key", "")

    def get_api_keys(self) -> dict:
        return self.get_secret("phantomflow/threat_intel_keys")
