import asyncio
import functools
import logging

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    log_level: str = "info"
    port: int = Field(default=8080, ge=1, le=65535)
    scanner_timeout: float = Field(default=10.0, gt=0)
    deep_scanner_timeout: float = Field(default=30.0, gt=0)
    dev_bypass_auth: bool = False
    rapidapi_proxy_secret: str = ""
    nvd_api_key: str = ""
    job_ttl_seconds: int = Field(default=3600, gt=0)
    job_cleanup_interval: int = Field(default=300, gt=0)
    webhook_timeout: float = Field(default=5.0, gt=0)
    webhook_max_retries: int = Field(default=3, ge=0)
    max_concurrent_scans: int = Field(default=5, ge=1, le=50)
    nmap_max_concurrent: int = Field(default=6, ge=1, le=20)

    model_config = {"env_prefix": "INFRAPROBE_", "env_file": ".env", "extra": "ignore"}

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        level = logging.getLevelNamesMapping().get(v.upper())
        if level is None:
            raise ValueError(f"Invalid log level: {v!r}. Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        return v

    @model_validator(mode="after")
    def _require_secrets_unless_bypass(self) -> "Settings":
        if self.dev_bypass_auth:
            return self
        if not self.rapidapi_proxy_secret:
            raise ValueError("INFRAPROBE_RAPIDAPI_PROXY_SECRET is required (or set INFRAPROBE_DEV_BYPASS_AUTH=true)")
        return self


settings = Settings()


@functools.cache
def scan_semaphore() -> asyncio.Semaphore:
    """Return a singleton semaphore limiting concurrent scan operations."""
    return asyncio.Semaphore(settings.max_concurrent_scans)


@functools.cache
def nmap_semaphore() -> asyncio.Semaphore:
    """Return a singleton semaphore limiting concurrent nmap processes."""
    return asyncio.Semaphore(settings.nmap_max_concurrent)
