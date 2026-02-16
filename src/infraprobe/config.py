from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    log_level: str = "info"
    port: int = 8080
    scanner_timeout: float = 10.0
    deep_scanner_timeout: float = 30.0
    rapidapi_proxy_secret: str | None = None
    nvd_api_key: str | None = None
    job_ttl_seconds: int = 3600
    job_cleanup_interval: int = 300
    webhook_timeout: float = 5.0
    webhook_max_retries: int = 3

    model_config = {"env_prefix": "INFRAPROBE_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
