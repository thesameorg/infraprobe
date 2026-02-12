from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    env: str = "development"
    log_level: str = "info"
    port: int = 8080
    scanner_timeout: float = 10.0
    deep_scanner_timeout: float = 30.0

    model_config = {"env_prefix": "INFRAPROBE_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
