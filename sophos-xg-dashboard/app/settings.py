import json
import os
from pathlib import Path
from pydantic import BaseModel, Field

OPTIONS_PATH = Path("/data/options.json")


class Settings(BaseModel):
    sophos_host: str = Field(default="https://192.0.2.10:4444")
    verify_ssl: bool = Field(default=False)
    username: str = Field(default="")
    password: str = Field(default="")
    request_timeout: int = Field(default=30, ge=3, le=120)
    refresh_interval: int = Field(default=60, ge=10, le=3600)


def load_settings() -> Settings:
    if OPTIONS_PATH.exists():
        return Settings(**json.loads(OPTIONS_PATH.read_text(encoding="utf-8")))

    # Local development fallback only. Do not use this for HA add-on secrets.
    return Settings(
        sophos_host=os.getenv("SOPHOS_HOST", "https://192.0.2.10:4444"),
        verify_ssl=os.getenv("SOPHOS_VERIFY_SSL", "false").lower() in {"1", "true", "yes"},
        username=os.getenv("SOPHOS_USERNAME", ""),
        password=os.getenv("SOPHOS_PASSWORD", ""),
        request_timeout=int(os.getenv("SOPHOS_REQUEST_TIMEOUT", "30")),
        refresh_interval=int(os.getenv("SOPHOS_REFRESH_INTERVAL", "60")),
    )
