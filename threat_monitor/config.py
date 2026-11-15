from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_ignore_empty=True, extra="ignore", hide_input_in_errors=True
    )

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_key: SecretStr | None = None
    guest_access_enabled: bool = False
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None

    database_url: SecretStr | None = None
    aiven_token: SecretStr | None = None
    context_dev_api_key: SecretStr | None = None
    context_dev_timeout_seconds: int = Field(default=25, ge=1, le=300)
    tor_socks_proxy: str | None = None
    gemini_api_key: SecretStr | None = None
    gemini_filter_model: str | None = "gemini-4-hydrogen"
    embedding_model: str = "gemini-embedding-001"

    modal_inference_url: str | None = None
    modal_inference_token: SecretStr | None = None
    analysis_provider: Literal["modal", "gemini"] = "gemini"
    analysis_model: str = "gemini-4-carbon"
    analysis_model_revision: str | None = None
    modal_gpu: str = "H100"
    analysis_context_length: int = Field(default=8192, gt=0)

    collection_interval_seconds: int = Field(default=86400, gt=0)
    worker_poll_seconds: float = Field(default=2, gt=0)
    analysis_batch_size: int = Field(default=4, ge=1, le=100)

    @model_validator(mode="after")
    def matching_analysis_provider(self):
        gemini_model = self.analysis_model.startswith("gemini-")
        if self.analysis_provider == "gemini":
            if not gemini_model or self.analysis_model_revision is not None:
                raise ValueError("Gemini analysis requires a gemini- model ID and blank ANALYSIS_MODEL_REVISION")
        elif gemini_model or self.analysis_model.startswith("models/gemini-"):
            raise ValueError("Set ANALYSIS_PROVIDER=gemini for a Gemini analysis model")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
