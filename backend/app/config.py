from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "sqlite+aiosqlite:///./vulnscanner.db"
    RATE_LIMIT_RPS: int = 10
    APP_VERSION: str = "1.0.0"


settings = Settings()
