from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from pydantic import AnyHttpUrl, PostgresDsn, validator, EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import secrets
import os

class Settings(BaseSettings):
    # Application
    PROJECT_NAME: str = "SOAR Phishing Analysis"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = True
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [
        "http://localhost:3000",
        "http://localhost:8000",
    ]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "soar_phishing"
    DATABASE_URI: Optional[PostgresDsn] = None
    ASYNC_DATABASE_URI: Optional[str] = None
    
    @validator("DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            username=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            path=f"{values.get('POSTGRES_DB') or ''}",
        )
    
    @validator("ASYNC_DATABASE_URI")
    def assemble_async_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return values.get("DATABASE_URI").replace("postgresql://", "postgresql+asyncpg://")
    
    # Security
    ALGORITHM: str = "HS256"
    
    # First superuser
    FIRST_SUPERUSER: EmailStr = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "admin123"
    
    # Email
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = None
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    EMAILS_FROM_NAME: Optional[str] = None
    
    @validator("EMAILS_FROM_NAME")
    def get_project_name(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if not v:
            return values["PROJECT_NAME"]
        return v
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    # File Upload
    UPLOAD_FOLDER: str = "uploads"
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16MB
    
    # Threat Intelligence
    VIRUS_TOTAL_API_KEY: str = ""
    ALIENVAULT_OTX_KEY: str = ""
    
    # Model Config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

# Create settings instance
settings = Settings()

# Create uploads directory if it doesn't exist
Path(settings.UPLOAD_FOLDER).mkdir(exist_ok=True)

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Logging configuration
LOG_FILE = os.path.join(BASE_DIR, "logs", "app.log")

# Create necessary directories
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
