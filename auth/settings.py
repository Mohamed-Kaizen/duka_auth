"""Settings for Duka Auth Project."""
import pathlib
from datetime import timedelta
from typing import List, Set

from passlib.context import CryptContext
from pydantic import BaseSettings
from redis import Redis

BASE_DIR = pathlib.Path(__file__).parent.parent


class EnvSettings(BaseSettings):
    """Base settings for Duka Auth."""

    PROJECT_NAME: str = "Duka Auth"

    PROJECT_DESCRIPTION: str = "A microservice that handle Auth for Duka project."

    DOCS_URL: str = "/docs"

    REDOC_URL: str = "/redoc"

    OPENAPI_URL: str = "/openapi.json"

    ALLOWED_HOSTS: List[str] = ["*"]

    CORS_ORIGINS: List[str] = ["*"]

    CORS_ALLOW_CREDENTIALS: bool = True

    CORS_ALLOW_METHODS: List[str] = ["*"]

    CORS_ALLOW_HEADERS: List[str] = ["*"]

    LOG_LEVEL: str = "DEBUG"

    HASURA_GRAPHQL_ADMIN_SECRET: str

    HASURA_ENDPOINT_URL: str

    authjwt_secret_key: str

    authjwt_denylist_enabled: bool = True

    authjwt_denylist_token_checks: Set[str] = {"access", "refresh"}

    authjwt_access_token_expires: timedelta = timedelta(days=7)

    authjwt_refresh_token_expires: timedelta = timedelta(days=30)

    PASSWORD_RESET_TIMEOUT: int = 259200

    SMTP_HOST_ADDR: str = "smtp.gmail.com"

    SMTP_HOST_PORT: int = 587

    EMAIL_USER: str

    EMAIL_PASSWORD: str

    PASSWORD_RESET_CALLBACK_URL: str = "http://localhost:3000/password-reset/"

    EMAIL_VERIFY_CALLBACK_URL: str = "http://localhost:3000/email-verify/"

    REDIS_HOST: str

    REDIS_PORT: int

    REDIS_PASSWORD: str

    # Don't decrease this number unless you have a good reason not to.
    # Please read
    # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    # #maximum-password-lengths
    MINIMUM_PASSWORD_LENGTH: int = 8

    # Don't increase this number unless you have a good reason not to.
    # Please read
    # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    # #maximum-password-lengths
    MAXIMUM_PASSWORD_LENGTH: int = 16


SETTINGS = EnvSettings()

PASSWORD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


REDIS = Redis(host=SETTINGS.REDIS_HOST, port=SETTINGS.REDIS_PORT, password=SETTINGS.REDIS_PASSWORD, decode_responses=True)
