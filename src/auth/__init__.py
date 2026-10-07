"""
Authentication package for Adaptive RAG.
Provides Argon2 password hashing, JWT generation/verification,
SQLite user store, and API token middleware.
"""

from src.auth.database import get_user_by_username, create_user_record, init_auth_db
from src.auth.dependencies import api_token_store, verify_api_token, verify_jwt
from src.auth.models import (
    ChatRequest,
    ChatResponse,
    CreateUserRequest,
    LoginRequest,
    StatusResponse,
    TokenResponse,
)
from src.auth.security import (
    generate_jwt,
    hash_password,
    validate_jwt,
    verify_password,
)

__all__ = [
    "hash_password",
    "verify_password",
    "generate_jwt",
    "validate_jwt",
    "init_auth_db",
    "create_user_record",
    "get_user_by_username",
    "api_token_store",
    "verify_api_token",
    "verify_jwt",
    "TokenResponse",
    "CreateUserRequest",
    "LoginRequest",
    "ChatRequest",
    "ChatResponse",
    "StatusResponse",
]
