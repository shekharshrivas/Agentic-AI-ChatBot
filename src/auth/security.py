"""
Security utilities for password hashing and JWT token handling.
Replicates the Argon2 and JWT authentication logic previously implemented in Rust.
"""

# Standard library imports
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

# Third-party imports
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
import jwt

# Local imports
from src.core.logger import logger

# Configuration constants
JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_jwt_key_adaptive_rag_2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600

# Initialize Argon2 password hasher
_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id algorithm.

    Args:
        password: Raw plain text password to hash.

    Returns:
        The Argon2id password hash string.
    """
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plain password against an Argon2id password hash.

    Args:
        password: Plain text password to check.
        password_hash: Stored Argon2id hash from database.

    Returns:
        True if password matches hash, False otherwise.
    """
    logger.info("Verifying password against DB hash")
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError) as exc:
        logger.error("Failed to verify password: %s", exc)
        return False
    except Exception as exc:
        logger.error("Unexpected error during password verification: %s", exc)
        return False


def generate_jwt(user_id: str, secret: str = JWT_SECRET, expires_in: int = JWT_EXPIRATION_SECONDS) -> str:
    """
    Generate a JSON Web Token for the authenticated user.

    Args:
        user_id: The unique identifier (username) of the user.
        secret: Secret key used to sign the token.
        expires_in: Expiration duration in seconds (default: 3600).

    Returns:
        Encoded JWT string.
    """
    exp_time = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    payload = {
        "sub": user_id,
        "exp": int(exp_time.timestamp())
    }
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
    return token


def validate_jwt(token: str, secret: str = JWT_SECRET) -> Optional[Dict[str, Any]]:
    """
    Validate and decode a JSON Web Token.

    Args:
        token: The encoded JWT string.
        secret: Secret key used to decode the token.

    Returns:
        Decoded payload dictionary if valid, None if invalid or expired.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return None
    except jwt.InvalidTokenError as exc:
        logger.warning("Invalid JWT token: %s", exc)
        return None
