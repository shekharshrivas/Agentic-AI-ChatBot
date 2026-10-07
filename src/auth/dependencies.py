"""
FastAPI dependencies and token stores for API token and JWT authentication.
"""

# Standard library imports
import threading
from typing import Any, Dict, Optional
import uuid

# Third-party imports
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Local imports
from src.auth.security import validate_jwt
from src.core.logger import logger


class ApiTokenStore:
    """
    Thread-safe in-memory store for active API tokens.
    Replicates Arc<Mutex<HashSet<String>>> from the Rust Agentic-BFF state.
    """

    def __init__(self):
        """Initialize the thread-safe token store."""
        self._tokens = set()
        self._lock = threading.Lock()

    def generate_token(self) -> str:
        """
        Generate a new UUIDv4 API token and store it.

        Returns:
            The generated UUID string.
        """
        token = str(uuid.uuid4())
        with self._lock:
            self._tokens.add(token)
        logger.info("Generated new API token: %s", token)
        return token

    def is_valid(self, token: Optional[str]) -> bool:
        """
        Check if an API token exists in the store.

        Args:
            token: API token to check.

        Returns:
            True if valid, False otherwise.
        """
        if not token:
            return False
        with self._lock:
            return token in self._tokens

    def add_token(self, token: str) -> None:
        """
        Manually add a known API token to the store.

        Args:
            token: API token to add.
        """
        with self._lock:
            self._tokens.add(token)

    def remove_token(self, token: str) -> None:
        """
        Remove an API token from the store.

        Args:
            token: API token to remove.
        """
        with self._lock:
            self._tokens.discard(token)

    def count(self) -> int:
        """
        Get count of active API tokens.

        Returns:
            Number of registered API tokens.
        """
        with self._lock:
            return len(self._tokens)


# Singleton token store instance
api_token_store = ApiTokenStore()

# Bearer security scheme for OpenAPI documentation
_bearer_scheme = HTTPBearer(auto_error=False)


async def verify_api_token(
    request: Request,
    x_api_token: Optional[str] = Header(None, alias="X-API-TOKEN")
) -> str:
    """
    Verify that incoming request provides a valid X-API-TOKEN header.

    Args:
        request: FastAPI Request instance.
        x_api_token: Value from X-API-TOKEN header.

    Returns:
        The validated API token.

    Raises:
        HTTPException: 401 if header is missing or token is not registered.
    """
    # Fallback to direct header check to support case-insensitive lookups
    token = x_api_token or request.headers.get("x-api-token") or request.headers.get("X-API-TOKEN")

    if not token or not api_token_store.is_valid(token):
        logger.warning("Unauthorized access attempt: Invalid or missing API token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token"
        )

    return token


async def verify_jwt(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme)
) -> Dict[str, Any]:
    """
    Verify that incoming request provides a valid JWT in Authorization header.

    Args:
        request: FastAPI Request instance.
        credentials: Extracted HTTP Bearer credentials.

    Returns:
        The decoded JWT payload dict containing 'sub' and 'exp'.

    Raises:
        HTTPException: 401 if Authorization header is missing or JWT is invalid.
    """
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        # Check raw Authorization header fallback
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if not token:
        logger.warning("Unauthorized access attempt: Missing Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT"
        )

    payload = validate_jwt(token)
    if not payload:
        logger.warning("Unauthorized access attempt: Invalid or expired JWT token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT"
        )

    return payload


async def get_current_user(
    jwt_payload: Dict[str, Any] = Depends(verify_jwt)
) -> str:
    """
    Extract the username (sub claim) from the verified JWT payload.

    Args:
        jwt_payload: Decoded JWT claims dictionary.

    Returns:
        The authenticated username.
    """
    return jwt_payload.get("sub", "")
