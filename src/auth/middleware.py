"""
FastAPI / Starlette middleware replicating Actix Web's ApiTokenMiddleware and JwtMiddleware.
"""

# Standard library imports
from typing import Callable

# Third-party imports
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Local imports
from src.auth.dependencies import api_token_store
from src.auth.security import validate_jwt
from src.core.logger import logger


class AuthMiddleware(BaseHTTPMiddleware):
    """
    HTTP Middleware replicating the layered Actix Web middleware from Agentic-BFF:
    1. ApiTokenMiddleware: requires valid X-API-TOKEN on /api/* except /api/init
    2. JwtMiddleware: requires valid Bearer JWT on /api/chat
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the incoming request and enforce API token and JWT requirements.

        Args:
            request: The incoming Starlette/FastAPI request.
            call_next: The next ASGI handler in the chain.

        Returns:
            The HTTP response.
        """
        path = request.url.path

        # Only inspect /api/ routes
        if not path.startswith("/api"):
            return await call_next(request)

        # Allow /api/init without API token or JWT
        if path.endswith("/init"):
            return await call_next(request)

        # Validate X-API-TOKEN for /api endpoints
        token = request.headers.get("x-api-token") or request.headers.get("X-API-TOKEN")
        if not token or not api_token_store.is_valid(token):
            logger.warning("Middleware rejected request to %s: Invalid API token", path)
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API token"}
            )

        # Validate JWT for endpoints that require JWT (e.g. /api/chat)
        if path.endswith("/chat"):
            auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                logger.warning("Middleware rejected request to %s: Missing Bearer token", path)
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid JWT"}
                )

            jwt_token = auth_header[7:].strip()
            payload = validate_jwt(jwt_token)
            if not payload:
                logger.warning("Middleware rejected request to %s: Invalid or expired JWT", path)
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid JWT"}
                )

            # Store verified user info in request state
            request.state.user = payload.get("sub")
            request.state.jwt_payload = payload

        return await call_next(request)
