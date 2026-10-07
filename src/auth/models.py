"""
Pydantic models for authentication and BFF communication.
"""

from typing import Optional

from pydantic import BaseModel, Field


class CreateUserRequest(BaseModel):
    """
    Request model for creating a new user account.
    """

    username: str = Field(..., description="Unique username for the account")
    password: str = Field(..., min_length=1, description="Password for the account")


class LoginRequest(BaseModel):
    """
    Request model for user login authentication.
    """

    username: str = Field(..., description="Username for login")
    password: str = Field(..., min_length=1, description="Password for login")


class TokenResponse(BaseModel):
    """
    Response model containing API token or JWT authentication token.
    """

    api_token: Optional[str] = Field(
        default=None,
        description="Session API token (returned on /init)"
    )
    jwt: Optional[str] = Field(
        default=None,
        description="JSON Web Token (returned on /login)"
    )


class ChatRequest(BaseModel):
    """
    Request model for chat interaction.
    """

    query: str = Field(..., min_length=1, description="User query message")


class ChatResponse(BaseModel):
    """
    Response model for chat interaction.
    """

    answer: str = Field(..., description="AI generated answer")


class StatusResponse(BaseModel):
    """
    Generic status response model.
    """

    status: str = Field(..., description="Operation status result")
