"""
API routes for authentication and BFF chat interactions.
Replicates the endpoints previously hosted in the Rust Agentic-BFF service.
"""

# Standard library imports
from typing import Any, Dict

# Third-party imports
from fastapi import APIRouter, Depends, HTTPException, Request, status

# Local imports
from src.auth.database import create_user_record, get_user_by_username
from src.auth.dependencies import api_token_store, get_current_user, verify_api_token, verify_jwt
from src.auth.models import (
    ChatRequest,
    ChatResponse,
    CreateUserRequest,
    LoginRequest,
    StatusResponse,
    TokenResponse,
)
from src.auth.security import generate_jwt, hash_password, verify_password
from src.core.logger import logger

router = APIRouter(prefix="/api", tags=["Authentication & BFF"])


@router.post("/init", response_model=TokenResponse)
async def init_session() -> TokenResponse:
    """
    Initialize a client session by generating an API token.
    Public endpoint: does not require X-API-TOKEN or JWT.

    Returns:
        TokenResponse containing the generated api_token.
    """
    logger.info("Init API called")
    token = api_token_store.generate_token()
    return TokenResponse(api_token=token, jwt=None)


@router.post("/create_user", response_model=StatusResponse)
async def create_user(
    payload: CreateUserRequest,
    _: str = Depends(verify_api_token)
) -> StatusResponse:
    """
    Register a new user account with hashed password stored in SQLite.
    Requires a valid X-API-TOKEN header.

    Args:
        payload: Username and password for the new user.

    Returns:
        StatusResponse indicating successful creation.

    Raises:
        HTTPException: 400 if username is already taken.
    """
    logger.info("Creating user: %s", payload.username)
    hashed_pwd = hash_password(payload.password)
    success = create_user_record(payload.username, hashed_pwd)
    if not success:
        logger.warning("Failed to create user '%s': already exists", payload.username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )

    return StatusResponse(status="created")


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    _: str = Depends(verify_api_token)
) -> TokenResponse:
    """
    Authenticate user credentials and issue a JSON Web Token.
    Requires a valid X-API-TOKEN header.

    Args:
        payload: Login credentials (username and password).

    Returns:
        TokenResponse containing the generated JWT token.

    Raises:
        HTTPException: 401 if credentials are invalid.
    """
    logger.info("Login attempt for user: %s", payload.username)
    user_record = get_user_by_username(payload.username)

    if not user_record:
        logger.warning("Login failed: User '%s' not found", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    _, stored_hash = user_record
    if not verify_password(payload.password, stored_hash):
        logger.warning("Login failed: Password mismatch for user '%s'", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    jwt_token = generate_jwt(payload.username)
    logger.info("Login successful for user: %s", payload.username)
    return TokenResponse(api_token=None, jwt=jwt_token)


@router.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    current_user: str = Depends(get_current_user),
    _: str = Depends(verify_api_token)
) -> ChatResponse:
    """
    Protected chat endpoint requiring both a valid API token and JWT Bearer token.
    Processes the user query and returns the AI generated answer.

    Args:
        payload: Chat query request.
        current_user: Authenticated username extracted from JWT.

    Returns:
        ChatResponse containing the AI answer.
    """
    logger.info("Chat query from authenticated user '%s': %s", current_user, payload.query)

    try:
        from langchain_core.messages import HumanMessage, AIMessage
        from src.memory.chat_history_mongo import ChatHistory
        from src.api.routes import get_builder

        session_id = current_user
        chat_history = ChatHistory.get_session_history(session_id)
        await chat_history.add_message(HumanMessage(content=payload.query))

        messages = await chat_history.get_messages()
        rag_builder = get_builder()
        result = rag_builder.invoke({"messages": messages})
        answer_text = result["messages"][-1].content


        await chat_history.add_message(AIMessage(content=answer_text))
        return ChatResponse(answer=answer_text)

    except Exception as exc:
        logger.error("Error executing chat query: %s", exc)
        # If downstream RAG backend (MongoDB/Qdrant/LLM) encounters an error, return graceful message
        return ChatResponse(answer=f"AI service encountered an issue: {str(exc)}")
