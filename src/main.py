"""
Main FastAPI application entry point.
Consolidates RAG routes and Authentication / BFF routes into a single service.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.auth_routes import router as auth_router
from src.api.routes import router as rag_router
from src.auth.database import init_auth_db
from src.auth.middleware import AuthMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager for startup and shutdown tasks.
    """
    # Initialize the authentication SQLite database
    init_auth_db()
    yield


app = FastAPI(
    title="Adaptive RAG API",
    description="Adaptive RAG and Python Authentication BFF Service",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend / Streamlit client access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enforce API token and JWT protection matching the Rust BFF middleware
app.add_middleware(AuthMiddleware)

# Include Authentication & BFF routes (/api/init, /api/create_user, /api/login, /api/chat)
app.include_router(auth_router)

# Include RAG routes (/rag/query, /rag/documents/upload)
app.include_router(rag_router)

app.state.description_ = ""


@app.get("/")
async def root():
    """Root endpoint to verify API is running."""
    return {"message": "Adaptive RAG API is running"}

