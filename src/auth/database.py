"""
Database management for SQLite authentication backend.
Replicates and manages the users table previously maintained in Rust with rusqlite.
"""

# Standard library imports
import os
from pathlib import Path
import sqlite3
from typing import List, Optional, Tuple

# Local imports
from src.core.logger import logger

# Default to users.db in the Adaptive-Rag project root
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "users.db"
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH", str(DEFAULT_DB_PATH))


def get_db_connection(db_path: str = AUTH_DB_PATH) -> sqlite3.Connection:
    """
    Establish a connection to the SQLite users database.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        sqlite3.Connection configured with Row factory.
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db(db_path: str = AUTH_DB_PATH) -> None:
    """
    Initialize the SQLite database and create the users table if it does not exist.

    Args:
        db_path: Path to the SQLite database file.
    """
    logger.info("Initializing authentication database at: %s", db_path)
    with get_db_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()


def create_user_record(
    username: str,
    password_hash: str,
    db_path: str = AUTH_DB_PATH
) -> bool:
    """
    Insert a new user record into the database.

    Args:
        username: Unique username.
        password_hash: Argon2id hash of user password.
        db_path: Path to the SQLite database file.

    Returns:
        True if the user was successfully created, False if user already exists.
    """
    init_auth_db(db_path)
    try:
        with get_db_connection(db_path) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            logger.info("User '%s' registered successfully", username)
            return True
    except sqlite3.IntegrityError:
        logger.warning("User '%s' already exists", username)
        return False
    except Exception as exc:
        logger.error("Error creating user '%s': %s", username, exc)
        return False


def get_user_by_username(
    username: str,
    db_path: str = AUTH_DB_PATH
) -> Optional[Tuple[str, str]]:
    """
    Retrieve user record by username.

    Args:
        username: Username to look up.
        db_path: Path to the SQLite database file.

    Returns:
        Tuple of (username, password_hash) if found, None otherwise.
    """
    init_auth_db(db_path)
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, password_hash FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                return (row["username"], row["password_hash"])
            return None
    except Exception as exc:
        logger.error("Error fetching user '%s': %s", username, exc)
        return None


def list_users(db_path: str = AUTH_DB_PATH) -> List[str]:
    """
    List all registered usernames in the database.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        List of usernames.
    """
    init_auth_db(db_path)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        return [row["username"] for row in cursor.fetchall()]
