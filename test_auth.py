"""
Comprehensive test script for the Python authentication system.
Tests hashing, JWT, SQLite database, and FastAPI endpoints.
"""

# Standard library imports
import os
import sys
import unittest
import uuid

# Third-party imports
from fastapi.testclient import TestClient

# Local imports
from src.main import app
from src.auth.database import (
    create_user_record,
    get_user_by_username,
    init_auth_db,
    list_users,
    AUTH_DB_PATH
)
from src.auth.dependencies import api_token_store
from src.auth.security import (
    generate_jwt,
    hash_password,
    validate_jwt,
    verify_password
)


class TestAuthenticationUnit(unittest.TestCase):
    """Unit tests for security and database helpers."""

    def test_argon2_hashing(self):
        """Test password hashing and verification with Argon2."""
        raw_password = "SecurePassword123!"
        hashed = hash_password(raw_password)
        self.assertTrue(hashed.startswith("$argon2id$"))
        self.assertTrue(verify_password(raw_password, hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))

    def test_jwt_generation_and_validation(self):
        """Test JWT token generation and validation."""
        username = "test_user_jwt"
        token = generate_jwt(username, expires_in=60)
        self.assertIsInstance(token, str)

        payload = validate_jwt(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], username)
        self.assertIn("exp", payload)

        # Invalid token check
        self.assertIsNone(validate_jwt("invalid.token.here"))

    def test_database_operations(self):
        """Test SQLite database user creation and retrieval."""
        test_user = f"user_{uuid.uuid4().hex[:8]}"
        test_pwd_hash = hash_password("secret_pwd")

        created = create_user_record(test_user, test_pwd_hash)
        self.assertTrue(created)

        # Duplicate user creation should fail
        duplicate = create_user_record(test_user, test_pwd_hash)
        self.assertFalse(duplicate)

        # Fetch user
        user = get_user_by_username(test_user)
        self.assertIsNotNone(user)
        self.assertEqual(user[0], test_user)
        self.assertEqual(user[1], test_pwd_hash)

    def test_existing_database_users(self):
        """Test that pre-existing users (e.g. alice from Agentic-BFF) are present."""
        users = list_users()
        self.assertIn("alice", users)
        alice_record = get_user_by_username("alice")
        self.assertIsNotNone(alice_record)
        self.assertTrue(alice_record[1].startswith("$argon2id$"))


class TestAuthenticationApi(unittest.TestCase):
    """Integration tests for FastAPI endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        """Test root / health endpoint."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Adaptive RAG API is running"})

    def test_full_auth_flow(self):
        """Test full end-to-end authentication flow: init -> create_user -> login -> chat."""
        # Step 1: /api/init
        init_resp = self.client.post("/api/init")
        self.assertEqual(init_resp.status_code, 200)
        init_data = init_resp.json()
        self.assertIn("api_token", init_data)
        api_token = init_data["api_token"]
        self.assertIsNotNone(api_token)
        self.assertIsNone(init_data.get("jwt"))

        # Step 2: Attempt /api/create_user without API token (should fail 401)
        test_username = f"flow_user_{uuid.uuid4().hex[:8]}"
        test_password = "SuperPassword2026!"
        unauth_resp = self.client.post(
            "/api/create_user",
            json={"username": test_username, "password": test_password}
        )
        self.assertEqual(unauth_resp.status_code, 401)

        # Step 3: /api/create_user with valid API token
        create_resp = self.client.post(
            "/api/create_user",
            json={"username": test_username, "password": test_password},
            headers={"X-API-TOKEN": api_token}
        )
        self.assertEqual(create_resp.status_code, 200)
        self.assertEqual(create_resp.json(), {"status": "created"})

        # Step 4: /api/login with invalid password
        bad_login = self.client.post(
            "/api/login",
            json={"username": test_username, "password": "WrongPassword!"},
            headers={"X-API-TOKEN": api_token}
        )
        self.assertEqual(bad_login.status_code, 401)

        # Step 5: /api/login with valid credentials
        login_resp = self.client.post(
            "/api/login",
            json={"username": test_username, "password": test_password},
            headers={"X-API-TOKEN": api_token}
        )
        self.assertEqual(login_resp.status_code, 200)
        login_data = login_resp.json()
        self.assertIsNone(login_data.get("api_token"))
        self.assertIsNotNone(login_data.get("jwt"))
        jwt_token = login_data["jwt"]

        # Step 6: /api/chat without headers (should fail 401)
        chat_unauth = self.client.post(
            "/api/chat",
            json={"query": "Hello world"}
        )
        self.assertEqual(chat_unauth.status_code, 401)

        # Step 7: /api/chat with valid X-API-TOKEN and valid Bearer JWT
        from unittest.mock import MagicMock, patch
        from langchain_core.messages import AIMessage

        mock_builder = MagicMock()
        mock_builder.invoke.return_value = {"messages": [AIMessage(content="Hello! I am your AI Assistant.")]}

        with patch("src.api.routes.get_builder", return_value=mock_builder):
            chat_resp = self.client.post(
                "/api/chat",
                json={"query": "Hello world"},
                headers={
                    "X-API-TOKEN": api_token,
                    "Authorization": f"Bearer {jwt_token}"
                }
            )
            self.assertEqual(chat_resp.status_code, 200)
            self.assertIn("answer", chat_resp.json())


if __name__ == "__main__":
    unittest.main()

