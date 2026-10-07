"""
End-to-end integration test verifying that streamlit_app/utils/api_client.py
communicates successfully with the new Python FastAPI authentication endpoints.
"""

import threading
import time
import unittest
import uvicorn
import requests

from streamlit_app.utils.api_client import get_api_token, create_user, login_user

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000


class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        config = uvicorn.Config("src.main:app", host=SERVER_HOST, port=SERVER_PORT, log_level="warning")
        self.server = uvicorn.Server(config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


class TestApiClientWithServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_thread = ServerThread()
        cls.server_thread.start()
        # Wait for server to boot
        for _ in range(30):
            try:
                resp = requests.get(f"http://{SERVER_HOST}:{SERVER_PORT}/")
                if resp.status_code == 200:
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("Failed to start test FastAPI server")

    @classmethod
    def tearDownClass(cls):
        cls.server_thread.stop()

    def test_streamlit_api_client_flow(self):
        """Verify get_api_token, create_user, and login_user work as expected from api_client."""
        # 1. get_api_token()
        token = get_api_token()
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 10)

        # 2. create_user()
        test_username = f"st_user_{int(time.time())}"
        test_password = "SecretPassword123"
        success = create_user(test_username, test_password, token)
        self.assertTrue(success)

        # 3. login_user()
        login_res = login_user(test_username, test_password, token)
        self.assertIsNotNone(login_res)
        self.assertIn("jwt", login_res)
        self.assertIsNotNone(login_res["jwt"])
        print(f"\n[SUCCESS] Streamlit api_client end-to-end test passed! JWT: {login_res['jwt'][:20]}...")


if __name__ == "__main__":
    unittest.main()
