import os
import tempfile
import unittest
import server

class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        server.DB = os.path.join(self.tmp.name, "test.sqlite3")
        server.init()

    def tearDown(self):
        server.DB = self.old_db
        self.tmp.cleanup()

    def test_schema_initializes(self):
        with server.db() as conn:
            names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"users", "tasks", "events", "messages", "calls", "signals"}.issubset(names))

    def test_password_hash_is_salted_and_stable(self):
        salt = b"0123456789abcdef"
        first = server.pw_hash("a-long-test-password", salt)
        self.assertEqual(first, server.pw_hash("a-long-test-password", salt))
        self.assertNotEqual(first, server.pw_hash("different-password", salt))

    def test_tokens_are_hashed(self):
        token = "example-session-token"
        self.assertNotEqual(token, server.token_hash(token))
        self.assertEqual(server.token_hash(token), server.token_hash(token))

if __name__ == "__main__":
    unittest.main()
