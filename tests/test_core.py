import unittest
import os
import sys

# Ensure library is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel_guard import Sentinel
from sentinel_guard.overseer import Overseer
from sentinel_guard.sql_proxy import SQLProxy

class TestSentinel(unittest.TestCase):
    
    def setUp(self):
        # Initialize Sentinel (uses default policy.json in parent dir which relies on working dir)
        # For tests, we assume running from root
        self.sentinel = Sentinel()

    def test_benign_plan(self):
        """Test that a safe plan is approved."""
        plan = {
            "id": "test-1",
            "agent": "TestBot",
            "role": "admin",
            "steps": [{"tool": "search_web", "args": {"query": "hello"}}]
        }
        allowed, reason = self.sentinel.overseer.review_plan(plan)
        self.assertTrue(allowed)
        self.assertIn("Approved", reason)

    def test_malicious_file_access(self):
        """Test that accessing .env is blocked."""
        plan = {
            "id": "test-2",
            "agent": "TestBot",
            "role": "admin",
            "steps": [{"tool": "read_file", "args": {"path": "C:/Users/Rohan/.env"}}]
        }
        allowed, reason = self.sentinel.overseer.review_plan(plan)
        self.assertFalse(allowed)
        self.assertIn("sensitive file", reason)

    def test_destructive_sql(self):
        """Test that DROP TABLE is blocked."""
        query = "DROP TABLE users"
        allowed, reason = self.sentinel.sql_proxy.intercept_query(query)
        self.assertFalse(allowed)
        self.assertIn("Forbidden keyword 'DROP'", reason)

    def test_exfiltration_sql(self):
        """Test that SELECT without LIMIT is blocked."""
        query = "SELECT * FROM users"
        allowed, reason = self.sentinel.sql_proxy.intercept_query(query)
        self.assertFalse(allowed)
        self.assertIn("missing LIMIT", reason)
        
    def test_valid_sql(self):
        """Test that SELECT with WHERE is allowed."""
        query = "SELECT * FROM users WHERE id=1"
        allowed, reason = self.sentinel.sql_proxy.intercept_query(query)
        self.assertTrue(allowed)

if __name__ == '__main__':
    unittest.main()
