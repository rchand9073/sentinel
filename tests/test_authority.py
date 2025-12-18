import unittest
from sentinel_guard.overseer import Overseer
import os
import json

class TestAuthoritySystem(unittest.TestCase):
    def setUp(self):
        # Create a temporary auth policy for testing
        self.test_auth_policy = {
            "roles": {
                "limited_viewer": {
                    "allowed_tools": ["read_file"],
                    "resource_scopes": {
                        "read_file": ["public/*.txt"]
                    }
                },
                "powerful_admin": {
                    "allowed_tools": ["*"],
                    "resource_scopes": {
                        "*": ["*"]
                    }
                },
                "suspicious_user": {
                    "allowed_tools": ["read_file"],
                    "resource_scopes": {
                        "read_file": ["public/*.txt"]
                    }
                }
            }
        }
        with open("test_auth_policy.json", "w") as f:
            json.dump(self.test_auth_policy, f)
            
        self.overseer = Overseer(policy_path="policy.json", auth_policy_path="test_auth_policy.json")

    def tearDown(self):
        if os.path.exists("test_auth_policy.json"):
            os.remove("test_auth_policy.json")

    def test_restricted_role_blocked_by_default(self):
        """Test that an agent with no role (defaults to restricted) is blocked."""
        plan = {
            "id": "test_1",
            "agent": "Guest",
            # No role specified -> restricted
            "steps": [
                {"tool": "read_file", "args": {"path": "public/readme.txt"}}
            ]
        }
        allowed, reason = self.overseer.review_plan(plan)
        self.assertFalse(allowed)
        self.assertIn("BLOCKED by AUTHORITY", reason)

    def test_limited_role_allowed_access(self):
        """Test that a role with specific permission can access potential resources."""
        plan = {
            "id": "test_2",
            "agent": "ViewerBot",
            "role": "limited_viewer",
            "steps": [
                {"tool": "read_file", "args": {"path": "public/readme.txt"}}
            ]
        }
        allowed, reason = self.overseer.review_plan(plan)
        self.assertTrue(allowed, f"Reason: {reason}")

    def test_limited_role_blocked_wrong_file(self):
        """Test context-scoped execution: Role allowed 'read_file' but not this specific file."""
        plan = {
            "id": "test_3",
            "agent": "ViewerBot",
            "role": "limited_viewer",
            "steps": [
                {"tool": "read_file", "args": {"path": "private/secret.txt"}}
            ]
        }
        allowed, reason = self.overseer.review_plan(plan)
        self.assertFalse(allowed)
        self.assertIn("Scope Violation", reason)

    def test_limited_role_blocked_wrong_tool(self):
        """Test role trying to use a tool not in allowed_tools."""
        plan = {
            "id": "test_4",
            "agent": "ViewerBot",
            "role": "limited_viewer",
            "steps": [
                {"tool": "run_command", "args": {"command": "ls"}}
            ]
        }
        allowed, reason = self.overseer.review_plan(plan)
        self.assertFalse(allowed)
        self.assertIn("not allowed to use tool", reason)

    def test_admin_role_access(self):
        """Test admin role with wildcard permissions."""
        plan = {
            "id": "test_5",
            "agent": "AdminBot",
            "role": "powerful_admin",
            "steps": [
                {"tool": "run_command", "args": {"command": "rm -rf /"}} # Dangerous but allowed for admin in this scope logic
            ]
        }
        # Note: It might still be caught by blacklist if configured, but here we focus on Auth.
        # Ensure our setUp didn't load a restrictive policy.json that blocks 'rm'.
        # The default Overseer loads 'policy.json' if it exists.
        
        allowed, reason = self.overseer.review_plan(plan)
        
        # If 'rm' is prohibited in policy.json, this checks Defense in Depth.
        # Let's assume policy.json might block it.
        # For this test, let's use a benign command that requires admin rights usually, 
        # or just check that Auth passed.
        
        # Let's use a benign command
        plan["steps"][0]["args"]["command"] = "ls -la"
        allowed, reason = self.overseer.review_plan(plan)
        self.assertTrue(allowed, f"Reason: {reason}")

    def test_defense_in_depth(self):
        """Test that even if Auth allows it, Blacklist can still block it (Confidentiality)."""
        # "suspicious_user" is allowed to read public txt files.
        # But let's say "public/virus.txt" is in the blacklist "sensitive_files" (mocking it)
        
        # We need to mock the blacklist policy for this specific test instance
        self.overseer.policy = {
            "rules": {
                "sensitive_files": ["public/virus.txt"]
            }
        }
        
        plan = {
            "id": "test_6",
            "agent": "Mole",
            "role": "suspicious_user",
            "steps": [
                {"tool": "read_file", "args": {"path": "public/virus.txt"}}
            ]
        }
        
        allowed, reason = self.overseer.review_plan(plan)
        self.assertFalse(allowed)
        self.assertIn("BLOCKED by BLACKLIST", reason)

if __name__ == '__main__':
    unittest.main()
