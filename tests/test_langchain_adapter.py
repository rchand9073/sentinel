import unittest
from sentinel_guard import Sentinel
import os

# Mock LangChain Object using simple Class
class AgentAction:
    def __init__(self, tool, tool_input, log=""):
        self.tool = tool
        self.tool_input = tool_input
        self.log = log
    
    def __repr__(self):
        return f"AgentAction(tool='{self.tool}', tool_input='{self.tool_input}')"

class TestLangChainAdapter(unittest.TestCase):
    
    def setUp(self):
        # Initialize Sentinel (will auto-gen defaults if missing, which is great to test too)
        # We explicitly set default_role to 'admin' for one test to ensure it overrides defaults
        self.sentinel = Sentinel(default_role="restricted")

    def test_adapter_blocking(self):
        """Test that a LangChain action (AgentAction) is intercepted and blocked for restricted role."""
        
        @self.sentinel.guard
        def execute_agent_action(action):
            return "Executed"

        # Action: read a sensitive file
        # Since default_role is 'restricted', this should fail immediately (no tools allowed)
        action = AgentAction(tool="read_file", tool_input={"path": ".env"})
        
        with self.assertRaises(PermissionError) as cm:
            execute_agent_action(action)
        
        print(f"\n[LangChain Test] Blocked Message: {cm.exception}")
        self.assertIn("Sentinel Blocked", str(cm.exception))

    def test_adapter_allowed(self):
        """Test that a LangChain action allows valid tools if we give permissions."""
        
        # Use a sentinel instance where default_role is 'admin' (just to verify flow works)
        # Note: In real usage, you'd configure 'auth_policy.json' to have a role for this.
        # But 'admin' is in the DEFAULT_AUTH_POLICY we just auto-generated (or existing).
        
        admin_sentinel = Sentinel(default_role="admin")
        
        @admin_sentinel.guard
        def execute_agent_action(action):
            return "Executed"

        action = AgentAction(tool="read_file", tool_input={"path": "logs/system.log"})
        
        try:
            result = execute_agent_action(action)
            self.assertEqual(result, "Executed")
            print("\n[LangChain Test] Allowed Action Passed!")
        except PermissionError:
            self.fail("LangChain Adapter should have allowed admin action.")

if __name__ == "__main__":
    unittest.main()
