import unittest
import os
import json
from sentinel_guard import Sentinel

class TestAutoConfig(unittest.TestCase):
    
    def setUp(self):
        # Clean up existing policies to force auto-gen
        self.files = ["dummy_policy.json", "dummy_auth.json", "dummy_sql.json"]
        for f in self.files:
            if os.path.exists(f):
                os.remove(f)

    def tearDown(self):
        # Cleanup
        for f in self.files:
            if os.path.exists(f):
                os.remove(f)

    def test_auto_generate_defaults(self):
        """Test that Sentinel creates missing policy files with defaults."""
        
        # Files shouldn't exist yet
        for f in self.files:
            self.assertFalse(os.path.exists(f))
            
        # Init Sentinel with these paths
        Sentinel(policy_path=self.files[0], auth_policy_path=self.files[1], sql_policy_path=self.files[2])
        
        # Files should now exist
        for f in self.files:
            self.assertTrue(os.path.exists(f), f"File {f} was not auto-generated")
            
        # Verify content of one
        with open(self.files[0], 'r') as f:
            data = json.load(f)
            self.assertIn("description", data)
            self.assertIn("Safe Default", data["description"])

if __name__ == "__main__":
    unittest.main()
