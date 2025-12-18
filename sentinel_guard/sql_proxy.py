import json
import logging
import re
import datetime

# Configure Logging (shared with Overseer or separate)
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SQLProxy:
    """
    The SQL Data Guard. Intercepts SQL queries and enforces Zero Trust data policies.
    """
    
    def __init__(self, policy_path="sql_policy.json"):
        self.policy = self._load_policy(policy_path)
        
    def _load_policy(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load SQL policy: {e}")
            return {"rules": {}}

    def intercept_query(self, query, agent_name="Unknown-Agent"):
        """
        Analyzes a SQL query against the policy.
        """
        print(f"[SQL Data Guard] Intercepting Query from {agent_name}: '{query}'")
        logging.info(f"SQL_INTERCEPT: agent={agent_name} query='{query}'")
        
        rules = self.policy.get("rules", {})
        query_upper = query.upper()
        
        # Rule 1: Forbidden Keywords (Destruction)
        for keyword in rules.get("forbidden_keywords", []):
            # Check for keyword surrounded by word boundaries
            if re.search(r'\b' + re.escape(keyword) + r'\b', query_upper):
                reason = f"Data Destruction Prevention: Forbidden keyword '{keyword}' detected."
                logging.warning(f"SQL_BLOCK: agent={agent_name} reason='{reason}'")
                return False, reason
                
        # Rule 2: Limit Enforcement (Data Dump Prevention)
        # Simplified logic: If it's a SELECT and doesn't have a LIMIT clause or specific ID check
        if "SELECT" in query_upper:
            # Check for generic "dump" patterns (no where, no limit)
            # This is a heuristic for the PoC
            has_limit = "LIMIT" in query_upper
            has_where_id = "ID =" in query_upper or "ID=" in query_upper
            
            if rules.get("require_limit") and not has_limit and not has_where_id:
                 reason = f"Data Exfiltration Prevention: SELECT query missing LIMIT clause or specific ID constraint."
                 logging.warning(f"SQL_BLOCK: agent={agent_name} reason='{reason}'")
                 return False, reason

        logging.info(f"SQL_APPROVE: agent={agent_name} status=APPROVED")
        return True, "Query Approved. Policy checks passed."

if __name__ == "__main__":
    print("This is the SQLProxy library. Please run 'sql_simulation.py' to see the demo.")
