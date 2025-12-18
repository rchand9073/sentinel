import json
import logging
import datetime
import os

# Setup Audit Logging
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class Overseer:
    """
    The Defense Agent. Intercepts plans and validates them against an external security policy.
    Now with Audit Logging and Configurable Rules.
    """
    
    
    def __init__(self, policy_path="policy.json", auth_policy_path="auth_policy.json"):
        # Keep legacy policy for backward compatibility if needed, but primary is Auth now.
        self.policy = self._load_policy(policy_path)
        from .auth import AuthorityManager
        self.auth_manager = AuthorityManager(auth_policy_path)
        
    def _load_policy(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            # Non-critical if using Auth now, but good to log
            print(f"[ERROR] Failed to load legacy policy: {e}")
            return {"rules": {}}

    def review_plan(self, plan):
        """
        Analyzes a plan for security violations using the Authority Manager (Allowlist)
        AND the legacy Policy (Blacklist) as a defense-in-depth layer.
        """
        plan_id = plan.get("id")
        agent_name = plan.get("agent")
        role = plan.get("role", "restricted") # Default to restricted if no role
        
        print(f"[Overseer] Intercepting Plan ID: {plan_id} Agent: {agent_name} Role: {role}...")
        logging.info(f"INTERCEPT_EVENT: plan_id={plan_id} agent={agent_name} role={role}")
        
        steps = plan.get("steps", [])
        
        for i, step in enumerate(steps):
            tool = step.get("tool")
            args = step.get("args", {})
            
            # --- LAYER 1: Authority Check (Hard Enforcement) ---
            allowed, reason = self.auth_manager.check_permission(role, tool, args)
            if not allowed:
                 log_reason = f"Step {i+1} BLOCKED by AUTHORITY: {reason}"
                 logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{log_reason}'")
                 return False, log_reason

            # --- LAYER 2: Legacy Policy (Blacklist / Defense in Depth) ---
            # Even if allowed by role, we might want to catch specific known bad patterns
            # defined in policy.json (like specific suspicious domains independent of role)
            
            rules = self.policy.get("rules", {})
            
            # File Access additional checks
            if tool in ["read_file", "view_file", "read_url_content"]: 
                path = args.get("path") or args.get("AbsolutePath") or args.get("TargetFile") or ""
                for sensitive in rules.get("sensitive_files", []):
                    # If the auth policy was loose (e.g. logs/*), but we have a specific blacklist 
                    # for logs/secret.log, this catches it.
                    if sensitive in path:
                         log_reason = f"Step {i+1} BLOCKED by BLACKLIST: Access to sensitive file '{sensitive}'."
                         logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{log_reason}'")
                         return False, log_reason

            # Command Safety additional checks
            if tool == "run_command":
                cmd = args.get("command") or args.get("CommandLine") or ""
                for prohibited in rules.get("prohibited_commands", []):
                    if prohibited in cmd:
                        log_reason = f"Step {i+1} BLOCKED by BLACKLIST: Prohibited command pattern '{prohibited}'."
                        logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{log_reason}'")
                        return False, log_reason

        logging.info(f"APPROVE_EVENT: plan_id={plan_id} status=APPROVED")
        return True, "Plan Approved."

if __name__ == "__main__":
    print("This is the Overseer library. Please run 'main.py' to see the simulation.")

if __name__ == "__main__":
    print("This is the Overseer library. Please run 'main.py' to see the simulation.")
