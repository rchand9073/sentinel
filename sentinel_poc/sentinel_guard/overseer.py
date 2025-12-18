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
    
    def __init__(self, policy_path="policy.json"):
        self.policy = self._load_policy(policy_path)
        
    def _load_policy(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load policy: {e}")
            return {"rules": {}}

    def review_plan(self, plan):
        """
        Analyzes a plan for security violations using the loaded policy.
         Logs all decisions to audit.log.
        """
        plan_id = plan.get("id")
        agent_name = plan.get("agent")
        
        print(f"[Overseer] Intercepting Plan ID: {plan_id} from Agent: {agent_name}...")
        logging.info(f"INTERCEPT_EVENT: plan_id={plan_id} agent={agent_name}")
        
        steps = plan.get("steps", [])
        rules = self.policy.get("rules", {})
        
        for i, step in enumerate(steps):
            tool = step.get("tool")
            args = step.get("args", {})
            
            # Policy 1: File Access Control
            if tool in ["read_file", "view_file", "read_url_content"]: 
                path = args.get("path") or args.get("AbsolutePath") or args.get("TargetFile") or ""
                for sensitive in rules.get("sensitive_files", []):
                    if sensitive in path:
                        reason = f"Step {i+1} BLOCKED: Attempt to access sensitive file '{sensitive}'."
                        logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{reason}'")
                        return False, reason

            # Policy 2: Command/Network Safety
            if tool == "run_command":
                cmd = args.get("command") or args.get("CommandLine") or ""
                
                for prohibited in rules.get("prohibited_commands", []):
                    if prohibited in cmd:
                        reason = f"Step {i+1} BLOCKED: Prohibited command pattern detected '{prohibited}'."
                        logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{reason}'")
                        return False, reason
                
                for domain in rules.get("suspicious_domains", []):
                    if domain in cmd:
                        reason = f"Step {i+1} BLOCKED: Data exfiltration attempt to suspicious domain '{domain}'."
                        logging.warning(f"BLOCK_EVENT: plan_id={plan_id} reason='{reason}'")
                        return False, reason

        logging.info(f"APPROVE_EVENT: plan_id={plan_id} status=APPROVED")
        return True, "Plan Approved. No policy violations detected."

if __name__ == "__main__":
    print("This is the Overseer library. Please run 'main.py' to see the simulation.")

if __name__ == "__main__":
    print("This is the Overseer library. Please run 'main.py' to see the simulation.")
