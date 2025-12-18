import sys
import os

# Emulating installing the package by adding current dir to path
sys.path.append(os.getcwd())

from sentinel_guard import Sentinel
from rogue_agent import RogueAgent

# --- THE CUSTOMER CODEBASE ---

# 1. Initialize Sentinel (The only setup required)
sentinel = Sentinel()

class CustomerAgentPlatform:
    """
    This represents a startup's agent infrastructure (e.g. built on LangChain).
    """
    
    def __init__(self):
        self.agent_sim = RogueAgent()

    # 2. Add the Guard (The Integration)
    @sentinel.guard
    def execute_plan(self, plan):
        """
        Executes the agent's plan.
        We decorate this to ensure NO dangerous plan ever runs.
        """
        print(f"[Platform] Attempting to execute plan: {plan['goal']}")
        print("[Platform] Executing tools...")
        # ... logic to run tools ...
        print("[Platform] Success! Plan finished.")

# --- THE DEMO ---


def run_integration_demo():
    print("Initializing Customer Platform with Sentinel Protection...")
    platform = CustomerAgentPlatform()
    
    print("\n--- TEST 1: Benign Plan (viewer role) ---")
    try:
        # Agent generates a safe plan
        safe_plan = platform.agent_sim.generate_plan("benign")
        # Inject Identity/Role
        safe_plan["role"] = "analyst"  # Analyst allows reading files/searching
        # Note: If benign is 'search_web', we need to make sure 'analyst' allows it.
        # Let's check rogue_agent content next step, but for now assuming 'analyst' is privileged enough.
        platform.execute_plan(safe_plan)
    except PermissionError as e:
        print(f"[Sentinel Blocked]: {e}")
        
    print("\n--- TEST 2: Malicious Plan (viewer role) ---")
    try:
        # Agent generates a dangerous plan (reading .env)
        dangerous_plan = platform.agent_sim.generate_plan("malicious")
        dangerous_plan["role"] = "viewer" # Viewer trying to read .env
        platform.execute_plan(dangerous_plan)
    except PermissionError as e:
        print(f"[Sentinel CAUGHT IT!]: {e}")
        
    print("\n--- TEST 3: Admin Plan (admin role) ---")
    try:
        # Admin trying something usually blocked, but maybe allowed for admin?
        # Or just show admin works.
        admin_plan = {"goal": "Admin Maintenance", "agent": "Admin", "role": "admin", "steps": [{"tool": "read_file", "args": {"path": "logs/system.log"}}]}
        platform.execute_plan(admin_plan)
    except PermissionError as e:
         print(f"[Sentinel Blocked]: {e}")

if __name__ == "__main__":
    run_integration_demo()
