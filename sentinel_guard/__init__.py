from .overseer import Overseer
from .sql_proxy import SQLProxy
from .auth import AuthorityManager
import functools
import json
import os

# --- DEFAULTS ---
DEFAULT_POLICY = {
    "rules": {
        "sensitive_files": ["/etc/passwd", ".env", "id_rsa", "config.yaml"],
        "prohibited_commands": ["rm -rf", "shutdown", ":(){ :|:& };:", "wget", "curl"]
    }
}

DEFAULT_AUTH = {
    "roles": {
        "restricted": {
            "allowed_tools": ["read_file"],
            "resource_scopes": {"read_file": ["/public/*", "*.log"]}
        },
        "admin": {
            "allowed_tools": ["*"],
            "resource_scopes": {"*": ["*"]}
        }
    }
}

DEFAULT_SQL = {
    "rules": {
        "forbidden_keywords": ["DROP", "TRUNCATE", "DELETE", "ALTER"],
        "require_limit": True
    }
}

class Sentinel:
    """
    The Unified Agentic Firewall.
    Wraps Agent functions to enforce security policies automatically.
    """
    
    def __init__(self, 
                 policy_path="policy.json", 
                 sql_policy_path="sql_policy.json", 
                 auth_policy_path="auth_policy.json",
                 auto_init=True):
        
        # 1. Zero-Config: Generate defaults if missing
        if auto_init:
            self._ensure_policies(policy_path, sql_policy_path, auth_policy_path)

        # 2. Initialize Components
        self.overseer = Overseer(policy_path, auth_policy_path)
        self.sql_proxy = SQLProxy(sql_policy_path)

    def _ensure_policies(self, p_path, s_path, a_path):
        """Helper to create default files if they don't exist."""
        configs = [
            (p_path, DEFAULT_POLICY),
            (s_path, DEFAULT_SQL),
            (a_path, DEFAULT_AUTH)
        ]
        for path, default_content in configs:
            if not os.path.exists(path):
                print(f"[Sentinel] First run detected. Creating safe default: {path}")
                try:
                    with open(path, 'w') as f:
                        json.dump(default_content, f, indent=4)
                except IOError:
                    print(f"[Sentinel] Warning: Could not write to {path}. Using in-memory defaults.")

    def guard(self, func):
        """
        Decorator to guard a function execution. 
        Supports generic dicts AND LangChain AgentAction objects.
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Intelligent Inspection
            potential_plan = None
            
            # A. Check for LangChain AgentAction (Duck Typing)
            # LangChain passes (tool, tool_input, log) or AgentAction objects
            for arg in args:
                if hasattr(arg, "tool") and hasattr(arg, "tool_input"):
                    potential_plan = self._normalize_langchain(arg)
                    break
            
            # B. Check for Standard "plan" dict in args/kwargs
            if not potential_plan:
                for arg in args:
                    if isinstance(arg, dict) and "steps" in arg:
                        potential_plan = arg
                        break
                if not potential_plan and "plan" in kwargs:
                    potential_plan = kwargs["plan"]
                
            # C. Execute Check
            if potential_plan:
                allowed, reason = self.overseer.review_plan(potential_plan)
                if not allowed:
                        raise PermissionError(f"Sentinel Blocked Execution: {reason}")
            
            return func(*args, **kwargs)
        return wrapper

    def _normalize_langchain(self, action):
        """Converts a LangChain AgentAction into a Sentinel Plan."""
        # Handle tool_input being a string (common in LC) or dict
        args = action.tool_input
        if isinstance(args, str):
            # Try to guess the key if it's a string, or wrap it
            # Simple heuristic: treat string input as "primary argument"
            args = {"input": args}
            
        return {
            "id": "langchain_action",
            "agent": "LangChainAgent",
            "role": "restricted",  # SAFE DEFAULT
            "steps": [{
                "tool": action.tool, 
                "args": args
            }]
        }
    
    def check_sql(self, query, agent_name="Agent"):
        allowed, reason = self.sql_proxy.intercept_query(query, agent_name)
        if not allowed:
            raise PermissionError(f"Sentinel Blocked SQL: {reason}")
        return True
