from .overseer import Overseer
from .sql_proxy import SQLProxy
import functools

class Sentinel:
    """
    The Unified Agentic Firewall.
    Wraps Agent functions to enforce security policies automatically.
    """
    
    def __init__(self, policy_path="policy.json", sql_policy_path="sql_policy.json"):
        self.overseer = Overseer(policy_path)
        self.sql_proxy = SQLProxy(sql_policy_path)

    def guard(self, func):
        """
        Decorator to guard a function execution using the Overseer policy.
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Intelligent Inspection: Look for the plan in args or kwargs
            potential_plan = None
            
            # Check args
            for arg in args:
                if isinstance(arg, dict) and "steps" in arg:
                    potential_plan = arg
                    break
            
            # Check kwargs if not found
            if not potential_plan and "plan" in kwargs:
                potential_plan = kwargs["plan"]
                
            if potential_plan:
                allowed, reason = self.overseer.review_plan(potential_plan)
                if not allowed:
                        raise PermissionError(f"Sentinel Blocked Execution: {reason}")
            
            return func(*args, **kwargs)
        return wrapper
    
    def check_sql(self, query, agent_name="Agent"):
        """
        Direct check for SQL queries.
        """
        allowed, reason = self.sql_proxy.intercept_query(query, agent_name)
        if not allowed:
            raise PermissionError(f"Sentinel Blocked SQL: {reason}")
        return True
