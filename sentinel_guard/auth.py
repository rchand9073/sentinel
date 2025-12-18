import json
import fnmatch
import logging

class AuthorityManager:
    """
    Manages Role-Based Access Control (RBAC) and Capability Tokens.
    Enforces 'Hard Enforcement' by checking permissions against a white-list policy.
    """
    
    def __init__(self, policy_path="auth_policy.json"):
        self.policy = self._load_policy(policy_path)
        
    def _load_policy(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"[Auth] Failed to load policy from {path}: {e}")
            return {"roles": {}}

    def check_permission(self, role, tool, args):
        """
        Determines if an agent with `role` is allowed to use `tool` with `args`.
        Returns: (bool, reason)
        """
        roles_config = self.policy.get("roles", {})
        
        if role not in roles_config:
            return False, f"Role '{role}' is not defined in auth policy."
            
        role_def = roles_config[role]
        allowed_tools = role_def.get("allowed_tools", [])
        
        # 1. Tool Permission Check
        if "*" not in allowed_tools and tool not in allowed_tools:
            return False, f"Rule Violation: Role '{role}' is not allowed to use tool '{tool}'."
            
        # 2. Context/Resource Scope Check (Capability Tokens)
        # If the tool operates on resources (files, commands), check the scope.
        resource_scopes = role_def.get("resource_scopes", {})
        
        # Extract target resource from args based on common conventions
        target_resource = self._extract_resource(tool, args)
        
        if target_resource:
            # If we have a specific scope for this tool, check it.
            # If "*" is in allowed_tools, we still might want to restrict resources if scopes are defined? 
            # Impl: If "*" is in allowed tools, and NO specific scope for tool, allow everything? 
            # Better security: Even if allowed_tool is "*", if resource_scopes has specific constraints, enforce them.
            # But usually "admin" has "*": ["*"].
            
            scopes = resource_scopes.get(tool, [])
            if "*" in resource_scopes: # Global override
                 scopes.extend(resource_scopes["*"])
            
            if not scopes:
                 # If tool is allowed but no scope is defined... 
                 # Secure by default: If target_resource is identified but no scope allows it, BLOCK?
                 # Or assume if allowed_tools has it, and scope is empty, it means ALL scopes?
                 # Let's go with: if scope is missing, default to DENY unless allowed_tools has * (super admin)
                 if "*" in allowed_tools:
                     return True, "Authorized (Admin)."
                 return False, f"Scope Violation: No resource scope defined for tool '{tool}'."

            # Check if target matches any allowed scope pattern
            matched = False
            for pattern in scopes:
                if fnmatch.fnmatch(target_resource, pattern):
                    matched = True
                    break
            
            if not matched:
                return False, f"Scope Violation: Access to '{target_resource}' not permitted by role '{role}'."

        return True, "Authorized."

    def _extract_resource(self, tool, args):
        """
        Helper to extract the primary resource (file path, command string) from tool args.
        """
        if not args:
            return None
            
        # File tools
        if tool in ["read_file", "view_file", "write_to_file", "run_command", "read_url_content"]:
            # Try common keys
            return args.get("path") or args.get("AbsolutePath") or args.get("TargetFile") or args.get("command") or args.get("CommandLine") or args.get("Url")
            
        return None
