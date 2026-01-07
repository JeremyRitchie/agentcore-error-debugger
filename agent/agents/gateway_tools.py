"""
Gateway Tools - Call Lambda functions via AgentCore Gateway (MCP Protocol)

This module provides the interface for agents running in the Runtime
to call external Lambda tools via the Gateway.

In DEMO mode, it falls back to simulated responses.
In LIVE mode, it calls the actual Gateway → Lambda.
"""
import os
import json
import logging
import boto3
from typing import Dict, Any, Optional

from .config import DEMO_MODE

logger = logging.getLogger(__name__)

# Gateway configuration
GATEWAY_ID = os.environ.get('GATEWAY_ID', '')

# Initialize Gateway client (only in live mode)
gateway_client = None
if not DEMO_MODE and GATEWAY_ID:
    try:
        gateway_client = boto3.client('bedrock-agentcore')
        logger.info(f"✅ Gateway client initialized: {GATEWAY_ID[:20]}...")
    except Exception as e:
        logger.warning(f"⚠️ Gateway client init failed: {e}")


class GatewayTools:
    """
    Wrapper for calling Lambda tools via AgentCore Gateway.
    
    Each method corresponds to a Lambda function exposed as an MCP tool.
    """
    
    @staticmethod
    def call_tool(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool via the Gateway.
        
        Args:
            tool_name: Name of the MCP tool (e.g., "parse_error", "scan_security")
            params: Tool parameters
            
        Returns:
            Tool response as dict
        """
        if DEMO_MODE or not gateway_client:
            logger.info(f"📦 Demo mode: Simulating {tool_name}")
            return GatewayTools._simulate_tool(tool_name, params)
        
        try:
            logger.info(f"🌐 Calling Gateway tool: {tool_name}")
            
            response = gateway_client.invoke_gateway(
                gatewayId=GATEWAY_ID,
                toolName=tool_name,
                toolInput=json.dumps(params)
            )
            
            result = json.loads(response.get('toolOutput', '{}'))
            logger.info(f"✅ Gateway tool {tool_name} completed")
            return result
            
        except Exception as e:
            logger.error(f"❌ Gateway call failed for {tool_name}: {e}")
            # Fall back to simulation on error
            return GatewayTools._simulate_tool(tool_name, params)
    
    @staticmethod
    def _simulate_tool(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate tool responses for demo mode."""
        
        if tool_name == "parse_error":
            return GatewayTools._simulate_parser(params)
        elif tool_name == "scan_security":
            return GatewayTools._simulate_security(params)
        elif tool_name == "search_error_context":
            return GatewayTools._simulate_context(params)
        elif tool_name == "manage_error_stats":
            return GatewayTools._simulate_stats(params)
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    
    # =========================================================================
    # PARSER TOOL
    # =========================================================================
    @staticmethod
    def parse_error(error_text: str) -> Dict[str, Any]:
        """
        Parse an error message to extract structured information.
        
        Calls: Parser Lambda via Gateway
        """
        return GatewayTools.call_tool("parse_error", {
            "error_text": error_text
        })
    
    @staticmethod
    def _simulate_parser(params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate parser response."""
        import re
        
        error_text = params.get("error_text", "")
        
        # Extract stack frames
        frames = []
        python_pattern = r'File "(.+)", line (\d+), in (\w+)'
        for match in re.finditer(python_pattern, error_text):
            frames.append({
                "file": match.group(1),
                "line": int(match.group(2)),
                "function": match.group(3)
            })
        
        js_pattern = r'at\s+(\w+)\s+\(([^:]+):(\d+):(\d+)\)'
        for match in re.finditer(js_pattern, error_text):
            frames.append({
                "file": match.group(2),
                "line": int(match.group(3)),
                "function": match.group(1)
            })
        
        # Detect language with comprehensive patterns
        language = "unknown"
        language_confidence = 0
        
        language_patterns = {
            "python": [
                (r'Traceback \(most recent call last\)', 95),
                (r'File ".*\.py"', 90),
                (r'\.py:', 80),
                (r'\bdef\s+\w+\s*\(', 60),
                (r'\bclass\s+\w+\s*[:\(]', 60),
                (r"(TypeError|ValueError|AttributeError|ImportError|KeyError|IndexError):", 70),
                (r"'NoneType' object", 85),
                (r'\bself\.\w+', 50),
            ],
            "javascript": [
                (r'at\s+\w+\s+\([^)]*\.js:\d+:\d+\)', 95),
                (r'\.js:\d+', 85),
                (r'TypeError:.*undefined', 80),
                (r'ReferenceError:', 75),
                (r"Cannot read propert", 70),
                (r'\bconst\s+\w+\s*=', 50),
                (r'\bfunction\s+\w+\s*\(', 50),
                (r'module\.exports', 70),
                (r'require\([\'"]', 65),
            ],
            "typescript": [
                (r'\.ts:\d+', 90),
                (r'\.tsx:\d+', 90),
                (r'error TS\d+:', 95),
                (r'interface\s+\w+\s*\{', 60),
            ],
            "java": [
                (r'at\s+[\w.]+\([\w]+\.java:\d+\)', 95),
                (r'\.java:\d+', 85),
                (r'Exception in thread', 90),
                (r'(NullPointerException|ClassNotFoundException|IOException)', 85),
                (r'public\s+(static\s+)?void\s+main', 70),
            ],
            "go": [
                (r'panic:', 95),
                (r'goroutine \d+', 90),
                (r'\.go:\d+', 85),
                (r'runtime error:', 80),
                (r'\bfunc\s+\w+\s*\(', 50),
            ],
            "rust": [
                (r'error\[E\d+\]:', 95),
                (r"thread '.*' panicked", 90),
                (r'\.rs:\d+', 85),
                (r'\bfn\s+\w+\s*\(', 50),
            ],
            "ruby": [
                (r'\.rb:\d+:in\s+', 95),
                (r'from\s+.*\.rb:\d+', 85),
                (r"(NoMethodError|NameError|ArgumentError):", 75),
            ],
            "php": [
                (r'PHP Fatal error:', 95),
                (r'PHP Warning:', 90),
                (r'\.php:\d+', 85),
                (r'Stack trace:', 70),
            ],
            "csharp": [
                (r'\.cs:\d+', 85),
                (r'at\s+[\w.]+\s+in\s+.*\.cs:line\s+\d+', 95),
                (r'(NullReferenceException|ArgumentException)', 80),
            ],
        }
        
        for lang, patterns in language_patterns.items():
            score = 0
            for pattern, weight in patterns:
                if re.search(pattern, error_text, re.IGNORECASE):
                    score += weight
            if score > language_confidence:
                language_confidence = score
                language = lang
        
        # Classify error type
        error_type = "unknown"
        error_lower = error_text.lower()
        if "undefined" in error_lower or "null" in error_lower or "none" in error_lower:
            error_type = "null_reference"
        elif "typeerror" in error_lower:
            error_type = "type_error"
        elif "syntaxerror" in error_lower:
            error_type = "syntax_error"
        elif "import" in error_lower or "module" in error_lower:
            error_type = "import_error"
        elif "connection" in error_lower or "timeout" in error_lower:
            error_type = "connection_error"
        
        return {
            "error_type": error_type,
            "language": language,
            "stack_frames": frames,
            "frame_count": len(frames),
            "mode": "demo"
        }
    
    # =========================================================================
    # SECURITY TOOL
    # =========================================================================
    @staticmethod
    def scan_security(text: str) -> Dict[str, Any]:
        """
        Scan text for PII and secrets.
        
        Calls: Security Lambda via Gateway
        """
        return GatewayTools.call_tool("scan_security", {
            "text": text
        })
    
    @staticmethod
    def _simulate_security(params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate security response."""
        import re
        
        text = params.get("text", "")
        
        # Detect secrets
        secrets = []
        secret_patterns = {
            "AWS_ACCESS_KEY": r'AKIA[0-9A-Z]{16}',
            "GITHUB_TOKEN": r'ghp_[A-Za-z0-9]{36}',
            "GENERIC_API_KEY": r'(?i)(api[_-]?key|token)\s*[=:]\s*[\'"]?([A-Za-z0-9_-]{20,})',
        }
        
        for secret_type, pattern in secret_patterns.items():
            if re.search(pattern, text):
                secrets.append(secret_type)
        
        # Detect PII
        pii = []
        pii_patterns = {
            "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "PHONE": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        }
        
        for pii_type, pattern in pii_patterns.items():
            if re.search(pattern, text):
                pii.append({"type": pii_type, "score": 0.9})
        
        has_sensitive = bool(secrets) or bool(pii)
        
        return {
            "has_sensitive_data": has_sensitive,
            "pii_entities": pii,
            "secrets_detected": secrets,
            "risk_level": "high" if secrets else "medium" if pii else "low",
            "mode": "demo"
        }
    
    # =========================================================================
    # CONTEXT TOOL
    # =========================================================================
    @staticmethod
    def search_context(error_text: str, language: str = "") -> Dict[str, Any]:
        """
        Search GitHub Issues and Stack Overflow for error context.
        
        Calls: Context Lambda via Gateway
        """
        return GatewayTools.call_tool("search_error_context", {
            "error_text": error_text,
            "language": language
        })
    
    @staticmethod
    def _simulate_context(params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate context response with REAL working URLs."""
        import urllib.parse
        
        error_text = params.get("error_text", "")
        error_lower = error_text.lower()
        
        # Extract search terms for real URLs
        import re
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', error_text)
        noise = {'the', 'a', 'an', 'is', 'are', 'was', 'in', 'on', 'for', 'to', 'of', 'at', 'line', 'file'}
        terms = [w for w in words if w.lower() not in noise and len(w) > 2][:5]
        search_query = ' '.join(terms)
        encoded_query = urllib.parse.quote(search_query)
        
        github_issues = []
        so_questions = []
        
        if "undefined" in error_lower or "null" in error_lower:
            github_issues.append({
                "title": "Cannot read property of undefined - React",
                "url": f"https://github.com/search?q={encoded_query}+is%3Aissue&type=issues",
                "state": "search",
                "comments": 0
            })
            so_questions.append({
                "title": "How to fix 'Cannot read property of undefined'?",
                "url": f"https://stackoverflow.com/search?q={encoded_query}",
                "score": 245,
                "is_answered": True
            })
        
        if "import" in error_lower or "module" in error_lower:
            github_issues.append({
                "title": "ModuleNotFoundError / ImportError",
                "url": f"https://github.com/search?q={encoded_query}+is%3Aissue&type=issues",
                "state": "search",
                "comments": 0
            })
            so_questions.append({
                "title": "ImportError: No module named X",
                "url": f"https://stackoverflow.com/search?q={encoded_query}",
                "score": 567,
                "is_answered": True
            })
        
        if "type" in error_lower and "error" in error_lower:
            so_questions.append({
                "title": "TypeError troubleshooting",
                "url": f"https://stackoverflow.com/search?q={encoded_query}+TypeError",
                "score": 189,
                "is_answered": True
            })
        
        if "connection" in error_lower or "timeout" in error_lower:
            so_questions.append({
                "title": "Connection/Timeout errors",
                "url": f"https://stackoverflow.com/search?q={encoded_query}",
                "score": 156,
                "is_answered": True
            })
        
        # Always add a general search link
        if not github_issues:
            github_issues.append({
                "title": f"Search GitHub for: {search_query[:40]}",
                "url": f"https://github.com/search?q={encoded_query}&type=issues",
                "state": "search",
                "comments": 0
            })
        
        if not so_questions:
            so_questions.append({
                "title": f"Search Stack Overflow for: {search_query[:40]}",
                "url": f"https://stackoverflow.com/search?q={encoded_query}",
                "score": 0,
                "is_answered": False
            })
        
        return {
            "query": search_query,
            "github_issues": github_issues,
            "stackoverflow_questions": so_questions,
            "total_results": len(github_issues) + len(so_questions),
            "search_urls": {
                "github": f"https://github.com/search?q={encoded_query}&type=issues",
                "stackoverflow": f"https://stackoverflow.com/search?q={encoded_query}"
            },
            "mode": "demo"
        }
    
    # =========================================================================
    # STATS TOOL
    # =========================================================================
    @staticmethod
    def record_error(error_type: str, language: str, resolved: bool = False) -> Dict[str, Any]:
        """
        Record an error occurrence.
        
        Calls: Stats Lambda via Gateway
        """
        return GatewayTools.call_tool("manage_error_stats", {
            "action": "record",
            "error_type": error_type,
            "language": language,
            "resolved": resolved
        })
    
    @staticmethod
    def get_frequency(error_type: str = "", days: int = 30) -> Dict[str, Any]:
        """
        Get error frequency.
        
        Calls: Stats Lambda via Gateway
        """
        return GatewayTools.call_tool("manage_error_stats", {
            "action": "get_frequency",
            "error_type": error_type,
            "days": days
        })
    
    @staticmethod
    def get_trend(error_type: str = "", window_days: int = 7) -> Dict[str, Any]:
        """
        Get error trend.
        
        Calls: Stats Lambda via Gateway
        """
        return GatewayTools.call_tool("manage_error_stats", {
            "action": "get_trend",
            "error_type": error_type,
            "window_days": window_days
        })
    
    @staticmethod
    def _simulate_stats(params: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate stats response."""
        from datetime import datetime
        
        action = params.get("action", "record")
        error_type = params.get("error_type", "unknown")
        
        if action == "record":
            return {
                "success": True,
                "action": "record",
                "error_type": error_type,
                "timestamp": datetime.utcnow().isoformat(),
                "mode": "demo"
            }
        elif action == "get_frequency":
            days = params.get("days", 30)
            return {
                "error_type": error_type or "all",
                "period_days": days,
                "count": 15,  # Simulated
                "frequency_per_day": round(15 / days, 2),
                "mode": "demo"
            }
        elif action == "get_trend":
            return {
                "error_type": error_type or "all",
                "window_days": params.get("window_days", 7),
                "current_count": 8,
                "previous_count": 5,
                "change_percent": 60.0,
                "trend": "increasing",
                "mode": "demo"
            }
        
        return {"error": f"Unknown action: {action}"}


# Convenience exports
parse_error = GatewayTools.parse_error
scan_security = GatewayTools.scan_security
search_context = GatewayTools.search_context
record_error = GatewayTools.record_error
get_frequency = GatewayTools.get_frequency
get_trend = GatewayTools.get_trend

