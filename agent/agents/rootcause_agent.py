"""
Root Cause Agent - Analyzes errors to determine root cause
Tools: Bedrock Claude for reasoning, pattern matching

Uses Bedrock Claude in live mode, pattern matching fallback in demo mode.
"""
import re
import json
import logging
import boto3
from typing import Dict, Any, List
from strands import Agent, tool

from .config import DEMO_MODE, AWS_REGION

logger = logging.getLogger(__name__)

# Initialize Bedrock client (only in live mode)
bedrock_runtime = None
if not DEMO_MODE:
    try:
        bedrock_runtime = boto3.client('bedrock-runtime', region_name=AWS_REGION)
        logger.info("✅ Bedrock runtime client initialized")
    except Exception as e:
        logger.warning(f"⚠️ Bedrock client init failed: {e}")

# =============================================================================
# KNOWN PATTERNS DATABASE
# =============================================================================

KNOWN_PATTERNS = {
    "react_undefined_map": {
        "pattern": r"Cannot read propert.*'map'.*of undefined",
        "root_cause": "Array data is undefined when .map() is called, likely because async data hasn't loaded yet",
        "solution": "Add null check: data?.map() or data && data.map(), or initialize with empty array",
        "category": "async_data_race"
    },
    "python_none_attribute": {
        "pattern": r"'NoneType' object has no attribute",
        "root_cause": "Function returned None when object was expected, or variable was not properly initialized",
        "solution": "Check if function returns None on error. Add 'if variable is not None' check before use",
        "category": "null_reference"
    },
    "node_require_not_found": {
        "pattern": r"Cannot find module|MODULE_NOT_FOUND",
        "root_cause": "Node.js cannot locate the required module in node_modules or the specified path",
        "solution": "Run 'npm install' to install dependencies, or check import path spelling",
        "category": "import_error"
    },
    "python_import_circular": {
        "pattern": r"ImportError.*partially initialized module.*circular import",
        "root_cause": "Two modules import each other, creating a dependency cycle",
        "solution": "Move shared code to third module, or use lazy imports (import inside function)",
        "category": "circular_import"
    },
    "cors_error": {
        "pattern": r"CORS|Access-Control-Allow-Origin|blocked by CORS policy",
        "root_cause": "Server doesn't include CORS headers, blocking cross-origin requests from browser",
        "solution": "Configure server to send Access-Control-Allow-Origin header, or use a proxy",
        "category": "cors"
    },
    "connection_refused": {
        "pattern": r"ECONNREFUSED|Connection refused|connect ECONNREFUSED",
        "root_cause": "Target service is not running or not accepting connections on the specified port",
        "solution": "Verify service is running. Check port number. Check firewall rules.",
        "category": "connection_error"
    },
    "permission_denied_file": {
        "pattern": r"EACCES|Permission denied.*open|PermissionError.*open",
        "root_cause": "Process lacks read/write permission for the file or directory",
        "solution": "Check file permissions with ls -la. Change ownership or permissions with chmod/chown",
        "category": "permission_error"
    },
    "async_await_missing": {
        "pattern": r"\[object Promise\]|Promise.*pending|is not a function.*then",
        "root_cause": "Async function result used without await, resulting in Promise object instead of value",
        "solution": "Add 'await' before the async function call, or use .then() to handle the Promise",
        "category": "async_error"
    },
    "json_parse_error": {
        "pattern": r"JSON\.parse|Unexpected token.*JSON|SyntaxError.*JSON",
        "root_cause": "Attempting to parse invalid JSON string, often from API response",
        "solution": "Validate JSON format. Check API response content-type. Log raw response before parsing.",
        "category": "parse_error"
    },
    "database_connection": {
        "pattern": r"ETIMEDOUT.*sql|ER_ACCESS_DENIED|connection.*timeout.*database",
        "root_cause": "Database connection failed due to timeout, wrong credentials, or network issues",
        "solution": "Verify database host, port, credentials. Check network connectivity. Increase timeout.",
        "category": "database_error"
    },
}

# =============================================================================
# TOOLS - Root cause analysis
# =============================================================================

@tool(name="match_known_patterns")
def match_known_patterns(error_text: str) -> str:
    """
    Match error against database of known error patterns.
    Uses regex patterns to identify well-documented issues.
    
    Args:
        error_text: The error message to analyze
    
    Returns:
        JSON with matched patterns and known solutions
    """
    logger.info(f"🔍 Matching against {len(KNOWN_PATTERNS)} known patterns")
    
    matches = []
    
    for pattern_id, pattern_info in KNOWN_PATTERNS.items():
        if re.search(pattern_info["pattern"], error_text, re.IGNORECASE):
            matches.append({
                "pattern_id": pattern_id,
                "root_cause": pattern_info["root_cause"],
                "solution": pattern_info["solution"],
                "category": pattern_info["category"],
                "confidence": 90  # High confidence for pattern matches
            })
    
    result = {
        "matched_count": len(matches),
        "matches": matches,
        "has_known_solution": len(matches) > 0
    }
    
    logger.info(f"✅ Found {len(matches)} pattern matches")
    return json.dumps(result)


@tool(name="analyze_with_llm")
def analyze_with_llm(error_text: str, context: str = "") -> str:
    """
    Use Bedrock Claude to analyze the error and hypothesize root cause.
    Provides reasoning-based analysis for errors without known patterns.
    
    Args:
        error_text: The error message
        context: Additional context (parsed info, stack frames)
    
    Returns:
        JSON with LLM analysis and hypotheses
    """
    logger.info("🧠 Analyzing with Bedrock Claude")
    
    prompt = f"""Analyze this error and provide a root cause hypothesis.

Error:
{error_text}

{f"Additional Context: {context}" if context else ""}

Respond with a JSON object containing:
{{
    "root_cause": "Brief explanation of what caused this error",
    "explanation": "Detailed technical explanation",
    "confidence": 0-100,
    "likely_location": "Where in code this error originates",
    "contributing_factors": ["factor1", "factor2"]
}}"""

    if bedrock_runtime:
        try:
            response = bedrock_runtime.invoke_model(
                modelId="anthropic.claude-3-sonnet-20240229-v1:0",
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            response_body = json.loads(response['body'].read())
            content = response_body.get('content', [{}])[0].get('text', '{}')
            
            # Try to extract JSON from response
            try:
                start = content.find('{')
                end = content.rfind('}') + 1
                if start != -1 and end > start:
                    return content[start:end]
            except:
                pass
                
        except Exception as e:
            logger.warning(f"Bedrock call failed: {str(e)}, using fallback")
    
    # Fallback analysis
    return json.dumps(_fallback_analysis(error_text))


def _fallback_analysis(error_text: str) -> Dict[str, Any]:
    """Fallback root cause analysis without LLM - comprehensive pattern matching."""
    error_lower = error_text.lower()
    
    # Check for specific error patterns with detailed analysis
    
    # Null/Undefined errors
    if "cannot read propert" in error_lower and "undefined" in error_lower:
        return {
            "root_cause": "Accessing property on undefined object - likely async data not loaded",
            "explanation": "Code is trying to access a property (like .map, .length, etc.) on an undefined value. This commonly happens when: 1) API data hasn't loaded yet, 2) Object path is wrong, 3) Optional chaining not used.",
            "confidence": 85,
            "likely_location": "The line accessing the property - check the stack trace for the exact location",
            "contributing_factors": ["Missing null/undefined check", "Async race condition", "Wrong object path", "API returned null"]
        }
    elif "'nonetype' object has no attribute" in error_lower:
        return {
            "root_cause": "Method called on None in Python - function returned None unexpectedly",
            "explanation": "A function returned None instead of an expected object, and then code tried to call a method or access an attribute on that None value.",
            "confidence": 85,
            "likely_location": "Check what function returned None - look one level up in the call stack",
            "contributing_factors": ["Function missing return statement", "Error case returning None", "Failed API/DB call"]
        }
    elif "undefined" in error_lower or "null" in error_lower or "none" in error_lower:
        return {
            "root_cause": "Null or undefined value accessed",
            "explanation": "A variable or property is null/undefined when accessed. This commonly occurs with async data, optional values, or uninitialized variables.",
            "confidence": 75,
            "likely_location": "Property access or method call site",
            "contributing_factors": ["Missing null check", "Async timing issue", "Uninitialized variable"]
        }
    
    # Import/Module errors
    elif "no module named" in error_lower or "modulenotfounderror" in error_lower:
        return {
            "root_cause": "Python module not installed or not in path",
            "explanation": "Python cannot find the specified module. Either it's not installed, or it's not in the Python path.",
            "confidence": 90,
            "likely_location": "The import statement at the top of the file",
            "contributing_factors": ["Run 'pip install <module>'", "Activate virtual environment", "Check spelling of module name", "Check __init__.py exists for local modules"]
        }
    elif "cannot find module" in error_lower or "module_not_found" in error_lower:
        return {
            "root_cause": "Node.js module not found",
            "explanation": "Node.js cannot locate the required module in node_modules or the specified path.",
            "confidence": 90,
            "likely_location": "The require() or import statement",
            "contributing_factors": ["Run 'npm install'", "Check package.json", "Verify import path spelling", "Check if package exists"]
        }
    elif "import" in error_lower or "module" in error_lower:
        return {
            "root_cause": "Module import failure",
            "explanation": "The application cannot find or load a required module.",
            "confidence": 75,
            "likely_location": "Import statement at top of file",
            "contributing_factors": ["Missing dependency installation", "Wrong import path", "Circular import"]
        }
    
    # Type errors
    elif "is not a function" in error_lower:
        return {
            "root_cause": "Calling something that isn't a function",
            "explanation": "Code tried to call something as a function, but it's actually undefined, null, or a different type. Common when: 1) Method name is misspelled, 2) Object doesn't have that method, 3) Import is wrong.",
            "confidence": 85,
            "likely_location": "The function call site in the stack trace",
            "contributing_factors": ["Check method name spelling", "Verify object has the method", "Check import statement"]
        }
    elif "typeerror" in error_lower:
        return {
            "root_cause": "Type mismatch - operation on wrong type",
            "explanation": "An operation was performed on a value of unexpected type.",
            "confidence": 70,
            "likely_location": "Function call or operation site",
            "contributing_factors": ["Wrong argument type", "Unexpected data format", "Missing type conversion"]
        }
    
    # Syntax errors
    elif "syntaxerror" in error_lower or "unexpected token" in error_lower:
        return {
            "root_cause": "Code syntax is invalid",
            "explanation": "The code has a syntax error that prevents it from being parsed. This is usually a missing bracket, quote, or typo.",
            "confidence": 90,
            "likely_location": "The exact line/column mentioned in the error",
            "contributing_factors": ["Missing closing bracket/brace/paren", "Unclosed string", "Typo in keyword", "Invalid character"]
        }
    
    # Connection errors
    elif "econnrefused" in error_lower or "connection refused" in error_lower:
        return {
            "root_cause": "Target service not running or not accepting connections",
            "explanation": "The code tried to connect to a server/service that refused the connection. The target is either not running or blocking the connection.",
            "confidence": 90,
            "likely_location": "Network/API call in the code",
            "contributing_factors": ["Start the target service", "Check host/port is correct", "Check firewall rules", "Verify network connectivity"]
        }
    elif "timeout" in error_lower or "etimedout" in error_lower:
        return {
            "root_cause": "Network operation timed out",
            "explanation": "A network request took too long and was terminated. The server might be slow, unreachable, or overloaded.",
            "confidence": 85,
            "likely_location": "Network/API call in the code",
            "contributing_factors": ["Increase timeout value", "Check server health", "Check network connectivity", "Implement retry logic"]
        }
    
    # Permission errors
    elif "permission denied" in error_lower or "eacces" in error_lower:
        return {
            "root_cause": "Insufficient permissions for file/resource access",
            "explanation": "The process doesn't have permission to access the file, directory, or resource.",
            "confidence": 90,
            "likely_location": "File or resource access in the code",
            "contributing_factors": ["Check file permissions (ls -la)", "Run with appropriate user", "chmod/chown the file", "Check SELinux/AppArmor"]
        }
    
    # Key/Index errors
    elif "keyerror" in error_lower:
        return {
            "root_cause": "Dictionary key doesn't exist",
            "explanation": "Code tried to access a dictionary key that doesn't exist. The key name shown in the error is not in the dictionary.",
            "confidence": 90,
            "likely_location": "Dictionary access in the code",
            "contributing_factors": ["Use dict.get(key, default)", "Check key exists first", "Verify data structure", "Check for typos in key name"]
        }
    elif "indexerror" in error_lower or "index out of" in error_lower:
        return {
            "root_cause": "Array/list index out of bounds",
            "explanation": "Code tried to access an array/list index that doesn't exist. The list is shorter than expected.",
            "confidence": 90,
            "likely_location": "Array/list access in the code",
            "contributing_factors": ["Check array length before access", "Verify data is populated", "Use safe access patterns", "Check loop bounds"]
        }
    
    # Async errors
    elif "[object promise]" in error_lower or "promise" in error_lower and "pending" in error_lower:
        return {
            "root_cause": "Missing await on async function",
            "explanation": "An async function was called without 'await', so the code received a Promise object instead of the actual value.",
            "confidence": 85,
            "likely_location": "Async function call site",
            "contributing_factors": ["Add 'await' before the async call", "Use .then() to handle Promise", "Make parent function async"]
        }
    
    # Default fallback with better guidance
    else:
        return {
            "root_cause": "Error requires source code analysis for precise diagnosis",
            "explanation": "The error pattern doesn't match common templates. To provide accurate root cause analysis: 1) Check the stack trace for the exact file and line, 2) Review the code at that location, 3) Look at recent changes to that area.",
            "confidence": 40,
            "likely_location": "Check the stack trace - first file that's YOUR code (not library code)",
            "contributing_factors": [
                "Review the stack trace for exact location",
                "Check recent git commits to affected files", 
                "Add logging around the error location",
                "Verify input data is as expected"
            ]
        }


@tool(name="synthesize_hypothesis")
def synthesize_hypothesis(parsed_info: str, pattern_matches: str, llm_analysis: str) -> str:
    """
    Synthesize a final root cause hypothesis from multiple sources.
    Combines pattern matching and LLM analysis for best result.
    
    Args:
        parsed_info: JSON from parser agent
        pattern_matches: JSON from pattern matching
        llm_analysis: JSON from LLM analysis
    
    Returns:
        JSON with synthesized hypothesis
    """
    logger.info("🎯 Synthesizing root cause hypothesis")
    
    try:
        parsed = json.loads(parsed_info) if isinstance(parsed_info, str) else parsed_info
        patterns = json.loads(pattern_matches) if isinstance(pattern_matches, str) else pattern_matches
        llm = json.loads(llm_analysis) if isinstance(llm_analysis, str) else llm_analysis
    except json.JSONDecodeError:
        parsed, patterns, llm = {}, {}, {}
    
    # Prioritize pattern matches (highest confidence)
    if patterns.get("matches"):
        best_match = patterns["matches"][0]
        hypothesis = {
            "root_cause": best_match["root_cause"],
            "solution": best_match["solution"],
            "confidence": best_match["confidence"],
            "source": "known_pattern",
            "pattern_id": best_match["pattern_id"],
            "category": best_match.get("category", "unknown"),
            "additional_insights": llm.get("contributing_factors", [])
        }
    else:
        # Fall back to LLM analysis
        hypothesis = {
            "root_cause": llm.get("root_cause", "Unable to determine"),
            "solution": _generate_solution_from_llm(llm),
            "confidence": llm.get("confidence", 50),
            "source": "llm_analysis",
            "category": parsed.get("error_type", "unknown"),
            "additional_insights": llm.get("contributing_factors", [])
        }
    
    # Add parsed context
    hypothesis["error_type"] = parsed.get("error_type", "unknown")
    hypothesis["language"] = parsed.get("language", "unknown")
    
    logger.info(f"✅ Hypothesis: {hypothesis['root_cause'][:50]}...")
    return json.dumps(hypothesis)


def _generate_solution_from_llm(llm: Dict) -> str:
    """Generate solution suggestion from LLM analysis."""
    factors = llm.get("contributing_factors", [])
    
    if factors:
        return f"Address these factors: {', '.join(factors)}"
    
    return f"Investigate: {llm.get('likely_location', 'the error location')}"


# =============================================================================
# AGENT - Strands Agent with analysis tools
# =============================================================================

ROOTCAUSE_AGENT_PROMPT = """You are a Root Cause Analysis Specialist Agent.

## YOUR ROLE
Determine the root cause of errors by combining pattern matching and reasoning.
Provide actionable diagnosis for debugging.

## YOUR TOOLS
- match_known_patterns: Match against database of known error patterns (fast, high confidence)
- analyze_with_llm: Use Bedrock Claude for deeper reasoning (thorough, moderate confidence)
- synthesize_hypothesis: Combine findings into final hypothesis

## YOUR WORKFLOW
1. Call match_known_patterns to check for recognized errors
2. If no pattern match, call analyze_with_llm for reasoning
3. Call synthesize_hypothesis to combine all findings

## OUTPUT FORMAT
Return a JSON object with:
{
    "root_cause": "Clear explanation of what caused the error",
    "solution": "Actionable steps to fix the issue",
    "confidence": 0-100,
    "category": "error category",
    "source": "known_pattern|llm_analysis",
    "additional_insights": ["insight1", "insight2"]
}

Always return valid JSON only, no additional text.
"""

rootcause_agent = Agent(
    system_prompt=ROOTCAUSE_AGENT_PROMPT,
    tools=[match_known_patterns, analyze_with_llm, synthesize_hypothesis],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def analyze(error_text: str, parsed_info: Dict = None) -> Dict[str, Any]:
    """
    Analyze root cause of an error.
    
    Args:
        error_text: The error message
        parsed_info: Optional parsed info from parser agent
        
    Returns:
        Dict with root cause analysis
    """
    logger.info(f"🔎 RootCauseAgent: Analyzing error")
    
    try:
        context = json.dumps(parsed_info) if parsed_info else ""
        
        prompt = f"""Analyze the root cause of this error:

Error: {error_text}

{f"Parsed context: {context}" if context else ""}

Use pattern matching first, then LLM analysis if needed. Synthesize a hypothesis."""
        
        result = rootcause_agent(prompt)
        response_text = str(result)
        
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ RootCauseAgent complete: {parsed.get('confidence', 0)}% confidence")
                return parsed
        except json.JSONDecodeError:
            pass
        
        return _direct_analyze(error_text, parsed_info)
        
    except Exception as e:
        logger.error(f"❌ RootCauseAgent error: {str(e)}")
        return _direct_analyze(error_text, parsed_info)


def _direct_analyze(error_text: str, parsed_info: Dict = None) -> Dict[str, Any]:
    """Direct analysis fallback."""
    try:
        patterns = json.loads(match_known_patterns(error_text))
        llm = json.loads(analyze_with_llm(error_text))
        
        parsed_json = json.dumps(parsed_info or {})
        patterns_json = json.dumps(patterns)
        llm_json = json.dumps(llm)
        
        return json.loads(synthesize_hypothesis(parsed_json, patterns_json, llm_json))
    except Exception as e:
        return {
            "root_cause": "Analysis failed",
            "solution": "Manual investigation required",
            "confidence": 0,
            "category": "unknown",
            "source": "error",
            "error": str(e)
        }

