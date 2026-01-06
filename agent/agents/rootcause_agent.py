"""
Root Cause Agent - Analyzes errors to determine root cause
Tools: Bedrock Claude for reasoning, pattern matching
"""
import re
import json
import logging
import boto3
from typing import Dict, Any, List
from strands import Agent, tool

logger = logging.getLogger(__name__)

# Initialize Bedrock client
try:
    bedrock_runtime = boto3.client('bedrock-runtime')
except Exception:
    bedrock_runtime = None

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
    """Fallback root cause analysis without LLM."""
    error_lower = error_text.lower()
    
    # Simple heuristic analysis
    if "undefined" in error_lower or "null" in error_lower:
        return {
            "root_cause": "Null or undefined value accessed",
            "explanation": "A variable or property is null/undefined when accessed. This commonly occurs with async data, optional values, or uninitialized variables.",
            "confidence": 70,
            "likely_location": "Property access or method call site",
            "contributing_factors": ["Missing null check", "Async timing issue", "Uninitialized variable"]
        }
    elif "import" in error_lower or "module" in error_lower:
        return {
            "root_cause": "Module import failure",
            "explanation": "The application cannot find or load a required module. This can be due to missing dependencies, wrong paths, or circular imports.",
            "confidence": 75,
            "likely_location": "Import statement at top of file",
            "contributing_factors": ["Missing npm install/pip install", "Wrong import path", "Typo in module name"]
        }
    elif "type" in error_lower and "error" in error_lower:
        return {
            "root_cause": "Type mismatch",
            "explanation": "An operation was performed on a value of unexpected type. This includes calling non-functions, wrong argument types, or unexpected data shapes.",
            "confidence": 65,
            "likely_location": "Function call or operation site",
            "contributing_factors": ["Wrong argument type", "Function doesn't exist", "Unexpected data format"]
        }
    else:
        return {
            "root_cause": "Error requires detailed analysis",
            "explanation": "The error pattern doesn't match common templates. Manual investigation recommended.",
            "confidence": 30,
            "likely_location": "Unknown",
            "contributing_factors": ["Check stack trace", "Review recent changes", "Verify data flow"]
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

