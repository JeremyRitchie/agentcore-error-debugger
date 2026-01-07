"""
Root Cause Agent - The reasoning brain of the error debugger

This agent's job is to THINK about the error using an LLM.
It synthesizes information from:
- Parser (language, error type, stack trace)
- Context (GitHub issues, Stack Overflow answers)
- Memory (previous similar errors)

The LLM is the PRIMARY reasoner, not a fallback.
Pattern matching is just a quick lookup for well-known errors.
"""
import json
import logging
import boto3
from typing import Dict, Any, Optional
from strands import Agent, tool

from .config import DEMO_MODE, AWS_REGION, BEDROCK_MODEL_ID

logger = logging.getLogger(__name__)

# Initialize Bedrock client
bedrock_runtime = None
try:
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=AWS_REGION)
    logger.info("✅ Bedrock runtime client initialized for RootCauseAgent")
except Exception as e:
    logger.warning(f"⚠️ Bedrock client init failed: {e}")


# =============================================================================
# QUICK LOOKUP - Known patterns (optional speed optimization, not the brain)
# =============================================================================

QUICK_SOLUTIONS = {
    # These are FAST lookups for well-documented errors
    # They supplement LLM reasoning, they don't replace it
    
    "cannot read property": "Null/undefined access - use optional chaining (?.) or add null check",
    "'nonetype' object has no attribute": "Function returned None - check return values and add None handling",
    "no module named": "Module not installed - run 'pip install <module>' and activate virtual environment",
    "cannot find module": "Package not installed - run 'npm install' and check import path",
    "econnrefused": "Service not running - start the target service and verify host/port",
    "unsupported block type": "Terraform block not supported - check provider docs for valid blocks",
}


def get_quick_solution(error_text: str) -> Optional[str]:
    """Fast lookup for well-known errors. Returns None if no quick match."""
    error_lower = error_text.lower()
    for pattern, solution in QUICK_SOLUTIONS.items():
        if pattern in error_lower:
            return solution
    return None


# =============================================================================
# TOOLS - Available for the agent
# =============================================================================

@tool(name="reason_about_error")
def reason_about_error(
    error_text: str,
    language: str = "unknown",
    error_type: str = "unknown",
    stack_trace: str = "",
    external_context: str = "",
    memory_context: str = ""
) -> str:
    """
    Use Bedrock Claude to reason about the error and determine root cause.
    This is the PRIMARY analysis method - uses LLM intelligence.
    
    Args:
        error_text: The full error message
        language: Detected programming language
        error_type: Classified error type
        stack_trace: Extracted stack trace frames
        external_context: Relevant GitHub/SO findings
        memory_context: Similar past errors from memory
    
    Returns:
        JSON with reasoning-based root cause analysis
    """
    logger.info("🧠 Using LLM to reason about error")
    
    # Build the analysis prompt
    prompt = f"""You are an expert software debugger. Analyze this error and determine the root cause.

## ERROR
```
{error_text}
```

## CONTEXT
- Language: {language}
- Error Type: {error_type}
{f"- Stack Trace: {stack_trace}" if stack_trace else ""}
{f"- External Context (from GitHub/StackOverflow): {external_context}" if external_context else ""}
{f"- Similar Past Errors: {memory_context}" if memory_context else ""}

## YOUR TASK
1. Determine the ROOT CAUSE - what specifically went wrong
2. Explain WHY it happened - the underlying mechanism
3. Provide the SOLUTION - actionable steps to fix it
4. Rate your CONFIDENCE (0-100)

## RESPONSE FORMAT
Respond with ONLY this JSON, no other text:
{{
    "root_cause": "One clear sentence explaining what caused this error",
    "explanation": "2-3 sentences explaining the underlying mechanism and why this happened",
    "solution": "Numbered list of specific steps to fix this",
    "confidence": 85,
    "category": "null_reference|import_error|config_error|type_error|connection_error|syntax_error|permission_error|async_error|other"
}}"""

    if not bedrock_runtime:
        logger.warning("Bedrock client not available")
        return json.dumps({
            "root_cause": "Unable to analyze - LLM not available",
            "explanation": "The Bedrock LLM service is not configured. Please check AWS credentials and region.",
            "solution": "1. Verify AWS credentials are configured\n2. Check Bedrock access is enabled\n3. Verify the region supports Bedrock",
            "confidence": 0,
            "category": "other",
            "error": "bedrock_not_available"
        })
    
    try:
        response = bedrock_runtime.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1500,
                "temperature": 0.2,  # Lower temperature for more precise analysis
                "messages": [{"role": "user", "content": prompt}]
            })
        )
        
        response_body = json.loads(response['body'].read())
        content = response_body.get('content', [{}])[0].get('text', '')
        
        logger.info(f"🧠 LLM response received ({len(content)} chars)")
        
        # Extract JSON from response
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end > start:
                result = json.loads(content[start:end])
                logger.info(f"✅ LLM analysis complete: {result.get('confidence', 0)}% confidence")
                return json.dumps(result)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON: {e}")
            # Return the raw content if JSON parsing fails
            return json.dumps({
                "root_cause": content[:200] if content else "LLM response parsing failed",
                "explanation": content,
                "solution": "Review the LLM response above for insights",
                "confidence": 30,
                "category": "other"
            })
            
    except Exception as e:
        logger.error(f"❌ Bedrock call failed: {str(e)}")
        return json.dumps({
            "root_cause": f"LLM analysis failed: {str(e)}",
            "explanation": "The Bedrock LLM call failed. This could be due to throttling, permissions, or service issues.",
            "solution": "1. Check CloudWatch logs for details\n2. Verify IAM permissions\n3. Try again in a moment",
            "confidence": 0,
            "category": "other",
            "error": str(e)
        })


@tool(name="check_known_solutions")
def check_known_solutions(error_text: str) -> str:
    """
    Quick lookup in known solutions database.
    This is a FAST supplementary check, not the primary analysis.
    
    Args:
        error_text: The error message to check
    
    Returns:
        JSON with known solution if found, empty if not
    """
    logger.info("🔍 Checking known solutions database")
    
    quick = get_quick_solution(error_text)
    
    if quick:
        logger.info(f"✅ Found known solution: {quick[:50]}...")
        return json.dumps({
            "found": True,
            "quick_solution": quick,
            "note": "This is a well-known error pattern. The LLM analysis may provide more detailed context."
        })
    
    logger.info("No known solution match")
    return json.dumps({
        "found": False,
        "note": "No quick match found. Use LLM analysis for detailed reasoning."
    })


# =============================================================================
# AGENT - The reasoning brain
# =============================================================================

ROOTCAUSE_AGENT_PROMPT = """You are the Root Cause Analysis Brain.

## YOUR PURPOSE
You THINK about errors using intelligence, not just pattern matching.
Your job is to REASON about why an error occurred and how to fix it.

## YOUR APPROACH
1. First, check_known_solutions for a quick answer (optional speed optimization)
2. Always use reason_about_error to deeply analyze the error
3. Combine quick solutions with deep analysis for the best answer

## WHAT YOU RECEIVE
- The error message (always)
- Parsed info: language, error type (from Parser agent)
- External context: GitHub issues, Stack Overflow answers (from Context agent)
- Memory context: Similar past errors (from Memory agent)

## WHAT YOU PRODUCE
A JSON object with:
{
    "root_cause": "Clear, specific explanation of what went wrong",
    "explanation": "Why this happened - the underlying mechanism",
    "solution": "Actionable steps to fix it",
    "confidence": 0-100,
    "category": "error category"
}

## IMPORTANT
- Be SPECIFIC, not generic. "Null pointer" is bad. "user.profile is undefined because the API returns null for deleted users" is good.
- Your solution should be ACTIONABLE. Not "fix the bug" but "add optional chaining: user?.profile?.name"
- Use the context provided to give INTELLIGENT analysis, not template responses.
"""

rootcause_agent = Agent(
    system_prompt=ROOTCAUSE_AGENT_PROMPT,
    tools=[reason_about_error, check_known_solutions],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def analyze(
    error_text: str,
    parsed_info: Dict = None,
    external_context: Dict = None,
    memory_context: Dict = None
) -> Dict[str, Any]:
    """
    Analyze root cause of an error using LLM reasoning.
    
    This is the main entry point for the root cause agent.
    It uses the LLM to THINK about the error, not just pattern match.
    
    Args:
        error_text: The full error message
        parsed_info: Output from parser agent (language, error_type, etc.)
        external_context: Output from context agent (GitHub, SO findings)
        memory_context: Output from memory agent (past similar errors)
        
    Returns:
        Dict with intelligent root cause analysis
    """
    logger.info("🔎 RootCauseAgent: Starting intelligent analysis")
    
    # Extract context for the LLM
    parsed = parsed_info or {}
    language = parsed.get('language', 'unknown')
    error_type = parsed.get('error_type', 'unknown')
    stack_trace = parsed.get('stack_trace', '')
    
    # Format external context
    ext_ctx = ""
    if external_context:
        github = external_context.get('github_results', [])
        so = external_context.get('stackoverflow_results', [])
        if github:
            ext_ctx += f"GitHub issues: {json.dumps(github[:3])}\n"
        if so:
            ext_ctx += f"StackOverflow: {json.dumps(so[:3])}\n"
    
    # Format memory context - but only if it's actually relevant
    mem_ctx = ""
    if memory_context:
        matches = memory_context.get('results', memory_context.get('matches', []))
        has_relevant = memory_context.get('has_relevant_match', False)
        best_score = memory_context.get('best_match_score', 0)
        
        if matches and has_relevant and best_score >= 70:
            # Only include memory context if it's actually a good match
            mem_ctx = f"Similar past errors (relevance: {best_score}%): {json.dumps(matches[:2])}"
        elif matches and best_score >= 50:
            # Include with a warning if it's a moderate match
            mem_ctx = f"Possibly related past errors (relevance: {best_score}% - verify these are relevant): {json.dumps(matches[:1])}"
        # If best_score < 50, don't include memory context at all - it's likely noise
    
    try:
        # Build the analysis request
        prompt = f"""Analyze this error:

Error: {error_text}

Available context:
- Language: {language}
- Error Type: {error_type}
{f"- Stack Trace: {stack_trace}" if stack_trace else ""}
{f"- External findings: {ext_ctx}" if ext_ctx else ""}
{f"- Past similar errors: {mem_ctx}" if mem_ctx else ""}

Use reason_about_error to provide intelligent analysis."""

        # Run the agent
        result = rootcause_agent(prompt)
        response_text = str(result)
        
        # Extract JSON from response
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed_result = json.loads(response_text[start:end])
                logger.info(f"✅ RootCauseAgent complete: {parsed_result.get('confidence', 0)}% confidence")
                return parsed_result
        except json.JSONDecodeError:
            pass
        
        # If agent response isn't JSON, call the tool directly
        logger.info("Agent response not JSON, calling tool directly")
        return _direct_analyze(error_text, language, error_type, stack_trace, ext_ctx, mem_ctx)
        
    except Exception as e:
        logger.error(f"❌ RootCauseAgent error: {str(e)}")
        return _direct_analyze(error_text, language, error_type, stack_trace, ext_ctx, mem_ctx)


def _direct_analyze(
    error_text: str,
    language: str = "unknown",
    error_type: str = "unknown",
    stack_trace: str = "",
    external_context: str = "",
    memory_context: str = ""
) -> Dict[str, Any]:
    """Direct tool call when agent wrapper fails."""
    try:
        result = reason_about_error(
            error_text=error_text,
            language=language,
            error_type=error_type,
            stack_trace=stack_trace,
            external_context=external_context,
            memory_context=memory_context
        )
        return json.loads(result)
    except Exception as e:
        logger.error(f"❌ Direct analysis failed: {str(e)}")
        return {
            "root_cause": "Analysis requires LLM - please check Bedrock configuration",
            "explanation": f"The root cause agent could not complete analysis. Error: {str(e)}",
            "solution": "1. Check that Bedrock is enabled in your AWS account\n2. Verify IAM permissions for bedrock:InvokeModel\n3. Check the AWS region supports Claude",
            "confidence": 0,
            "category": "other",
            "error": str(e)
        }
