"""
Error Debugger - Supervisor Agent
Multi-agent system using Strands framework on AgentCore Runtime

This supervisor orchestrates specialist agents to provide comprehensive
error analysis with diverse tools: parsing, security, context, root cause,
fixes, memory, and statistics.

BLOG SERIES FEATURE FLAGS:
- Part 1: Basic multi-agent system (5 agents: Supervisor, Parser, Security, Root Cause, Fix)
- Part 2: Advanced features (All 7 agents + Memory, Context, Stats)

DEMO MODE:
- DEMO_MODE=true: Use simulated responses (for local testing)
- DEMO_MODE=false: Use real AWS APIs (for production)
"""
import os
import sys
import json
import logging
from datetime import datetime
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# ============================================================================
# Configuration
# ============================================================================
# Import shared config to ensure consistency across all agents
from agents.config import DEMO_MODE, FEATURE_PART, AWS_REGION, BEDROCK_MODEL_ID

# Gateway Tools - Lambda functions called via Gateway (Parser, Security, Context, Stats)
from agents import gateway_tools

# Local agents that run in Runtime (Root Cause, Fix - LLM heavy)
from agents import (
    rootcause_agent,
    fix_agent,
)

# Part 2 agents (Memory runs locally for low latency)
if FEATURE_PART >= 2:
    from agents import memory_agent
else:
    memory_agent = None

# ============================================================================
# AgentCore Runtime App
# ============================================================================
app = BedrockAgentCoreApp()

# ============================================================================
# Logging Configuration
# ============================================================================
class SessionFilter(logging.Filter):
    """Add session_id to log records for tracing"""
    def __init__(self):
        super().__init__()
        self.session_id = None
    
    def set_session_id(self, session_id):
        self.session_id = session_id
    
    def filter(self, record):
        record.session_id = self.session_id or "unknown"
        return True

session_filter = SessionFilter()

def setup_logging():
    handler = logging.StreamHandler()
    handler.addFilter(session_filter)
    formatter = logging.Formatter("%(session_id)s | %(levelname)s | %(name)s | %(message)s")
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    
    # Configure strands logger
    strands_logger = logging.getLogger("strands")
    strands_logger.setLevel(logging.DEBUG)
    strands_logger.handlers.clear()
    strands_logger.addHandler(handler)
    strands_logger.propagate = False
    
    # Configure other loggers
    for logger_name in ['bedrock_agentcore', 'boto3', 'botocore']:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False

setup_logging()
logger = logging.getLogger(__name__)

# Log startup configuration
logger.info("=" * 60)
logger.info("🐛 Error Debugger Agent Starting")
logger.info(f"   Mode: {'DEMO' if DEMO_MODE else 'LIVE'}")
logger.info(f"   Feature Part: {FEATURE_PART}")
logger.info(f"   Agents: {'7 (full)' if FEATURE_PART >= 2 else '5 (core)'}")
logger.info("=" * 60)

# ============================================================================
# Component Status Tracking
# ============================================================================
# This tracks the status of each component and streams it to the frontend
component_status = {
    "supervisor": {"status": "idle", "message": None, "error": None},
    "parser": {"status": "idle", "message": None, "error": None},
    "security": {"status": "idle", "message": None, "error": None},
    "context": {"status": "idle", "message": None, "error": None},
    "github_file": {"status": "idle", "message": None, "error": None},
    "rootcause": {"status": "idle", "message": None, "error": None},
    "fix": {"status": "idle", "message": None, "error": None},
    "memory": {"status": "idle", "message": None, "error": None},
    "stats": {"status": "idle", "message": None, "error": None},
}

# ============================================================================
# Session Context Accumulator
# ============================================================================
# This accumulates context from all agents as they run.
# The supervisor should pass this accumulated context to subsequent agents.
session_context = {
    # Original error
    "original_error": "",
    
    # From Parser (structural info only - no static error_type classification)
    "parsed": {
        "language": "unknown",
        "language_confidence": 0,
        "core_message": "",
        "stack_frames": [],
        "file_paths": [],
        "raw_error": "",
    },
    
    # From Security
    "security": {
        "risk_level": "unknown",
        "safe_to_store": True,
        "pii_found": [],
        "secrets_found": [],
    },
    
    # From Memory
    "memory": {
        "matches": [],
        "has_solution": False,
        "best_match_similarity": 0,
    },
    
    # From Context
    "external": {
        "github_issues": [],
        "stackoverflow_questions": [],
        "stackoverflow_answers": [],
        "code_examples": [],
        "top_solutions": [],
        "common_causes": [],
    },
    
    # From Root Cause
    "analysis": {
        "root_cause": "",
        "explanation": "",
        "confidence": 0,
        "category": "",
        "contributing_factors": [],
    },
    
    # From Fix
    "fix": {
        "fixed_code": "",
        "fix_type": "",
        "explanation": "",
        "prevention": [],
    },
    
    # Reasoning trace
    "reasoning": [],
}

def reset_session_context():
    """Reset session context for new analysis."""
    global session_context
    session_context = {
        "original_error": "",
        "parsed": {"language": "unknown", "language_confidence": 0, "core_message": "", "stack_frames": [], "file_paths": [], "raw_error": ""},
        "security": {"risk_level": "unknown", "safe_to_store": True, "pii_found": [], "secrets_found": []},
        "memory": {"matches": [], "has_solution": False, "best_match_similarity": 0},
        "external": {"github_issues": [], "stackoverflow_questions": [], "stackoverflow_answers": [], "code_examples": [], "top_solutions": [], "common_causes": []},
        "analysis": {"root_cause": "", "explanation": "", "confidence": 0, "category": "", "contributing_factors": []},
        "fix": {"fixed_code": "", "fix_type": "", "explanation": "", "prevention": []},
        "reasoning": [],
    }

def update_session_context(section: str, data: dict):
    """Update a section of the session context."""
    if section in session_context and isinstance(session_context[section], dict):
        session_context[section].update(data)
    logger.info(f"📝 Session context updated: {section}")

def add_reasoning(step: str, thought: str):
    """Add a reasoning step to the trace."""
    session_context["reasoning"].append({
        "step": step,
        "thought": thought,
        "timestamp": datetime.utcnow().isoformat()
    })

def get_accumulated_context() -> str:
    """Get the full accumulated context as JSON for passing to agents."""
    return json.dumps(session_context, indent=2)

def reset_component_status():
    """Reset all component status to idle."""
    for key in component_status:
        component_status[key] = {"status": "idle", "message": None, "error": None}
    reset_session_context()

def update_component_status(component: str, status: str, message: str = None, error: str = None):
    """Update a component's status and log it."""
    component_status[component] = {
        "status": status,
        "message": message,
        "error": error,
    }
    if status == "running":
        logger.info(f"🔄 [{component.upper()}] Starting: {message or 'Processing...'}")
    elif status == "success":
        logger.info(f"✅ [{component.upper()}] Success: {message or 'Complete'}")
    elif status == "error":
        logger.error(f"❌ [{component.upper()}] Error: {error or 'Unknown error'}")
    elif status == "skipped":
        logger.info(f"⏭️ [{component.upper()}] Skipped: {message or 'Not needed'}")

def format_status_update(component: str) -> str:
    """Format a status update as a JSON string for streaming."""
    import json
    return f"\n[[STATUS:{json.dumps({'component': component, **component_status[component]})}]]\n"

# ============================================================================
# Tool Execution Callback
# ============================================================================
def event_loop_tracker(**kwargs):
    """Track tool executions for observability"""
    if "current_tool_use" in kwargs and kwargs["current_tool_use"].get("name"):
        tool_name = kwargs["current_tool_use"]["name"]
        tool_descriptions = {
            # Parser Agent Tools
            "parser_agent_tool": "📋 EXECUTING: Parser Agent (extracting stack frames, detecting language)",
            
            # Security Agent Tools
            "security_agent_tool": "🔒 EXECUTING: Security Agent (PII detection, secret scanning)",
            
            # Context Agent Tools
            "context_agent_tool": "🔍 EXECUTING: Context Agent (GitHub, StackOverflow search)",
            
            # GitHub File Reader
            "read_github_file_tool": "📄 EXECUTING: Reading file from GitHub repository",
            
            # Root Cause Agent Tools
            "rootcause_agent_tool": "🎯 EXECUTING: Root Cause Agent (LLM reasoning with all context)",
            
            # Fix Agent Tools
            "fix_agent_tool": "🔧 EXECUTING: Fix Agent (code generation, validation)",
            
            # Memory Operations
            "search_memory": "🔎 EXECUTING: Searching long-term memory for similar errors",
            "store_pattern": "💾 EXECUTING: Storing error pattern in memory",
            
            # Stats Operations
            "record_stats": "📊 EXECUTING: Recording error statistics",
            "get_trend": "📈 EXECUTING: Analyzing error trends",
            
            # Context Accumulation
            "update_context": "📝 CONTEXT: Updating accumulated session context",
            "get_context": "📋 CONTEXT: Retrieving accumulated context",
            "add_reasoning_step": "💭 THINKING: Recording reasoning step",
            
            # Reflection/Iteration
            "evaluate_progress": "🤔 REFLECTING: Evaluating progress and deciding next steps",
        }
        description = tool_descriptions.get(tool_name, f"🔧 EXECUTING: {tool_name}")
        logger.info(description)

    if "data" in kwargs:
        data_snippet = kwargs["data"][:100] + ("..." if len(kwargs["data"]) > 100 else "")
        logger.info(f"📟 Streaming: {data_snippet}")


# ============================================================================
# PARSER TOOL (Lambda via Gateway)
# ============================================================================
@tool(
    name="parser_agent_tool",
    description="Parse error messages to extract structured information: stack frames, programming language, error type classification. Calls Parser Lambda via Gateway."
)
def parser_agent_tool(error_text: str) -> str:
    """Call Parser Lambda via Gateway to parse error messages."""
    update_component_status("parser", "running", f"Parsing {len(error_text)} chars...")
    try:
        result = gateway_tools.parse_error(error_text)
        language = result.get('language', 'unknown')
        
        if result.get('error'):
            update_component_status("parser", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("parser", "success", f"Detected: {language}")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("parser", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e)})


# ============================================================================
# SECURITY TOOL (Lambda via Gateway)
# ============================================================================
@tool(
    name="security_agent_tool",
    description="Scan error messages for security issues: PII detection, hardcoded secrets. Calls Security Lambda via Gateway."
)
def security_agent_tool(error_text: str) -> str:
    """Call Security Lambda via Gateway to scan for sensitive data."""
    update_component_status("security", "running", "Scanning for PII and secrets...")
    try:
        result = gateway_tools.scan_security(error_text)
        risk_level = result.get('risk_level', 'unknown')
        secrets = len(result.get('secrets_detected', []))
        pii = len(result.get('pii_entities', []))
        
        if result.get('error'):
            update_component_status("security", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("security", "success", f"Risk: {risk_level} | {secrets} secrets, {pii} PII")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("security", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "risk_level": "unknown"})


# ============================================================================
# CONTEXT TOOL (Lambda via Gateway)
# ============================================================================
@tool(
    name="context_agent_tool",
    description="""Search external resources for error context: GitHub Issues, Stack Overflow.
    
    IMPORTANT: Pass the actual values from the parser for better search results:
    - error_message: The core error message (not the full stack trace)
    - error_type: The classified error type (null_reference, import_error, config_error, etc.)
    - language: The detected programming language
    
    The more context you provide, the better the search results."""
)
def context_agent_tool(error_message: str, error_type: str = "unknown", language: str = "unknown") -> str:
    """Call Context Lambda via Gateway to search external resources."""
    update_component_status("context", "running", f"Searching GitHub/StackOverflow for {language} {error_type}...")
    try:
        # Pass all context to the search for better results
        result = gateway_tools.search_context(error_message, language, error_type)
        total_results = result.get('total_results', 0)
        
        if result.get('error'):
            update_component_status("context", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("context", "success", f"Found {total_results} external resources")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("context", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "github_issues": [], "stackoverflow_questions": []})


# ============================================================================
# GITHUB FILE READER TOOL (For reading source code from repos)
# ============================================================================
@tool(
    name="read_github_file_tool",
    description="Read a file from a GitHub repository to get source code context. Use when you have a repo URL and file path from the stack trace to understand the code causing the error."
)
def read_github_file_tool(repo_url: str, file_path: str, branch: str = "main") -> str:
    """Read a file from GitHub to get source code context."""
    update_component_status("github_file", "running", f"Reading {file_path}...")
    try:
        from agents.context_agent import read_github_file
        result = read_github_file(repo_url, file_path, branch)
        # result is already a JSON string from the tool
        parsed = json.loads(result)
        if parsed.get("success"):
            update_component_status("github_file", "success", f"Read {parsed.get('line_count', 0)} lines from {file_path}")
        else:
            update_component_status("github_file", "error", error=parsed.get('error', 'File not found'))
        return result
    except Exception as e:
        update_component_status("github_file", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e)})


# ============================================================================
# ROOT CAUSE AGENT TOOL (Uses: Pattern DB, Bedrock Claude)
# ============================================================================
@tool(
    name="rootcause_agent_tool",
    description="""Analyze error root cause using Bedrock Claude LLM for reasoning.
    
    IMPORTANT: This should be called LAST, after gathering all context.
    Pass ALL the context you've collected so the LLM can reason intelligently:
    - parsed_info: JSON from parser_agent_tool
    - external_context: JSON from context_agent_tool (GitHub/SO results)
    - memory_context: JSON from search_memory (similar past errors)
    
    The LLM will synthesize all this information to determine the root cause.
    Returns hypothesis with confidence score."""
)
def rootcause_agent_tool(
    error_text: str, 
    parsed_info: str = "{}", 
    external_context: str = "{}",
    memory_context: str = "{}"
) -> str:
    """Route root cause analysis to the RootCause Agent with all gathered context."""
    update_component_status("rootcause", "running", "LLM reasoning with all gathered context...")
    try:
        # Parse all the context
        parsed = json.loads(parsed_info) if isinstance(parsed_info, str) else parsed_info
        external = json.loads(external_context) if isinstance(external_context, str) else external_context
        memory = json.loads(memory_context) if isinstance(memory_context, str) else memory_context
        
        # Pass all context to the root cause agent
        result = rootcause_agent.analyze(
            error_text=error_text, 
            parsed_info=parsed,
            external_context=external,
            memory_context=memory
        )
        
        confidence = result.get('confidence', 0)
        
        if result.get('error'):
            update_component_status("rootcause", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("rootcause", "success", f"{confidence}% confidence (LLM reasoning)")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("rootcause", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "root_cause": "unknown", "confidence": 0})


# ============================================================================
# FIX AGENT TOOL (Uses: Bedrock Claude, AST validation)
# ============================================================================
@tool(
    name="fix_agent_tool",
    description="""Generate code fixes using Bedrock Claude code generation.
    
    Pass context for the LLM to analyze:
    - error_text: The full error message and stack trace
    - root_cause: The identified root cause (from rootcause_agent)
    - language: The detected programming language
    - stack_frames: JSON of stack frames (helps identify which file/line to fix)
    - external_solutions: JSON of solutions found from GitHub/SO (optional but helpful)
    
    The LLM will analyze the error and generate an appropriate fix."""
)
def fix_agent_tool(
    error_text: str, 
    root_cause: str, 
    language: str = "unknown",
    stack_frames: str = "[]",
    external_solutions: str = "{}"
) -> str:
    """Route fix generation to the Fix Agent with full context."""
    update_component_status("fix", "running", f"Generating fix for {language}...")
    try:
        # Parse additional context
        frames = json.loads(stack_frames) if isinstance(stack_frames, str) else stack_frames
        solutions = json.loads(external_solutions) if isinstance(external_solutions, str) else external_solutions
        
        # Build enhanced context for the fix agent
        enhanced_context = {
            "error_text": error_text,
            "root_cause": root_cause,
            "stack_frames": frames,
            "external_solutions": solutions
        }
        
        result = fix_agent.generate(
            error_text=error_text,
            root_cause=root_cause,
            language=language,
            context=enhanced_context
        )
        fix_type = result.get('fix_type', 'unknown')
        
        if result.get('error'):
            update_component_status("fix", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("fix", "success", f"Generated {fix_type} fix")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("fix", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "fix_type": "unknown"})


# ============================================================================
# MEMORY TOOLS (Uses: AgentCore Memory API)
# ============================================================================
@tool(
    name="search_memory",
    description="""Search LONG-TERM memory for similar past errors.
    
    Uses AgentCore semantic search to find relevant debugging history and known solutions.
    
    TIP: Include language and error_type in the search text for better results.
    Example: "python import_error: No module named 'requests'" instead of just the error."""
)
def search_memory(error_text: str, limit: int = 5, language: str = "", error_type: str = "") -> str:
    """Search AgentCore memory for similar errors with context."""
    update_component_status("memory", "running", "Searching for similar past errors...")
    try:
        # Enhance search query with context for better semantic matching
        search_query = error_text
        if language and language != "unknown":
            search_query = f"[{language}] {search_query}"
        if error_type and error_type != "unknown":
            search_query = f"{error_type}: {search_query}"
        
        result = memory_agent.search(search_query, limit)
        count = result.get('count', 0)
        
        if result.get('error'):
            update_component_status("memory", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("memory", "success", f"Found {count} similar errors in memory")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("memory", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "results": []})


@tool(
    name="store_pattern",
    description="Store an error pattern and its solution in LONG-TERM semantic memory. Enables learning from past debugging to speed up future analysis."
)
def store_pattern(error_type: str, signature: str, root_cause: str, solution: str, language: str = "unknown") -> str:
    """Store error pattern in AgentCore memory."""
    logger.info(f"💾 Storing pattern: {error_type}")
    try:
        result = memory_agent.store_pattern(error_type, signature, root_cause, solution, language)
        logger.info(f"✅ Pattern stored")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Store pattern error: {str(e)}")
        return json.dumps({"error": str(e)})


# NOTE: store_session tool REMOVED
# Short-term memory was causing stale/wrong data to pollute new analyses.
# We now use the local session_context dict which is reset on each analysis.


# ============================================================================
# STATS TOOLS (Lambda via Gateway)
# ============================================================================
@tool(
    name="record_stats",
    description="Record error statistics. Calls Stats Lambda via Gateway to persist to DynamoDB."
)
def record_stats(error_type: str, language: str, resolved: bool = False) -> str:
    """Call Stats Lambda via Gateway to record an error occurrence."""
    update_component_status("stats", "running", f"Recording {error_type} stats...")
    try:
        result = gateway_tools.record_error(error_type, language, resolved)
        
        if result.get('error'):
            update_component_status("stats", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        update_component_status("stats", "success", f"Recorded {error_type} occurrence")
        return json.dumps({"success": True, **result})
    except Exception as e:
        update_component_status("stats", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e)})


@tool(
    name="get_trend",
    description="Analyze error trends. Calls Stats Lambda via Gateway to query DynamoDB."
)
def get_trend(error_type: str = "", window_days: int = 7) -> str:
    """Call Stats Lambda via Gateway to get trend analysis."""
    logger.info(f"📈 Calling Stats Lambda for trend: {error_type or 'all'}")
    try:
        result = gateway_tools.get_trend(error_type, window_days)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Stats Lambda error: {str(e)}")
        return json.dumps({"error": str(e)})


# ============================================================================
# CONTEXT ACCUMULATION TOOL
# ============================================================================
@tool(
    name="update_context",
    description="""Update the accumulated session context with new information.
    
    Call this after each agent returns to accumulate context.
    The accumulated context is then available to subsequent agents.
    
    Sections: parsed, security, memory, external, analysis, fix
    
    Example: update_context(section="parsed", data='{"language": "python", "error_type": "import_error"}')"""
)
def update_context(section: str, data: str) -> str:
    """Update accumulated session context."""
    try:
        parsed_data = json.loads(data) if isinstance(data, str) else data
        update_session_context(section, parsed_data)
        return json.dumps({
            "success": True,
            "section": section,
            "message": f"Context updated for {section}"
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@tool(
    name="get_context",
    description="""Get the full accumulated context from all agents so far.
    
    Returns everything learned during this session:
    - parsed: language, error_type, stack_frames
    - security: risk level, PII/secrets found
    - memory: similar past errors and solutions
    - external: GitHub issues, SO answers, code examples
    - analysis: root cause hypothesis
    - fix: generated fix
    
    Use this to review what you know before deciding next steps."""
)
def get_context() -> str:
    """Get full accumulated session context."""
    return get_accumulated_context()


@tool(
    name="add_reasoning_step",
    description="""Record a reasoning step in the session trace.
    
    Call this to document your thinking process.
    Helps with debugging and understanding the analysis flow."""
)
def add_reasoning_step(step: str, thought: str) -> str:
    """Add a reasoning step to the trace."""
    add_reasoning(step, thought)
    return json.dumps({"success": True, "step": step})


# ============================================================================
# REFLECTION TOOL - For iterative reasoning
# ============================================================================
@tool(
    name="evaluate_progress",
    description="""Evaluate your current progress and decide whether to continue gathering information or produce final output.
    
    Call this tool to:
    1. Summarize what you know so far
    2. Identify gaps in your knowledge
    3. Assess your confidence level
    4. Decide next action
    
    This helps you iterate until you have a confident answer."""
)
def evaluate_progress(
    known_language: str = "unknown",
    known_error_type: str = "unknown",
    root_cause_hypothesis: str = "",
    confidence_percent: int = 0,
    gaps_in_knowledge: str = "",
    tools_already_used: str = "",
    proposed_next_action: str = ""
) -> str:
    """
    Reflection tool for the supervisor to evaluate its own progress.
    This encourages iterative thinking rather than linear execution.
    """
    logger.info(f"🤔 Evaluating progress: {confidence_percent}% confidence")
    
    # Determine recommendation
    if confidence_percent >= 80:
        recommendation = "HIGH_CONFIDENCE: You can produce final output."
        should_continue = False
    elif confidence_percent >= 60:
        recommendation = "MODERATE_CONFIDENCE: Consider gathering one more piece of context, or proceed if time-constrained."
        should_continue = True
    elif confidence_percent >= 40:
        recommendation = "LOW_CONFIDENCE: You should gather more information before concluding."
        should_continue = True
    else:
        recommendation = "VERY_LOW_CONFIDENCE: You need significantly more information. Re-examine your approach."
        should_continue = True
    
    # Suggest next actions based on gaps
    suggested_actions = []
    gaps_lower = gaps_in_knowledge.lower()
    tools_used = tools_already_used.lower()
    
    if "language" in gaps_lower and "parser" not in tools_used:
        suggested_actions.append("Call parser_agent_tool to detect language")
    if "context" in gaps_lower and "context" not in tools_used:
        suggested_actions.append("Call context_agent_tool to search external resources")
    if "root cause" in gaps_lower and "rootcause" not in tools_used:
        suggested_actions.append("Call rootcause_agent_tool with all gathered context")
    if "memory" in gaps_lower and "memory" not in tools_used:
        suggested_actions.append("Call search_memory to find similar past errors")
    if "file" in gaps_lower or "code" in gaps_lower:
        suggested_actions.append("Call read_github_file_tool if you have a repo/file reference")
    
    if not suggested_actions and should_continue:
        suggested_actions.append("Try context_agent_tool with different search terms")
        suggested_actions.append("Re-examine the error for patterns you might have missed")
    
    result = {
        "current_state": {
            "language": known_language,
            "error_type": known_error_type,
            "root_cause_hypothesis": root_cause_hypothesis,
            "confidence": confidence_percent
        },
        "assessment": {
            "recommendation": recommendation,
            "should_continue_gathering": should_continue,
            "gaps_identified": gaps_in_knowledge
        },
        "suggested_next_actions": suggested_actions,
        "your_proposed_action": proposed_next_action
    }
    
    logger.info(f"📊 Evaluation: {recommendation}")
    return json.dumps(result, indent=2)


# ============================================================================
# Supervisor Agent System Prompt
# ============================================================================
SUPERVISOR_PROMPT = """You are an Expert Error Debugging Supervisor. You are an ITERATIVE, REFLECTIVE agent.

# YOUR CORE BEHAVIOR

You do NOT just run tools in a linear pipeline and output results.
You THINK → ACT → OBSERVE → REFLECT → DECIDE whether to continue or output.

**You keep iterating until you are CONFIDENT you have the correct answer.**

## The Loop

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. THINK: What do I know? What do I need to find out?              │
│  2. ACT: Call a tool to gather information                          │
│  3. OBSERVE: What did the tool return? Is it useful?                │
│  4. REFLECT: Do I have enough information? Am I confident?          │
│  5. DECIDE:                                                          │
│     - If confident (≥90%) → Produce final output                    │
│     - If not confident → Loop back to step 1                        │
└─────────────────────────────────────────────────────────────────────┘
```

## When to Loop Back

Re-run or try different approaches when:
- Parser returned "unknown" for language → Try inferring from patterns in the error
- Root cause confidence < 90% → Gather more context, try different search terms
- External context found 0 results → Try different search queries
- The fix doesn't seem to address the root cause → Re-analyze
- You realize you missed something → Go back and get it

## When to Produce Output

Only produce final output when:
- You have identified the language with reasonable confidence
- You have a root cause hypothesis with ≥90% confidence
- You have a concrete, actionable fix
- The fix actually addresses the root cause

# AVAILABLE TOOLS

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `parser_agent_tool` | Extract language, error type, stack trace | ALWAYS first |
| `security_agent_tool` | Detect PII/secrets | Before storing anything |
| `search_memory` | Find similar past errors | Early - might have instant solution |
| `context_agent_tool` | Search GitHub/StackOverflow | After parsing, for external solutions |
| `read_github_file_tool` | Read source code from repo | When stack trace references a file |
| `rootcause_agent_tool` | LLM reasoning with all context | After gathering ALL context |
| `fix_agent_tool` | Generate code fix | After root cause is determined |
| `record_stats` | Track statistics | At the end |
| `store_pattern` | Save solution to memory | When confident solution works |

# THINKING PROCESS

Before each action, think out loud:

```
<thinking>
What I know so far:
- Language: [known/unknown]
- Error type: [known/unknown]
- Root cause: [hypothesis/unknown]
- Confidence: [0-100]%

What I need to find out:
- [list gaps in knowledge]

Next action:
- [what tool to call and why]
</thinking>
```

After each tool result, reflect:

```
<reflection>
Tool returned: [summary]
This tells me: [insight]
My confidence is now: [0-100]%
Should I continue gathering info or am I ready to conclude?
</reflection>
```

# RECOMMENDED WORKFLOW

## Phase 1: Initial Information Gathering

1. **PARSE** the error to get structured data
   - If language is "unknown", look at the error patterns yourself
   - If error_type is "unknown", classify it based on keywords

2. **SECURITY** scan (parallel) - check for PII/secrets

3. **MEMORY** search - check for similar past errors
   - If high-similarity match found (>0.8), you might be done early!

## Phase 2: External Research (if needed)

4. **CONTEXT** search with good search terms
   - Use the actual error message, not generic terms
   - If 0 results, try different search terms
   - If stack trace mentions a GitHub repo, consider reading the file

## Phase 3: Reasoning (with ALL context)

5. **ROOT CAUSE** analysis
   - Pass ALL context gathered: parsed info, external findings, memory matches
   - If confidence < 90%, consider gathering more context
   - If the root cause seems wrong, question it

## Phase 4: Solution (only when confident)

6. **FIX** generation
   - Must match the detected language
   - Must address the identified root cause
   - If the fix seems generic or wrong, reconsider

7. **RECORD** stats and optionally store pattern for future

# ITERATION EXAMPLES

## Example 1: Low Confidence → Gather More
```
<thinking>
Parser returned language: unknown, error_type: unknown
Confidence: 20%
I need more information. Let me look at the error patterns myself.
The error mentions ".tf line 94" and "resource" - this is Terraform!
</thinking>

I'll re-interpret: this is a Terraform config_error. Now let me search for context...
```

## Example 2: Poor Search Results → Retry
```
<reflection>
Context search returned 0 GitHub issues.
Search term was too generic. Let me try with the specific error message.
</reflection>

context_agent_tool(error_message="Unsupported block type logging_configuration", ...)
```

## Example 3: Uncertain Root Cause → Dig Deeper
```
<reflection>
Root cause confidence: 55%
The analysis says "configuration error" but doesn't explain WHY.
Let me check if there's a GitHub file I can read for more context.
</reflection>

read_github_file_tool(repo_url="...", file_path="gateway.tf")
```

# OUTPUT FORMAT (only when ready)

When you are CONFIDENT (≥90%), produce the final output:

```markdown
## 🔍 Analysis Complete

**Language**: [language]
**Error Type**: [error_type]
**Confidence**: [confidence]%

### 📋 What Happened
[Clear explanation of the error]

### 🎯 Root Cause  
[Specific root cause - not generic]

**Why this happened**: [Technical explanation]

### 🔧 Solution

```[language]
[Actual code fix]
```

**Explanation**: [Why this fixes it]

### 📚 Resources
[Real URLs from context search]

### 🛡️ Prevention
[How to avoid this in the future]
```

# CRITICAL RULES

1. **ITERATE UNTIL CONFIDENT** - Don't output until you're sure
2. **THINK OUT LOUD** - Show your reasoning process
3. **REFLECT ON RESULTS** - Question tool outputs, don't blindly accept
4. **RE-RUN IF NEEDED** - Low confidence? Gather more info.
5. **BE SPECIFIC** - Generic answers are useless
6. **USE REAL DATA** - Only include URLs/info that came from tools
"""

# ============================================================================
# Supervisor Agent Instance
# ============================================================================

# Build tools list based on feature flags
def build_tools_list():
    """Build the tools list based on FEATURE_PART."""
    # Part 1: Core agents (always included)
    tools = [
        parser_agent_tool,
        security_agent_tool,
        rootcause_agent_tool,
        fix_agent_tool,
        # Context and reasoning tools (always available)
        update_context,           # Accumulate context between agents
        get_context,              # View accumulated context
        add_reasoning_step,       # Document thinking
        evaluate_progress,        # Reflection for iterative reasoning
    ]
    
    # Part 2: Advanced agents and features
    if FEATURE_PART >= 2:
        tools.extend([
            context_agent_tool,      # GitHub Issues, StackOverflow search
            read_github_file_tool,   # Read source files from GitHub repos
            search_memory,           # Memory operations
            store_pattern,
            # NOTE: store_session REMOVED - we use local session_context instead
            # Short-term memory was causing stale data to pollute new analyses
            record_stats,            # Statistics
            get_trend,
        ])
        logger.info(f"🔧 Part 2 enabled: {len(tools)} tools loaded (including Memory, Context, GitHub files, Stats)")
    else:
        logger.info(f"🔧 Part 1 enabled: {len(tools)} tools loaded (core agents only)")
    
    return tools

# Create supervisor with explicit model - don't use Strands default!
supervisor = Agent(
    model=BedrockModel(model_id=BEDROCK_MODEL_ID),  # Use Haiku 4.5, not Sonnet 4
    system_prompt=SUPERVISOR_PROMPT,
    tools=build_tools_list(),
    callback_handler=event_loop_tracker
)

logger.info(f"🤖 Supervisor using model: {BEDROCK_MODEL_ID}")

# ============================================================================
# AgentCore Runtime Entrypoint
# ============================================================================
@app.entrypoint
async def error_debugger(payload, context):
    """
    Main entrypoint for the error debugger supervisor agent.
    Invoked by AgentCore runtime for each request.
    """
    import traceback
    
    logger.info("=" * 50)
    logger.info("🚀 Error Debugger Entrypoint Called")
    logger.info(f"Payload: {payload}")
    logger.info("=" * 50)
    
    try:
        user_input = payload.get("prompt", "") if isinstance(payload, dict) else str(payload)
        session_id = payload.get("session_id", "unknown") if isinstance(payload, dict) else "unknown"
        mode = payload.get("mode", "comprehensive") if isinstance(payload, dict) else "comprehensive"
    
    # Set session context for logging
    session_filter.set_session_id(session_id)
    
        yield f"🔍 Starting error analysis...\n"
        yield f"📋 Mode: {mode}\n"
        
        if not user_input:
            yield "❌ Error: No error text provided\n"
            return
        
        logger.info(f"Input: {user_input[:200]}...")
    
    # Bypass tool consent for automation
    os.environ["BYPASS_TOOL_CONSENT"] = "true"
    
        # Build prompt
        if mode == "quick":
            prompt = f"""Quickly analyze this error:

ERROR: {user_input}

Run: parser, security, root cause, fix. Skip external searches.
"""
        else:
            prompt = f"""Comprehensively debug this error:

ERROR: {user_input}

Follow the full analysis workflow with all agents.
"""
        
        yield f"🤖 Invoking supervisor agent...\n"
        
        if supervisor is None:
            yield "❌ Error: Supervisor agent not initialized\n"
            return
        
        # Stream responses from supervisor agent
        event_count = 0
        async for event in supervisor.stream_async(prompt):
            event_count += 1
            
            if isinstance(event, dict):
            if "data" in event:
                yield event["data"]
                elif "text" in event:
                    yield event["text"]
                elif "content" in event:
                    yield str(event["content"])
                else:
                    yield json.dumps(event, default=str)
            elif isinstance(event, str):
                yield event
            else:
                yield str(event)
        
        yield f"\n✅ Analysis complete ({event_count} events)\n"
                
    except Exception as e:
        error_msg = f"❌ Error during analysis: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        yield error_msg + "\n"
        yield f"Stack trace:\n{traceback.format_exc()}\n"


# ============================================================================
# Main Entry Point
# ============================================================================
if __name__ == "__main__":
    logger.info("🚀 Starting Error Debugger AgentCore Runtime")
    logger.info("📦 Loaded agents: parser, security, context, rootcause, fix, memory, stats")
    logger.info("🔧 Tools: Regex, AST, Comprehend, GitHub API, StackOverflow API, Bedrock Claude, AgentCore Memory")
    app.run()

