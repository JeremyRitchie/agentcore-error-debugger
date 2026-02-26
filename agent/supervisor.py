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
from agents.config import DEMO_MODE, FEATURE_PART, AWS_REGION

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
    
    # From Memory (search_memory populates "results" and syncs to "matches")
    "memory": {
        "matches": [],
        "results": [],
        "has_solution": False,
        "has_solutions": False,
        "best_match_similarity": 0,
        "memory_searched": False,
        "pattern_stored": False,
        "stored_patterns": [],
    },
    
    # From Context (GitHub/StackOverflow search results)
    # NOTE: Key is "context" to match what context_agent_tool stores
    "context": {
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
    
    # From Stats
    # NOTE: Key is "stats" to match what record_stats tool stores
    "stats": {
        "error_type": "",
        "occurrence_count": 0,
        "trend": "stable",
    },
    
    # Reasoning trace
    "reasoning": [],
    
    # Runtime error log — every failure is captured here and sent to the frontend
    "_runtime_errors": [],
}


def log_runtime_error(component: str, operation: str, error: str, fatal: bool = False):
    """
    Log a runtime error so it reaches both CloudWatch (via print) AND the frontend console.
    Every call site that catches an exception should call this.
    """
    import traceback
    entry = {
        "component": component,
        "operation": operation,
        "error": str(error)[:500],
        "fatal": fatal,
        "timestamp": datetime.utcnow().isoformat(),
    }
    session_context.setdefault("_runtime_errors", []).append(entry)
    
    severity = "FATAL" if fatal else "ERROR"
    print(f"[RUNTIME_{severity}] [{component}] {operation}: {str(error)[:300]}")
    logger.error(f"[{component}] {operation}: {error}")

def reset_session_context():
    """Reset session context for new analysis."""
    global session_context
    session_context = {
        "original_error": "",
        "parsed": {"language": "unknown", "language_confidence": 0, "core_message": "", "stack_frames": [], "file_paths": [], "raw_error": ""},
        "security": {"risk_level": "unknown", "safe_to_store": True, "pii_found": [], "secrets_found": []},
        "memory": {"matches": [], "results": [], "has_solution": False, "has_solutions": False, "best_match_similarity": 0, "memory_searched": False, "pattern_stored": False, "stored_patterns": []},
        "context": {"github_issues": [], "stackoverflow_questions": [], "stackoverflow_answers": [], "code_examples": [], "top_solutions": [], "common_causes": []},
        "analysis": {"root_cause": "", "explanation": "", "confidence": 0, "category": "", "contributing_factors": []},
        "fix": {"fixed_code": "", "fix_type": "", "explanation": "", "prevention": []},
        "stats": {"error_type": "", "occurrence_count": 0, "trend": "stable"},
        "reasoning": [],
        "_runtime_errors": [],
    }
    logger.info("🔄 Session context reset with keys: " + ", ".join(session_context.keys()))

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
    logger.info("📥 parser_agent_tool CALLED")
    update_component_status("parser", "running", f"Parsing {len(error_text)} chars...")
    try:
        result = gateway_tools.parse_error(error_text)
        language = result.get('language', 'unknown')
        logger.info(f"📤 parser_agent_tool result: language={language}")
        
        if result.get('error'):
            update_component_status("parser", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        # Store in session context for final output
        update_session_context("parsed", result)
        logger.info(f"✅ parser_agent_tool updated session_context['parsed']")
        
        update_component_status("parser", "success", f"Detected: {language}")
        return json.dumps({"success": True, **result})
    except Exception as e:
        logger.error(f"❌ parser_agent_tool error: {e}")
        log_runtime_error("parser", "parse_error", str(e))
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
    logger.info("📥 security_agent_tool CALLED")
    update_component_status("security", "running", "Scanning for PII and secrets...")
    try:
        result = gateway_tools.scan_security(error_text)
        risk_level = result.get('risk_level', 'unknown')
        secrets = len(result.get('secrets_detected', []))
        pii = len(result.get('pii_entities', []))
        logger.info(f"📤 security_agent_tool result: risk={risk_level}, secrets={secrets}, pii={pii}")
        
        if result.get('error'):
            update_component_status("security", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        # Store in session context for final output
        update_session_context("security", result)
        
        update_component_status("security", "success", f"Risk: {risk_level} | {secrets} secrets, {pii} PII")
        return json.dumps({"success": True, **result})
    except Exception as e:
        log_runtime_error("security", "scan_security", str(e))
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
        
        # Store in session context for final output
        update_session_context("context", result)
        
        update_component_status("context", "success", f"Found {total_results} external resources")
        return json.dumps({"success": True, **result})
    except Exception as e:
        log_runtime_error("context", "search_error_context", str(e))
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
        log_runtime_error("github", "read_github_file", str(e))
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
    logger.info("📥 rootcause_agent_tool CALLED")
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
        
        # Store in session context for final output
        update_session_context("analysis", result)
        logger.info(f"✅ rootcause_agent_tool updated session_context['analysis'] - confidence: {confidence}%")
        
        update_component_status("rootcause", "success", f"{confidence}% confidence (LLM reasoning)")
        return json.dumps({"success": True, **result})
    except Exception as e:
        log_runtime_error("rootcause", "analyze_root_cause", str(e))
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
    logger.info("📥 fix_agent_tool CALLED")
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
        
        # Store in session context for final output
        update_session_context("fix", result)
        logger.info(f"✅ fix_agent_tool updated session_context['fix'] - type: {fix_type}")
        
        update_component_status("fix", "success", f"Generated {fix_type} fix")
        return json.dumps({"success": True, **result})
    except Exception as e:
        log_runtime_error("fix", "generate_fix", str(e))
        update_component_status("fix", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "fix_type": "unknown"})


# ============================================================================
# MEMORY TOOLS (Uses: AgentCore Memory API)
# ============================================================================
@tool(
    name="search_memory",
    description="""Search LONG-TERM memory for similar past errors. Call this AFTER parsing
    so you know the language and error type — this lets you judge if matches are truly relevant.
    
    If a high-similarity match (>0.7) is found with a working solution, you can SKIP external
    research and root cause analysis entirely — go straight to fix generation using the
    remembered solution. This is how memory accelerates problem solving.
    
    If no relevant match is found, ignore memory and proceed with full analysis.
    
    TIP: Include language and error_type for targeted results.
    Example: "python import_error: No module named 'requests'" not just the raw error."""
)
def search_memory(error_text: str, limit: int = 5, language: str = "", error_type: str = "") -> str:
    """Search AgentCore memory for similar errors with context."""
    local_count = memory_agent.get_local_pattern_count() if memory_agent else 0
    logger.info(f"🔎 SUPERVISOR search_memory CALLED: query_len={len(error_text)}, lang={language}, type={error_type}, local_patterns={local_count}")
    print(f"[SUPERVISOR] search_memory called: query_len={len(error_text)}, lang={language}, type={error_type}, local_patterns={local_count}")
    update_component_status("memory", "running", f"Searching memory ({local_count} local patterns)...")
    try:
        # Enhance search query with context for better semantic matching
        search_query = error_text
        if language and language != "unknown":
            search_query = f"[{language}] {search_query}"
        if error_type and error_type != "unknown":
            search_query = f"{error_type}: {search_query}"
        
        logger.info(f"🔎 SUPERVISOR search_memory: enhanced query = {search_query[:120]}...")
        
        result = memory_agent.search(search_query, limit)
        count = result.get('count', 0)
        best_score = result.get('best_match_score', 0)
        has_relevant = result.get('has_relevant_match', False)
        
        logger.info(f"🔎 SUPERVISOR search_memory RESULT: count={count}, best_score={best_score}, has_relevant={has_relevant}")
        print(f"[SUPERVISOR] search_memory result: count={count}, best_score={best_score}%, has_relevant={has_relevant}")
        
        if result.get('error'):
            logger.error(f"❌ SUPERVISOR search_memory ERROR: {result.get('error')}")
            update_component_status("memory", "error", error=result.get('error'))
            return json.dumps({"success": False, "error": result.get('error'), **result})
        
        # Store in session context for final output
        # Preserve any stored_patterns from store_pattern calls
        existing_stored = session_context.get("memory", {}).get("stored_patterns", [])
        update_session_context("memory", result)
        if existing_stored:
            session_context["memory"]["stored_patterns"] = existing_stored
        
        # CRITICAL: Sync "results" → "matches" for frontend compatibility
        search_results = session_context["memory"].get("results", [])
        session_context["memory"]["matches"] = search_results
        
        # Sync has_solution/has_solutions naming (frontend checks both)
        session_context["memory"]["has_solution"] = result.get("has_solutions", False)
        
        # Also set 'searched' flag so frontend knows memory was actively used
        session_context["memory"]["memory_searched"] = True
        session_context["memory"]["search_query"] = search_query[:100]
        
        logger.info(f"📝 SUPERVISOR search_memory: session_context['memory'] updated — {count} results synced, memory_searched=True, has_solution={result.get('has_solutions', False)}")
        
        update_component_status("memory", "success", f"Found {count} similar errors (best: {best_score}%)")
        return json.dumps({"success": True, **result})
    except Exception as e:
        logger.error(f"❌ SUPERVISOR search_memory EXCEPTION: {str(e)}")
        log_runtime_error("memory", "search_memory", str(e))
        update_component_status("memory", "error", error=str(e))
        return json.dumps({"success": False, "error": str(e), "results": []})


@tool(
    name="store_pattern",
    description="Store an error pattern and its solution in LONG-TERM semantic memory. Enables learning from past debugging to speed up future analysis."
)
def store_pattern(error_type: str, signature: str, root_cause: str, solution: str, language: str = "unknown") -> str:
    """Store error pattern in AgentCore memory."""
    local_count_before = memory_agent.get_local_pattern_count() if memory_agent else 0
    logger.info(f"💾 SUPERVISOR store_pattern CALLED: type={error_type}, lang={language}, sig={signature[:60]}")
    logger.info(f"💾 SUPERVISOR store_pattern: root_cause={root_cause[:80]}..., solution={solution[:80]}...")
    logger.info(f"💾 SUPERVISOR store_pattern: local_patterns_before={local_count_before}")
    print(f"[SUPERVISOR] store_pattern: type={error_type}, lang={language}, sig={signature[:60]}")
    try:
        result = memory_agent.store_pattern(error_type, signature, root_cause, solution, language)
        local_count_after = memory_agent.get_local_pattern_count() if memory_agent else 0
        logger.info(f"✅ SUPERVISOR store_pattern SUCCESS: local_patterns_after={local_count_after}, result={json.dumps(result)[:200]}")
        print(f"[SUPERVISOR] store_pattern ✅: local_after={local_count_after}, api_success={result.get('success')}, mode={result.get('mode')}")
        
        # Update session_context["memory"] so the frontend can see what was learned
        stored_pattern = {
            "error_type": error_type,
            "signature": signature,
            "root_cause": root_cause,
            "solution": solution,
            "language": language,
            "stored_this_session": True,
        }
        memory_ctx = session_context.get("memory", {})
        if "stored_patterns" not in memory_ctx:
            memory_ctx["stored_patterns"] = []
        memory_ctx["stored_patterns"].append(stored_pattern)
        memory_ctx["pattern_stored"] = True
        memory_ctx["stored_count"] = len(memory_ctx["stored_patterns"])
        update_session_context("memory", memory_ctx)
        logger.info(f"📝 SUPERVISOR store_pattern: session_context updated, stored_patterns_count={memory_ctx['stored_count']}")
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ SUPERVISOR store_pattern EXCEPTION: {str(e)}")
        log_runtime_error("memory", "store_pattern", str(e))
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
        
        # Store in session context for final output
        update_session_context("stats", result)
        
        update_component_status("stats", "success", f"Recorded {error_type} occurrence")
        return json.dumps({"success": True, **result})
    except Exception as e:
        log_runtime_error("stats", "record_stats", str(e))
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
        log_runtime_error("stats", "get_trend", str(e))
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
        log_runtime_error("context", "update_context", str(e))
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


def generate_final_summary(context: dict) -> dict:
    """
    Generate a comprehensive final summary from all collected agent data.
    This provides a clear, actionable overview for the frontend.
    """
    parsed = context.get("parsed", {})
    security = context.get("security", {})
    analysis = context.get("analysis", {})
    fix = context.get("fix", {})
    ctx = context.get("context", {})
    memory = context.get("memory", {})
    
    # Extract key information
    language = parsed.get("language", "unknown")
    language_confidence = parsed.get("confidence", parsed.get("language_confidence", 0))
    error_type = parsed.get("error_type", "unknown")
    core_message = parsed.get("core_message", parsed.get("error_message", ""))
    
    root_cause = analysis.get("root_cause", analysis.get("cause", ""))
    cause_confidence = analysis.get("confidence", 0)
    solution = analysis.get("solution", analysis.get("explanation", ""))
    
    fix_type = fix.get("fix_type", "")
    fix_before = fix.get("before", "")
    fix_after = fix.get("after", "")
    fix_explanation = fix.get("explanation", "")
    
    risk_level = security.get("risk_level", "unknown")
    
    # Count external resources
    github_count = len(ctx.get("github_issues", []))
    so_count = len(ctx.get("stackoverflow_answers", []))
    memory_count = len(memory.get("matches", memory.get("results", [])))
    
    # Build summary text
    summary_parts = []
    
    # Language and error type
    if language != "unknown":
        summary_parts.append(f"**Language**: {language} ({language_confidence}% confidence)")
    if error_type != "unknown":
        summary_parts.append(f"**Error Type**: {error_type}")
    
    # Core message
    if core_message:
        summary_parts.append(f"**Error**: {core_message[:200]}")
    
    # Root cause
    if root_cause:
        summary_parts.append(f"\n**Root Cause** ({cause_confidence}% confidence): {root_cause}")
    
    # Solution
    if solution:
        summary_parts.append(f"\n**Solution**: {solution}")
    
    # Fix
    if fix_after:
        summary_parts.append(f"\n**Suggested Fix** ({fix_type}):")
        if fix_before:
            summary_parts.append(f"Before: `{fix_before[:100]}`")
        summary_parts.append(f"After: `{fix_after[:100]}`")
        if fix_explanation:
            summary_parts.append(f"Explanation: {fix_explanation[:200]}")
    
    # Resources found
    resources = []
    if github_count > 0:
        resources.append(f"{github_count} GitHub issues")
    if so_count > 0:
        resources.append(f"{so_count} Stack Overflow answers")
    if memory_count > 0:
        resources.append(f"{memory_count} similar past errors")
    if resources:
        summary_parts.append(f"\n**Resources Found**: {', '.join(resources)}")
    
    # Security
    if risk_level != "unknown":
        summary_parts.append(f"\n**Security Risk**: {risk_level}")
    
    summary_text = "\n".join(summary_parts) if summary_parts else "Analysis complete but no specific results captured."
    
    return {
        "text": summary_text,
        "language": language,
        "languageConfidence": language_confidence,
        "errorType": error_type,
        "coreMessage": core_message,
        "rootCause": root_cause,
        "rootCauseConfidence": cause_confidence,
        "solution": solution,
        "fixType": fix_type,
        "fixBefore": fix_before,
        "fixAfter": fix_after,
        "fixExplanation": fix_explanation,
        "riskLevel": risk_level,
        "resourceCounts": {
            "github": github_count,
            "stackoverflow": so_count,
            "memory": memory_count
        }
    }


# ============================================================================
# Supervisor Agent System Prompts (Part 1 vs Part 2)
# ============================================================================

# Part 1: Basic Multi-Agent System (5 agents: Supervisor, Parser, Security, Root Cause, Fix)
SUPERVISOR_PROMPT_PART1 = """You are an Expert Error Debugging Supervisor. You are an ITERATIVE, REFLECTIVE agent.

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
│     - If confident (≥80%) → Produce final output                    │
│     - If not confident → Loop back to step 1                        │
└─────────────────────────────────────────────────────────────────────┘
```

## When to Loop Back

Re-run or try different approaches when:
- Parser returned "unknown" for language → Try inferring from patterns in the error
- Root cause confidence < 80% → Re-analyze with different approach
- The fix doesn't seem to address the root cause → Re-analyze
- You realize you missed something → Go back and get it

## When to Produce Output

Only produce final output when:
- You have identified the language with reasonable confidence
- You have a root cause hypothesis with ≥80% confidence
- You have a concrete, actionable fix
- The fix actually addresses the root cause

# AVAILABLE TOOLS (Part 1 - Core Agents)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `parser_agent_tool` | Extract language, error type, stack trace | ALWAYS first |
| `security_agent_tool` | Detect PII/secrets | Before storing anything |
| `rootcause_agent_tool` | LLM reasoning to determine why error occurred | After parsing |
| `fix_agent_tool` | Generate code fix | After root cause is determined |

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

## Phase 1: Parse and Understand

1. **PARSE** the error to get structured data
   - If language is "unknown", look at the error patterns yourself
   - If error_type is "unknown", classify it based on keywords

2. **SECURITY** scan - check for PII/secrets

## Phase 2: Analyze Root Cause

3. **ROOT CAUSE** analysis
   - Pass the parsed info and original error
   - If confidence < 80%, try a different approach
   - If the root cause seems wrong, question it

## Phase 3: Generate Fix

4. **FIX** generation
   - Must match the detected language
   - Must address the identified root cause
   - If the fix seems generic or wrong, reconsider

# OUTPUT FORMAT (only when ready)

When you are CONFIDENT (≥80%), produce the final output:

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

### 🛡️ Prevention
[How to avoid this in the future]
```

# CRITICAL RULES

1. **ITERATE UNTIL CONFIDENT** - Don't output until you're sure
2. **THINK OUT LOUD** - Show your reasoning process
3. **REFLECT ON RESULTS** - Question tool outputs, don't blindly accept
4. **RE-RUN IF NEEDED** - Low confidence? Try again with different approach
5. **BE SPECIFIC** - Generic answers are useless
"""

# Part 2: Full System with Memory, Context, Stats, and GitHub Integration
SUPERVISOR_PROMPT_PART2 = """You are an Expert Error Debugging Supervisor. You are an ITERATIVE, REFLECTIVE agent.

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
│     - If confident (≥80%) → Produce final output                    │
│     - If not confident → Loop back to step 1                        │
└─────────────────────────────────────────────────────────────────────┘
```

## When to Loop Back

Re-run or try different approaches when:
- Parser returned "unknown" for language → Try inferring from patterns in the error
- Root cause confidence < 80% → Gather more context, try different search terms
- External context found 0 results → Try different search queries
- The fix doesn't seem to address the root cause → Re-analyze
- You realize you missed something → Go back and get it

## When to Produce Output

Only produce final output when:
- You have identified the language with reasonable confidence
- You have a root cause hypothesis with ≥80% confidence
- You have a concrete, actionable fix
- The fix actually addresses the root cause

# AVAILABLE TOOLS (Part 2 - Full System)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `parser_agent_tool` | Extract language, error type, stack trace | ALWAYS first — understand the error |
| `security_agent_tool` | Detect PII/secrets | After parsing, before storing anything |
| `search_memory` | Find similar past errors | After parsing — the decision gate |
| `context_agent_tool` | Search GitHub/StackOverflow | Only if memory has no relevant match |
| `read_github_file_tool` | Read source code from repo | Only if memory has no match AND stack trace references a file |
| `rootcause_agent_tool` | LLM reasoning with all context | Only if memory has no relevant match |
| `fix_agent_tool` | Generate code fix | Always — either from memory solution or fresh root cause |
| `record_stats` | Track statistics | At the end, always |
| `store_pattern` | Save solution to memory | At the end, always — this is how you learn |

# ⚡ THE TWO-PATH STRATEGY: Memory is Your Accelerator

The entire purpose of memory is to **vastly speed up** problem solving when you've seen
something similar before. After you understand what the error IS, memory is the decision
gate that determines which path you take:

```
                    ┌──────────────┐
                    │  1. PARSE    │  Understand the error first
                    │  2. SECURITY │  (language, type, structure)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ 3. MEMORY    │  Search with language + error_type + message
                    │    SEARCH    │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     MATCH FOUND (>0.7)          NO RELEVANT MATCH
     with a solution              or low similarity
              │                         │
     ┌────────▼────────┐      ┌────────▼────────┐
     │  ⚡ FAST PATH   │      │  🔍 FULL PATH   │
     │                 │      │                  │
     │  Skip to FIX    │      │  4. CONTEXT      │
     │  using the      │      │  5. ROOT CAUSE   │
     │  remembered     │      │  6. FIX          │
     │  solution as    │      │                  │
     │  guidance       │      │  (Full analysis) │
     └────────┬────────┘      └────────┬─────────┘
              │                         │
              └────────────┬────────────┘
                           │
                    ┌──────▼───────┐
                    │ 7. STORE     │  ALWAYS save what you learned
                    │ 8. STATS     │  (even on fast path — reinforces the pattern)
                    └──────────────┘
```

# THINKING PROCESS

Before each action, think out loud:

```
<thinking>
What I know so far:
- Language: [known/unknown]
- Error type: [known/unknown]
- Root cause: [hypothesis/unknown]
- Memory match: [yes/no/not searched yet]
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

## Phase 1: Understand the Error

1. **PARSE** the error to get structured data
   - Extract: language, error_type, core message, stack frames, file paths
   - If language is "unknown", look at the error patterns yourself
   - If error_type is "unknown", classify it based on keywords

2. **SECURITY** scan - check for PII/secrets before anything is stored

## Phase 2: Memory Decision Gate

3. **SEARCH MEMORY** using language + error_type + core error message
   - Pass the language and error_type you just learned from parsing
   - This makes the search targeted so you can judge if results are truly relevant

   **Evaluate the results critically:**
   - Is the matched error actually the SAME type of problem? (not just similar words)
   - Does the stored solution apply to this specific situation?
   - Is the similarity score high enough (>0.7)?

### ⚡ FAST PATH — Memory match is relevant

If memory returned a match that is clearly the same type of error with a working solution:
- Your confidence should already be high (≥80%)
- Go directly to **FIX generation**, using the remembered root cause and solution as the basis
- You do NOT need to run context_agent_tool or rootcause_agent_tool
- This is the speed advantage of memory — skip expensive external research

### 🔍 FULL PATH — No relevant memory match

If memory returned no results, or the results don't actually match your problem:
- **Forget about memory for now** — it has nothing useful for this error
- Proceed with full analysis (Phase 3 below)

## Phase 3: Full Analysis (only on FULL PATH)

4. **CONTEXT** search with good search terms
   - Use the actual error message, not generic terms
   - If 0 results, try different search terms
   - If stack trace mentions a GitHub repo, consider reading the file

5. **ROOT CAUSE** analysis
   - Pass ALL context gathered: parsed info, external findings
   - If confidence < 80%, consider gathering more context
   - If the root cause seems wrong, question it

## Phase 4: Solution

6. **FIX** generation
   - On FAST PATH: use the remembered solution as guidance, adapt it to the specific error
   - On FULL PATH: generate from scratch based on root cause analysis
   - Must match the detected language
   - Must address the identified root cause

## Phase 5: Learn and Record (ALWAYS — both paths)

7. **STORE PATTERN** in memory — ALWAYS call `store_pattern` with the error type,
   a signature (the core error message), root cause, solution, and language.
   This is how the system LEARNS. Every error you solve makes future solves faster.
   On the fast path, this reinforces the pattern. On the full path, this teaches a new one.

8. **RECORD STATS** — call `record_stats` to track this error type

# ITERATION EXAMPLES

## Example 1: Memory Hit → Fast Path
```
<thinking>
Parser says: Python, ImportError, "No module named 'requests'"
Let me check memory for this exact pattern.
</thinking>

search_memory("python import_error: No module named 'requests'", language="python", error_type="import_error")

<reflection>
Memory returned a match with 0.92 similarity!
Stored solution: "pip install requests" or add to requirements.txt
This is clearly the same problem. Confidence: 95%
I can skip external research and go straight to generating the fix.
</reflection>
```

## Example 2: Memory Miss → Full Path
```
<thinking>
Parser says: Terraform, config_error at gateway.tf line 94
Let me check memory.
</thinking>

search_memory("terraform config_error: Unsupported block type", language="terraform", error_type="config_error")

<reflection>
Memory returned 0 results. This is a new error pattern.
Forget memory — I need to do full analysis.
Let me search for context on this Terraform error.
</reflection>

context_agent_tool(error_message="Unsupported block type logging_configuration", ...)
```

## Example 3: Memory Match but NOT Relevant → Full Path
```
<reflection>
Memory returned a match (0.6 similarity) for a different Python import error.
But that was about 'numpy' version conflicts, and my error is about a missing
custom module 'myapp.utils'. The stored solution doesn't apply here.
This is NOT a fast-path case — I need full analysis.
</reflection>
```

## Example 4: Uncertain Root Cause → Dig Deeper
```
<reflection>
Root cause confidence: 55%
The analysis says "configuration error" but doesn't explain WHY.
Let me check if there's a GitHub file I can read for more context.
</reflection>

read_github_file_tool(repo_url="...", file_path="gateway.tf")
```

# OUTPUT FORMAT (only when ready)

When you are CONFIDENT (≥80%), produce the final output:

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
[Real URLs from context search, or "Resolved from memory — seen this pattern before"]

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
7. **MEMORY IS YOUR ACCELERATOR** - ALWAYS call `search_memory` after parsing to check
   for known solutions. If the match is relevant, FAST PATH to the fix — this is the
   whole point. If not, do full analysis and forget about memory until the end.
8. **ALWAYS LEARN** - ALWAYS call `store_pattern` at the end. Every solved error
   makes the next one faster. This is how you get smarter over time.
"""

# Select the correct prompt based on feature part
def get_supervisor_prompt():
    """Return the appropriate system prompt based on FEATURE_PART."""
    if FEATURE_PART >= 2:
        logger.info("📋 Using Part 2 supervisor prompt (full system)")
        return SUPERVISOR_PROMPT_PART2
    else:
        logger.info("📋 Using Part 1 supervisor prompt (core agents only)")
        return SUPERVISOR_PROMPT_PART1

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

supervisor = Agent(
    system_prompt=get_supervisor_prompt(),
    tools=build_tools_list(),
    callback_handler=event_loop_tracker
)

# ============================================================================
# Memory Fast Path — Skip Full Agent Loop When Solution Already Known
# ============================================================================

# Minimum relevance score (0-100) to trigger the fast path.
MEMORY_FAST_PATH_THRESHOLD = 70


def _quick_parse(error_text: str) -> dict:
    """
    Ultra-lightweight regex-based error parsing. No Gateway/Lambda calls.
    Used ONLY by the fast path to build a better memory search query.
    The full supervisor loop will re-parse properly via Gateway if fast path misses.
    """
    import re
    result = {"language": "unknown", "error_type": "unknown", "core_message": error_text[:200]}
    text_lower = error_text.lower()

    # Detect language
    lang_patterns = {
        "python": [r"traceback", r"\.py[\"\s:,]", r"import_error", r"modulenotfounderror", r"nameerror", r"typeerror.*python", r"pip install"],
        "javascript": [r"\.js[\"\s:,]", r"referenceerror", r"syntaxerror.*\bjs\b", r"node_modules", r"npm", r"uncaught"],
        "typescript": [r"\.ts[\"\s:,]", r"ts\(\d+\)", r"cannot find module.*\.ts"],
        "java": [r"\.java[\"\s:,]", r"java\.\w+\.\w+exception", r"at\s+\w+\.\w+\(.*\.java:\d+\)"],
        "go": [r"\.go[\"\s:,]", r"goroutine", r"panic:"],
        "rust": [r"\.rs[\"\s:,]", r"thread.*panicked", r"cargo"],
        "terraform": [r"\.tf[\"\s:,]", r"terraform", r"resource\s+\""],
        "ruby": [r"\.rb[\"\s:,]", r"nomethoderror", r"undefined method"],
    }
    for lang, patterns in lang_patterns.items():
        if any(re.search(p, text_lower) for p in patterns):
            result["language"] = lang
            break

    # Detect error type
    error_type_patterns = [
        (r"(ModuleNotFoundError|ImportError|import_error)", "import_error"),
        (r"(TypeError|type_error)", "type_error"),
        (r"(KeyError|key_error)", "key_error"),
        (r"(ValueError|value_error)", "value_error"),
        (r"(AttributeError|attribute_error)", "attribute_error"),
        (r"(NameError|name_error)", "name_error"),
        (r"(SyntaxError|syntax_error)", "syntax_error"),
        (r"(IndexError|index_error)", "index_error"),
        (r"(ConnectionError|connection_error|ECONNREFUSED)", "connection_error"),
        (r"(TimeoutError|timeout_error|ETIMEDOUT)", "timeout_error"),
        (r"(PermissionError|permission_error|EACCES)", "permission_error"),
        (r"(FileNotFoundError|file_not_found|ENOENT)", "file_not_found"),
        (r"(NullPointerException|null_pointer)", "null_pointer"),
        (r"(ReferenceError|reference_error)", "reference_error"),
        (r"(RuntimeError|runtime_error)", "runtime_error"),
        (r"(ConfigError|config_error|configuration)", "config_error"),
    ]
    for pattern, etype in error_type_patterns:
        if re.search(pattern, error_text, re.IGNORECASE):
            result["error_type"] = etype
            break

    # Extract core message (first meaningful line)
    for line in error_text.strip().split("\n"):
        line = line.strip()
        if line and len(line) > 10 and not line.startswith("at ") and not line.startswith("File "):
            result["core_message"] = line[:200]
            break

    return result


def _try_memory_fast_path(user_input: str, session_id: str) -> dict:
    """
    Attempt to resolve the error from memory WITHOUT invoking the full supervisor agent.
    
    DESIGN: This function does ONE thing — search memory. No Gateway calls.
    - Quick regex parse to build a better search query (microseconds)
    - Memory search via AgentCore API + local cache (~0.3-1s)
    - If match found, populate session_context directly
    
    Returns dict with:
      {"hit": True/False, "elapsed": float, "error": str or None, "details": str}
    """
    import time
    fast_start = time.time()
    
    if not memory_agent:
        return {"hit": False, "elapsed": 0, "error": None, "details": "memory_agent not available"}
    
    local_count = memory_agent.get_local_pattern_count()
    logger.info(f"⚡ FAST PATH START: local_patterns={local_count}, input_len={len(user_input)}")
    print(f"[FAST_PATH] Starting memory fast path. Local patterns: {local_count}")
    
    try:
        # ── Step 1: Quick regex parse (NO Gateway call) ─────────────
        parsed = _quick_parse(user_input)
        language = parsed["language"]
        error_type = parsed["error_type"]
        core_message = parsed["core_message"]
        
        logger.info(f"⚡ Quick parse: lang={language}, type={error_type}, core={core_message[:60]}")
        print(f"[FAST_PATH] Quick parse: lang={language}, type={error_type}")
        
        # ── Step 2: Memory search (single API call) ─────────────────
        search_query = core_message
        if language != "unknown":
            search_query = f"[{language}] {search_query}"
        if error_type != "unknown":
            search_query = f"{error_type}: {search_query}"
        
        logger.info(f"⚡ Memory search query: {search_query[:100]}")
        print(f"[FAST_PATH] Searching memory: {search_query[:80]}...")
        
        mem_result = memory_agent.search(search_query, limit=5)
        mem_count = mem_result.get("count", 0)
        has_relevant = mem_result.get("has_relevant_match", False)
        best_score = mem_result.get("best_match_score", 0)
        results = mem_result.get("results", [])
        api_count = mem_result.get("api_count", 0)
        local_match_count = mem_result.get("local_count", 0)
        api_error = mem_result.get("api_error")
        
        search_elapsed = time.time() - fast_start
        logger.info(f"⚡ Memory search done in {search_elapsed:.1f}s: {mem_count} results, "
                    f"best={best_score}%, relevant={has_relevant}, local={local_match_count}, api={api_count}")
        print(f"[FAST_PATH] Memory search: {mem_count} results, best_score={best_score}%, "
              f"local={local_match_count}, api={api_count}, time={search_elapsed:.1f}s")
        
        if api_error:
            logger.warning(f"⚡ Memory API error (non-fatal): {api_error}")
            print(f"[FAST_PATH] API error: {api_error}")
        
        # ── Decision Gate ───────────────────────────────────────────
        if not has_relevant or not results:
            elapsed = time.time() - fast_start
            msg = f"No relevant match ({mem_count} results, best={best_score}%)"
            logger.info(f"⚡ Fast path MISS: {msg}")
            print(f"[FAST_PATH] MISS: {msg}")
            return {"hit": False, "elapsed": elapsed, "error": None, "details": msg}
        
        best_match = results[0]
        relevance = best_match.get("relevance_score", 0)
        stored_solution = best_match.get("solution", "")
        stored_root_cause = best_match.get("root_cause", "")
        
        if relevance < MEMORY_FAST_PATH_THRESHOLD or not stored_solution:
            elapsed = time.time() - fast_start
            msg = f"Match too weak ({relevance}% < {MEMORY_FAST_PATH_THRESHOLD}%) or no solution"
            logger.info(f"⚡ Fast path MISS: {msg}")
            print(f"[FAST_PATH] MISS: {msg}")
            return {"hit": False, "elapsed": elapsed, "error": None, "details": msg}
        
        # ── FAST PATH HIT! ────────────────────────────────────────
        logger.info(f"⚡⚡⚡ FAST PATH HIT! score={relevance}%, source={best_match.get('source')}")
        print(f"[FAST_PATH] ⚡ HIT! score={relevance}%, solution={stored_solution[:60]}...")
        
        # Populate session_context directly (same structure as full loop)
        
        # Memory data
        session_context["memory"].update({
            "matches": results,
            "results": results,
            "count": mem_count,
            "has_solution": True,
            "has_solutions": True,
            "memory_searched": True,
            "search_query": search_query[:100],
            "fast_path": True,
            "best_match_score": best_score,
            "api_count": api_count,
            "local_count": local_match_count,
            "mode": mem_result.get("mode", "live"),
        })
        
        # Parsed data (from quick parse — not as rich as Gateway parse, but sufficient)
        update_session_context("parsed", {
            "language": language,
            "error_type": error_type,
            "error_message": core_message,
            "core_message": core_message,
            "confidence": 70,  # Quick parse is less confident
            "source": "fast_path_regex",
        })
        
        # Security (minimal — no scan, but safe default)
        update_session_context("security", {
            "risk_level": "low",
            "source": "fast_path_default",
        })
        
        # Root cause from memory
        update_session_context("analysis", {
            "root_cause": stored_root_cause,
            "explanation": f"Resolved from memory ({relevance}% match). "
                          f"This error was seen before and the solution was validated.",
            "confidence": min(relevance, 95),
            "category": best_match.get("error_type", error_type),
            "source": "memory_fast_path",
        })
        
        # Fix from memory
        update_session_context("fix", {
            "fix_type": "memory_recall",
            "before": "",
            "after": stored_solution,
            "fixed_code": stored_solution,
            "explanation": f"Previously validated solution. Root cause: {stored_root_cause}",
            "prevention": best_match.get("prevention", []),
            "source": "memory_fast_path",
        })
        
        elapsed = time.time() - fast_start
        logger.info(f"⚡ FAST PATH COMPLETE in {elapsed:.1f}s")
        print(f"[FAST_PATH] ✅ Complete in {elapsed:.1f}s")
        
        return {"hit": True, "elapsed": elapsed, "error": None, 
                "details": f"Match: {relevance}% from {best_match.get('source', 'unknown')}"}
        
    except Exception as e:
        elapsed = time.time() - fast_start
        error_msg = f"{type(e).__name__}: {e}"
        logger.error(f"⚠️ FAST PATH CRASHED after {elapsed:.1f}s: {error_msg}")
        print(f"[FAST_PATH] ❌ CRASHED: {error_msg}")
        import traceback
        traceback.print_exc()
        return {"hit": False, "elapsed": elapsed, "error": error_msg, "details": "exception"}


# ============================================================================
# AgentCore Runtime Entrypoint
# ============================================================================
@app.entrypoint
async def error_debugger(payload, context):
    """
    Main entrypoint for the error debugger supervisor agent.
    Invoked by AgentCore runtime for each request.
    
    Two execution paths:
    1. FAST PATH (Part 2 only): parse → memory search → if match, return in <15s
    2. FULL PATH: Full supervisor agent loop with all tools (~60-120s)
    """
    import traceback
    import time
    
    logger.info("=" * 50)
    logger.info("🚀 Error Debugger Entrypoint Called")
    logger.info(f"Payload: {payload}")
    logger.info("=" * 50)
    
    # CRITICAL: Reset session context for each new request
    # Without this, stale data from previous requests would pollute the results
    reset_session_context()
    logger.info("🔄 Session context reset for new analysis")
    
    try:
        user_input = payload.get("prompt", "") if isinstance(payload, dict) else str(payload)
        session_id = payload.get("session_id", "unknown") if isinstance(payload, dict) else "unknown"
        mode = payload.get("mode", "comprehensive") if isinstance(payload, dict) else "comprehensive"
        github_repo = payload.get("github_repo", "") if isinstance(payload, dict) else ""
        
        # Store original error in session context
        session_context["original_error"] = user_input
        
        # Set session context for logging
        session_filter.set_session_id(session_id)
        
        yield f"🔍 Starting error analysis...\n"
        yield f"📋 Mode: {mode}\n"
        if github_repo:
            yield f"📂 Repository: {github_repo}\n"
        
        if not user_input:
            yield "❌ Error: No error text provided\n"
            return
        
        logger.info(f"Input: {user_input[:200]}...")
        if github_repo:
            logger.info(f"GitHub repo: {github_repo}")
        
        # Bypass tool consent for automation
        os.environ["BYPASS_TOOL_CONSENT"] = "true"
        
        # ================================================================
        # MEMORY FAST PATH (Part 2 only)
        # Before starting the expensive supervisor agent loop, check if
        # we've seen this error before. If memory has a high-confidence
        # match with a validated solution, skip the full analysis entirely.
        # This drops response time from ~100s to ~5-10s.
        # ================================================================
        start_time = time.time()
        
        if FEATURE_PART >= 2 and memory_agent and mode != "quick":
            yield f"⚡ Checking memory for known solutions...\n"
            fp = _try_memory_fast_path(user_input, session_id)
            
            if fp.get("error"):
                yield f"⚠️ Memory fast path error: {fp['error']} ({fp['elapsed']:.1f}s)\n"
                logger.warning(f"Fast path error surfaced to user: {fp['error']}")
            
            if fp.get("hit"):
                elapsed = fp["elapsed"]
                yield f"⚡ Memory hit! Resolved from stored solution in {elapsed:.1f}s\n"
                yield f"\n✅ Analysis complete (fast path — memory recall)\n"
                
                # Generate summary and yield final result (same format as full path)
                summary = generate_final_summary(session_context)
                
                agents_data = {
                    "parser": session_context.get("parsed", {}),
                    "security": session_context.get("security", {}),
                    "rootcause": session_context.get("analysis", {}),
                    "fix": session_context.get("fix", {}),
                    "context": session_context.get("context", {}),
                    "memory": session_context.get("memory", {}),
                    "stats": session_context.get("stats", {}),
                }
                
                final_result = {
                    "_agentcore_final_result": True,
                    "agents": agents_data,
                    "summary": summary,
                    "eventCount": 0,
                    "sessionId": session_id,
                    "fastPath": True,
                    "fastPathElapsed": round(elapsed, 1),
                    "_runtime_errors": session_context.get("_runtime_errors", []),
                }
                
                logger.info(f"⚡ Fast path result yielded in {elapsed:.1f}s (runtime_errors={len(final_result['_runtime_errors'])})")
                yield json.dumps(final_result)
                return  # Done! No need for full supervisor.
            else:
                yield f"📝 No memory match ({fp['elapsed']:.1f}s — {fp.get('details', '')}). Running full analysis...\n"
        
        # ================================================================
        # FULL PATH — Standard supervisor agent loop
        # ================================================================
        
        # Build prompt with optional repo context
        repo_context = f"\nGitHub Repository: {github_repo}" if github_repo else ""
        
        if mode == "quick":
            prompt = f"""Quickly analyze this error:

ERROR: {user_input}{repo_context}

Run: parser, security, root cause, fix. Skip external searches.
"""
        else:
            prompt = f"""Comprehensively debug this error:

ERROR: {user_input}{repo_context}

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
        
        elapsed = time.time() - start_time
        yield f"\n✅ Analysis complete ({event_count} events, {elapsed:.1f}s)\n"
        
        # Log what's in session_context before generating summary
        logger.info("=" * 40)
        logger.info("📊 Session Context Summary (before final yield):")
        for key, value in session_context.items():
            if isinstance(value, dict):
                non_empty = {k: v for k, v in value.items() if v}
                logger.info(f"  {key}: {len(non_empty)} non-empty fields - {list(non_empty.keys())[:5]}")
            else:
                logger.info(f"  {key}: {str(value)[:100]}")
        logger.info("=" * 40)
        
        # Generate a final summary from all collected data
        summary = generate_final_summary(session_context)
        
        # Build the agents data based on feature part
        # Part 1: parser, security, rootcause, fix
        # Part 2: Part 1 + context, memory, stats
        agents_data = {
            "parser": session_context.get("parsed", {}),
            "security": session_context.get("security", {}),
            "rootcause": session_context.get("analysis", {}),
            "fix": session_context.get("fix", {}),
        }
        
        # Part 2 only: Include memory, context, and stats agents
        if FEATURE_PART >= 2:
            agents_data["context"] = session_context.get("context", {})
            agents_data["memory"] = session_context.get("memory", {})
            agents_data["stats"] = session_context.get("stats", {})
        
        # Log which agents have data
        agents_with_data = [k for k, v in agents_data.items() if v and (isinstance(v, dict) and any(v.values()))]
        logger.info(f"🎯 Agents with actual data: {agents_with_data}")
        
        # Yield structured results from session_context for frontend
        # Use "_agentcore_final_result" marker so Lambda can identify this among thousands of events
        final_result = {
            "_agentcore_final_result": True,  # Marker for Lambda to identify this
            "agents": agents_data,
            "summary": summary,
            "eventCount": event_count,
            "sessionId": session_id,
            "_runtime_errors": session_context.get("_runtime_errors", []),
        }
        
        runtime_err_count = len(final_result["_runtime_errors"])
        logger.info(f"🎯 Yielding final structured result with keys: {list(final_result.keys())}")
        logger.info(f"🎯 Summary length: {len(str(summary))}, runtime_errors: {runtime_err_count}")
        if runtime_err_count > 0:
            print(f"[SUPERVISOR] ⚠️ {runtime_err_count} runtime errors collected:")
            for idx, err in enumerate(final_result["_runtime_errors"]):
                print(f"  [{idx+1}] [{err['component']}] {err['operation']}: {err['error'][:200]}")
        yield json.dumps(final_result)
                
    except Exception as e:
        log_runtime_error("supervisor", "error_debugger", str(e), fatal=True)
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

