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
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# ============================================================================
# Configuration
# ============================================================================
# Feature part (1 = basic, 2 = advanced)
FEATURE_PART = int(os.environ.get('FEATURE_PART', '2'))

# Demo mode (true = simulated, false = real APIs)
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() in ('true', '1', 'yes')

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
            
            # Root Cause Agent Tools
            "rootcause_agent_tool": "🎯 EXECUTING: Root Cause Agent (pattern matching, LLM analysis)",
            
            # Fix Agent Tools
            "fix_agent_tool": "🔧 EXECUTING: Fix Agent (code generation, validation)",
            
            # Memory Operations
            "search_memory": "🔎 EXECUTING: Searching long-term memory for similar errors",
            "store_pattern": "💾 EXECUTING: Storing error pattern in memory",
            "store_session": "📝 EXECUTING: Storing session context",
            
            # Stats Operations
            "record_stats": "📊 EXECUTING: Recording error statistics",
            "get_trend": "📈 EXECUTING: Analyzing error trends",
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
    logger.info(f"📋 Calling Parser Lambda via Gateway ({len(error_text)} chars)")
    try:
        result = gateway_tools.parse_error(error_text)
        logger.info(f"✅ Parser Lambda returned: {result.get('error_type', 'unknown')}")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Parser Lambda error: {str(e)}")
        return json.dumps({"error": str(e), "error_type": "unknown"})


# ============================================================================
# SECURITY TOOL (Lambda via Gateway)
# ============================================================================
@tool(
    name="security_agent_tool",
    description="Scan error messages for security issues: PII detection, hardcoded secrets. Calls Security Lambda via Gateway."
)
def security_agent_tool(error_text: str) -> str:
    """Call Security Lambda via Gateway to scan for sensitive data."""
    logger.info(f"🔒 Calling Security Lambda via Gateway ({len(error_text)} chars)")
    try:
        result = gateway_tools.scan_security(error_text)
        logger.info(f"✅ Security Lambda returned: risk_level={result.get('risk_level', 'unknown')}")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Security Lambda error: {str(e)}")
        return json.dumps({"error": str(e), "risk_level": "unknown"})


# ============================================================================
# CONTEXT TOOL (Lambda via Gateway)
# ============================================================================
@tool(
    name="context_agent_tool",
    description="Search external resources for error context: GitHub Issues, Stack Overflow. Calls Context Lambda via Gateway."
)
def context_agent_tool(error_message: str, error_type: str = "unknown", language: str = "unknown") -> str:
    """Call Context Lambda via Gateway to search external resources."""
    logger.info(f"🔍 Calling Context Lambda via Gateway for {error_type} in {language}")
    try:
        result = gateway_tools.search_context(error_message, language)
        logger.info(f"✅ Context Lambda returned: {result.get('total_results', 0)} results")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Context Lambda error: {str(e)}")
        return json.dumps({"error": str(e), "github_issues": [], "stackoverflow_questions": []})


# ============================================================================
# GITHUB FILE READER TOOL (For reading source code from repos)
# ============================================================================
@tool(
    name="read_github_file_tool",
    description="Read a file from a GitHub repository to get source code context. Use when you have a repo URL and file path from the stack trace to understand the code causing the error."
)
def read_github_file_tool(repo_url: str, file_path: str, branch: str = "main") -> str:
    """Read a file from GitHub to get source code context."""
    logger.info(f"📄 Reading GitHub file: {repo_url}/{file_path}")
    try:
        from agents.context_agent import read_github_file
        result = read_github_file(repo_url, file_path, branch)
        # result is already a JSON string from the tool
        parsed = json.loads(result)
        if parsed.get("success"):
            logger.info(f"✅ GitHub file read: {parsed.get('line_count', 0)} lines")
        else:
            logger.warning(f"⚠️ GitHub file read failed: {parsed.get('error', 'unknown')}")
        return result
    except Exception as e:
        logger.error(f"❌ GitHub file read error: {str(e)}")
        return json.dumps({"success": False, "error": str(e)})


# ============================================================================
# ROOT CAUSE AGENT TOOL (Uses: Pattern DB, Bedrock Claude)
# ============================================================================
@tool(
    name="rootcause_agent_tool",
    description="Analyze error root cause using pattern matching against known errors database and Bedrock Claude for reasoning. Returns hypothesis with confidence score."
)
def rootcause_agent_tool(error_text: str, parsed_info: str = "{}") -> str:
    """Route root cause analysis to the RootCause Agent with pattern/LLM tools."""
    logger.info(f"🎯 Invoking RootCauseAgent")
    try:
        parsed = json.loads(parsed_info) if isinstance(parsed_info, str) else parsed_info
        result = rootcause_agent.analyze(error_text, parsed)
        logger.info(f"✅ RootCauseAgent returned: {result.get('confidence', 0)}% confidence")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ RootCauseAgent error: {str(e)}")
        return json.dumps({"error": str(e), "root_cause": "unknown", "confidence": 0})


# ============================================================================
# FIX AGENT TOOL (Uses: Bedrock Claude, AST validation)
# ============================================================================
@tool(
    name="fix_agent_tool",
    description="Generate code fixes using Bedrock Claude code generation. Validates syntax with AST parsers. Suggests prevention measures and creates test cases."
)
def fix_agent_tool(error_text: str, root_cause: str, language: str = "javascript") -> str:
    """Route fix generation to the Fix Agent with Bedrock/AST tools."""
    logger.info(f"🔧 Invoking FixAgent for {language}")
    try:
        result = fix_agent.generate(error_text, root_cause, language)
        logger.info(f"✅ FixAgent returned: {result.get('fix_type', 'unknown')}")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ FixAgent error: {str(e)}")
        return json.dumps({"error": str(e), "fix_type": "unknown"})


# ============================================================================
# MEMORY TOOLS (Uses: AgentCore Memory API)
# ============================================================================
@tool(
    name="search_memory",
    description="Search LONG-TERM memory for similar past errors. Uses AgentCore semantic search to find relevant debugging history and known solutions."
)
def search_memory(error_text: str, limit: int = 5) -> str:
    """Search AgentCore memory for similar errors."""
    logger.info(f"🔎 Searching memory for similar errors")
    try:
        result = memory_agent.search(error_text, limit)
        logger.info(f"✅ Memory search returned: {result.get('count', 0)} matches")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Memory search error: {str(e)}")
        return json.dumps({"error": str(e), "results": []})


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


@tool(
    name="store_session",
    description="Store context in SHORT-TERM session memory. Maintains state during debugging session (24hr TTL)."
)
def store_session(context_type: str, content: str) -> str:
    """Store session context."""
    logger.info(f"📝 Storing session: {context_type}")
    try:
        result = memory_agent.store_context(context_type, content)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Store session error: {str(e)}")
        return json.dumps({"error": str(e)})


# ============================================================================
# STATS TOOLS (Lambda via Gateway)
# ============================================================================
@tool(
    name="record_stats",
    description="Record error statistics. Calls Stats Lambda via Gateway to persist to DynamoDB."
)
def record_stats(error_type: str, language: str, resolved: bool = False) -> str:
    """Call Stats Lambda via Gateway to record an error occurrence."""
    logger.info(f"📊 Calling Stats Lambda to record: {error_type}")
    try:
        result = gateway_tools.record_error(error_type, language, resolved)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Stats Lambda error: {str(e)}")
        return json.dumps({"error": str(e)})


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
# Supervisor Agent System Prompt
# ============================================================================
SUPERVISOR_PROMPT = """You are an Expert Error Debugging Supervisor managing a team of specialist agents.

## YOUR ROLE
You coordinate a multi-agent system to provide comprehensive error debugging and analysis.
Each specialist agent has unique tools for different aspects of error analysis.

## YOUR SPECIALIST AGENTS AND THEIR TOOLS

### 1. Parser Agent (parser_agent_tool)
**Tools:** Regex patterns, AST parsing, Comprehend language detection
- Extracts stack frames, file paths, line numbers
- Detects programming language
- Classifies error type

### 2. Security Agent (security_agent_tool)
**Tools:** AWS Comprehend PII detection, Regex secret scanning
- Detects PII (emails, SSNs, phone numbers)
- Finds hardcoded secrets (API keys, tokens, passwords)
- Provides redacted version safe for logging

### 3. Context Agent (context_agent_tool)
**Tools:** GitHub Issues API, Stack Overflow API
- Searches GitHub for similar issues
- Finds Stack Overflow Q&A
- Fetches relevant documentation

### 3b. GitHub File Reader (read_github_file_tool)
**Tools:** GitHub Raw Content API
- Reads source code files directly from GitHub repositories
- Use when stack trace shows a file path and you have a repo URL
- Provides actual code context to understand what's happening at the error location

### 4. Root Cause Agent (rootcause_agent_tool)
**Tools:** Known patterns database, Bedrock Claude reasoning
- Matches against database of known error patterns
- Uses LLM for deep reasoning when patterns don't match
- Synthesizes hypothesis with confidence score

### 5. Fix Agent (fix_agent_tool)
**Tools:** Bedrock Claude code generation, AST syntax validation
- Generates specific code fixes
- Validates generated code syntax
- Suggests prevention measures
- Creates test cases

### 6. Memory Operations
**Tools:** AgentCore Memory API (semantic search, storage)
- search_memory: Find similar past errors
- store_pattern: Save error solutions for future
- store_session: Maintain session context

### 7. Stats Operations
**Tools:** Time-series analysis, frequency calculation
- record_stats: Track errors analyzed
- get_trend: Detect error trends

## ANALYSIS WORKFLOW

For comprehensive error debugging:

1. **SEARCH MEMORY FIRST** (search_memory)
   - Look for similar past errors before analyzing
   - This provides instant solutions for known issues

2. **PARSE ERROR** (parser_agent_tool)
   - Extract structure: language, type, stack frames
   - **IMPORTANT**: Identify file paths and line numbers from stack trace
   - This feeds into other agents

3. **SECURITY SCAN** (security_agent_tool)
   - Check for PII and secrets
   - Ensure safe to store and display

4. **READ SOURCE CODE** (read_github_file_tool) - When repo URL is available
   - If user provides a GitHub repo URL or the error mentions one
   - Read the files mentioned in the stack trace
   - Get actual code context at the error location
   - This dramatically improves root cause accuracy

5. **GET CONTEXT** (context_agent_tool)
   - Search GitHub Issues and Stack Overflow
   - Find community solutions

6. **ANALYZE ROOT CAUSE** (rootcause_agent_tool)
   - Match known patterns first
   - Use LLM reasoning for complex cases
   - **Use the source code context from step 4 for better analysis**

7. **GENERATE FIX** (fix_agent_tool)
   - Create code fix based on root cause
   - Validate syntax and suggest tests

8. **UPDATE MEMORY** (store_pattern)
   - Store new patterns learned
   - Track statistics

## OUTPUT FORMAT

```
## 🔍 Error Overview
- **Type**: [error type]
- **Language**: [language] ([confidence]%)
- **Security**: [risk level]

## 🧠 Memory Match
[If similar error found in memory, show previous solution]

## 📋 Parsed Information
- **Core Message**: [error message]
- **Stack Frames**: [count] frames
- **Classification**: [category]

## 🔒 Security Assessment
- **Risk Level**: [low/medium/high/critical]
- **PII Found**: [count]
- **Secrets Found**: [count]
[Recommendations if any]

## 🎯 Root Cause Analysis
- **Root Cause**: [explanation]
- **Confidence**: [percentage]%
- **Source**: [known_pattern/llm_analysis]

## 🔧 Suggested Fix
```[language]
[fixed code]
```
- **Explanation**: [why this fixes it]
- **Valid Syntax**: [yes/no]

## 📚 External Resources
- GitHub Issues: [count] related issues
- Stack Overflow: [count] related questions
[Top links]

## 🛡️ Prevention
[Recommendations to prevent this error]

## 📊 Statistics
- Similar errors in last 30 days: [count]
- Trend: [increasing/stable/decreasing]
```

## RULES
- Always search memory first for instant solutions
- Always parse before analyzing root cause
- Always check security before storing in memory
- **If a GitHub repo URL is mentioned or can be inferred, read the relevant source files**
- **Use file paths from stack traces to read actual code for better context**
- Store successful solutions in long-term memory
- Provide specific, actionable code fixes
- **NEVER say "language unknown" - use your best inference from the error patterns**
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
    ]
    
    # Part 2: Advanced agents and features
    if FEATURE_PART >= 2:
        tools.extend([
            context_agent_tool,      # GitHub Issues, StackOverflow search
            read_github_file_tool,   # Read source files from GitHub repos
            search_memory,           # Memory operations
            store_pattern,
            store_session,
            record_stats,            # Statistics
            get_trend,
        ])
        logger.info(f"🔧 Part 2 enabled: {len(tools)} tools loaded (including Memory, Context, GitHub files, Stats)")
    else:
        logger.info(f"🔧 Part 1 enabled: {len(tools)} tools loaded (core agents only)")
    
    return tools

supervisor = Agent(
    system_prompt=SUPERVISOR_PROMPT,
    tools=build_tools_list(),
    callback_handler=event_loop_tracker
)

# ============================================================================
# AgentCore Runtime Entrypoint
# ============================================================================
@app.entrypoint
async def error_debugger(payload, context):
    """
    Main entrypoint for the error debugger supervisor agent.
    Invoked by AgentCore runtime for each request.
    """
    user_input = payload.get("prompt", "")
    session_id = payload.get("session_id", "unknown")
    mode = payload.get("mode", "comprehensive")  # comprehensive, quick
    
    # Set session context for logging
    session_filter.set_session_id(session_id)
    
    logger.info(f"🚀 Error Debugger started (mode: {mode})")
    logger.info(f"📥 Input: {user_input[:100]}...")
    
    # Bypass tool consent for automation
    os.environ["BYPASS_TOOL_CONSENT"] = "true"
    
    try:
        # Build prompt based on mode
        if mode == "quick":
            prompt = f"""Quickly analyze this error (skip external searches):

ERROR: {user_input}

Run: parser, security, memory search, root cause, fix.
Focus on immediate solution, skip GitHub/StackOverflow.
"""
        else:
            prompt = f"""Comprehensively debug this error:

ERROR: {user_input}

Follow the full analysis workflow with all agents.
Search memory first, then parse, scan, research, analyze, and generate fix.
"""
        
        # Stream responses from supervisor agent
        async for event in supervisor.stream_async(prompt):
            if "data" in event:
                yield event["data"]
                
    except Exception as e:
        error_message = f"❌ Error during analysis: {str(e)}"
        logger.error(error_message)
        yield error_message


# ============================================================================
# Main Entry Point
# ============================================================================
if __name__ == "__main__":
    logger.info("🚀 Starting Error Debugger AgentCore Runtime")
    logger.info("📦 Loaded agents: parser, security, context, rootcause, fix, memory, stats")
    logger.info("🔧 Tools: Regex, AST, Comprehend, GitHub API, StackOverflow API, Bedrock Claude, AgentCore Memory")
    app.run()

