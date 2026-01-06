"""
Error Debugger - Supervisor Agent
Multi-agent system using Strands framework on AgentCore Runtime

This supervisor orchestrates specialist agents to provide comprehensive
error analysis with diverse tools: parsing, security, context, root cause,
fixes, memory, and statistics.

BLOG SERIES FEATURE FLAGS:
- Part 1: Basic multi-agent system (5 agents: Supervisor, Parser, Security, Root Cause, Fix)
- Part 2: Advanced features (All 7 agents + Memory, Context, Stats)
"""
import os
import sys
import json
import logging
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# ============================================================================
# Feature Flags - Blog Post Parts
# ============================================================================
# Set via environment variable: FEATURE_PART=1 or FEATURE_PART=2
FEATURE_PART = int(os.environ.get('FEATURE_PART', '2'))

# Part 1 agents (always imported)
from agents import (
    parser_agent,
    security_agent,
    rootcause_agent,
    fix_agent,
)

# Part 2 agents (conditionally imported)
if FEATURE_PART >= 2:
    from agents import (
        context_agent,
        memory_agent,
        stats_agent,
    )
else:
    context_agent = None
    memory_agent = None
    stats_agent = None

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
# PARSER AGENT TOOL (Uses: Regex, Comprehend, AST)
# ============================================================================
@tool(
    name="parser_agent_tool",
    description="Parse error messages to extract structured information: stack frames, programming language, error type classification. Uses regex patterns, AST parsing, and Comprehend language detection."
)
def parser_agent_tool(error_text: str) -> str:
    """Route parsing to the Parser Agent with Regex/AST/Comprehend tools."""
    logger.info(f"📋 Invoking ParserAgent with {len(error_text)} chars")
    try:
        result = parser_agent.parse(error_text)
        logger.info(f"✅ ParserAgent returned: {result.get('error_type', 'unknown')}")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ ParserAgent error: {str(e)}")
        return json.dumps({"error": str(e), "error_type": "unknown"})


# ============================================================================
# SECURITY AGENT TOOL (Uses: Comprehend PII, Regex secrets)
# ============================================================================
@tool(
    name="security_agent_tool",
    description="Scan error messages for security issues: PII using AWS Comprehend, hardcoded secrets using regex patterns. Provides redacted versions safe for logging."
)
def security_agent_tool(error_text: str) -> str:
    """Route security scanning to the Security Agent with Comprehend/Regex tools."""
    logger.info(f"🔒 Invoking SecurityAgent with {len(error_text)} chars")
    try:
        result = security_agent.scan(error_text)
        logger.info(f"✅ SecurityAgent returned: risk_level={result.get('risk_level', 'unknown')}")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ SecurityAgent error: {str(e)}")
        return json.dumps({"error": str(e), "risk_level": "unknown"})


# ============================================================================
# CONTEXT AGENT TOOL (Uses: GitHub API, StackOverflow API)
# ============================================================================
@tool(
    name="context_agent_tool",
    description="Search external resources for error context: GitHub Issues API, Stack Overflow API, official documentation. Finds similar issues and community solutions."
)
def context_agent_tool(error_message: str, error_type: str = "unknown", language: str = "unknown") -> str:
    """Route context research to the Context Agent with external API tools."""
    logger.info(f"🔍 Invoking ContextAgent for {error_type} in {language}")
    try:
        result = context_agent.research(error_message, error_type, language)
        logger.info(f"✅ ContextAgent returned: {result.get('total_resources', 0)} resources")
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ ContextAgent error: {str(e)}")
        return json.dumps({"error": str(e), "github_issues": [], "stackoverflow_questions": []})


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
# STATS TOOLS (Uses: Time-series, frequency analysis)
# ============================================================================
@tool(
    name="record_stats",
    description="Record error statistics for the current debugging session. Tracks error types, languages, and resolution times."
)
def record_stats(error_type: str, language: str, resolution_time: float = 0) -> str:
    """Record error statistics."""
    logger.info(f"📊 Recording stats: {error_type}")
    try:
        result = stats_agent.record(error_type, language, resolution_time)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Record stats error: {str(e)}")
        return json.dumps({"error": str(e)})


@tool(
    name="get_trend",
    description="Analyze error trends - detect if errors are increasing or decreasing over time. Compares current period to previous period."
)
def get_trend(error_type: str = "", window_days: int = 7) -> str:
    """Get error trend analysis."""
    logger.info(f"📈 Getting trend for: {error_type or 'all'}")
    try:
        result = stats_agent.get_trend(error_type, window_days)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"❌ Get trend error: {str(e)}")
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
   - This feeds into other agents

3. **SECURITY SCAN** (security_agent_tool)
   - Check for PII and secrets
   - Ensure safe to store and display

4. **GET CONTEXT** (context_agent_tool)
   - Search GitHub and Stack Overflow
   - Find community solutions

5. **ANALYZE ROOT CAUSE** (rootcause_agent_tool)
   - Match known patterns first
   - Use LLM reasoning for complex cases

6. **GENERATE FIX** (fix_agent_tool)
   - Create code fix based on root cause
   - Validate syntax and suggest tests

7. **UPDATE MEMORY** (store_pattern)
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
- Store successful solutions in long-term memory
- Provide specific, actionable code fixes
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
            context_agent_tool,  # GitHub, StackOverflow search
            search_memory,       # Memory operations
            store_pattern,
            store_session,
            record_stats,        # Statistics
            get_trend,
        ])
        logger.info(f"🔧 Part 2 enabled: {len(tools)} tools loaded (including Memory, Context, Stats)")
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

