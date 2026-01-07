"""
Parser Agent - Extracts structured information from error messages
Tools: Regex-based parsing, language detection, error classification

Uses regex for structural extraction (stack traces, file paths).
Uses LLM fallback for ambiguous language/error detection.
"""
import re
import json
import logging
import boto3
from typing import Dict, Any, List
from strands import Agent, tool

from .config import DEMO_MODE, AWS_REGION

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock_runtime = None
try:
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=AWS_REGION)
    logger.info("✅ Bedrock client initialized for ParserAgent")
except Exception as e:
    logger.warning(f"⚠️ Bedrock client init failed: {e}")

# =============================================================================
# ERROR PATTERNS - For classification
# =============================================================================

ERROR_PATTERNS = {
    # Infrastructure / Config errors
    "config_error": [
        r"(?i)(Unsupported block type|Unsupported argument|Missing required argument)",
        r"(?i)(Invalid reference|Reference to undeclared|blocks of type.*not expected)",
        r"(?i)(Error:.*on.*\.tf|Error:.*terraform)",
        r"(?i)(Invalid.*configuration|Configuration.*invalid)",
    ],
    "null_reference": [
        r"(?i)(cannot read propert|undefined is not|null pointer|NoneType|'None' object)",
        r"(?i)(TypeError:.*undefined|TypeError:.*null)",
    ],
    "type_error": [
        r"(?i)(TypeError|type mismatch|expected.*got|cannot convert)",
        r"(?i)(argument.*type|invalid type)",
    ],
    "syntax_error": [
        r"(?i)(SyntaxError|unexpected token|parse error|invalid syntax)",
        r"(?i)(missing.*bracket|unterminated string)",
    ],
    "import_error": [
        r"(?i)(ImportError|ModuleNotFoundError|No module named|cannot find module)",
        r"(?i)(require\(|import.*from.*failed)",
    ],
    "connection_error": [
        r"(?i)(ConnectionError|ECONNREFUSED|timeout|network.*unreachable)",
        r"(?i)(failed to connect|connection refused|socket error)",
    ],
    "permission_error": [
        r"(?i)(PermissionError|Access denied|EACCES|forbidden|unauthorized)",
        r"(?i)(permission denied|not permitted)",
    ],
    "memory_error": [
        r"(?i)(MemoryError|OutOfMemory|heap.*overflow|stack overflow)",
        r"(?i)(memory allocation|out of memory|ENOMEM)",
    ],
    "file_error": [
        r"(?i)(FileNotFoundError|ENOENT|No such file|file not found)",
        r"(?i)(cannot open|failed to read|path does not exist)",
    ],
    "key_error": [
        r"(?i)(KeyError|index out of|IndexError|undefined index)",
        r"(?i)(array index|list index|key.*not found)",
    ],
    "validation_error": [
        r"(?i)(ValidationError|invalid.*format|does not match|assertion failed)",
        r"(?i)(constraint violation|schema.*invalid)",
    ],
}

LANGUAGE_PATTERNS = {
    "python": [r"\.py:", r"Traceback \(most recent call last\)", r"File \".*\.py\""],
    "javascript": [r"\.js:", r"at\s+\w+\s+\(.*\.js:", r"TypeError:.*undefined"],
    "typescript": [r"\.ts:", r"\.tsx:", r"at\s+\w+\s+\(.*\.ts:"],
    "java": [r"\.java:", r"at\s+[\w.]+\([\w]+\.java:", r"Exception in thread"],
    "go": [r"\.go:", r"panic:", r"goroutine \d+"],
    "rust": [r"\.rs:", r"thread '.*' panicked", r"error\[E\d+\]:"],
    "ruby": [r"\.rb:", r"from.*\.rb:\d+:in"],
    "php": [r"\.php:", r"PHP Fatal error:", r"PHP Warning:"],
    "csharp": [r"\.cs:", r"at\s+[\w.]+\s+in\s+.*\.cs:"],
    "terraform": [r"\.tf:", r"on\s+\w+\.tf\s+line", r"terraform", r"Error:.*terraform", r"aws_", r"resource\s+\""],
    "cloudformation": [r"\.yaml:", r"\.yml:", r"CloudFormation", r"AWS::"],
    "dockerfile": [r"Dockerfile", r"docker build", r"FROM\s+\w+"],
    "bash": [r"\.sh:", r"bash:", r"command not found", r"/bin/bash"],
}

# =============================================================================
# TOOLS - Regex-based parsing and analysis
# =============================================================================

@tool(name="extract_stack_frames")
def extract_stack_frames(error_text: str) -> str:
    """
    Extract structured stack trace information using regex patterns.
    Parses file paths, line numbers, function names, and code snippets.
    
    Args:
        error_text: The raw error message and stack trace
    
    Returns:
        JSON with extracted stack frames
    """
    logger.info(f"🔧 Extracting stack frames from {len(error_text)} chars")
    
    frames = []
    
    # Python stack trace pattern
    python_pattern = r'File "([^"]+)", line (\d+), in (\w+)'
    for match in re.finditer(python_pattern, error_text):
        frames.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "function": match.group(3),
            "language": "python"
        })
    
    # JavaScript/Node stack trace pattern
    js_pattern = r'at\s+(\w+)\s+\(([^:]+):(\d+):(\d+)\)'
    for match in re.finditer(js_pattern, error_text):
        frames.append({
            "file": match.group(2),
            "line": int(match.group(3)),
            "column": int(match.group(4)),
            "function": match.group(1),
            "language": "javascript"
        })
    
    # Generic file:line pattern
    generic_pattern = r'([/\w\-_.]+\.\w+):(\d+)'
    if not frames:
        for match in re.finditer(generic_pattern, error_text):
            frames.append({
                "file": match.group(1),
                "line": int(match.group(2)),
                "function": "unknown",
                "language": "unknown"
            })
    
    result = {
        "frame_count": len(frames),
        "frames": frames[:10],  # Limit to top 10 frames
        "has_stack_trace": len(frames) > 0
    }
    
    logger.info(f"✅ Extracted {len(frames)} stack frames")
    return json.dumps(result)


@tool(name="detect_programming_language")
def detect_programming_language(error_text: str) -> str:
    """
    Detect the programming language from error message patterns.
    Uses regex patterns first, then LLM fallback for low-confidence cases.
    
    Args:
        error_text: The error message to analyze
    
    Returns:
        JSON with detected language and confidence
    """
    logger.info("🔧 Detecting programming language")
    
    # First try regex patterns (fast)
    scores = {}
    for language, patterns in LANGUAGE_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, error_text, re.IGNORECASE):
                score += 1
        if score > 0:
            scores[language] = score
    
    if scores:
        detected = max(scores, key=scores.get)
        confidence = min(scores[detected] / len(LANGUAGE_PATTERNS[detected]) * 100, 100)
    else:
        detected = "unknown"
        confidence = 0
    
    # If low confidence and LLM available, use LLM
    if confidence < 50 and bedrock_runtime:
        logger.info("Low confidence, using LLM for language detection")
        try:
            llm_result = _detect_language_with_llm(error_text)
            if llm_result and llm_result.get("confidence", 0) > confidence:
                detected = llm_result.get("language", detected)
                confidence = llm_result.get("confidence", confidence)
                logger.info(f"LLM detected: {detected} ({confidence}%)")
        except Exception as e:
            logger.warning(f"LLM detection failed: {e}")
    
    result = {
        "language": detected,
        "confidence": round(confidence, 1),
        "all_matches": scores
    }
    
    logger.info(f"✅ Detected language: {detected} ({confidence}%)")
    return json.dumps(result)


def _detect_language_with_llm(error_text: str) -> Dict[str, Any]:
    """Use LLM to detect programming language when regex is uncertain."""
    if not bedrock_runtime:
        return {}
    
    prompt = f"""What programming language or tool produced this error? Respond with ONLY JSON.

Error:
```
{error_text[:1500]}
```

Respond ONLY with this JSON format:
{{"language": "python|javascript|typescript|java|go|rust|ruby|php|terraform|bash|unknown", "confidence": 0-100}}"""

    try:
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",  # Fast model for quick detection
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 100,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}]
            })
        )
        
        response_body = json.loads(response['body'].read())
        content = response_body.get('content', [{}])[0].get('text', '{}')
        
        start = content.find('{')
        end = content.rfind('}') + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
    except Exception as e:
        logger.warning(f"LLM language detection failed: {e}")
    
    return {}


@tool(name="classify_error_type")
def classify_error_type(error_text: str) -> str:
    """
    Classify the error into predefined categories using pattern matching.
    Categories: null_reference, type_error, syntax_error, import_error, etc.
    
    Args:
        error_text: The error message to classify
    
    Returns:
        JSON with error classification and matched patterns
    """
    logger.info("🔧 Classifying error type")
    
    matches = []
    for error_type, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, error_text):
                matches.append({
                    "type": error_type,
                    "pattern": pattern,
                    "match": re.search(pattern, error_text).group(0)
                })
                break  # One match per type is enough
    
    # Determine primary error type
    primary_type = matches[0]["type"] if matches else "unknown"
    
    result = {
        "primary_type": primary_type,
        "all_types": [m["type"] for m in matches],
        "match_count": len(matches),
        "matches": matches[:5]  # Limit details
    }
    
    logger.info(f"✅ Classified as: {primary_type}")
    return json.dumps(result)


@tool(name="extract_error_message")
def extract_error_message(error_text: str) -> str:
    """
    Extract the core error message from a stack trace.
    Removes stack trace noise to get the actual error.
    
    Args:
        error_text: The full error output
    
    Returns:
        JSON with extracted error message
    """
    logger.info("🔧 Extracting core error message")
    
    lines = error_text.strip().split('\n')
    
    # Common error message patterns
    error_patterns = [
        r'^(Error|TypeError|SyntaxError|ReferenceError|ValueError|KeyError|AttributeError|ImportError|RuntimeError):(.+)$',
        r'^(Traceback.*:)$',
        r'^(\w+Error):(.+)$',
        r'^(panic:)(.+)$',
        r'^(Exception in thread .+:)(.+)$',
    ]
    
    error_message = None
    error_type = None
    
    for line in lines:
        line = line.strip()
        for pattern in error_patterns:
            match = re.match(pattern, line)
            if match:
                error_type = match.group(1)
                error_message = match.group(2).strip() if len(match.groups()) > 1 else ""
                break
        if error_message:
            break
    
    # If no match, use the first non-empty line
    if not error_message:
        for line in lines:
            if line.strip() and not line.strip().startswith('at '):
                error_message = line.strip()
                break
    
    result = {
        "error_type": error_type or "Unknown",
        "message": error_message or error_text[:200],
        "full_first_line": lines[0] if lines else ""
    }
    
    logger.info(f"✅ Extracted: {error_type}")
    return json.dumps(result)


# =============================================================================
# AGENT - Strands Agent with parsing tools
# =============================================================================

PARSER_AGENT_PROMPT = """You are a Stack Trace Parser Specialist Agent.

## YOUR ROLE
Parse and extract structured information from error messages and stack traces.
You are the first agent in the analysis pipeline - your output feeds other agents.

## YOUR TOOLS
- extract_stack_frames: Parse file paths, line numbers, and function names from stack traces
- detect_programming_language: Identify which language produced the error  
- classify_error_type: Categorize the error (null_reference, type_error, syntax_error, etc.)
- extract_error_message: Extract the core error message from noisy output

## YOUR WORKFLOW
1. Call extract_error_message to get the core error
2. Call detect_programming_language to identify the source language
3. Call classify_error_type to categorize the error
4. Call extract_stack_frames to get the stack trace structure

## OUTPUT FORMAT
Return a JSON object with:
{
    "error_type": "null_reference|type_error|syntax_error|...",
    "language": "python|javascript|go|...",
    "language_confidence": 0-100,
    "core_message": "The actual error message",
    "stack_frames": [{"file": "...", "line": N, "function": "..."}],
    "frame_count": N,
    "classification_confidence": 0-100
}

Always return valid JSON only, no additional text.
"""

parser_agent = Agent(
    system_prompt=PARSER_AGENT_PROMPT,
    tools=[extract_stack_frames, detect_programming_language, classify_error_type, extract_error_message],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def parse(error_text: str) -> Dict[str, Any]:
    """
    Parse an error message using the Parser Agent.
    This is the interface called by the Supervisor Agent.
    
    Args:
        error_text: Raw error message/stack trace
        
    Returns:
        Dict with parsed error structure
    """
    logger.info(f"📋 ParserAgent: Starting parse of {len(error_text)} chars")
    
    try:
        result = parser_agent(f"Parse this error message and extract structured information:\n\n{error_text}")
        response_text = str(result)
        
        # Try to extract JSON from response
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ ParserAgent complete: {parsed.get('error_type', 'unknown')}")
                return parsed
        except json.JSONDecodeError:
            pass
        
        # Fallback: call tools directly
        logger.warning("Agent response not JSON, falling back to direct tool calls")
        return _direct_parse(error_text)
        
    except Exception as e:
        logger.error(f"❌ ParserAgent error: {str(e)}")
        return _direct_parse(error_text)


def _direct_parse(error_text: str) -> Dict[str, Any]:
    """Direct parsing fallback without agent reasoning."""
    try:
        msg_result = json.loads(extract_error_message(error_text))
        lang_result = json.loads(detect_programming_language(error_text))
        type_result = json.loads(classify_error_type(error_text))
        frames_result = json.loads(extract_stack_frames(error_text))
        
        return {
            "error_type": type_result.get("primary_type", "unknown"),
            "language": lang_result.get("language", "unknown"),
            "language_confidence": lang_result.get("confidence", 0),
            "core_message": msg_result.get("message", error_text[:200]),
            "stack_frames": frames_result.get("frames", []),
            "frame_count": frames_result.get("frame_count", 0),
            "classification_confidence": min(len(type_result.get("matches", [])) * 25, 100)
        }
    except Exception as e:
        logger.error(f"Direct parse failed: {str(e)}")
        return {
            "error_type": "unknown",
            "language": "unknown",
            "language_confidence": 0,
            "core_message": error_text[:200],
            "stack_frames": [],
            "frame_count": 0,
            "classification_confidence": 0,
            "error": str(e)
        }

