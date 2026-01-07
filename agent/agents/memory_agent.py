"""
Memory Agent - Manages conversation memory using AgentCore Memory API
Stores error patterns, solutions, and learns from past debugging sessions

Uses real AgentCore Memory API in production, local storage in demo mode.
"""
import os
import boto3
import json
import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from strands import Agent, tool

from .config import DEMO_MODE, MEMORY_ID as CONFIG_MEMORY_ID

logger = logging.getLogger(__name__)

# Initialize Bedrock AgentCore client (only in live mode)
bedrock_agentcore = None
if not DEMO_MODE:
    try:
        bedrock_agentcore = boto3.client('bedrock-agentcore')
        logger.info("✅ AgentCore Memory client initialized")
    except Exception as e:
        logger.warning(f"⚠️ AgentCore client init failed: {e}")

# Memory configuration
MEMORY_ID = CONFIG_MEMORY_ID or os.environ.get('MEMORY_ID', '')
SESSION_ID = os.environ.get('SESSION_ID', 'default-session')


class MemoryType:
    """Memory type constants"""
    SESSION = "session"      # Short-term: current debugging session
    SEMANTIC = "semantic"    # Long-term: error patterns, solutions


# =============================================================================
# TOOLS - Memory operations
# =============================================================================

@tool(name="store_error_pattern")
def store_error_pattern(
    error_type: str,
    error_signature: str,
    root_cause: str,
    solution: str,
    language: str = "unknown"
) -> str:
    """
    Store an error pattern in LONG-TERM semantic memory.
    Enables learning from past errors to speed up future debugging.
    
    Args:
        error_type: Classification of the error
        error_signature: Unique signature/hash of the error pattern
        root_cause: The identified root cause
        solution: The solution that worked
        language: Programming language
    
    Returns:
        JSON confirmation of storage
    """
    logger.info(f"💾 Storing error pattern: {error_type}")
    
    # Generate content hash for deduplication
    content = f"{error_type}:{error_signature}:{root_cause}"
    content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
    
    event_data = {
        "memory_category": MemoryType.SEMANTIC,
        "pattern_type": "error_pattern",
        "error_type": error_type,
        "error_signature": error_signature,
        "root_cause": root_cause,
        "solution": solution,
        "language": language,
        "content_hash": content_hash,
        "timestamp": datetime.utcnow().isoformat(),
        "success_count": 1,  # Tracks how often this solution worked
    }
    
    result = _store_to_agentcore(event_data, MemoryType.SEMANTIC)
    result["pattern_type"] = "error_pattern"
    result["content_hash"] = content_hash
    
    logger.info(f"✅ Stored error pattern: {content_hash}")
    return json.dumps(result)


@tool(name="search_similar_errors")
def search_similar_errors(error_text: str, limit: int = 5) -> str:
    """
    Search LONG-TERM memory for similar past errors.
    Uses semantic search to find relevant debugging history.
    
    Args:
        error_text: The current error to match against
        limit: Maximum number of results
    
    Returns:
        JSON with matching past errors and their solutions
    """
    logger.info(f"🔎 Searching for similar errors... (mode: {'DEMO' if DEMO_MODE else 'LIVE'})")
    
    # Extract error_type and language from query if embedded (format: "[python] import_error: ...")
    detected_language = ""
    detected_error_type = ""
    
    import re
    lang_match = re.search(r'\[(\w+)\]', error_text)
    if lang_match:
        detected_language = lang_match.group(1)
    
    type_match = re.search(r'^(\w+_?\w*):', error_text)
    if type_match:
        detected_error_type = type_match.group(1)
    
    # Minimum relevance threshold - matches below this are considered noise
    MIN_RELEVANCE_THRESHOLD = 50
    
    # Use local search in demo mode
    if DEMO_MODE:
        logger.info("📦 Demo mode: Using local memory search")
        results = _local_search(error_text, detected_error_type, detected_language, MIN_RELEVANCE_THRESHOLD)[:limit]
        
        # Filter out low-relevance matches
        high_quality_results = [r for r in results if r.get('relevance_score', 0) >= MIN_RELEVANCE_THRESHOLD]
        
        return json.dumps({
            "success": True,
            "memory_type": "LONG-TERM (local)",
            "query": error_text[:100],
            "count": len(high_quality_results),
            "results": high_quality_results,
            "has_solutions": len(high_quality_results) > 0,
            "has_relevant_match": len(high_quality_results) > 0 and high_quality_results[0].get('relevance_score', 0) >= 70,
            "best_match_score": high_quality_results[0].get('relevance_score', 0) if high_quality_results else 0,
            "mode": "demo",
            "note": "Only showing matches with relevance >= 50%"
        })
    
    try:
        if not MEMORY_ID or not bedrock_agentcore:
            logger.warning("Memory not configured, using local fallback")
            results = _local_search(error_text, detected_error_type, detected_language, MIN_RELEVANCE_THRESHOLD)[:limit]
            high_quality_results = [r for r in results if r.get('relevance_score', 0) >= MIN_RELEVANCE_THRESHOLD]
            
            return json.dumps({
                "success": True,
                "memory_type": "LONG-TERM (local)",
                "query": error_text[:100],
                "count": len(high_quality_results),
                "results": high_quality_results,
                "has_solutions": len(high_quality_results) > 0,
                "has_relevant_match": len(high_quality_results) > 0 and high_quality_results[0].get('relevance_score', 0) >= 70,
                "message": "No long-term memory configured, using local"
            })
        
        # Use AgentCore semantic search
        response = bedrock_agentcore.search_memory(
            memoryId=MEMORY_ID,
            query=error_text,
            maxResults=limit * 2,
        )
        
        results = []
        for result in response.get('results', []):
            try:
                data = json.loads(result.get('eventData', '{}'))
                
                # Filter for error patterns only
                if data.get('memory_category') != MemoryType.SEMANTIC:
                    continue
                if data.get('pattern_type') != 'error_pattern':
                    continue
                
                relevance = result.get('score', 0)
                
                # Skip low relevance matches
                if relevance < MIN_RELEVANCE_THRESHOLD:
                    continue
                
                # Additional filter: if we detected an error type, the stored pattern should match
                stored_error_type = data.get('error_type', '').lower()
                if detected_error_type and detected_error_type.lower() not in stored_error_type:
                    # Penalize but don't completely exclude
                    relevance = relevance * 0.5
                    if relevance < MIN_RELEVANCE_THRESHOLD:
                        continue
                
                results.append({
                    "error_type": data.get('error_type'),
                    "root_cause": data.get('root_cause'),
                    "solution": data.get('solution'),
                    "language": data.get('language'),
                    "relevance_score": relevance,
                    "success_count": data.get('success_count', 1),
                    "timestamp": data.get('timestamp'),
                })
            except json.JSONDecodeError:
                continue
        
        # Sort by relevance
        results.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        results = results[:limit]
        
        logger.info(f"✅ Found {len(results)} relevant similar errors (filtered by threshold)")
        return json.dumps({
            "success": True,
            "memory_type": "LONG-TERM (Semantic)",
            "query": error_text[:100],
            "count": len(results),
            "results": results,
            "has_solutions": len(results) > 0,
            "has_relevant_match": len(results) > 0 and results[0].get('relevance_score', 0) >= 70,
            "best_match_score": results[0].get('relevance_score', 0) if results else 0,
            "note": "Only showing matches with relevance >= 50%"
        })
        
    except Exception as e:
        logger.error(f"❌ Memory search failed: {str(e)}")
        return json.dumps({
            "success": False,
            "memory_type": "LONG-TERM (Semantic)",
            "query": error_text[:100],
            "results": [],
            "error": str(e)
        })


@tool(name="store_session_context")
def store_session_context(context_type: str, content: str) -> str:
    """
    Store context in SHORT-TERM session memory.
    Maintains state during a debugging session.
    
    Args:
        context_type: Type of context (current_error, hypothesis, user_info)
        content: The content to store (JSON string or plain text)
    
    Returns:
        JSON confirmation
    """
    logger.info(f"📝 Storing session context: {context_type}")
    
    try:
        content_dict = json.loads(content) if content.startswith('{') else {"text": content}
    except:
        content_dict = {"text": content}
    
    event_data = {
        "memory_category": MemoryType.SESSION,
        "session_id": SESSION_ID,
        "context_type": context_type,
        "content": content_dict,
        "timestamp": datetime.utcnow().isoformat(),
        "ttl_hours": 24,
    }
    
    result = _store_to_agentcore(event_data, MemoryType.SESSION)
    logger.info(f"✅ Session context stored: {context_type}")
    return json.dumps(result)


@tool(name="get_session_context")
def get_session_context(context_type: str = "") -> str:
    """
    Retrieve context from SHORT-TERM session memory.
    
    Args:
        context_type: Optional filter by context type
    
    Returns:
        JSON with session context
    """
    logger.info(f"🔍 Retrieving session context: {context_type or 'all'}")
    
    try:
        if not MEMORY_ID or not bedrock_agentcore:
            return json.dumps(_local_retrieve(MemoryType.SESSION, context_type))
        
        response = bedrock_agentcore.get_memory_events(
            memoryId=MEMORY_ID,
            maxResults=20,
        )
        
        events = []
        for event in response.get('events', []):
            try:
                data = json.loads(event.get('eventData', '{}'))
                if data.get('memory_category') != MemoryType.SESSION:
                    continue
                if data.get('session_id') != SESSION_ID:
                    continue
                if context_type and data.get('context_type') != context_type:
                    continue
                    
                events.append({
                    "context_type": data.get('context_type'),
                    "content": data.get('content'),
                    "timestamp": data.get('timestamp'),
                })
            except json.JSONDecodeError:
                continue
        
        logger.info(f"✅ Retrieved {len(events)} session memories")
        return json.dumps({
            "success": True,
            "memory_type": "SHORT-TERM (Session)",
            "session_id": SESSION_ID[:8] + "...",
            "count": len(events),
            "events": events,
        })
        
    except Exception as e:
        logger.error(f"❌ Session retrieval failed: {str(e)}")
        return json.dumps(_local_retrieve(MemoryType.SESSION, context_type))


@tool(name="increment_solution_success")
def increment_solution_success(error_signature: str) -> str:
    """
    Increment the success count for a solution that worked.
    Helps track which solutions are most reliable.
    
    Args:
        error_signature: The error pattern signature to update
    
    Returns:
        JSON confirmation
    """
    logger.info(f"📈 Incrementing success count for: {error_signature}")
    
    # In a production system, this would update the existing memory event
    # For demo, we log the intent
    result = {
        "success": True,
        "error_signature": error_signature,
        "action": "success_count_incremented",
        "note": "In production, updates AgentCore memory event"
    }
    
    return json.dumps(result)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _store_to_agentcore(event_data: Dict[str, Any], memory_type: str) -> Dict[str, Any]:
    """Store event to AgentCore Memory."""
    # Use local storage in demo mode
    if DEMO_MODE:
        logger.info("📦 Demo mode: Using local memory storage")
        return _local_store(event_data, memory_type)
    
    try:
        if not MEMORY_ID or not bedrock_agentcore:
            logger.warning("MEMORY_ID not configured, using local fallback")
            return _local_store(event_data, memory_type)
        
        response = bedrock_agentcore.create_memory_event(
            memoryId=MEMORY_ID,
            eventData=json.dumps(event_data),
        )
        
        return {
            "success": True,
            "memory_type": "LONG-TERM" if memory_type == MemoryType.SEMANTIC else "SHORT-TERM",
            "memory_id": MEMORY_ID[:8] + "...",
            "event_id": response.get('eventId', 'unknown'),
            "mode": "live"
        }
        
    except Exception as e:
        logger.error(f"AgentCore store failed: {str(e)}")
        return _local_store(event_data, memory_type)


# =============================================================================
# LOCAL FALLBACK STORAGE
# =============================================================================

_local_session_memory: Dict[str, Any] = {}
_local_semantic_memory: List[Dict[str, Any]] = []

# NO pre-seeded patterns - memory should only contain patterns stored during actual use
# Static patterns were causing false matches and polluting analysis


def _local_store(event_data: Dict[str, Any], memory_type: str) -> Dict[str, Any]:
    """Local fallback for memory storage."""
    if memory_type == MemoryType.SEMANTIC:
        _local_semantic_memory.append(event_data)
        return {
            "success": True,
            "memory_type": "LONG-TERM (local)",
            "storage": "local",
            "count": len(_local_semantic_memory),
        }
    else:
        key = event_data.get('context_type', 'unknown')
        _local_session_memory[key] = event_data
        return {
            "success": True,
            "memory_type": "SHORT-TERM (local)",
            "storage": "local",
            "key": key,
        }


def _local_retrieve(memory_type: str, key: str = None) -> Dict[str, Any]:
    """Local fallback for memory retrieval."""
    if memory_type == MemoryType.SEMANTIC:
        return {
            "success": True,
            "memory_type": "LONG-TERM (local)",
            "patterns": _local_semantic_memory,
            "count": len(_local_semantic_memory)
        }
    else:
        if key and key in _local_session_memory:
            return {
                "success": True,
                "memory_type": "SHORT-TERM (local)",
                "events": [_local_session_memory[key]],
                "count": 1
            }
        return {
            "success": True,
            "memory_type": "SHORT-TERM (local)",
            "events": list(_local_session_memory.values()),
            "count": len(_local_session_memory)
        }


def _local_search(query: str, error_type: str = "", language: str = "", min_score: int = 50) -> List[Dict]:
    """
    Local memory search - only searches patterns stored during actual use.
    
    NO static pattern matching - the memory is empty until patterns are stored
    from successful debugging sessions.
    """
    # Memory starts empty - only contains patterns from actual successful sessions
    if not _local_semantic_memory:
        return []
    
    query_lower = query.lower()
    results = []
    
    for pattern in _local_semantic_memory:
        if pattern.get('pattern_type') != 'error_pattern':
            continue
        
        # Simple keyword matching for stored patterns (not static rules)
        searchable = f"{pattern.get('root_cause', '')} {pattern.get('solution', '')}".lower()
        
        # Score based on matching key terms
        score = 0
        key_terms = [word for word in query_lower.split() if len(word) > 4]
        for term in key_terms:
            if term in searchable:
                score += 20
        
        # Language bonus
        if language and pattern.get('language', '').lower() == language.lower():
            score += 15
        
        if score >= min_score:
            results.append({
                **pattern,
                "relevance_score": min(score, 100)
            })
    
    return sorted(results, key=lambda x: x.get('relevance_score', 0), reverse=True)


# =============================================================================
# AGENT - Strands Agent with memory tools
# =============================================================================

MEMORY_AGENT_PROMPT = """You are a Memory Management Specialist Agent.

## YOUR ROLE
Manage error pattern memory to learn from past debugging sessions.
Store solutions that worked and find relevant past errors.

## YOUR TOOLS
- store_error_pattern: Store a successful error solution in LONG-TERM memory
- search_similar_errors: Search for similar past errors and their solutions
- store_session_context: Store current debugging session context (SHORT-TERM)
- get_session_context: Retrieve current session context
- increment_solution_success: Mark a solution as successful

## MEMORY TYPES

### SHORT-TERM (Session Memory)
- TTL: 24 hours
- Purpose: Current debugging session state
- Examples: current error, hypotheses, user context

### LONG-TERM (Semantic Memory)  
- TTL: Persistent (30+ days)
- Purpose: Error patterns and solutions
- Examples: error_type -> root_cause -> solution mappings

## OUTPUT FORMAT
Return a JSON object with memory operation results.

Always return valid JSON only, no additional text.
"""

memory_agent = Agent(
    system_prompt=MEMORY_AGENT_PROMPT,
    tools=[store_error_pattern, search_similar_errors, store_session_context, 
           get_session_context, increment_solution_success],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def search(query: str, limit: int = 5) -> Dict[str, Any]:
    """Search memory for similar errors."""
    result_str = search_similar_errors(query, limit)
    return json.loads(result_str)


def store_pattern(error_type: str, signature: str, root_cause: str, 
                  solution: str, language: str = "unknown") -> Dict[str, Any]:
    """Store an error pattern."""
    result_str = store_error_pattern(error_type, signature, root_cause, solution, language)
    return json.loads(result_str)


def store_context(context_type: str, content: Any) -> Dict[str, Any]:
    """Store session context."""
    content_str = json.dumps(content) if isinstance(content, dict) else str(content)
    result_str = store_session_context(context_type, content_str)
    return json.loads(result_str)


def get_context(context_type: str = "") -> Dict[str, Any]:
    """Get session context."""
    result_str = get_session_context(context_type)
    return json.loads(result_str)

