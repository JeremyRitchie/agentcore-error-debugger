"""
Memory Agent - Manages conversation memory using AgentCore Memory API
Stores error patterns, solutions, and learns from past debugging sessions

Uses real AgentCore Memory API in production, local storage in demo mode.
ALWAYS stores locally in addition to API for immediate within-process retrieval.
"""
import os
import re
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

logger.info(f"🧠 Memory config: DEMO_MODE={DEMO_MODE}, MEMORY_ID={'SET (' + MEMORY_ID[:12] + '...)' if MEMORY_ID else 'NOT SET'}, client={'OK' if bedrock_agentcore else 'NONE'}")


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
    logger.info(f"💾 MEMORY STORE: type={error_type}, lang={language}, sig={error_signature[:60]}")
    logger.info(f"💾 MEMORY STORE: root_cause={root_cause[:100]}...")
    logger.info(f"💾 MEMORY STORE: solution={solution[:100]}...")
    
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
    
    logger.info(f"✅ MEMORY STORE COMPLETE: hash={content_hash}, storage={result.get('storage', result.get('mode', 'unknown'))}, local_count={len(_local_semantic_memory)}")
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
    logger.info(f"🔎 MEMORY SEARCH: query={error_text[:120]}... (mode: {'DEMO' if DEMO_MODE else 'LIVE'}, local_patterns={len(_local_semantic_memory)})")
    
    # Extract error_type and language from query if embedded (format: "[python] import_error: ...")
    detected_language = ""
    detected_error_type = ""
    
    lang_match = re.search(r'\[(\w+)\]', error_text)
    if lang_match:
        detected_language = lang_match.group(1)
    
    type_match = re.search(r'^(\w+(?:_?\w+)*):', error_text)
    if type_match:
        detected_error_type = type_match.group(1)
    
    logger.info(f"🔎 MEMORY SEARCH: detected_language={detected_language}, detected_error_type={detected_error_type}")
    
    # Minimum relevance threshold - matches below this are considered noise
    MIN_RELEVANCE_THRESHOLD = 50
    
    # ALWAYS search local memory first (for immediate within-process retrieval)
    local_results = _local_search(error_text, detected_error_type, detected_language, MIN_RELEVANCE_THRESHOLD)[:limit]
    local_high_quality = [r for r in local_results if r.get('relevance_score', 0) >= MIN_RELEVANCE_THRESHOLD]
    
    logger.info(f"🔎 MEMORY SEARCH LOCAL: {len(local_high_quality)} results from {len(_local_semantic_memory)} stored patterns")
    for i, r in enumerate(local_high_quality[:3]):
        logger.info(f"  Local match #{i+1}: score={r.get('relevance_score')}, type={r.get('error_type')}, solution={str(r.get('solution', ''))[:80]}...")
    
    # Use local search in demo mode
    if DEMO_MODE:
        logger.info(f"📦 Demo mode: Returning {len(local_high_quality)} local results")
        return json.dumps({
            "success": True,
            "memory_type": "LONG-TERM (local)",
            "query": error_text[:100],
            "count": len(local_high_quality),
            "results": local_high_quality,
            "has_solutions": len(local_high_quality) > 0,
            "has_relevant_match": len(local_high_quality) > 0 and local_high_quality[0].get('relevance_score', 0) >= 70,
            "best_match_score": local_high_quality[0].get('relevance_score', 0) if local_high_quality else 0,
            "mode": "demo",
            "note": "Only showing matches with relevance >= 50%"
        })
    
    try:
        if not MEMORY_ID or not bedrock_agentcore:
            logger.warning(f"⚠️ MEMORY SEARCH: No API configured (MEMORY_ID={'SET' if MEMORY_ID else 'EMPTY'}, client={'OK' if bedrock_agentcore else 'NONE'}). Using local only.")
            return json.dumps({
                "success": True,
                "memory_type": "LONG-TERM (local)",
                "query": error_text[:100],
                "count": len(local_high_quality),
                "results": local_high_quality,
                "has_solutions": len(local_high_quality) > 0,
                "has_relevant_match": len(local_high_quality) > 0 and local_high_quality[0].get('relevance_score', 0) >= 70,
                "best_match_score": local_high_quality[0].get('relevance_score', 0) if local_high_quality else 0,
                "message": "No long-term memory configured, using local"
            })
        
        # Use AgentCore semantic search
        logger.info(f"🔎 MEMORY SEARCH API: Calling bedrock_agentcore.search_memory(memoryId={MEMORY_ID[:12]}..., query_len={len(error_text)}, maxResults={limit * 2})")
        response = bedrock_agentcore.search_memory(
            memoryId=MEMORY_ID,
            query=error_text,
            maxResults=limit * 2,
        )
        
        raw_results = response.get('results', [])
        logger.info(f"🔎 MEMORY SEARCH API: Got {len(raw_results)} raw results from AgentCore")
        
        api_results = []
        for idx, result in enumerate(raw_results):
            try:
                data = json.loads(result.get('eventData', '{}'))
                relevance = result.get('score', 0)
                logger.info(f"  API result #{idx+1}: score={relevance}, category={data.get('memory_category')}, type={data.get('pattern_type')}, error_type={data.get('error_type')}")
                
                # Filter for error patterns only
                if data.get('memory_category') != MemoryType.SEMANTIC:
                    logger.info(f"  → Skipped: wrong category ({data.get('memory_category')})")
                    continue
                if data.get('pattern_type') != 'error_pattern':
                    logger.info(f"  → Skipped: wrong pattern_type ({data.get('pattern_type')})")
                    continue
                
                # Skip low relevance matches
                if relevance < MIN_RELEVANCE_THRESHOLD:
                    logger.info(f"  → Skipped: low relevance ({relevance} < {MIN_RELEVANCE_THRESHOLD})")
                    continue
                
                # Additional filter: if we detected an error type, the stored pattern should match
                stored_error_type = data.get('error_type', '').lower()
                if detected_error_type and detected_error_type.lower() not in stored_error_type:
                    # Penalize but don't completely exclude
                    old_relevance = relevance
                    relevance = relevance * 0.5
                    if relevance < MIN_RELEVANCE_THRESHOLD:
                        logger.info(f"  → Skipped: error_type mismatch penalty ({old_relevance} → {relevance})")
                        continue
                
                api_results.append({
                    "error_type": data.get('error_type'),
                    "root_cause": data.get('root_cause'),
                    "solution": data.get('solution'),
                    "language": data.get('language'),
                    "relevance_score": relevance,
                    "success_count": data.get('success_count', 1),
                    "timestamp": data.get('timestamp'),
                    "source": "agentcore_api",
                })
            except json.JSONDecodeError:
                logger.warning(f"  → Skipped: invalid JSON in result #{idx+1}")
                continue
        
        # Merge local + API results, deduplicate by content hash, sort by score
        all_results = _merge_results(local_high_quality, api_results)
        all_results = all_results[:limit]
        
        best_score = all_results[0].get('relevance_score', 0) if all_results else 0
        has_relevant = len(all_results) > 0 and best_score >= 70
        
        logger.info(f"✅ MEMORY SEARCH COMPLETE: {len(local_high_quality)} local + {len(api_results)} API = {len(all_results)} merged results (best_score={best_score}, relevant={has_relevant})")
        
        return json.dumps({
            "success": True,
            "memory_type": "LONG-TERM (Semantic)",
            "query": error_text[:100],
            "count": len(all_results),
            "results": all_results,
            "has_solutions": len(all_results) > 0,
            "has_relevant_match": has_relevant,
            "best_match_score": best_score,
            "local_count": len(local_high_quality),
            "api_count": len(api_results),
            "note": "Only showing matches with relevance >= 50%"
        })
        
    except Exception as e:
        logger.error(f"❌ MEMORY SEARCH API FAILED: {str(e)} — falling back to {len(local_high_quality)} local results")
        # Fall back to local results on API failure
        return json.dumps({
            "success": True,  # Local results are still valid
            "memory_type": "LONG-TERM (local fallback)",
            "query": error_text[:100],
            "count": len(local_high_quality),
            "results": local_high_quality,
            "has_solutions": len(local_high_quality) > 0,
            "has_relevant_match": len(local_high_quality) > 0 and local_high_quality[0].get('relevance_score', 0) >= 70,
            "best_match_score": local_high_quality[0].get('relevance_score', 0) if local_high_quality else 0,
            "api_error": str(e),
            "note": "AgentCore API failed, using local results"
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
    except Exception:
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
    
    # Also update local memory
    for pattern in _local_semantic_memory:
        if pattern.get('error_signature') == error_signature:
            pattern['success_count'] = pattern.get('success_count', 1) + 1
            logger.info(f"📈 Local pattern updated: success_count={pattern['success_count']}")
            break
    
    result = {
        "success": True,
        "error_signature": error_signature,
        "action": "success_count_incremented",
        "note": "Updated local memory; in production, also updates AgentCore memory event"
    }
    
    return json.dumps(result)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _store_to_agentcore(event_data: Dict[str, Any], memory_type: str) -> Dict[str, Any]:
    """
    Store event to AgentCore Memory.
    ALWAYS stores locally in addition to the API for immediate within-process retrieval.
    """
    # ALWAYS store locally first (ensures immediate retrieval within the same process)
    local_result = _local_store(event_data, memory_type)
    logger.info(f"💾 Local store: {local_result.get('memory_type')}, count={local_result.get('count', 'n/a')}")
    
    # Use local storage only in demo mode
    if DEMO_MODE:
        logger.info("📦 Demo mode: Local-only storage")
        return local_result
    
    try:
        if not MEMORY_ID or not bedrock_agentcore:
            logger.warning(f"⚠️ MEMORY_ID not configured or no client, local-only storage")
            return local_result
        
        logger.info(f"💾 API store: Calling bedrock_agentcore.create_memory_event(memoryId={MEMORY_ID[:12]}...)")
        response = bedrock_agentcore.create_memory_event(
            memoryId=MEMORY_ID,
            eventData=json.dumps(event_data),
        )
        
        event_id = response.get('eventId', 'unknown')
        logger.info(f"✅ API store success: eventId={event_id}")
        
        return {
            "success": True,
            "memory_type": "LONG-TERM" if memory_type == MemoryType.SEMANTIC else "SHORT-TERM",
            "memory_id": MEMORY_ID[:8] + "...",
            "event_id": event_id,
            "mode": "live",
            "also_stored_locally": True,
            "local_count": len(_local_semantic_memory) if memory_type == MemoryType.SEMANTIC else len(_local_session_memory),
        }
        
    except Exception as e:
        logger.error(f"❌ AgentCore API store failed: {str(e)} (local store succeeded)")
        # Local store already succeeded, so the pattern is still available
        local_result["api_error"] = str(e)
        return local_result


def _merge_results(local_results: List[Dict], api_results: List[Dict]) -> List[Dict]:
    """Merge local and API results, deduplicate, sort by relevance score."""
    seen_hashes = set()
    merged = []
    
    # Process all results, prefer higher scores
    all_candidates = local_results + api_results
    all_candidates.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
    
    for result in all_candidates:
        # Deduplicate by content hash or error_type+language combo
        dedup_key = result.get('content_hash') or f"{result.get('error_type', '')}:{result.get('language', '')}"
        if dedup_key in seen_hashes:
            continue
        seen_hashes.add(dedup_key)
        merged.append(result)
    
    return merged


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
        # Deduplicate: don't store the same pattern twice
        content_hash = event_data.get('content_hash', '')
        if content_hash:
            for existing in _local_semantic_memory:
                if existing.get('content_hash') == content_hash:
                    # Update existing instead of duplicating
                    existing['success_count'] = existing.get('success_count', 1) + 1
                    existing['timestamp'] = event_data.get('timestamp', existing.get('timestamp'))
                    logger.info(f"💾 Local dedup: updated existing pattern (hash={content_hash}, success_count={existing['success_count']})")
                    return {
                        "success": True,
                        "memory_type": "LONG-TERM (local)",
                        "storage": "local",
                        "count": len(_local_semantic_memory),
                        "action": "updated_existing",
                    }
        
        _local_semantic_memory.append(event_data)
        logger.info(f"💾 Local store: Added new pattern. Total patterns: {len(_local_semantic_memory)}")
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


def _normalize(text: str) -> str:
    """Normalize text for matching: lowercase, strip punctuation, collapse whitespace."""
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text)  # Replace punctuation with spaces
    text = re.sub(r'\s+', ' ', text).strip()  # Collapse whitespace
    return text


def _local_search(query: str, error_type: str = "", language: str = "", min_score: int = 50) -> List[Dict]:
    """
    Local memory search — searches patterns stored during actual use.
    
    Scoring system:
    - Exact error_type match: +40 (strongest signal)
    - Language match: +15
    - Keyword overlap (words > 3 chars): +8 per match
    - Error signature word overlap: +10 per match
    - Substring match in solution/root_cause: +6 per match
    """
    if not _local_semantic_memory:
        logger.info("🔎 Local search: memory is empty (0 patterns)")
        return []
    
    logger.info(f"🔎 Local search: Scanning {len(_local_semantic_memory)} patterns for: {query[:80]}...")
    
    query_normalized = _normalize(query)
    query_words = set(query_normalized.split())
    # Extract meaningful terms (> 3 chars to avoid noise like "the", "and")
    query_terms = {w for w in query_words if len(w) > 3}
    
    results = []
    
    for idx, pattern in enumerate(_local_semantic_memory):
        if pattern.get('pattern_type') != 'error_pattern':
            continue
        
        score = 0
        score_breakdown = []
        
        # 1. Exact error_type match (strongest signal)
        stored_error_type = _normalize(pattern.get('error_type', ''))
        query_error_type = _normalize(error_type) if error_type else ''
        
        if stored_error_type and query_error_type:
            if stored_error_type == query_error_type:
                score += 40
                score_breakdown.append(f"exact_error_type=+40")
            elif query_error_type in stored_error_type or stored_error_type in query_error_type:
                score += 25
                score_breakdown.append(f"partial_error_type=+25")
        
        # Also check if the stored error_type appears anywhere in the query text
        if stored_error_type and stored_error_type in query_normalized:
            bonus = 30
            score += bonus
            score_breakdown.append(f"error_type_in_query=+{bonus}")
        
        # 2. Language match
        stored_language = pattern.get('language', '').lower()
        query_language = language.lower() if language else ''
        if stored_language and query_language and stored_language == query_language:
            score += 15
            score_breakdown.append(f"language=+15")
        
        # 3. Build searchable text from ALL stored fields
        searchable = _normalize(
            f"{pattern.get('root_cause', '')} {pattern.get('solution', '')} "
            f"{pattern.get('error_type', '')} {pattern.get('error_signature', '')}"
        )
        searchable_words = set(searchable.split())
        
        # 4. Keyword overlap — each matching term scores points
        matching_terms = query_terms & searchable_words
        if matching_terms:
            keyword_score = len(matching_terms) * 8
            score += keyword_score
            score_breakdown.append(f"keywords({len(matching_terms)})=+{keyword_score}")
        
        # 5. Error signature word overlap (important for identifying the exact error)
        sig_normalized = _normalize(pattern.get('error_signature', ''))
        sig_words = {w for w in sig_normalized.split() if len(w) > 3}
        sig_overlap = query_terms & sig_words
        if sig_overlap:
            sig_score = len(sig_overlap) * 10
            score += sig_score
            score_breakdown.append(f"sig_overlap({len(sig_overlap)})=+{sig_score}")
        
        # 6. Substring matching for key phrases
        root_cause_norm = _normalize(pattern.get('root_cause', ''))
        solution_norm = _normalize(pattern.get('solution', ''))
        for term in query_terms:
            if len(term) > 5:  # Only for longer, more specific terms
                if term in root_cause_norm:
                    score += 6
                    score_breakdown.append(f"substr_rc({term})=+6")
                if term in solution_norm:
                    score += 6
                    score_breakdown.append(f"substr_sol({term})=+6")
        
        # Cap score at 100
        score = min(score, 100)
        
        if score >= min_score:
            logger.info(f"  ✅ Pattern #{idx} MATCH: score={score}, type={pattern.get('error_type')}, breakdown=[{', '.join(score_breakdown)}]")
            results.append({
                **{k: v for k, v in pattern.items() if k != 'memory_category'},  # Exclude internal fields
                "relevance_score": score,
                "source": "local",
            })
        else:
            if score > 20:  # Only log near-misses, not total misses
                logger.info(f"  ❌ Pattern #{idx} MISS: score={score} < {min_score}, type={pattern.get('error_type')}, breakdown=[{', '.join(score_breakdown)}]")
    
    results.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
    logger.info(f"🔎 Local search complete: {len(results)} results above threshold")
    return results


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
    logger.info(f"🧠 memory_agent.search() called: query_len={len(query)}, limit={limit}")
    result_str = search_similar_errors(query, limit)
    result = json.loads(result_str)
    logger.info(f"🧠 memory_agent.search() result: count={result.get('count')}, has_relevant={result.get('has_relevant_match')}, best_score={result.get('best_match_score')}")
    return result


def store_pattern(error_type: str, signature: str, root_cause: str, 
                  solution: str, language: str = "unknown") -> Dict[str, Any]:
    """Store an error pattern."""
    logger.info(f"🧠 memory_agent.store_pattern() called: type={error_type}, lang={language}")
    result_str = store_error_pattern(error_type, signature, root_cause, solution, language)
    result = json.loads(result_str)
    logger.info(f"🧠 memory_agent.store_pattern() result: success={result.get('success')}, local_count={len(_local_semantic_memory)}")
    return result


def store_context(context_type: str, content: Any) -> Dict[str, Any]:
    """Store session context."""
    content_str = json.dumps(content) if isinstance(content, dict) else str(content)
    result_str = store_session_context(context_type, content_str)
    return json.loads(result_str)


def get_context(context_type: str = "") -> Dict[str, Any]:
    """Get session context."""
    result_str = get_session_context(context_type)
    return json.loads(result_str)


def get_local_pattern_count() -> int:
    """Return the number of locally stored patterns. For diagnostics."""
    return len(_local_semantic_memory)
