"""
Memory Agent - Manages conversation memory using AgentCore Memory API
Stores error patterns, solutions, and learns from past debugging sessions

Uses REAL AgentCore Memory API:
  - batch_create_memory_records() to store searchable records
  - retrieve_memory_records() to semantically search
  - create_event() for session event logging
  - Local in-memory cache as additional fast fallback
"""
import os
import re
import boto3
import json
import uuid
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
        logger.info("✅ AgentCore Memory client initialized (bedrock-agentcore)")
    except Exception as e:
        logger.warning(f"⚠️ AgentCore client init failed: {e}")

# Memory configuration
MEMORY_ID = CONFIG_MEMORY_ID or os.environ.get('MEMORY_ID', '')
SESSION_ID = os.environ.get('SESSION_ID', 'default-session')
MEMORY_NAMESPACE = "error_patterns"  # Namespace for all error pattern records
ACTOR_ID = "error_debugger"  # Actor ID for event-based storage

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

    pattern_data = {
        "error_type": error_type,
        "error_signature": error_signature,
        "root_cause": root_cause,
        "solution": solution,
        "language": language,
        "content_hash": content_hash,
        "timestamp": datetime.utcnow().isoformat(),
        "success_count": 1,
    }

    # Always store locally first for within-process retrieval
    local_result = _local_store(pattern_data)
    logger.info(f"💾 Local store done: count={local_result.get('count')}")

    # Store to AgentCore managed memory (AWS persistent store)
    api_result = _store_to_agentcore_records(pattern_data)

    # Also log as an event for the managed event pipeline
    _store_as_event(pattern_data)

    result = api_result if api_result.get("success") else local_result
    result["pattern_type"] = "error_pattern"
    result["content_hash"] = content_hash

    logger.info(f"✅ MEMORY STORE COMPLETE: hash={content_hash}, mode={result.get('mode', 'local')}, local_count={len(_local_semantic_memory)}")
    return json.dumps(result)


@tool(name="search_similar_errors")
def search_similar_errors(error_text: str, limit: int = 5) -> str:
    """
    Search LONG-TERM memory for similar past errors.
    Uses AgentCore semantic search (retrieve_memory_records) plus local fallback.

    Args:
        error_text: The current error to match against
        limit: Maximum number of results

    Returns:
        JSON with matching past errors and their solutions
    """
    logger.info(f"🔎 MEMORY SEARCH: query={error_text[:120]}... (mode: {'DEMO' if DEMO_MODE else 'LIVE'}, local_patterns={len(_local_semantic_memory)})")

    # Extract error_type and language from query if embedded
    detected_language = ""
    detected_error_type = ""

    lang_match = re.search(r'\[(\w+)\]', error_text)
    if lang_match:
        detected_language = lang_match.group(1)

    type_match = re.search(r'^(\w+(?:_?\w+)*):', error_text)
    if type_match:
        detected_error_type = type_match.group(1)

    logger.info(f"🔎 MEMORY SEARCH: detected_language={detected_language}, detected_error_type={detected_error_type}")

    MIN_RELEVANCE_THRESHOLD = 50

    # 1. Always search local memory (fast, within-process)
    local_results = _local_search(error_text, detected_error_type, detected_language, MIN_RELEVANCE_THRESHOLD)[:limit]
    logger.info(f"🔎 LOCAL SEARCH: {len(local_results)} results from {len(_local_semantic_memory)} patterns")
    for i, r in enumerate(local_results[:3]):
        logger.info(f"  Local #{i+1}: score={r.get('relevance_score')}, type={r.get('error_type')}")

    # 2. In demo mode, return local only
    if DEMO_MODE:
        return _build_search_response(local_results, [], error_text, MIN_RELEVANCE_THRESHOLD, mode="demo")

    # 3. Search AgentCore managed memory (persistent, semantic search)
    api_results = []
    api_error = None

    if MEMORY_ID and bedrock_agentcore:
        try:
            logger.info(f"🔎 API SEARCH: retrieve_memory_records(memoryId={MEMORY_ID[:12]}..., namespace={MEMORY_NAMESPACE}, query_len={len(error_text)}, topK={limit})")
            response = bedrock_agentcore.retrieve_memory_records(
                memoryId=MEMORY_ID,
                namespace=MEMORY_NAMESPACE,
                searchCriteria={
                    "searchQuery": error_text,
                    "topK": limit,
                },
            )

            raw_records = response.get('memoryRecordSummaries', [])
            logger.info(f"🔎 API SEARCH: Got {len(raw_records)} records from AgentCore")

            for idx, record in enumerate(raw_records):
                try:
                    text = record.get('content', {}).get('text', '')
                    score_raw = record.get('score', 0)
                    # API scores are typically 0.0-1.0; convert to 0-100
                    score = int(score_raw * 100) if score_raw <= 1.0 else int(score_raw)
                    record_id = record.get('memoryRecordId', 'unknown')

                    logger.info(f"  API #{idx+1}: score_raw={score_raw}, score={score}, record_id={record_id[:16]}..., text_len={len(text)}")

                    # Parse the stored pattern data from the text
                    parsed = _parse_record_text(text)
                    if not parsed:
                        logger.info(f"  → Skipped: could not parse record text")
                        continue

                    if score < MIN_RELEVANCE_THRESHOLD:
                        logger.info(f"  → Skipped: low relevance ({score} < {MIN_RELEVANCE_THRESHOLD})")
                        continue

                    api_results.append({
                        "error_type": parsed.get("error_type", ""),
                        "root_cause": parsed.get("root_cause", ""),
                        "solution": parsed.get("solution", ""),
                        "language": parsed.get("language", ""),
                        "relevance_score": score,
                        "success_count": int(parsed.get("success_count", 1)),
                        "timestamp": parsed.get("timestamp", ""),
                        "source": "agentcore_api",
                        "memory_record_id": record_id,
                    })
                except Exception as parse_err:
                    logger.warning(f"  → Skipped: error parsing record #{idx+1}: {parse_err}")
                    continue

            logger.info(f"🔎 API SEARCH: {len(api_results)} valid results after filtering")

        except Exception as e:
            api_error = str(e)
            logger.error(f"❌ API SEARCH FAILED: {api_error}")
    else:
        logger.warning(f"⚠️ API SEARCH skipped: MEMORY_ID={'SET' if MEMORY_ID else 'EMPTY'}, client={'OK' if bedrock_agentcore else 'NONE'}")

    return _build_search_response(local_results, api_results, error_text, MIN_RELEVANCE_THRESHOLD, api_error=api_error)


@tool(name="store_session_context")
def store_session_context(context_type: str, content: str) -> str:
    """
    Store context in SHORT-TERM session memory via create_event().

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

    # Store locally
    _local_session_memory[context_type] = {
        "context_type": context_type,
        "content": content_dict,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Store as event in AgentCore
    if not DEMO_MODE and MEMORY_ID and bedrock_agentcore:
        try:
            bedrock_agentcore.create_event(
                memoryId=MEMORY_ID,
                actorId=ACTOR_ID,
                sessionId=SESSION_ID,
                eventTimestamp=datetime.utcnow(),
                payload=[{
                    "conversational": {
                        "role": "ASSISTANT",
                        "content": {"text": json.dumps({"context_type": context_type, **content_dict})},
                    }
                }],
                clientToken=str(uuid.uuid4()),
            )
            logger.info(f"✅ Session context stored via create_event: {context_type}")
            return json.dumps({"success": True, "memory_type": "SHORT-TERM (event)", "context_type": context_type, "mode": "live"})
        except Exception as e:
            logger.error(f"❌ Session context store failed: {e}")

    logger.info(f"✅ Session context stored locally: {context_type}")
    return json.dumps({"success": True, "memory_type": "SHORT-TERM (local)", "context_type": context_type, "mode": "local"})


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

    # For now, use local session memory (events API requires sessionId+actorId)
    if context_type and context_type in _local_session_memory:
        events = [_local_session_memory[context_type]]
    else:
        events = list(_local_session_memory.values())

    return json.dumps({
        "success": True,
        "memory_type": "SHORT-TERM (local)",
        "session_id": SESSION_ID[:8] + "...",
        "count": len(events),
        "events": events,
    })


@tool(name="increment_solution_success")
def increment_solution_success(error_signature: str) -> str:
    """
    Increment the success count for a solution that worked.

    Args:
        error_signature: The error pattern signature to update

    Returns:
        JSON confirmation
    """
    logger.info(f"📈 Incrementing success count for: {error_signature}")

    for pattern in _local_semantic_memory:
        if pattern.get('error_signature') == error_signature:
            pattern['success_count'] = pattern.get('success_count', 1) + 1
            logger.info(f"📈 Local pattern updated: success_count={pattern['success_count']}")
            break

    return json.dumps({
        "success": True,
        "error_signature": error_signature,
        "action": "success_count_incremented",
    })


# =============================================================================
# AGENTCORE API HELPERS
# =============================================================================

def _format_record_text(pattern: Dict[str, Any]) -> str:
    """Format pattern data as natural language text for semantic search."""
    return (
        f"Error Type: {pattern.get('error_type', 'unknown')}\n"
        f"Language: {pattern.get('language', 'unknown')}\n"
        f"Error Signature: {pattern.get('error_signature', '')}\n"
        f"Root Cause: {pattern.get('root_cause', '')}\n"
        f"Solution: {pattern.get('solution', '')}\n"
        f"Success Count: {pattern.get('success_count', 1)}\n"
        f"Timestamp: {pattern.get('timestamp', '')}"
    )


def _parse_record_text(text: str) -> Optional[Dict[str, str]]:
    """Parse stored record text back into structured data."""
    if not text:
        return None

    result = {}
    field_map = {
        "error type": "error_type",
        "language": "language",
        "error signature": "error_signature",
        "root cause": "root_cause",
        "solution": "solution",
        "success count": "success_count",
        "timestamp": "timestamp",
    }

    for line in text.split('\n'):
        line = line.strip()
        if ':' not in line:
            continue
        key_part, _, value_part = line.partition(':')
        key_lower = key_part.strip().lower()
        if key_lower in field_map:
            result[field_map[key_lower]] = value_part.strip()

    return result if result else None


def _store_to_agentcore_records(pattern_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Store pattern as a memory record via batch_create_memory_records().
    Records are immediately searchable via retrieve_memory_records().
    """
    if DEMO_MODE or not MEMORY_ID or not bedrock_agentcore:
        logger.info(f"⏭️ Skipping API record store (DEMO={DEMO_MODE}, MEMORY_ID={'SET' if MEMORY_ID else 'EMPTY'}, client={'OK' if bedrock_agentcore else 'NONE'})")
        return {"success": False, "mode": "skipped"}

    try:
        record_text = _format_record_text(pattern_data)
        request_id = pattern_data.get('content_hash', str(uuid.uuid4())[:12])

        logger.info(f"💾 API STORE: batch_create_memory_records(memoryId={MEMORY_ID[:12]}..., namespace={MEMORY_NAMESPACE}, text_len={len(record_text)})")

        response = bedrock_agentcore.batch_create_memory_records(
            memoryId=MEMORY_ID,
            records=[{
                "requestIdentifier": request_id,
                "namespaces": [MEMORY_NAMESPACE],
                "content": {"text": record_text},
                "timestamp": datetime.utcnow(),
            }],
            clientToken=str(uuid.uuid4()),
        )

        successful = response.get('successfulRecords', [])
        failed = response.get('failedRecords', [])

        if failed:
            logger.warning(f"⚠️ API STORE: {len(failed)} records failed: {json.dumps(failed)[:200]}")
        if successful:
            logger.info(f"✅ API STORE SUCCESS: {len(successful)} records created in AgentCore managed memory")

        return {
            "success": len(successful) > 0,
            "memory_type": "LONG-TERM (AgentCore)",
            "memory_id": MEMORY_ID[:8] + "...",
            "records_created": len(successful),
            "records_failed": len(failed),
            "mode": "live",
            "also_stored_locally": True,
            "local_count": len(_local_semantic_memory),
        }

    except Exception as e:
        logger.error(f"❌ API STORE FAILED: {str(e)}")
        return {
            "success": False,
            "mode": "local_only",
            "api_error": str(e),
            "also_stored_locally": True,
            "local_count": len(_local_semantic_memory),
        }


def _store_as_event(pattern_data: Dict[str, Any]) -> None:
    """
    Also store pattern as an event via create_event() for the managed event pipeline.
    This feeds into AgentCore's automatic memory extraction.
    """
    if DEMO_MODE or not MEMORY_ID or not bedrock_agentcore:
        return

    try:
        event_text = _format_record_text(pattern_data)

        bedrock_agentcore.create_event(
            memoryId=MEMORY_ID,
            actorId=ACTOR_ID,
            sessionId=SESSION_ID,
            eventTimestamp=datetime.utcnow(),
            payload=[{
                "conversational": {
                    "role": "ASSISTANT",
                    "content": {"text": event_text},
                }
            }],
            clientToken=str(uuid.uuid4()),
        )
        logger.info(f"✅ Event stored via create_event (for managed extraction pipeline)")
    except Exception as e:
        # Non-critical — the memory record is the primary store
        logger.warning(f"⚠️ Event store failed (non-critical): {e}")


def _build_search_response(
    local_results: List[Dict],
    api_results: List[Dict],
    query: str,
    min_threshold: int,
    mode: str = "live",
    api_error: str = None,
) -> str:
    """Build a consistent search response from local + API results."""
    # Merge and deduplicate
    all_results = _merge_results(local_results, api_results)

    best_score = all_results[0].get('relevance_score', 0) if all_results else 0
    has_relevant = len(all_results) > 0 and best_score >= 70

    response = {
        "success": True,
        "memory_type": f"LONG-TERM ({'demo' if mode == 'demo' else 'AgentCore + local'})",
        "query": query[:100],
        "count": len(all_results),
        "results": all_results,
        "has_solutions": len(all_results) > 0,
        "has_relevant_match": has_relevant,
        "best_match_score": best_score,
        "local_count": len(local_results),
        "api_count": len(api_results),
        "mode": mode,
    }

    if api_error:
        response["api_error"] = api_error

    logger.info(f"✅ SEARCH RESPONSE: {len(local_results)} local + {len(api_results)} API = {len(all_results)} total (best={best_score}, relevant={has_relevant}, api_error={'YES: ' + api_error[:80] if api_error else 'none'})")
    return json.dumps(response)


def _merge_results(local_results: List[Dict], api_results: List[Dict]) -> List[Dict]:
    """Merge local and API results, deduplicate, sort by relevance score."""
    seen_hashes = set()
    merged = []

    all_candidates = local_results + api_results
    all_candidates.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)

    for result in all_candidates:
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


def _local_store(pattern_data: Dict[str, Any]) -> Dict[str, Any]:
    """Store pattern in local in-memory cache for within-process retrieval."""
    content_hash = pattern_data.get('content_hash', '')
    if content_hash:
        for existing in _local_semantic_memory:
            if existing.get('content_hash') == content_hash:
                existing['success_count'] = existing.get('success_count', 1) + 1
                existing['timestamp'] = pattern_data.get('timestamp', existing.get('timestamp'))
                logger.info(f"💾 Local dedup: updated existing (hash={content_hash}, success_count={existing['success_count']})")
                return {"success": True, "memory_type": "LONG-TERM (local)", "count": len(_local_semantic_memory), "action": "updated_existing"}

    _local_semantic_memory.append(pattern_data)
    logger.info(f"💾 Local store: Added new pattern. Total: {len(_local_semantic_memory)}")
    return {"success": True, "memory_type": "LONG-TERM (local)", "count": len(_local_semantic_memory), "action": "created_new"}


def _normalize(text: str) -> str:
    """Normalize text for matching."""
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _local_search(query: str, error_type: str = "", language: str = "", min_score: int = 50) -> List[Dict]:
    """
    Local memory search with scoring:
    - Exact error_type match: +40
    - Error type in query text: +30
    - Language match: +15
    - Keyword overlap: +8 per match
    - Signature overlap: +10 per match
    - Substring in root_cause/solution: +6 each
    """
    if not _local_semantic_memory:
        logger.info("🔎 Local search: memory is empty (0 patterns)")
        return []

    logger.info(f"🔎 Local search: Scanning {len(_local_semantic_memory)} patterns")

    query_normalized = _normalize(query)
    query_terms = {w for w in query_normalized.split() if len(w) > 3}
    results = []

    for idx, pattern in enumerate(_local_semantic_memory):
        score = 0
        breakdown = []

        stored_error_type = _normalize(pattern.get('error_type', ''))
        query_error_type = _normalize(error_type) if error_type else ''

        if stored_error_type and query_error_type:
            if stored_error_type == query_error_type:
                score += 40
                breakdown.append("exact_type=+40")
            elif query_error_type in stored_error_type or stored_error_type in query_error_type:
                score += 25
                breakdown.append("partial_type=+25")

        if stored_error_type and stored_error_type in query_normalized:
            score += 30
            breakdown.append("type_in_query=+30")

        stored_lang = pattern.get('language', '').lower()
        query_lang = language.lower() if language else ''
        if stored_lang and query_lang and stored_lang == query_lang:
            score += 15
            breakdown.append("language=+15")

        searchable = _normalize(
            f"{pattern.get('root_cause', '')} {pattern.get('solution', '')} "
            f"{pattern.get('error_type', '')} {pattern.get('error_signature', '')}"
        )
        searchable_words = set(searchable.split())
        matching = query_terms & searchable_words
        if matching:
            s = len(matching) * 8
            score += s
            breakdown.append(f"keywords({len(matching)})=+{s}")

        sig_norm = _normalize(pattern.get('error_signature', ''))
        sig_words = {w for w in sig_norm.split() if len(w) > 3}
        sig_overlap = query_terms & sig_words
        if sig_overlap:
            s = len(sig_overlap) * 10
            score += s
            breakdown.append(f"sig({len(sig_overlap)})=+{s}")

        rc_norm = _normalize(pattern.get('root_cause', ''))
        sol_norm = _normalize(pattern.get('solution', ''))
        for term in query_terms:
            if len(term) > 5:
                if term in rc_norm:
                    score += 6
                    breakdown.append(f"rc({term})=+6")
                if term in sol_norm:
                    score += 6
                    breakdown.append(f"sol({term})=+6")

        # Don't cap score here — keep raw score for accurate ranking
        # Cap to 100 only when returning to caller

        if score >= min_score:
            logger.info(f"  ✅ #{idx} MATCH: score={score}, type={pattern.get('error_type')}, [{', '.join(breakdown)}]")
            results.append({
                **{k: v for k, v in pattern.items() if k != 'memory_category'},
                "relevance_score": min(score, 100),  # Cap for display only
                "_raw_score": score,  # Keep raw for ranking
                "source": "local",
            })
        elif score > 20:
            logger.info(f"  ❌ #{idx} MISS: score={score} < {min_score}, [{', '.join(breakdown)}]")

    # Sort by raw score (uncapped) for accurate ranking, then clean up
    results.sort(key=lambda x: x.get('_raw_score', x.get('relevance_score', 0)), reverse=True)
    for r in results:
        r.pop('_raw_score', None)  # Remove internal field before returning
    logger.info(f"🔎 Local search: {len(results)} results above threshold")
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
# INTERFACE - For supervisor to call directly (no LLM)
# =============================================================================

def search(query: str, limit: int = 5, **kwargs) -> Dict[str, Any]:
    """Search memory for similar errors. kwargs are ignored (compat)."""
    logger.info(f"🧠 memory_agent.search() called: query_len={len(query)}, limit={limit}")
    result_str = search_similar_errors(query, limit)
    result = json.loads(result_str)
    logger.info(f"🧠 memory_agent.search() result: count={result.get('count')}, has_relevant={result.get('has_relevant_match')}, best_score={result.get('best_match_score')}, api_count={result.get('api_count')}, local_count={result.get('local_count')}, api_error={result.get('api_error', 'none')}")
    return result


def store_pattern(error_type: str, signature: str, root_cause: str,
                  solution: str, language: str = "unknown") -> Dict[str, Any]:
    """Store an error pattern."""
    logger.info(f"🧠 memory_agent.store_pattern() called: type={error_type}, lang={language}")
    result_str = store_error_pattern(error_type, signature, root_cause, solution, language)
    result = json.loads(result_str)
    logger.info(f"🧠 memory_agent.store_pattern() result: success={result.get('success')}, mode={result.get('mode')}, local_count={len(_local_semantic_memory)}")
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
