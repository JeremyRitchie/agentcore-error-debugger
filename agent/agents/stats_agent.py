"""
Stats Agent - Tracks error statistics and trends
Tools: Frequency calculation, trend detection, analytics

In demo mode, uses in-memory storage with pre-seeded data.
In live mode, uses DynamoDB for persistent statistics.
"""
import os
import json
import logging
import boto3
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict
from strands import Agent, tool

from .config import DEMO_MODE, AWS_REGION

logger = logging.getLogger(__name__)

# DynamoDB table name (for live mode)
STATS_TABLE = os.environ.get('STATS_TABLE', 'error-debugger-stats')

# Initialize DynamoDB client (only in live mode)
dynamodb = None
if not DEMO_MODE:
    try:
        dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
        logger.info("✅ DynamoDB client initialized for stats")
    except Exception as e:
        logger.warning(f"⚠️ DynamoDB init failed: {e}")

# =============================================================================
# IN-MEMORY STATS STORAGE (used in demo mode or as fallback)
# =============================================================================

_error_history: List[Dict[str, Any]] = []
_session_stats: Dict[str, Any] = {
    "total_errors": 0,
    "errors_by_type": defaultdict(int),
    "errors_by_language": defaultdict(int),
    "resolution_times": [],
    "session_start": datetime.utcnow().isoformat()
}

# Pre-seed with historical data (for demo mode)
if DEMO_MODE:
    _error_history.extend([
        {"type": "null_reference", "language": "javascript", "timestamp": (datetime.utcnow() - timedelta(days=7)).isoformat(), "resolved": True},
        {"type": "null_reference", "language": "javascript", "timestamp": (datetime.utcnow() - timedelta(days=6)).isoformat(), "resolved": True},
        {"type": "import_error", "language": "python", "timestamp": (datetime.utcnow() - timedelta(days=5)).isoformat(), "resolved": True},
        {"type": "type_error", "language": "typescript", "timestamp": (datetime.utcnow() - timedelta(days=4)).isoformat(), "resolved": True},
        {"type": "null_reference", "language": "javascript", "timestamp": (datetime.utcnow() - timedelta(days=3)).isoformat(), "resolved": True},
        {"type": "connection_error", "language": "python", "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat(), "resolved": False},
        {"type": "null_reference", "language": "javascript", "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat(), "resolved": True},
    ])


# =============================================================================
# TOOLS - Statistics and analytics
# =============================================================================

@tool(name="calculate_error_frequency")
def calculate_error_frequency(error_type: str = "", days: int = 30) -> str:
    """
    Calculate how frequently an error type occurs.
    Helps identify recurring issues that need attention.
    
    Args:
        error_type: Specific error type to check (empty for all)
        days: Number of days to look back
    
    Returns:
        JSON with frequency data
    """
    logger.info(f"📊 Calculating frequency for: {error_type or 'all types'}")
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Filter by date and optionally by type
    filtered = []
    for error in _error_history:
        try:
            error_date = datetime.fromisoformat(error["timestamp"].replace("Z", "+00:00").replace("+00:00", ""))
            if error_date >= cutoff:
                if not error_type or error.get("type") == error_type:
                    filtered.append(error)
        except:
            continue
    
    # Count by type
    type_counts = defaultdict(int)
    for error in filtered:
        type_counts[error.get("type", "unknown")] += 1
    
    # Calculate frequency
    total = len(filtered)
    frequency_per_day = total / days if days > 0 else 0
    
    result = {
        "error_type": error_type or "all",
        "period_days": days,
        "total_occurrences": total,
        "frequency_per_day": round(frequency_per_day, 2),
        "frequency_per_week": round(frequency_per_day * 7, 2),
        "breakdown_by_type": dict(type_counts),
        "most_common": max(type_counts, key=type_counts.get) if type_counts else None
    }
    
    logger.info(f"✅ Frequency: {frequency_per_day:.2f}/day")
    return json.dumps(result)


@tool(name="detect_trend")
def detect_trend(error_type: str = "", window_days: int = 7) -> str:
    """
    Detect if an error type is trending up or down.
    Compares current period to previous period.
    
    Args:
        error_type: Error type to analyze (empty for all)
        window_days: Size of comparison window in days
    
    Returns:
        JSON with trend analysis
    """
    logger.info(f"📈 Detecting trend for: {error_type or 'all types'}")
    
    now = datetime.utcnow()
    current_start = now - timedelta(days=window_days)
    previous_start = current_start - timedelta(days=window_days)
    
    current_count = 0
    previous_count = 0
    
    for error in _error_history:
        try:
            error_date = datetime.fromisoformat(error["timestamp"].replace("Z", "+00:00").replace("+00:00", ""))
            if error_type and error.get("type") != error_type:
                continue
                
            if error_date >= current_start:
                current_count += 1
            elif error_date >= previous_start:
                previous_count += 1
        except:
            continue
    
    # Calculate trend
    if previous_count == 0:
        change_percent = 100 if current_count > 0 else 0
    else:
        change_percent = ((current_count - previous_count) / previous_count) * 100
    
    if change_percent > 20:
        trend = "increasing"
        severity = "warning"
    elif change_percent < -20:
        trend = "decreasing"
        severity = "good"
    else:
        trend = "stable"
        severity = "neutral"
    
    result = {
        "error_type": error_type or "all",
        "window_days": window_days,
        "current_period_count": current_count,
        "previous_period_count": previous_count,
        "change_percent": round(change_percent, 1),
        "trend": trend,
        "severity": severity,
        "recommendation": _get_trend_recommendation(trend, error_type)
    }
    
    logger.info(f"✅ Trend: {trend} ({change_percent:+.1f}%)")
    return json.dumps(result)


@tool(name="get_session_summary")
def get_session_summary() -> str:
    """
    Get summary statistics for the current debugging session.
    Shows errors analyzed, resolution rate, and time spent.
    
    Returns:
        JSON with session statistics
    """
    logger.info("📋 Getting session summary")
    
    session_start = datetime.fromisoformat(_session_stats["session_start"])
    session_duration = datetime.utcnow() - session_start
    
    total = _session_stats["total_errors"]
    
    result = {
        "session_id": "current",
        "started_at": _session_stats["session_start"],
        "duration_minutes": round(session_duration.total_seconds() / 60, 1),
        "total_errors_analyzed": total,
        "errors_by_type": dict(_session_stats["errors_by_type"]),
        "errors_by_language": dict(_session_stats["errors_by_language"]),
        "avg_resolution_time_seconds": (
            sum(_session_stats["resolution_times"]) / len(_session_stats["resolution_times"])
            if _session_stats["resolution_times"] else 0
        ),
        "status": "active"
    }
    
    logger.info(f"✅ Session: {total} errors in {result['duration_minutes']:.1f} minutes")
    return json.dumps(result)


@tool(name="record_error_analyzed")
def record_error_analyzed(error_type: str, language: str, resolution_time: float = 0) -> str:
    """
    Record that an error was analyzed in the current session.
    Updates session statistics for reporting.
    
    Args:
        error_type: Type of error analyzed
        language: Programming language
        resolution_time: Time taken to resolve (seconds)
    
    Returns:
        JSON confirmation
    """
    logger.info(f"📝 Recording error: {error_type} ({language}) [mode: {'DEMO' if DEMO_MODE else 'LIVE'}]")
    
    timestamp = datetime.utcnow().isoformat()
    
    # Update in-memory session stats (always)
    _session_stats["total_errors"] += 1
    _session_stats["errors_by_type"][error_type] += 1
    _session_stats["errors_by_language"][language] += 1
    
    if resolution_time > 0:
        _session_stats["resolution_times"].append(resolution_time)
    
    error_record = {
        "type": error_type,
        "language": language,
        "timestamp": timestamp,
        "resolved": resolution_time > 0,
        "resolution_time": resolution_time
    }
    
    # Add to in-memory history
    _error_history.append(error_record)
    
    # In live mode, also persist to DynamoDB
    if not DEMO_MODE and dynamodb:
        try:
            table = dynamodb.Table(STATS_TABLE)
            table.put_item(Item={
                'pk': f"ERROR#{error_type}",
                'sk': timestamp,
                'error_type': error_type,
                'language': language,
                'resolved': resolution_time > 0,
                'resolution_time': int(resolution_time * 1000),  # milliseconds
                'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
            })
            logger.info("✅ Persisted to DynamoDB")
        except Exception as e:
            logger.warning(f"⚠️ DynamoDB write failed: {e}")
    
    result = {
        "success": True,
        "error_type": error_type,
        "language": language,
        "session_total": _session_stats["total_errors"],
        "mode": "demo" if DEMO_MODE else "live"
    }
    
    logger.info(f"✅ Recorded. Session total: {_session_stats['total_errors']}")
    return json.dumps(result)


@tool(name="get_top_errors")
def get_top_errors(limit: int = 5, days: int = 30) -> str:
    """
    Get the most common error types over a time period.
    Helps identify areas needing the most attention.
    
    Args:
        limit: Number of top errors to return
        days: Time period to analyze
    
    Returns:
        JSON with top error types
    """
    logger.info(f"🏆 Getting top {limit} errors from last {days} days")
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    type_counts = defaultdict(lambda: {"count": 0, "languages": set(), "resolved": 0})
    
    for error in _error_history:
        try:
            error_date = datetime.fromisoformat(error["timestamp"].replace("Z", "+00:00").replace("+00:00", ""))
            if error_date >= cutoff:
                error_type = error.get("type", "unknown")
                type_counts[error_type]["count"] += 1
                type_counts[error_type]["languages"].add(error.get("language", "unknown"))
                if error.get("resolved"):
                    type_counts[error_type]["resolved"] += 1
        except:
            continue
    
    # Convert to list and sort
    top_errors = []
    for error_type, data in type_counts.items():
        total = data["count"]
        resolved = data["resolved"]
        top_errors.append({
            "error_type": error_type,
            "count": total,
            "languages": list(data["languages"]),
            "resolution_rate": round((resolved / total * 100) if total > 0 else 0, 1)
        })
    
    top_errors.sort(key=lambda x: x["count"], reverse=True)
    top_errors = top_errors[:limit]
    
    result = {
        "period_days": days,
        "top_errors": top_errors,
        "total_unique_types": len(type_counts)
    }
    
    logger.info(f"✅ Found {len(type_counts)} unique error types")
    return json.dumps(result)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_trend_recommendation(trend: str, error_type: str) -> str:
    """Generate recommendation based on trend."""
    if trend == "increasing":
        if error_type:
            return f"'{error_type}' errors are increasing. Consider investigating common patterns and adding preventive measures."
        return "Overall errors are increasing. Review recent changes and consider code quality improvements."
    elif trend == "decreasing":
        return "Good progress! Continue current practices."
    else:
        return "Error rate is stable. Monitor for changes."


# =============================================================================
# AGENT - Strands Agent with stats tools
# =============================================================================

STATS_AGENT_PROMPT = """You are a Statistics and Analytics Specialist Agent.

## YOUR ROLE
Track and analyze error patterns, trends, and debugging effectiveness.
Provide insights to help improve code quality.

## YOUR TOOLS
- calculate_error_frequency: Calculate how often an error type occurs
- detect_trend: Detect if errors are increasing or decreasing
- get_session_summary: Get current debugging session statistics
- record_error_analyzed: Record an error that was analyzed
- get_top_errors: Get most common error types

## YOUR WORKFLOW
1. Record each error analyzed with record_error_analyzed
2. When asked, provide frequency and trend analysis
3. Summarize session statistics when requested

## OUTPUT FORMAT
Return a JSON object with statistics and insights.

Always return valid JSON only, no additional text.
"""

stats_agent = Agent(
    system_prompt=STATS_AGENT_PROMPT,
    tools=[calculate_error_frequency, detect_trend, get_session_summary,
           record_error_analyzed, get_top_errors],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def record(error_type: str, language: str, resolution_time: float = 0) -> Dict[str, Any]:
    """Record an analyzed error."""
    result_str = record_error_analyzed(error_type, language, resolution_time)
    return json.loads(result_str)


def get_frequency(error_type: str = "", days: int = 30) -> Dict[str, Any]:
    """Get error frequency."""
    result_str = calculate_error_frequency(error_type, days)
    return json.loads(result_str)


def get_trend(error_type: str = "", window: int = 7) -> Dict[str, Any]:
    """Get error trend."""
    result_str = detect_trend(error_type, window)
    return json.loads(result_str)


def get_summary() -> Dict[str, Any]:
    """Get session summary."""
    result_str = get_session_summary()
    return json.loads(result_str)


def get_top(limit: int = 5, days: int = 30) -> Dict[str, Any]:
    """Get top errors."""
    result_str = get_top_errors(limit, days)
    return json.loads(result_str)

