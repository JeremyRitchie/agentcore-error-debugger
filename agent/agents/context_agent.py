"""
Context Agent - Searches external resources for error context
Tools: GitHub Issues API, Stack Overflow API, documentation fetching
"""
import re
import json
import logging
import urllib.parse
from typing import Dict, Any, List
from strands import Agent, tool

logger = logging.getLogger(__name__)

# Note: In production, these would make real HTTP calls
# For demo purposes, we simulate the responses

# =============================================================================
# TOOLS - External API calls
# =============================================================================

@tool(name="search_github_issues")
def search_github_issues(error_message: str, language: str = "") -> str:
    """
    Search GitHub Issues for similar error reports.
    Finds related issues, solutions, and workarounds from the community.
    
    Args:
        error_message: The error message to search for
        language: Optional programming language filter
    
    Returns:
        JSON with matching GitHub issues
    """
    logger.info(f"🔍 Searching GitHub Issues for: {error_message[:50]}...")
    
    # Extract key terms from error message
    key_terms = _extract_search_terms(error_message)
    query = " ".join(key_terms[:5])
    
    # Simulate GitHub Issues API response
    # In production: GET https://api.github.com/search/issues?q={query}
    
    simulated_issues = _get_simulated_github_results(error_message, language)
    
    result = {
        "query": query,
        "total_count": len(simulated_issues),
        "issues": simulated_issues[:5],
        "source": "github_issues",
        "search_url": f"https://github.com/search?q={urllib.parse.quote(query)}&type=issues"
    }
    
    logger.info(f"✅ Found {len(simulated_issues)} GitHub issues")
    return json.dumps(result)


@tool(name="search_stackoverflow")
def search_stackoverflow(error_message: str, tags: str = "") -> str:
    """
    Search Stack Overflow for related questions and answers.
    Finds community solutions and accepted answers for similar errors.
    
    Args:
        error_message: The error message to search for
        tags: Optional comma-separated tags to filter (e.g., "python,django")
    
    Returns:
        JSON with matching Stack Overflow questions
    """
    logger.info(f"🔍 Searching Stack Overflow for: {error_message[:50]}...")
    
    key_terms = _extract_search_terms(error_message)
    query = " ".join(key_terms[:5])
    
    # Simulate Stack Overflow API response
    # In production: GET https://api.stackexchange.com/2.3/search/advanced?q={query}
    
    simulated_questions = _get_simulated_stackoverflow_results(error_message, tags)
    
    result = {
        "query": query,
        "total_count": len(simulated_questions),
        "questions": simulated_questions[:5],
        "source": "stackoverflow",
        "search_url": f"https://stackoverflow.com/search?q={urllib.parse.quote(query)}"
    }
    
    logger.info(f"✅ Found {len(simulated_questions)} Stack Overflow questions")
    return json.dumps(result)


@tool(name="fetch_documentation")
def fetch_documentation(error_type: str, language: str) -> str:
    """
    Fetch relevant documentation links for the error type.
    Returns official documentation and common resources.
    
    Args:
        error_type: Type of error (e.g., "TypeError", "null_reference")
        language: Programming language
    
    Returns:
        JSON with documentation links and excerpts
    """
    logger.info(f"📚 Fetching docs for {error_type} in {language}")
    
    # Documentation mapping
    doc_links = _get_documentation_links(error_type, language)
    
    result = {
        "error_type": error_type,
        "language": language,
        "documentation": doc_links,
        "doc_count": len(doc_links)
    }
    
    logger.info(f"✅ Found {len(doc_links)} documentation resources")
    return json.dumps(result)


@tool(name="get_error_explanation")
def get_error_explanation(error_type: str, language: str) -> str:
    """
    Get a human-readable explanation of the error type.
    Provides context about what causes this error and common scenarios.
    
    Args:
        error_type: Classified error type
        language: Programming language
    
    Returns:
        JSON with error explanation
    """
    logger.info(f"💡 Getting explanation for {error_type}")
    
    explanations = {
        "null_reference": {
            "what": "Attempting to access a property or method on a null/undefined value",
            "common_causes": [
                "Variable not initialized before use",
                "Async data not loaded yet",
                "Object doesn't exist in expected location",
                "API returned null instead of expected object"
            ],
            "prevention": "Always check for null/undefined before accessing properties. Use optional chaining (?.) or null checks."
        },
        "type_error": {
            "what": "Operation performed on a value of the wrong type",
            "common_causes": [
                "Calling a function that doesn't exist",
                "Passing wrong argument types",
                "Type coercion issues",
                "Missing type conversions"
            ],
            "prevention": "Use TypeScript or type hints. Validate input types at function boundaries."
        },
        "syntax_error": {
            "what": "Code structure doesn't follow language grammar rules",
            "common_causes": [
                "Missing brackets, parentheses, or quotes",
                "Typos in keywords",
                "Invalid character in code",
                "Mixing language syntaxes"
            ],
            "prevention": "Use a linter and IDE with syntax highlighting. Format code consistently."
        },
        "import_error": {
            "what": "Failed to load a required module or package",
            "common_causes": [
                "Package not installed",
                "Wrong package name",
                "Circular imports",
                "Virtual environment not activated"
            ],
            "prevention": "Maintain requirements.txt/package.json. Use virtual environments."
        },
        "connection_error": {
            "what": "Failed to establish network connection",
            "common_causes": [
                "Server is down",
                "Wrong URL or port",
                "Firewall blocking connection",
                "Network timeout"
            ],
            "prevention": "Implement retry logic. Check connectivity before requests. Use timeouts."
        },
        "permission_error": {
            "what": "Insufficient permissions for the requested operation",
            "common_causes": [
                "File/directory permissions",
                "Missing authentication",
                "Wrong user context",
                "Security policy restrictions"
            ],
            "prevention": "Run with appropriate permissions. Check file permissions. Verify authentication."
        },
        "memory_error": {
            "what": "Application ran out of available memory",
            "common_causes": [
                "Loading too much data at once",
                "Memory leak",
                "Infinite loop creating objects",
                "Very deep recursion"
            ],
            "prevention": "Process data in chunks. Profile memory usage. Use generators/iterators."
        },
        "key_error": {
            "what": "Accessing a dictionary/object with a key that doesn't exist",
            "common_causes": [
                "Typo in key name",
                "Key was deleted",
                "Wrong data structure",
                "Case sensitivity"
            ],
            "prevention": "Use .get() with defaults. Check key existence first. Validate data structure."
        },
    }
    
    explanation = explanations.get(error_type, {
        "what": f"An error of type {error_type}",
        "common_causes": ["Unknown - error type not in database"],
        "prevention": "Review documentation for this specific error type"
    })
    
    result = {
        "error_type": error_type,
        "language": language,
        "explanation": explanation,
        "has_detailed_explanation": error_type in explanations
    }
    
    logger.info(f"✅ Retrieved explanation for {error_type}")
    return json.dumps(result)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _extract_search_terms(text: str) -> List[str]:
    """Extract meaningful search terms from error text."""
    # Remove common noise
    noise_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'at', 'in', 'on', 'for', 'to', 'of'}
    
    # Extract words, filter noise
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text)
    words = [w for w in words if w.lower() not in noise_words and len(w) > 2]
    
    # Prioritize error-related terms
    priority_terms = [w for w in words if any(kw in w.lower() for kw in ['error', 'exception', 'failed', 'cannot', 'undefined'])]
    other_terms = [w for w in words if w not in priority_terms]
    
    return priority_terms + other_terms


def _get_simulated_github_results(error_message: str, language: str) -> List[Dict]:
    """Simulate GitHub Issues API results."""
    # In production, this would make real API calls
    # For demo, return relevant-looking simulated results
    
    error_lower = error_message.lower()
    
    results = []
    
    if "undefined" in error_lower or "null" in error_lower:
        results.append({
            "title": "Cannot read property of undefined in React component",
            "url": "https://github.com/facebook/react/issues/example1",
            "state": "closed",
            "comments": 15,
            "created_at": "2024-01-15",
            "labels": ["bug", "good first issue"]
        })
    
    if "module" in error_lower or "import" in error_lower:
        results.append({
            "title": "ModuleNotFoundError when importing from src",
            "url": "https://github.com/python/cpython/issues/example2",
            "state": "closed",
            "comments": 8,
            "created_at": "2024-02-20",
            "labels": ["import", "resolved"]
        })
    
    if "connection" in error_lower or "timeout" in error_lower:
        results.append({
            "title": "Connection timeout on high load",
            "url": "https://github.com/psf/requests/issues/example3",
            "state": "open",
            "comments": 23,
            "created_at": "2024-03-10",
            "labels": ["networking", "help wanted"]
        })
    
    # Add generic results
    results.append({
        "title": f"Error similar to: {error_message[:50]}...",
        "url": "https://github.com/search?type=issues",
        "state": "open",
        "comments": 5,
        "created_at": "2024-04-01",
        "labels": ["needs-investigation"]
    })
    
    return results


def _get_simulated_stackoverflow_results(error_message: str, tags: str) -> List[Dict]:
    """Simulate Stack Overflow API results."""
    error_lower = error_message.lower()
    
    results = []
    
    if "undefined" in error_lower or "null" in error_lower:
        results.append({
            "title": "How to fix 'Cannot read property of undefined'?",
            "url": "https://stackoverflow.com/questions/example1",
            "score": 245,
            "answer_count": 12,
            "is_answered": True,
            "accepted_answer_id": 12345,
            "tags": ["javascript", "react", "undefined"]
        })
    
    if "type" in error_lower:
        results.append({
            "title": "TypeError: X is not a function - what does it mean?",
            "url": "https://stackoverflow.com/questions/example2",
            "score": 189,
            "answer_count": 8,
            "is_answered": True,
            "tags": ["javascript", "typeerror"]
        })
    
    if "import" in error_lower or "module" in error_lower:
        results.append({
            "title": "Python ImportError: No module named X",
            "url": "https://stackoverflow.com/questions/example3",
            "score": 567,
            "answer_count": 15,
            "is_answered": True,
            "tags": ["python", "import", "module"]
        })
    
    results.append({
        "title": f"How to debug: {error_message[:40]}...",
        "url": "https://stackoverflow.com/search",
        "score": 45,
        "answer_count": 3,
        "is_answered": True,
        "tags": ["debugging", "error-handling"]
    })
    
    return results


def _get_documentation_links(error_type: str, language: str) -> List[Dict]:
    """Get documentation links for error type."""
    docs = []
    
    # Language-specific docs
    if language == "python":
        docs.append({
            "title": "Python Built-in Exceptions",
            "url": "https://docs.python.org/3/library/exceptions.html",
            "type": "official"
        })
    elif language == "javascript":
        docs.append({
            "title": "MDN Error Reference",
            "url": "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors",
            "type": "official"
        })
    elif language == "go":
        docs.append({
            "title": "Go Error Handling",
            "url": "https://go.dev/blog/error-handling-and-go",
            "type": "official"
        })
    
    # Error type specific
    if error_type == "null_reference":
        docs.append({
            "title": "Handling Null Reference Errors",
            "url": "https://example.com/null-reference-guide",
            "type": "guide"
        })
    
    return docs


# =============================================================================
# AGENT - Strands Agent with context tools
# =============================================================================

CONTEXT_AGENT_PROMPT = """You are a Context Research Specialist Agent.

## YOUR ROLE
Search external resources to provide context for errors.
Find similar issues, community solutions, and relevant documentation.

## YOUR TOOLS
- search_github_issues: Search GitHub Issues for similar error reports
- search_stackoverflow: Search Stack Overflow for Q&A about this error
- fetch_documentation: Get official documentation links
- get_error_explanation: Get human-readable explanation of the error type

## YOUR WORKFLOW
1. Call search_github_issues to find related issues
2. Call search_stackoverflow to find community solutions
3. Call get_error_explanation for educational context
4. Call fetch_documentation for official resources

## OUTPUT FORMAT
Return a JSON object with:
{
    "github_issues": [...],
    "stackoverflow_questions": [...],
    "documentation": [...],
    "explanation": {...},
    "total_resources": N,
    "has_solutions": true|false
}

Always return valid JSON only, no additional text.
"""

context_agent = Agent(
    system_prompt=CONTEXT_AGENT_PROMPT,
    tools=[search_github_issues, search_stackoverflow, fetch_documentation, get_error_explanation],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def research(error_message: str, error_type: str = "unknown", language: str = "unknown") -> Dict[str, Any]:
    """
    Research external context for an error.
    
    Args:
        error_message: The error message
        error_type: Classified error type
        language: Programming language
        
    Returns:
        Dict with research results
    """
    logger.info(f"🔬 ContextAgent: Researching error context")
    
    try:
        prompt = f"""Research this error:
Error Type: {error_type}
Language: {language}
Message: {error_message}

Find similar issues, solutions, and documentation."""
        
        result = context_agent(prompt)
        response_text = str(result)
        
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ ContextAgent complete")
                return parsed
        except json.JSONDecodeError:
            pass
        
        return _direct_research(error_message, error_type, language)
        
    except Exception as e:
        logger.error(f"❌ ContextAgent error: {str(e)}")
        return _direct_research(error_message, error_type, language)


def _direct_research(error_message: str, error_type: str, language: str) -> Dict[str, Any]:
    """Direct research fallback."""
    try:
        github_result = json.loads(search_github_issues(error_message, language))
        so_result = json.loads(search_stackoverflow(error_message))
        docs_result = json.loads(fetch_documentation(error_type, language))
        explanation = json.loads(get_error_explanation(error_type, language))
        
        return {
            "github_issues": github_result.get("issues", []),
            "stackoverflow_questions": so_result.get("questions", []),
            "documentation": docs_result.get("documentation", []),
            "explanation": explanation.get("explanation", {}),
            "total_resources": github_result.get("total_count", 0) + so_result.get("total_count", 0),
            "has_solutions": so_result.get("total_count", 0) > 0
        }
    except Exception as e:
        return {
            "github_issues": [],
            "stackoverflow_questions": [],
            "documentation": [],
            "explanation": {},
            "total_resources": 0,
            "has_solutions": False,
            "error": str(e)
        }

