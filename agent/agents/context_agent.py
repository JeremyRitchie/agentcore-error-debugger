"""
Context Agent - Searches external resources for error context
Tools: GitHub Issues API, Stack Overflow API, documentation fetching

Uses real API calls in production, simulated responses in demo mode.
"""
import re
import json
import logging
import urllib.parse
import urllib.request
from typing import Dict, Any, List
from strands import Agent, tool

from .config import DEMO_MODE, GITHUB_TOKEN, GITHUB_API_URL, STACKOVERFLOW_API_KEY, STACKOVERFLOW_API_URL

logger = logging.getLogger(__name__)


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
    
    if DEMO_MODE:
        logger.info("📦 Demo mode: Using simulated GitHub results")
        issues = _get_simulated_github_results(error_message, language)
    else:
        logger.info("🌐 Live mode: Calling GitHub API")
        issues = _call_github_api(query, language)
    
    result = {
        "query": query,
        "total_count": len(issues),
        "issues": issues[:5],
        "source": "github_issues",
        "search_url": f"https://github.com/search?q={urllib.parse.quote(query)}&type=issues",
        "mode": "demo" if DEMO_MODE else "live"
    }
    
    logger.info(f"✅ Found {len(issues)} GitHub issues")
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
    
    if DEMO_MODE:
        logger.info("📦 Demo mode: Using simulated Stack Overflow results")
        questions = _get_simulated_stackoverflow_results(error_message, tags)
    else:
        logger.info("🌐 Live mode: Calling Stack Overflow API")
        questions = _call_stackoverflow_api(query, tags)
    
    result = {
        "query": query,
        "total_count": len(questions),
        "questions": questions[:5],
        "source": "stackoverflow",
        "search_url": f"https://stackoverflow.com/search?q={urllib.parse.quote(query)}",
        "mode": "demo" if DEMO_MODE else "live"
    }
    
    logger.info(f"✅ Found {len(questions)} Stack Overflow questions")
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
    
    # Documentation mapping (this is static, no API needed)
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
# REAL API CALLS (used when DEMO_MODE=false)
# =============================================================================

def _call_github_api(query: str, language: str = "") -> List[Dict]:
    """Call the real GitHub Issues API."""
    try:
        # Build search query
        search_query = query
        if language:
            search_query += f" language:{language}"
        search_query += " is:issue"
        
        url = f"{GITHUB_API_URL}/search/issues?q={urllib.parse.quote(search_query)}&sort=updated&order=desc&per_page=10"
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ErrorDebugger/1.0'
        }
        if GITHUB_TOKEN:
            headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        issues = []
        for item in data.get('items', [])[:10]:
            issues.append({
                "title": item.get('title', ''),
                "url": item.get('html_url', ''),
                "state": item.get('state', ''),
                "comments": item.get('comments', 0),
                "created_at": item.get('created_at', '')[:10],
                "labels": [label.get('name', '') for label in item.get('labels', [])[:3]],
                "repository": item.get('repository_url', '').split('/')[-1] if item.get('repository_url') else ''
            })
        
        logger.info(f"✅ GitHub API returned {len(issues)} issues")
        return issues
        
    except Exception as e:
        logger.error(f"❌ GitHub API error: {str(e)}")
        # Fall back to simulated results on error
        return _get_simulated_github_results(query, language)


def _call_stackoverflow_api(query: str, tags: str = "") -> List[Dict]:
    """Call the real Stack Overflow API."""
    try:
        # Build API URL
        params = {
            'order': 'desc',
            'sort': 'relevance',
            'intitle': query[:100],  # Stack Overflow has title length limits
            'site': 'stackoverflow',
            'pagesize': 10
        }
        if tags:
            params['tagged'] = tags.replace(',', ';')
        if STACKOVERFLOW_API_KEY:
            params['key'] = STACKOVERFLOW_API_KEY
        
        query_string = urllib.parse.urlencode(params)
        url = f"{STACKOVERFLOW_API_URL}/search/advanced?{query_string}"
        
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'ErrorDebugger/1.0'
        }
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        questions = []
        for item in data.get('items', [])[:10]:
            questions.append({
                "title": item.get('title', ''),
                "url": item.get('link', ''),
                "score": item.get('score', 0),
                "answer_count": item.get('answer_count', 0),
                "is_answered": item.get('is_answered', False),
                "accepted_answer_id": item.get('accepted_answer_id'),
                "tags": item.get('tags', [])[:5],
                "view_count": item.get('view_count', 0)
            })
        
        logger.info(f"✅ Stack Overflow API returned {len(questions)} questions")
        return questions
        
    except Exception as e:
        logger.error(f"❌ Stack Overflow API error: {str(e)}")
        # Fall back to simulated results on error
        return _get_simulated_stackoverflow_results(query, tags)


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
    """Simulate GitHub Issues API results with REAL working search URLs."""
    import urllib.parse
    
    error_lower = error_message.lower()
    
    # Extract search terms
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', error_message)
    noise = {'the', 'a', 'an', 'is', 'are', 'was', 'in', 'on', 'for', 'to', 'of', 'at', 'line', 'file'}
    terms = [w for w in words if w.lower() not in noise and len(w) > 2][:5]
    search_query = ' '.join(terms)
    encoded_query = urllib.parse.quote(search_query)
    
    results = []
    
    if "undefined" in error_lower or "null" in error_lower:
        results.append({
            "title": "Cannot read property of undefined - similar issues",
            "url": f"https://github.com/search?q={encoded_query}+undefined&type=issues",
            "state": "search",
            "comments": 0,
            "created_at": "",
            "labels": ["search-result"]
        })
    
    if "module" in error_lower or "import" in error_lower:
        results.append({
            "title": "ModuleNotFoundError / ImportError issues",
            "url": f"https://github.com/search?q={encoded_query}+import+error&type=issues",
            "state": "search",
            "comments": 0,
            "created_at": "",
            "labels": ["search-result"]
        })
    
    if "connection" in error_lower or "timeout" in error_lower:
        results.append({
            "title": "Connection/Timeout related issues",
            "url": f"https://github.com/search?q={encoded_query}+connection&type=issues",
            "state": "search",
            "comments": 0,
            "created_at": "",
            "labels": ["search-result"]
        })
    
    # Always add a general search link
    results.append({
        "title": f"Search GitHub: {search_query[:50]}",
        "url": f"https://github.com/search?q={encoded_query}&type=issues",
        "state": "search",
        "comments": 0,
        "created_at": "",
        "labels": ["general-search"]
    })
    
    return results


def _get_simulated_stackoverflow_results(error_message: str, tags: str) -> List[Dict]:
    """Simulate Stack Overflow API results with REAL working search URLs."""
    import urllib.parse
    
    error_lower = error_message.lower()
    
    # Extract search terms
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', error_message)
    noise = {'the', 'a', 'an', 'is', 'are', 'was', 'in', 'on', 'for', 'to', 'of', 'at', 'line', 'file'}
    terms = [w for w in words if w.lower() not in noise and len(w) > 2][:5]
    search_query = ' '.join(terms)
    encoded_query = urllib.parse.quote(search_query)
    
    results = []
    
    if "undefined" in error_lower or "null" in error_lower:
        results.append({
            "title": "How to fix 'Cannot read property of undefined'?",
            "url": f"https://stackoverflow.com/search?q={encoded_query}+undefined",
            "score": 245,
            "answer_count": 12,
            "is_answered": True,
            "tags": ["javascript", "react", "undefined"]
        })
    
    if "type" in error_lower:
        results.append({
            "title": "TypeError troubleshooting",
            "url": f"https://stackoverflow.com/search?q={encoded_query}+TypeError",
            "score": 189,
            "answer_count": 8,
            "is_answered": True,
            "tags": ["javascript", "typeerror"]
        })
    
    if "import" in error_lower or "module" in error_lower:
        results.append({
            "title": "Python ImportError: No module named",
            "url": f"https://stackoverflow.com/search?q={encoded_query}+import",
            "score": 567,
            "answer_count": 15,
            "is_answered": True,
            "tags": ["python", "import", "module"]
        })
    
    # Always add general search
    results.append({
        "title": f"Search Stack Overflow: {search_query[:40]}",
        "url": f"https://stackoverflow.com/search?q={encoded_query}",
        "score": 0,
        "answer_count": 0,
        "is_answered": False,
        "tags": ["search"]
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
    elif language == "rust":
        docs.append({
            "title": "Rust Error Handling",
            "url": "https://doc.rust-lang.org/book/ch09-00-error-handling.html",
            "type": "official"
        })
    elif language == "java":
        docs.append({
            "title": "Java Exceptions Tutorial",
            "url": "https://docs.oracle.com/javase/tutorial/essential/exceptions/",
            "type": "official"
        })
    
    # Error type specific
    if error_type == "null_reference":
        docs.append({
            "title": "Handling Null Reference Errors",
            "url": "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Cant_access_property",
            "type": "guide"
        })
    elif error_type == "type_error":
        docs.append({
            "title": "Understanding Type Errors",
            "url": "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypeError",
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
    logger.info(f"🔬 ContextAgent: Researching error context (mode: {'DEMO' if DEMO_MODE else 'LIVE'})")
    
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
            "has_solutions": so_result.get("total_count", 0) > 0,
            "mode": "demo" if DEMO_MODE else "live"
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
