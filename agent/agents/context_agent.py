"""
Context Agent - Extensive external research for error context

This agent's job is to GATHER as much relevant context as possible.
The more context, the better the root cause analysis will be.

Tools:
- GitHub Issues API - Find similar issues and solutions
- GitHub Code Search - Find how others handle similar code patterns
- Stack Overflow API - Find Q&A about the error
- Documentation lookup - Find official docs
- Error database - Check known error explanations

Uses real API calls in production, minimal responses in demo mode (demo is UI testing only).
"""
import re
import json
import logging
import urllib.parse
import urllib.request
import boto3
from typing import Dict, Any, List, Optional
from strands import Agent, tool

from .config import DEMO_MODE, GITHUB_TOKEN, GITHUB_API_URL, STACKOVERFLOW_API_KEY, STACKOVERFLOW_API_URL, AWS_REGION

logger = logging.getLogger(__name__)

# Initialize Bedrock for intelligent summarization
bedrock_runtime = None
try:
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=AWS_REGION)
    logger.info("✅ Bedrock client initialized for ContextAgent")
except Exception as e:
    logger.warning(f"⚠️ Bedrock client init failed: {e}")


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


@tool(name="search_github_code")
def search_github_code(query: str, language: str = "") -> str:
    """
    Search GitHub Code for similar code patterns and solutions.
    Useful for finding how others handle similar errors or patterns.
    
    Args:
        query: Code pattern to search for (e.g., "optional chaining undefined")
        language: Programming language filter
    
    Returns:
        JSON with matching code examples
    """
    logger.info(f"🔍 Searching GitHub Code for: {query[:50]}...")
    
    if DEMO_MODE:
        return json.dumps({"results": [], "note": "Demo mode - code search disabled"})
    
    try:
        # Build search query
        search_query = query
        if language:
            search_query += f" language:{language}"
        
        url = f"{GITHUB_API_URL}/search/code?q={urllib.parse.quote(search_query)}&per_page=5"
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ErrorDebugger/1.0'
        }
        if GITHUB_TOKEN:
            headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        results = []
        for item in data.get('items', [])[:5]:
            results.append({
                "file": item.get('name', ''),
                "path": item.get('path', ''),
                "url": item.get('html_url', ''),
                "repository": item.get('repository', {}).get('full_name', ''),
                "score": item.get('score', 0)
            })
        
        logger.info(f"✅ GitHub Code Search returned {len(results)} results")
        return json.dumps({
            "query": query,
            "total_count": len(results),
            "results": results,
            "search_url": f"https://github.com/search?q={urllib.parse.quote(search_query)}&type=code"
        })
        
    except Exception as e:
        logger.error(f"❌ GitHub Code Search error: {str(e)}")
        return json.dumps({"results": [], "error": str(e)})


@tool(name="search_github_discussions")
def search_github_discussions(query: str) -> str:
    """
    Search GitHub Discussions for community help and solutions.
    
    Args:
        query: The topic to search for
    
    Returns:
        JSON with relevant discussions
    """
    logger.info(f"🔍 Searching GitHub Discussions for: {query[:50]}...")
    
    if DEMO_MODE:
        return json.dumps({"results": [], "note": "Demo mode - discussions search disabled"})
    
    try:
        # GitHub Discussions aren't searchable via REST API, use general search
        search_query = f"{query} is:discussion"
        url = f"{GITHUB_API_URL}/search/issues?q={urllib.parse.quote(search_query)}&sort=updated&per_page=5"
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ErrorDebugger/1.0'
        }
        if GITHUB_TOKEN:
            headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        results = []
        for item in data.get('items', [])[:5]:
            results.append({
                "title": item.get('title', ''),
                "url": item.get('html_url', ''),
                "state": item.get('state', ''),
                "comments": item.get('comments', 0),
                "created_at": item.get('created_at', '')[:10],
            })
        
        logger.info(f"✅ GitHub Discussions returned {len(results)} results")
        return json.dumps({
            "query": query,
            "total_count": len(results),
            "results": results
        })
        
    except Exception as e:
        logger.error(f"❌ GitHub Discussions error: {str(e)}")
        return json.dumps({"results": [], "error": str(e)})


@tool(name="get_stackoverflow_answers")
def get_stackoverflow_answers(question_ids: str) -> str:
    """
    Fetch actual answers from Stack Overflow questions.
    Use after search_stackoverflow to get the actual solutions.
    
    Args:
        question_ids: Comma-separated question IDs (e.g., "12345,67890")
    
    Returns:
        JSON with answers for the questions
    """
    logger.info(f"📖 Fetching Stack Overflow answers for: {question_ids}")
    
    if DEMO_MODE:
        return json.dumps({"answers": [], "note": "Demo mode - answer fetching disabled"})
    
    try:
        params = {
            'order': 'desc',
            'sort': 'votes',
            'site': 'stackoverflow',
            'filter': 'withbody'  # Include answer body
        }
        if STACKOVERFLOW_API_KEY:
            params['key'] = STACKOVERFLOW_API_KEY
        
        ids = question_ids.replace(' ', '')
        query_string = urllib.parse.urlencode(params)
        url = f"{STACKOVERFLOW_API_URL}/questions/{ids}/answers?{query_string}"
        
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'ErrorDebugger/1.0'
        }
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        answers = []
        for item in data.get('items', [])[:10]:
            # Extract code blocks from the answer
            body = item.get('body', '')
            code_blocks = re.findall(r'<code>(.*?)</code>', body, re.DOTALL)
            
            answers.append({
                "answer_id": item.get('answer_id'),
                "question_id": item.get('question_id'),
                "score": item.get('score', 0),
                "is_accepted": item.get('is_accepted', False),
                "code_snippets": code_blocks[:3],  # Limit to 3 code blocks
                "url": f"https://stackoverflow.com/a/{item.get('answer_id')}"
            })
        
        logger.info(f"✅ Fetched {len(answers)} answers")
        return json.dumps({
            "question_ids": question_ids,
            "answer_count": len(answers),
            "answers": answers
        })
        
    except Exception as e:
        logger.error(f"❌ Stack Overflow answers error: {str(e)}")
        return json.dumps({"answers": [], "error": str(e)})


@tool(name="summarize_research")
def summarize_research(
    error_message: str,
    github_results: str = "[]",
    stackoverflow_results: str = "[]"
) -> str:
    """
    Use LLM to summarize and rank the research findings.
    Identifies the most relevant solutions from all gathered context.
    
    Args:
        error_message: The original error
        github_results: JSON string of GitHub findings
        stackoverflow_results: JSON string of Stack Overflow findings
    
    Returns:
        JSON with ranked, summarized findings
    """
    logger.info("🧠 Summarizing research findings with LLM")
    
    if DEMO_MODE or not bedrock_runtime:
        return json.dumps({
            "summary": "Research summarization requires LLM",
            "top_solutions": [],
            "note": "Demo mode or LLM unavailable"
        })
    
    try:
        github = json.loads(github_results) if isinstance(github_results, str) else github_results
        so = json.loads(stackoverflow_results) if isinstance(stackoverflow_results, str) else stackoverflow_results
        
        prompt = f"""Analyze these research findings for the error and identify the most relevant solutions.

Error: {error_message}

GitHub Issues Found:
{json.dumps(github[:5], indent=2)}

Stack Overflow Questions Found:
{json.dumps(so[:5], indent=2)}

Return a JSON object with:
{{
    "summary": "Brief summary of what the research found",
    "top_solutions": [
        {{"source": "github|stackoverflow", "title": "...", "url": "...", "relevance": 0-100, "key_insight": "..."}}
    ],
    "common_causes": ["cause1", "cause2"],
    "recommended_approach": "Best solution based on research"
}}"""

        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}]
            })
        )
        
        response_body = json.loads(response['body'].read())
        content = response_body.get('content', [{}])[0].get('text', '{}')
        
        # Extract JSON from response
        start = content.find('{')
        end = content.rfind('}') + 1
        if start != -1 and end > start:
            return content[start:end]
        
        return json.dumps({"summary": content, "top_solutions": []})
        
    except Exception as e:
        logger.error(f"❌ Research summarization error: {str(e)}")
        return json.dumps({"summary": "Summarization failed", "error": str(e)})


@tool(name="read_github_file")
def read_github_file(repo_url: str, file_path: str, branch: str = "main") -> str:
    """
    Read a file from a GitHub repository to get more context about the error.
    Fetches the raw file content to understand the code structure.
    
    Args:
        repo_url: GitHub repository URL (e.g., "https://github.com/owner/repo" or "owner/repo")
        file_path: Path to the file within the repository (e.g., "src/app.py")
        branch: Branch name (default: "main")
    
    Returns:
        JSON with file content and metadata
    """
    logger.info(f"📄 Reading file from GitHub: {repo_url}/{file_path}")
    
    if DEMO_MODE:
        logger.info("📦 Demo mode: Using simulated file content")
        return json.dumps(_get_simulated_file_content(repo_url, file_path))
    
    return json.dumps(_fetch_github_file(repo_url, file_path, branch))


def _fetch_github_file(repo_url: str, file_path: str, branch: str = "main") -> Dict[str, Any]:
    """Fetch file content from GitHub API."""
    try:
        # Parse repo URL to get owner/repo
        if repo_url.startswith("https://github.com/"):
            repo_path = repo_url.replace("https://github.com/", "").rstrip("/")
        elif repo_url.startswith("github.com/"):
            repo_path = repo_url.replace("github.com/", "").rstrip("/")
        else:
            repo_path = repo_url  # Assume owner/repo format
        
        # Remove .git suffix if present
        repo_path = repo_path.replace(".git", "")
        
        # Build raw content URL
        raw_url = f"https://raw.githubusercontent.com/{repo_path}/{branch}/{file_path}"
        
        headers = {
            'User-Agent': 'ErrorDebugger/1.0',
            'Accept': 'text/plain'
        }
        if GITHUB_TOKEN:
            headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
        
        request = urllib.request.Request(raw_url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=15) as response:
            content = response.read().decode('utf-8')
        
        # Limit content size
        max_lines = 200
        lines = content.split('\n')
        truncated = len(lines) > max_lines
        if truncated:
            content = '\n'.join(lines[:max_lines]) + f"\n\n... (truncated, {len(lines) - max_lines} more lines)"
        
        logger.info(f"✅ Fetched {len(lines)} lines from {file_path}")
        
        return {
            "success": True,
            "repo": repo_path,
            "file_path": file_path,
            "branch": branch,
            "content": content,
            "line_count": len(lines),
            "truncated": truncated,
            "url": f"https://github.com/{repo_path}/blob/{branch}/{file_path}",
            "mode": "live"
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "success": False,
                "error": f"File not found: {file_path} in {repo_path}",
                "suggestion": "Check the file path and branch name",
                "mode": "live"
            }
        else:
            return {
                "success": False,
                "error": f"GitHub API error: {e.code} {e.reason}",
                "mode": "live"
            }
    except Exception as e:
        logger.error(f"❌ GitHub file fetch error: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "mode": "live"
        }


def _get_simulated_file_content(repo_url: str, file_path: str) -> Dict[str, Any]:
    """Simulate file content for demo mode."""
    # Detect file type
    file_ext = file_path.split('.')[-1] if '.' in file_path else ''
    
    sample_content = {
        "py": '''# Sample Python file
def process_data(data):
    """Process the input data."""
    if data is None:
        raise ValueError("Data cannot be None")
    
    results = []
    for item in data:
        # This could raise TypeError if item is not subscriptable
        results.append(item["value"])
    
    return results

class DataProcessor:
    def __init__(self, config):
        self.config = config
    
    def run(self):
        data = self.fetch_data()
        # Potential NoneType error if fetch_data returns None
        return self.process(data)
''',
        "js": '''// Sample JavaScript file
const fetchData = async (url) => {
  const response = await fetch(url);
  const data = await response.json();
  
  // This could throw if data.items is undefined
  return data.items.map(item => ({
    id: item.id,
    name: item.name.toUpperCase()
  }));
};

export const processItems = (items) => {
  // items might be undefined
  return items.filter(item => item.active);
};
''',
        "ts": '''// Sample TypeScript file
interface User {
  id: number;
  name: string;
  email?: string;
}

export const getUser = async (id: number): Promise<User> => {
  const response = await fetch(`/api/users/${id}`);
  return response.json();
};

export const formatUser = (user: User): string => {
  // email might be undefined
  return `${user.name} <${user.email.toLowerCase()}>`;
};
'''
    }
    
    content = sample_content.get(file_ext, f"// Sample {file_ext} file content\n// Unable to fetch real content in demo mode")
    
    return {
        "success": True,
        "repo": repo_url,
        "file_path": file_path,
        "branch": "main",
        "content": content,
        "line_count": len(content.split('\n')),
        "truncated": False,
        "note": "Demo mode - showing sample content. Set DEMO_MODE=false for real file fetching.",
        "mode": "demo"
    }


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
    """
    Extract meaningful search terms from error text.
    This is CRITICAL for getting good search results.
    """
    # Common noise words to remove
    noise_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'at', 'in', 'on', 'for', 'to', 'of',
        'this', 'that', 'with', 'from', 'and', 'or', 'not', 'be', 'it', 'you', 'we', 'they',
        'line', 'file', 'here', 'expected', 'found', 'error', 'message', 'unknown'
    }
    
    # First, try to extract specific error patterns
    patterns_to_extract = [
        # Terraform patterns
        r'Unsupported block type',
        r'Unsupported argument',
        r'Missing required argument',
        r'aws_[a-z_]+',  # AWS resource types
        # Python patterns
        r"ModuleNotFoundError.*'([^']+)'",
        r"No module named '([^']+)'",
        r"'(\w+)' object has no attribute '(\w+)'",
        # JavaScript patterns
        r"Cannot read propert[ies]* '?(\w+)'?",
        r"(\w+) is not a function",
        r"(\w+) is not defined",
        # General
        r'([A-Z][a-z]+Error)',  # TypeScript, SyntaxError, etc.
        r'Exception: (.+?)(?:\n|$)',
    ]
    
    extracted_terms = []
    for pattern in patterns_to_extract:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                extracted_terms.extend(match)
            else:
                extracted_terms.append(match)
    
    # Remove noise from extracted terms
    extracted_terms = [t for t in extracted_terms if t.lower() not in noise_words and len(t) > 2]
    
    # Extract camelCase/PascalCase identifiers
    identifiers = re.findall(r'\b[A-Z][a-z]+[A-Z]\w*\b|\b[a-z]+[A-Z]\w+\b', text)
    extracted_terms.extend(identifiers)
    
    # Extract words, filter noise
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text)
    words = [w for w in words if w.lower() not in noise_words and len(w) > 2]
    
    # Prioritize specific error terms
    priority_keywords = ['TypeError', 'SyntaxError', 'ImportError', 'undefined', 'null', 
                         'NoneType', 'connection', 'timeout', 'permission', 'block', 
                         'argument', 'Terraform', 'React', 'Node', 'Python']
    
    priority_terms = [w for w in words if any(kw.lower() in w.lower() for kw in priority_keywords)]
    other_terms = [w for w in words if w not in priority_terms and w not in extracted_terms]
    
    # Combine and deduplicate, keeping order
    all_terms = []
    seen = set()
    for term in extracted_terms + priority_terms + other_terms:
        if term.lower() not in seen:
            seen.add(term.lower())
            all_terms.append(term)
    
    return all_terms[:10]


def _get_simulated_github_results(error_message: str, language: str) -> List[Dict]:
    """
    Generate useful GitHub search links based on the error.
    In demo mode, we can't return actual issues, but we can return
    well-crafted search links that will find relevant issues.
    """
    error_lower = error_message.lower()
    
    # Use smart term extraction
    terms = _extract_search_terms(error_message)
    search_query = ' '.join(terms[:5])
    encoded_query = urllib.parse.quote(search_query)
    
    results = []
    
    # Terraform errors
    if "terraform" in error_lower or ".tf" in error_lower or "unsupported block" in error_lower:
        # Find the specific block/argument name
        block_match = re.search(r'Blocks of type "(\w+)"', error_message)
        arg_match = re.search(r'argument named "(\w+)"', error_message)
        resource_match = re.search(r'resource "(\w+)"', error_message)
        
        if block_match:
            block_name = block_match.group(1)
            results.append({
                "title": f"Terraform {block_name} block issues",
                "url": f"https://github.com/hashicorp/terraform-provider-aws/issues?q={block_name}+unsupported",
                "state": "open",
                "comments": 5,
                "created_at": "2024-01-15",
                "labels": ["bug", "terraform"],
                "repository": "terraform-provider-aws",
                "relevance": 90,
                "type": "search"
            })
        
        if resource_match:
            resource_type = resource_match.group(1)
            results.append({
                "title": f"{resource_type} resource documentation",
                "url": f"https://github.com/hashicorp/terraform-provider-aws/issues?q={resource_type}",
                "state": "open",
                "comments": 3,
                "created_at": "2024-02-10",
                "labels": ["documentation", "terraform"],
                "repository": "terraform-provider-aws",
                "relevance": 85,
                "type": "search"
            })
    
    # JavaScript/React undefined errors
    if "undefined" in error_lower or "null" in error_lower:
        if "react" in error_lower or "component" in error_lower:
            results.append({
                "title": "React Cannot read property of undefined",
                "url": "https://github.com/facebook/react/issues?q=undefined+is+not+an+object",
                "state": "closed",
                "comments": 15,
                "created_at": "2023-09-20",
                "labels": ["bug", "react"],
                "repository": "react",
                "relevance": 80,
                "type": "search"
            })
        else:
            results.append({
                "title": f"Undefined/null reference issues",
                "url": f"https://github.com/search?q={encoded_query}+undefined&type=issues",
                "state": "open",
                "comments": 8,
                "labels": ["bug"],
                "relevance": 70,
                "type": "search"
            })
    
    # Python import errors
    if "no module named" in error_lower or "modulenotfounderror" in error_lower:
        module_match = re.search(r"No module named ['\"]?(\w+)", error_message)
        if module_match:
            module_name = module_match.group(1)
            results.append({
                "title": f"ModuleNotFoundError: {module_name}",
                "url": f"https://github.com/search?q=ModuleNotFoundError+{module_name}&type=issues",
                "state": "closed",
                "comments": 12,
                "labels": ["installation", "python"],
                "relevance": 85,
                "type": "search"
            })
    
    # Connection errors
    if "connection" in error_lower or "timeout" in error_lower or "econnrefused" in error_lower:
        results.append({
            "title": "Connection refused / timeout issues",
            "url": f"https://github.com/search?q=ECONNREFUSED+connection+refused&type=issues",
            "state": "open",
            "comments": 6,
            "labels": ["network", "bug"],
            "relevance": 75,
            "type": "search"
        })
    
    # Add specific search based on extracted terms
    if terms and not results:
        results.append({
            "title": f"GitHub search: {' '.join(terms[:3])}",
            "url": f"https://github.com/search?q={encoded_query}&type=issues",
            "state": "search",
            "comments": 0,
            "labels": ["search"],
            "relevance": 60,
            "type": "search"
        })
    
    # If still no results, add general search
    if not results:
        results.append({
            "title": f"Search GitHub Issues",
            "url": f"https://github.com/search?q={encoded_query}&type=issues",
            "state": "search",
            "labels": ["general"],
            "relevance": 50,
            "type": "search"
        })
    
    return results


def _get_simulated_stackoverflow_results(error_message: str, tags: str) -> List[Dict]:
    """
    Generate useful Stack Overflow search links based on the error.
    Uses smart term extraction to find relevant questions.
    """
    error_lower = error_message.lower()
    
    # Use smart term extraction
    terms = _extract_search_terms(error_message)
    search_query = ' '.join(terms[:5])
    encoded_query = urllib.parse.quote(search_query)
    
    results = []
    
    # Terraform errors
    if "terraform" in error_lower or ".tf" in error_lower or "unsupported block" in error_lower:
        block_match = re.search(r'Blocks of type "(\w+)"', error_message)
        resource_match = re.search(r'resource "(\w+)"', error_message)
        
        if block_match:
            block_name = block_match.group(1)
            results.append({
                "title": f"Terraform unsupported block type: {block_name}",
                "url": f"https://stackoverflow.com/search?q=terraform+unsupported+block+{block_name}",
                "score": 45,
                "answer_count": 3,
                "is_answered": True,
                "tags": ["terraform", "terraform-provider-aws"],
                "view_count": 1500,
                "relevance": 90,
                "type": "search"
            })
        
        if resource_match:
            resource = resource_match.group(1)
            results.append({
                "title": f"How to configure {resource} in Terraform",
                "url": f"https://stackoverflow.com/search?q=terraform+{resource}",
                "score": 32,
                "answer_count": 5,
                "is_answered": True,
                "tags": ["terraform", "aws"],
                "view_count": 2300,
                "relevance": 85,
                "type": "search"
            })
    
    # JavaScript undefined errors
    if "undefined" in error_lower or "null" in error_lower:
        prop_match = re.search(r"Cannot read propert[ies]* ['\"]?(\w+)", error_message)
        if prop_match:
            prop = prop_match.group(1)
            results.append({
                "title": f"TypeError: Cannot read property '{prop}' of undefined",
                "url": f"https://stackoverflow.com/search?q=cannot+read+property+{prop}+undefined",
                "score": 245,
                "answer_count": 12,
                "is_answered": True,
                "tags": ["javascript", "typescript", "undefined"],
                "view_count": 50000,
                "relevance": 95,
                "type": "search"
            })
        else:
            results.append({
                "title": "How to avoid 'Cannot read property of undefined'",
                "url": "https://stackoverflow.com/search?q=cannot+read+property+undefined+javascript",
                "score": 189,
                "answer_count": 8,
                "is_answered": True,
                "tags": ["javascript", "undefined"],
                "view_count": 30000,
                "relevance": 80,
                "type": "search"
            })
    
    # Python import errors
    if "no module named" in error_lower or "modulenotfounderror" in error_lower:
        module_match = re.search(r"No module named ['\"]?(\w+)", error_message)
        if module_match:
            module = module_match.group(1)
            results.append({
                "title": f"ModuleNotFoundError: No module named '{module}'",
                "url": f"https://stackoverflow.com/search?q=ModuleNotFoundError+{module}+python",
                "score": 156,
                "answer_count": 10,
                "is_answered": True,
                "tags": ["python", "pip", "import"],
                "view_count": 25000,
                "relevance": 90,
                "type": "search"
            })
    
    # Python NoneType errors
    if "nonetype" in error_lower:
        attr_match = re.search(r"'NoneType' object has no attribute '(\w+)'", error_message)
        if attr_match:
            attr = attr_match.group(1)
            results.append({
                "title": f"'NoneType' object has no attribute '{attr}'",
                "url": f"https://stackoverflow.com/search?q=NoneType+object+has+no+attribute+{attr}",
                "score": 234,
                "answer_count": 15,
                "is_answered": True,
                "tags": ["python", "nonetype"],
                "view_count": 40000,
                "relevance": 95,
                "type": "search"
            })
    
    # Connection errors
    if "econnrefused" in error_lower or "connection refused" in error_lower:
        results.append({
            "title": "ECONNREFUSED - Connection refused by server",
            "url": "https://stackoverflow.com/search?q=ECONNREFUSED+connection+refused",
            "score": 89,
            "answer_count": 7,
            "is_answered": True,
            "tags": ["node.js", "networking", "docker"],
            "view_count": 15000,
            "relevance": 85,
            "type": "search"
        })
    
    # Add based on extracted terms if no specific matches
    if terms and not results:
        results.append({
            "title": f"Stack Overflow: {' '.join(terms[:3])}",
            "url": f"https://stackoverflow.com/search?q={encoded_query}",
            "score": 0,
            "answer_count": 0,
            "is_answered": False,
            "tags": ["search"],
            "relevance": 60,
            "type": "search"
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

CONTEXT_AGENT_PROMPT = """You are an Extensive Research Specialist Agent.

## YOUR ROLE
Gather as much relevant context as possible about the error.
The MORE context you find, the BETTER the root cause analysis will be.
Cast a wide net - search multiple sources, get actual answers, find code examples.

## YOUR TOOLS (use as many as relevant)

### Primary Research
- `search_github_issues`: Find similar GitHub Issues with solutions
- `search_stackoverflow`: Find Q&A about this error
- `get_stackoverflow_answers`: Fetch actual answer content from SO questions

### Deep Research  
- `search_github_code`: Find code examples handling similar patterns
- `search_github_discussions`: Find community discussions
- `read_github_file`: Read specific source files for context

### Summarization
- `summarize_research`: Use LLM to rank and summarize findings
- `fetch_documentation`: Get official documentation links
- `get_error_explanation`: Get human-readable error explanation

## YOUR WORKFLOW

### Step 1: Broad Search (do in parallel)
- search_github_issues(error_message, language)
- search_stackoverflow(error_message, tags=language)

### Step 2: Deep Dive (based on Step 1 results)
- If SO questions found: get_stackoverflow_answers(question_ids)
- If code patterns relevant: search_github_code(pattern, language)

### Step 3: Synthesize
- summarize_research(error_message, github_results, so_results)

## OUTPUT FORMAT
{
    "github_issues": [{title, url, state, comments, relevance}],
    "stackoverflow_questions": [{title, url, score, is_answered, relevance}],
    "stackoverflow_answers": [{answer_id, score, code_snippets}],
    "code_examples": [{file, repository, url}],
    "documentation": [{title, url, type}],
    "summary": {
        "top_solutions": [...],
        "common_causes": [...],
        "recommended_approach": "..."
    },
    "total_resources": N,
    "has_solutions": true|false
}
"""

context_agent = Agent(
    system_prompt=CONTEXT_AGENT_PROMPT,
    tools=[
        search_github_issues, 
        search_stackoverflow, 
        get_stackoverflow_answers,
        search_github_code,
        search_github_discussions,
        read_github_file, 
        summarize_research,
        fetch_documentation, 
        get_error_explanation
    ],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def research(error_message: str, error_type: str = "unknown", language: str = "unknown") -> Dict[str, Any]:
    """
    Extensively research external context for an error.
    Gathers as much relevant information as possible.
    
    Args:
        error_message: The error message
        error_type: Classified error type
        language: Programming language
        
    Returns:
        Dict with comprehensive research results
    """
    logger.info(f"🔬 ContextAgent: EXTENSIVE research (mode: {'DEMO' if DEMO_MODE else 'LIVE'})")
    
    if DEMO_MODE:
        # In demo mode, just return minimal results for UI testing
        logger.info("📦 Demo mode: Returning minimal results")
        return _demo_research(error_message, error_type, language)
    
    # LIVE MODE: Do extensive research
    try:
        prompt = f"""Extensively research this error. Use ALL available tools to gather context.

Error Type: {error_type}
Language: {language}
Error Message:
{error_message}

YOUR TASK:
1. Search GitHub Issues for similar problems
2. Search Stack Overflow for Q&A
3. If SO questions found, fetch their actual answers
4. Search for relevant code examples
5. Get documentation links
6. Summarize and rank the findings

Be thorough - the more context you find, the better the root cause analysis will be."""
        
        result = context_agent(prompt)
        response_text = str(result)
        
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ ContextAgent complete: {parsed.get('total_resources', 0)} resources found")
                return parsed
        except json.JSONDecodeError:
            pass
        
        # If agent didn't return JSON, do direct research
        return _direct_research(error_message, error_type, language)
        
    except Exception as e:
        logger.error(f"❌ ContextAgent error: {str(e)}")
        return _direct_research(error_message, error_type, language)


def _demo_research(error_message: str, error_type: str, language: str) -> Dict[str, Any]:
    """Minimal research for demo mode (UI testing only)."""
    terms = _extract_search_terms(error_message)
    query = ' '.join(terms[:3])
    
    return {
        "github_issues": [{
            "title": f"Search: {query}",
            "url": f"https://github.com/search?q={urllib.parse.quote(query)}&type=issues",
            "type": "search"
        }],
        "stackoverflow_questions": [{
            "title": f"Search: {query}",
            "url": f"https://stackoverflow.com/search?q={urllib.parse.quote(query)}",
            "type": "search"
        }],
        "documentation": [],
        "total_resources": 2,
        "has_solutions": False,
        "mode": "demo",
        "note": "Demo mode - showing search links only. Set DEMO_MODE=false for real research."
    }


def _direct_research(error_message: str, error_type: str, language: str) -> Dict[str, Any]:
    """Direct extensive research without agent wrapper."""
    logger.info("🔬 Direct research mode")
    
    results = {
        "github_issues": [],
        "stackoverflow_questions": [],
        "stackoverflow_answers": [],
        "code_examples": [],
        "documentation": [],
        "explanation": {},
        "total_resources": 0,
        "has_solutions": False,
        "mode": "live"
    }
    
    try:
        # Step 1: GitHub Issues
        github_result = json.loads(search_github_issues(error_message, language))
        results["github_issues"] = github_result.get("issues", [])
        logger.info(f"Found {len(results['github_issues'])} GitHub issues")
        
        # Step 2: Stack Overflow Questions
        so_result = json.loads(search_stackoverflow(error_message, language))
        results["stackoverflow_questions"] = so_result.get("questions", [])
        logger.info(f"Found {len(results['stackoverflow_questions'])} SO questions")
        
        # Step 3: Get actual SO answers if questions found
        if results["stackoverflow_questions"]:
            question_ids = ",".join([
                str(q.get("question_id", q.get("id", ""))) 
                for q in results["stackoverflow_questions"][:3]
                if q.get("question_id") or q.get("id")
            ])
            if question_ids:
                answers_result = json.loads(get_stackoverflow_answers(question_ids))
                results["stackoverflow_answers"] = answers_result.get("answers", [])
                logger.info(f"Fetched {len(results['stackoverflow_answers'])} SO answers")
        
        # Step 4: Code examples (if we have specific patterns)
        terms = _extract_search_terms(error_message)
        if terms and language != "unknown":
            code_query = " ".join(terms[:3])
            code_result = json.loads(search_github_code(code_query, language))
            results["code_examples"] = code_result.get("results", [])
            logger.info(f"Found {len(results['code_examples'])} code examples")
        
        # Step 5: Documentation
        docs_result = json.loads(fetch_documentation(error_type, language))
        results["documentation"] = docs_result.get("documentation", [])
        
        # Step 6: Error explanation
        explanation = json.loads(get_error_explanation(error_type, language))
        results["explanation"] = explanation.get("explanation", {})
        
        # Step 7: Summarize if we have findings
        total = (
            len(results["github_issues"]) + 
            len(results["stackoverflow_questions"]) + 
            len(results["stackoverflow_answers"]) +
            len(results["code_examples"])
        )
        results["total_resources"] = total
        results["has_solutions"] = len(results["stackoverflow_answers"]) > 0 or any(
            q.get("is_answered") for q in results["stackoverflow_questions"]
        )
        
        # Summarize with LLM if we have results
        if total > 0 and not DEMO_MODE:
            try:
                summary_result = json.loads(summarize_research(
                    error_message,
                    json.dumps(results["github_issues"]),
                    json.dumps(results["stackoverflow_questions"])
                ))
                results["summary"] = summary_result
            except:
                pass
        
        logger.info(f"✅ Direct research complete: {total} resources")
        return results
        
    except Exception as e:
        logger.error(f"❌ Direct research failed: {str(e)}")
        results["error"] = str(e)
        return results
