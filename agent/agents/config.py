"""
Shared configuration for Error Debugger agents.

DEMO_MODE controls whether agents use simulated responses (for local testing)
or real AWS/API calls (for production).

Set via environment variable: DEMO_MODE=true|false
"""
import os

# Demo mode: Use simulated responses instead of real API calls
# Default: False when deployed (set DEMO_MODE=true for local testing)
DEMO_MODE = os.environ.get('DEMO_MODE', 'false').lower() in ('true', '1', 'yes')

# Feature part (1 = basic, 2 = advanced)
FEATURE_PART = int(os.environ.get('FEATURE_PART', '2'))

# AWS Region
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# AgentCore Memory ID
MEMORY_ID = os.environ.get('MEMORY_ID', '')

# GitHub configuration (for Context Agent)
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')  # Optional: for higher rate limits
GITHUB_API_URL = 'https://api.github.com'

# Stack Overflow configuration (for Context Agent)  
STACKOVERFLOW_API_KEY = os.environ.get('STACKOVERFLOW_API_KEY', '')  # Optional: for higher rate limits
STACKOVERFLOW_API_URL = 'https://api.stackexchange.com/2.3'

# Logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def get_mode_string() -> str:
    """Return a string describing the current mode."""
    return "DEMO" if DEMO_MODE else "LIVE"

