"""
Error Debugger Specialist Agents
Each agent has unique tools for different analysis capabilities

Architecture:
- Lambda Tools (via Gateway): Parser, Security, Context, Stats
- Runtime Agents (local): Root Cause, Fix, Memory
"""
# Gateway tools for calling Lambda functions
from . import gateway_tools

# Local agents that run in Runtime (LLM-heavy or low-latency needs)
from . import rootcause_agent
from . import fix_agent
from . import memory_agent

# Legacy imports (these are now called via Gateway, not directly)
# Kept for backwards compatibility
from . import parser_agent
from . import security_agent
from . import context_agent
from . import stats_agent

__all__ = [
    'gateway_tools',
    'rootcause_agent',
    'fix_agent',
    'memory_agent',
    # Legacy
    'parser_agent',
    'security_agent', 
    'context_agent',
    'stats_agent',
]

