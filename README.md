# 🔍 Error Debugger - AWS AgentCore Multi-Agent Demo

A **tool-diverse multi-agent system** for debugging errors, built on AWS Bedrock AgentCore. This demo showcases how 7 specialized agents with 14+ distinct tools collaborate to analyze, diagnose, and fix errors.

## 🎯 Purpose

This is a technical demo for a two-part blog series on AWS AgentCore:

- **Part 1**: Core agents (Parser, Security, Root Cause, Fix, Memory)
- **Part 2**: Advanced features (Context APIs, Statistics, Long-term Learning)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SUPERVISOR AGENT                            │
│           Orchestrates all specialist agents                     │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Parser Agent  │    │Security Agent │    │ Memory Agent  │
├───────────────┤    ├───────────────┤    ├───────────────┤
│ 🔧 Regex      │    │ 🔧 Comprehend │    │ 🔧 AgentCore  │
│ 🔧 AST Parse  │    │    PII        │    │    Memory API │
│ 🔧 Comprehend │    │ 🔧 Regex      │    │ 🔧 Semantic   │
│    Language   │    │    Secrets    │    │    Search     │
└───────────────┘    └───────────────┘    └───────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Context Agent │    │ Root Cause    │    │  Fix Agent    │
├───────────────┤    ├───────────────┤    ├───────────────┤
│ 🔧 GitHub     │    │ 🔧 Pattern    │    │ 🔧 Bedrock    │
│    Issues API │    │    Database   │    │    Claude     │
│ 🔧 StackOver  │    │ 🔧 Bedrock    │    │ 🔧 AST        │
│    flow API   │    │    Claude     │    │    Validation │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
                              ▼
                    ┌───────────────┐
                    │ Stats Agent   │
                    ├───────────────┤
                    │ 🔧 Frequency  │
                    │ 🔧 Trends     │
                    └───────────────┘
```

## 🔧 Tools by Agent

| Agent | Tools | AWS/External Services |
|-------|-------|----------------------|
| **Parser** | `extract_stack_frames`, `detect_language`, `classify_error`, `extract_message` | Regex, AST, Comprehend |
| **Security** | `detect_pii`, `detect_secrets`, `redact_data`, `assess_risk` | Comprehend PII, Regex |
| **Context** | `search_github_issues`, `search_stackoverflow`, `fetch_docs`, `get_explanation` | GitHub API, SO API |
| **Root Cause** | `match_known_patterns`, `analyze_with_llm`, `synthesize_hypothesis` | Pattern DB, Bedrock Claude |
| **Fix** | `generate_code_fix`, `validate_syntax`, `suggest_prevention`, `generate_test` | Bedrock Claude, AST |
| **Memory** | `store_error_pattern`, `search_similar_errors`, `store_session`, `get_session` | AgentCore Memory API |
| **Stats** | `calculate_frequency`, `detect_trend`, `record_error`, `get_top_errors` | Time-series, Stats |

## 📁 Project Structure

```
error_debugger/
├── agent/                    # AgentCore Runtime
│   ├── supervisor.py        # 🎯 Main supervisor agent
│   ├── agents/              # 🔧 Specialist agents
│   │   ├── parser_agent.py  # Regex, AST, Comprehend
│   │   ├── security_agent.py # PII, Secrets scanning
│   │   ├── context_agent.py # GitHub, StackOverflow
│   │   ├── rootcause_agent.py # Patterns, LLM analysis
│   │   ├── fix_agent.py     # Code generation
│   │   ├── memory_agent.py  # AgentCore Memory
│   │   └── stats_agent.py   # Analytics
│   ├── Dockerfile
│   └── requirements.txt
├── app/                      # Frontend SPA
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── README.md
```

## 🧠 Memory System

### SHORT-TERM (Session Memory)
- **TTL**: 24 hours
- **Purpose**: Current debugging session context
- **Stores**: Current error, hypotheses, user context

### LONG-TERM (Semantic Memory)
- **TTL**: 30+ days (persistent)
- **Purpose**: Error patterns and solutions learned over time
- **Stores**: error_type → root_cause → solution mappings
- **Features**: Semantic search for similar past errors

## 🚀 Running Locally

### Frontend Only (Demo Mode)
```bash
cd app
python -m http.server 8080
# Open http://localhost:8080
```

### With Docker (Full AgentCore)
```bash
cd agent
docker build -t error-debugger .
docker run -e AWS_REGION=us-east-1 \
           -e MEMORY_ID=your-memory-id \
           error-debugger
```

## 📝 Blog Series Structure

### Part 1: Building a Multi-Agent Error Debugger
- Supervisor + 4 core agents
- Parser, Security, Root Cause, Fix agents
- Session memory for current context
- **Demo**: Paste error → Get diagnosis and fix

### Part 2: Learning from Every Error
- Add Context agent (external APIs)
- Add Stats agent (trends, frequency)
- Long-term semantic memory
- Similar error search: "We've seen this before"
- **Demo**: Error patterns accumulate and speed up future debugging

## 🎯 Key AgentCore Features Demonstrated

1. **AgentCore Runtime** - Serverless agent execution
2. **AgentCore Memory** - Session + Semantic memory with embeddings
3. **Multi-Agent Orchestration** - Supervisor pattern with specialists
4. **Tool Diversity** - Each agent has unique, distinct tools
5. **Strands Framework** - Python SDK for agent development

## 🔍 Sample Errors to Test

```javascript
TypeError: Cannot read properties of undefined (reading 'map')
    at UserList (src/components/UserList.tsx:15:23)
```

```python
ImportError: No module named 'pandas'
    at File "/app/analysis.py", line 3
```

```
Error: connect ECONNREFUSED 127.0.0.1:5432
    at TCPConnectWrap.afterConnect
```

## 📊 What Makes This Demo Impressive

1. **Tool Diversity**: Not just LLM prompts - real regex, AST, APIs
2. **Memory is the Hero**: "We've seen this before" is genuinely useful
3. **Clear Agent Roles**: Each agent has a specific job with specific tools
4. **Visual Flow**: Watch agents collaborate in real-time
5. **Practical Use Case**: Every developer debugs errors

---

Built with ❤️ for AWS AgentCore

