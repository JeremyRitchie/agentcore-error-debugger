# Error Debugger - Blog Series Feature Breakdown

> Use this document for prompt injection to understand the Part 1 vs Part 2 feature division.

---

## Part 1: Basic Multi-Agent System
*"Building a Multi-Agent Error Debugger with AWS AgentCore"*

### Agents (5 Total)

| Agent | Type | Purpose |
|-------|------|---------|
| **Supervisor** | Runtime | Orchestrates all agents, manages workflow |
| **Parser** | Lambda → Gateway | Extract stack frames, detect language, classify error type |
| **Security** | Lambda → Gateway | Scan for secrets, detect PII, risk assessment |
| **Root Cause** | Runtime | LLM reasoning to determine why the error occurred |
| **Fix** | Runtime | LLM code generation to propose a fix |

### Tools (4)

```python
tools = [
    parser_agent_tool,      # Parse error text
    security_agent_tool,    # Security scanning
    rootcause_agent_tool,   # LLM root cause analysis
    fix_agent_tool,         # LLM fix generation
]
```

### AWS Resources

| Resource | Purpose |
|----------|---------|
| CloudFront + S3 | Frontend hosting |
| AgentCore Gateway | MCP endpoint for Lambda tools |
| AgentCore Runtime | Supervisor + RootCause + Fix agents |
| Lambda (Parser) | Parser agent execution |
| Lambda (Security) | Security agent execution |
| Bedrock Claude | LLM for reasoning |
| Comprehend | Language detection, PII detection |

### UI Features

- Error input field
- Basic architecture visualization (5 agents)
- Parse results display
- Security scan results
- Root cause analysis
- Code fix generation
- Simple results panel

### NOT in Part 1

- ❌ Memory (no pattern storage/retrieval)
- ❌ Context Agent (no GitHub/StackOverflow search)
- ❌ Stats Agent (no error frequency tracking)
- ❌ GitHub Integration (no repo connection)
- ❌ Issue/PR Creation

---

## Part 2: Advanced Features
*"Extending Your AgentCore System with Memory, Context, and Integrations"*

### Agents (7 Total = Part 1 + 2 new)

| Agent | Type | Purpose | NEW |
|-------|------|---------|-----|
| Supervisor | Runtime | Orchestrates all agents | |
| Parser | Lambda → Gateway | Extract stack frames, detect language | |
| Security | Lambda → Gateway | Scan for secrets, detect PII | |
| Root Cause | Runtime | LLM reasoning for root cause | |
| Fix | Runtime | LLM code generation | |
| **Memory** | Runtime | Store/search error patterns | ✅ |
| **Context** | Lambda → Gateway | Search GitHub Issues & StackOverflow | ✅ |
| **Stats** | Lambda → Gateway | Track error frequency & trends | ✅ |

### Additional Tools (+7)

```python
tools = [
    # Part 1 tools
    parser_agent_tool,
    security_agent_tool,
    rootcause_agent_tool,
    fix_agent_tool,
    
    # Part 2 additions
    context_agent_tool,      # GitHub Issues, StackOverflow search
    read_github_file_tool,   # Read source files from GitHub repos
    search_memory,           # Semantic search for similar errors
    store_pattern,           # Store error patterns long-term
    store_session,           # Store session context short-term
    record_stats,            # Record error occurrence
    get_trend,               # Get error frequency trends
]
```

### Additional AWS Resources

| Resource | Purpose |
|----------|---------|
| AgentCore Memory | Semantic & session memory |
| KMS Key | Memory encryption |
| Lambda (Context) | GitHub/StackOverflow search |
| Lambda (Stats) | Error statistics |
| DynamoDB Table | Stats persistence |

### Additional UI Features

- Full architecture visualization (7 agents + connections)
- GitHub Integration panel (repository URL, PAT auth)
- External Resources section (GitHub Issues, StackOverflow links)
- Memory Matches section (similar past errors, previous fixes)
- Statistics panel (error frequency, trends)
- Create Issue / Create PR buttons

---

## Comparison Table

| Feature | Part 1 | Part 2 |
|---------|--------|--------|
| Agents | 5 | 7 |
| Tools | 4 | 11 |
| Lambdas | 2 (Parser, Security) | 4 (+Context, Stats) |
| Memory | ❌ | ✅ Semantic + Session |
| GitHub Search | ❌ | ✅ |
| StackOverflow Search | ❌ | ✅ |
| GitHub Integration | ❌ | ✅ (read files, create issues/PRs) |
| Stats & Trends | ❌ | ✅ |
| DynamoDB | ❌ | ✅ |
| KMS Encryption | ❌ | ✅ |

---

## Deployment

**Deploy Part 1:**
```bash
gh workflow run deploy.yml -f action=deploy -f feature_part=1
```

**Deploy Part 2:**
```bash
gh workflow run deploy.yml -f action=deploy -f feature_part=2
```

---

## Blog Narrative

### Part 1
> "Build a basic multi-agent error debugger using AWS AgentCore. Set up a Supervisor agent that orchestrates Parser, Security, Root Cause, and Fix agents. Use Lambda-backed tools exposed via AgentCore Gateway, and leverage Bedrock Claude for LLM reasoning."

**Key Learnings:**
- AgentCore Runtime setup
- Strands SDK for agent creation
- Lambda tools with MCP protocol
- Supervisor orchestration pattern

### Part 2
> "Extend your error debugger with advanced AgentCore features: persistent memory for learning from past errors, external context from GitHub and StackOverflow, and statistics tracking. Add GitHub integration for seamless DevOps workflows."

**Key Learnings:**
- AgentCore Memory (semantic + session)
- External API integration
- DynamoDB for persistence
- GitHub API integration
- Feature flagging for incremental deployment

