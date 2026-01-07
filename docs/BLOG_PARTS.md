# Error Debugger - Blog Series Feature Breakdown

> Use this document for prompt injection to understand the Part 1 vs Part 2 feature division.

---

## Architecture Overview

```
User → Frontend (CloudFront+S3) → API Proxy (Lambda URL) → AgentCore Runtime → Supervisor Agent
                                                                                    ↓
                                                          ┌─────────────────────────┼─────────────────────────┐
                                                          ↓                         ↓                         ↓
                                                    Gateway (MCP)              LLM Agents               Memory (Part 2)
                                                          ↓                         ↓
                                                  Lambda Tools              Bedrock Claude
                                              (Parser, Security,          (Root Cause, Fix)
                                               Context*, Stats*)
```

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Lambda Function URL** (not API Gateway) | Supports 15-minute timeout for long analyses |
| **Lambda Proxy** (not direct AgentCore) | AWS APIs don't support CORS for browser requests |
| **MCP Gateway** | Standardized tool interface - agents call tools by name |
| **Iterative Supervisor** | Real debugging is exploratory, not a fixed pipeline |
| **Streaming + Structured Output** | Lambda extracts structured data from 2000+ streaming events |

---

## Part 1: Basic Multi-Agent System
*"Building a Multi-Agent Error Debugger with AWS AgentCore"*

### Agents (5 Total)

| Agent | Type | Purpose |
|-------|------|---------|
| **Supervisor** | Runtime | Iterative orchestrator using THINK→ACT→OBSERVE→REFLECT→DECIDE loop |
| **Parser** | Lambda → Gateway | Extract stack frames, detect language (Comprehend), classify error type |
| **Security** | Lambda → Gateway | Scan for secrets, detect PII (Comprehend), risk assessment |
| **Root Cause** | Runtime (LLM) | Claude reasoning to determine *why* the error occurred |
| **Fix** | Runtime (LLM) | Claude code generation to propose actionable fix |

### Tools (8)

```python
tools = [
    # Core Agent Tools
    parser_agent_tool,        # Parse error text → language, stack frames, error type
    security_agent_tool,      # Security scan → PII, secrets, risk level
    rootcause_agent_tool,     # LLM analysis → root cause, confidence, solution
    fix_agent_tool,           # LLM generation → code fix, explanation, prevention
    
    # Reasoning Helpers (always available)
    update_context,           # Accumulate context between agent calls
    get_context,              # View accumulated context
    add_reasoning_step,       # Document thinking process
    evaluate_progress,        # Reflection for iterative reasoning
]
```

### AWS Resources

| Resource | Purpose |
|----------|---------|
| CloudFront + S3 | Frontend hosting (static HTML/CSS/JS) |
| Lambda Function URL | API Proxy with CORS + 15-min timeout |
| AgentCore Gateway | MCP endpoint routing to Lambda tools |
| AgentCore Runtime | Docker container running Supervisor + LLM agents |
| Lambda (Parser) | Error parsing, language detection |
| Lambda (Security) | PII/secret detection, risk assessment |
| Bedrock Claude (Haiku 4.5) | LLM for root cause reasoning & fix generation |
| Comprehend | Language detection, PII detection |
| CloudWatch Logs | Centralized logging for all components |

### Supervisor Behavior (Part 1)

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. THINK: What do I know? What do I need to find out?              │
│  2. ACT: Call parser_agent_tool, security_agent_tool                │
│  3. OBSERVE: What did the tools return? Is it useful?               │
│  4. REFLECT: Do I have enough information? Am I confident?          │
│  5. DECIDE:                                                          │
│     - If confident (≥80%) → Call rootcause + fix, produce output    │
│     - If not confident → Try different approach, loop back          │
└─────────────────────────────────────────────────────────────────────┘
```

### UI Features (Part 1)

- ✅ Error input text area with sample errors
- ✅ **Analysis Summary** section (top-level overview with badges)
- ✅ Parsed Information (language, stack frames, message)
- ✅ Security Assessment (risk level, PII/secrets found)
- ✅ Root Cause Analysis (cause, confidence %, solution)
- ✅ Suggested Fix (before/after code, explanation)
- ✅ Analysis Metrics (agents used, tool calls, execution time)
- ✅ CloudWatch Logs viewer (tabbed by component)
- ✅ Architecture visualization (5 agents)
- ✅ "PART 1 • LIVE" badge

### NOT in Part 1

- ❌ Memory Agent (no pattern storage/retrieval)
- ❌ Context Agent (no GitHub/StackOverflow search)
- ❌ Stats Agent (no error frequency tracking)
- ❌ GitHub Integration (no repo connection)
- ❌ Issue/PR Creation buttons
- ❌ External Resources section

---

## Part 2: Advanced Features
*"Extending Your AgentCore System with Memory, Context, and Integrations"*

### Agents (7 Total = Part 1 + 3 new)

| Agent | Type | Purpose | NEW |
|-------|------|---------|-----|
| Supervisor | Runtime | Orchestrates all agents with iterative reasoning | |
| Parser | Lambda → Gateway | Extract stack frames, detect language | |
| Security | Lambda → Gateway | Scan for secrets, detect PII | |
| Root Cause | Runtime (LLM) | LLM reasoning for root cause | |
| Fix | Runtime (LLM) | LLM code generation | |
| **Memory** | Runtime | Store/search error patterns with vector similarity | ✅ |
| **Context** | Lambda → Gateway | Search GitHub Issues & Stack Overflow | ✅ |
| **Stats** | Lambda → Gateway | Track error frequency & trends in DynamoDB | ✅ |

### Tools (13 = Part 1 + 5)

```python
tools = [
    # Part 1 tools (8)
    parser_agent_tool,
    security_agent_tool,
    rootcause_agent_tool,
    fix_agent_tool,
    update_context,
    get_context,
    add_reasoning_step,
    evaluate_progress,
    
    # Part 2 additions (5)
    context_agent_tool,       # GitHub Issues, StackOverflow search
    read_github_file_tool,    # Read source files from GitHub repos
    search_memory,            # Semantic search for similar errors
    store_pattern,            # Store error patterns long-term
    record_stats,             # Record error occurrence
    get_trend,                # Get error frequency trends
]
```

### Additional AWS Resources

| Resource | Purpose |
|----------|---------|
| AgentCore Memory | Semantic memory with vector similarity search |
| KMS Key | Memory encryption at rest |
| Lambda (Context) | GitHub API + Stack Overflow API integration |
| Lambda (Stats) | DynamoDB read/write for statistics |
| DynamoDB Table | Error statistics persistence |

### Supervisor Behavior (Part 2)

```
Phase 1: Initial Information Gathering
  1. PARSE → Get structured error data
  2. SECURITY → Check for PII/secrets (parallel)
  3. MEMORY → Search for similar past errors (might have instant solution!)

Phase 2: External Research (if confidence < 80%)
  4. CONTEXT → Search GitHub Issues, Stack Overflow
  5. READ FILE → Fetch source code from GitHub repo (if provided)

Phase 3: Reasoning (with ALL accumulated context)
  6. ROOT CAUSE → Pass everything gathered to LLM

Phase 4: Solution (only when confident ≥80%)
  7. FIX → Generate code fix addressing root cause
  8. STATS → Record occurrence for trend tracking
  9. STORE → Save pattern to memory for future
```

### Additional UI Features (Part 2)

- ✅ Full architecture visualization (7 agents + Memory + Gateway)
- ✅ GitHub Integration panel (repository URL, PAT input)
- ✅ **External Resources** section (ranked GitHub Issues, SO answers)
- ✅ **Memory Matches** section (similar past errors, previous fixes)
- ✅ Statistics in Analysis Metrics (trend: stable/increasing/decreasing)
- ✅ Create Issue / Create PR buttons (requires PAT)
- ✅ Memory panel showing stored patterns
- ✅ "PART 2 • LIVE" badge

---

## Comparison Table

| Feature | Part 1 | Part 2 |
|---------|--------|--------|
| **Agents** | 5 | 7 |
| **Tools** | 8 | 13 |
| **Lambdas** | 2 (Parser, Security) | 4 (+Context, Stats) |
| **Supervisor Prompt** | Core iterative reasoning | + Memory/Context workflow |
| **Memory** | ❌ | ✅ Semantic (vector search) |
| **GitHub Search** | ❌ | ✅ Issues search |
| **StackOverflow Search** | ❌ | ✅ Questions/answers search |
| **GitHub Integration** | ❌ | ✅ (read files, create issues/PRs) |
| **Stats & Trends** | ❌ | ✅ DynamoDB tracking |
| **DynamoDB** | ❌ | ✅ |
| **KMS Encryption** | ❌ | ✅ (Memory encryption) |
| **External Resources UI** | ❌ | ✅ Ranked list with relevance |
| **Memory Matches UI** | ❌ | ✅ Past solutions display |

---

## Data Flow

### Request Path
```
1. User submits error text in frontend
2. Frontend POSTs to Lambda Function URL (/analyze)
3. Lambda Proxy invokes AgentCore Runtime
4. Supervisor iteratively calls tools via Gateway + LLM
5. Lambda Proxy streams 2000+ events, extracts structured data
6. Frontend displays categorized results with Summary section
```

### Response Structure
```json
{
  "success": true,
  "agents": {
    "parser": { "language": "typescript", "stack_frames": [...], ... },
    "security": { "risk_level": "low", "pii_found": [], ... },
    "rootcause": { "root_cause": "...", "confidence": 95, ... },
    "fix": { "fixed_code": "...", "explanation": "...", ... },
    "context": { ... },   // Part 2 only
    "memory": { ... },    // Part 2 only
    "stats": { ... }      // Part 2 only
  },
  "summary": {
    "language": "typescript",
    "errorType": "json_parse_error",
    "rootCause": "JSON.parse() receiving HTML instead of JSON",
    "rootCauseConfidence": 95,
    "solution": "Add response validation before parsing",
    "riskLevel": "low"
  }
}
```

---

## Deployment

### Deploy Part 1 (Basic)
```bash
gh workflow run deploy.yml -f action=deploy -f feature_part=1
```

### Deploy Part 2 (Full)
```bash
gh workflow run deploy.yml -f action=deploy -f feature_part=2
```

### Environment Variables (Secrets)
| Secret | Purpose | Required |
|--------|---------|----------|
| `AWS_ROLE_ARN` | OIDC role for deployment | ✅ |
| `GH_PAT` | GitHub API token for Context Lambda | Optional |
| `STACKOVERFLOW_API_KEY` | Stack Overflow API key | Optional |

---

## Blog Narrative

### Part 1: "Building a Multi-Agent Error Debugger with AWS AgentCore"

> Build an intelligent error debugging system using AWS Bedrock AgentCore. Create a Supervisor agent that orchestrates Parser, Security, Root Cause, and Fix agents using an iterative reasoning loop. The system thinks, acts, observes, reflects, and decides—mimicking how an expert developer debugs code.

**Key Learnings:**
- AgentCore Runtime setup with Docker containers
- Strands SDK for building intelligent agents
- Lambda tools exposed via MCP Gateway protocol
- Iterative supervisor pattern (not fixed pipeline)
- Lambda Function URL for long-running operations
- Streaming response handling and structured data extraction

**Architecture Highlights:**
- THINK→ACT→OBSERVE→REFLECT→DECIDE loop
- 80% confidence threshold before producing output
- Feature-flagged supervisor prompts
- Real-time CloudWatch logs in frontend

### Part 2: "Extending Your AgentCore System with Memory, Context, and Integrations"

> Enhance your error debugger with persistent memory that learns from past errors, external context from GitHub and Stack Overflow, and statistics tracking for trend analysis. Add GitHub integration for seamless DevOps workflows including issue creation and PR generation.

**Key Learnings:**
- AgentCore Memory with semantic vector search
- External API integration (GitHub, Stack Overflow)
- DynamoDB for statistics persistence
- GitHub API for file reading and issue/PR creation
- Feature flagging for incremental deployment
- KMS encryption for sensitive memory data

**Architecture Highlights:**
- Memory-first search for instant solutions
- Multi-phase workflow with external research
- Ranked external resources with relevance scores
- Create Issue/PR directly from analysis results

---

## File Structure

```
agentcore-error-debugger/
├── agent/
│   ├── supervisor.py           # Main supervisor with Part 1/2 prompts
│   ├── Dockerfile              # Runtime container
│   ├── requirements.txt        # Python dependencies
│   └── agents/
│       ├── config.py           # Shared config (FEATURE_PART, DEMO_MODE)
│       ├── gateway_tools.py    # Gateway Lambda tool wrappers
│       ├── rootcause_agent.py  # LLM root cause analysis
│       ├── fix_agent.py        # LLM fix generation
│       ├── context_agent.py    # GitHub/SO search (Part 2)
│       └── memory_agent.py     # Memory operations (Part 2)
├── app/
│   ├── index.html              # Main HTML structure
│   ├── app.js                  # Frontend logic with feature flags
│   ├── styles.css              # Styling
│   └── favicon.svg             # App icon
├── terraform/agentcore/
│   ├── main.tf                 # Provider, locals
│   ├── variables.tf            # Input variables (feature_part)
│   ├── outputs.tf              # Frontend config injection
│   ├── runtime.tf              # AgentCore Runtime
│   ├── gateway.tf              # AgentCore Gateway + targets
│   ├── memory.tf               # AgentCore Memory (Part 2, conditional)
│   ├── tool_lambdas.tf         # Parser, Security, Context, Stats
│   ├── api_proxy.tf            # Lambda Function URL proxy
│   ├── logs_api.tf             # CloudWatch logs API
│   └── frontend.tf             # S3 + CloudFront
├── .github/workflows/
│   └── deploy.yml              # CI/CD with feature_part input
└── docs/
    ├── ARCHITECTURE.md         # Detailed architecture documentation
    └── BLOG_PARTS.md           # This file
```
