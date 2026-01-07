# 🔍 Error Debugger - AWS AgentCore Multi-Agent Demo

A **tool-diverse multi-agent system** for debugging errors, built on AWS Bedrock AgentCore. This demo showcases how 7 specialized agents with 14+ distinct tools collaborate to analyze, diagnose, and fix errors.

## 🎯 Purpose

This is a technical demo for a two-part blog series on AWS AgentCore:

- **Part 1**: Core agents (Parser, Security, Root Cause, Fix) - Basic multi-agent system
- **Part 2**: Advanced features (Memory, Context, Stats, GitHub integration, Live visualization)

---

## 🎛️ Feature Flags (Blog Post Parts)

The codebase supports feature flags to deploy either Part 1 or Part 2 features:

### Part 1: Basic Multi-Agent System
```
5 Agents: Supervisor, Parser, Security, Root Cause, Fix
Lambda Tools: Parser, Security
AWS Services: Comprehend, Bedrock Claude
```

### Part 2: Advanced Features (includes Part 1)
```
7 Agents: + Memory, Context, Stats
AgentCore Memory: Session + Semantic storage
GitHub Integration: Fetch code, create issues/PRs
Live Architecture Visualization
Activity Log
```

### How to Select

**GitHub Actions:**
```yaml
# Workflow dispatch allows selecting Part 1 or 2
workflow_dispatch:
  inputs:
    feature_part:
      description: 'Blog Series Part (1=basic, 2=advanced)'
      type: choice
      options: ['1', '2']
```

**Terraform:**
```hcl
variable "feature_part" {
  default = 2  # 1 or 2
}
```

**Frontend (config.js):**
```javascript
window.AGENTCORE_CONFIG = {
  part: 2,       // 1 or 2
  demoMode: true // true = simulated, false = real APIs
};
```

**Backend (environment variables):**
```bash
FEATURE_PART=2    # 1 or 2
DEMO_MODE=false   # true = simulated, false = real APIs
```

---

## 🔌 Demo Mode vs Live Mode

The codebase supports two operational modes:

### Demo Mode (`DEMO_MODE=true`)
- **Default for local development**
- Uses simulated API responses
- Pre-seeded memory patterns
- No AWS credentials required
- Works completely offline

### Live Mode (`DEMO_MODE=false`)
- **Default when deployed via Terraform**
- Real AWS Comprehend for PII detection
- Real Bedrock Claude for LLM reasoning
- Real GitHub/StackOverflow API calls
- Real AgentCore Memory for persistence
- Real DynamoDB for statistics

### What Changes by Mode

| Component | Demo Mode | Live Mode |
|-----------|-----------|-----------|
| **Parser Lambda** | Simulated in gateway_tools | Lambda via Gateway |
| **Security Lambda** | Simulated in gateway_tools | Lambda via Gateway |
| **Context Lambda** | Simulated in gateway_tools | Lambda via Gateway |
| **Stats Lambda** | Simulated in gateway_tools | Lambda via Gateway + DynamoDB |
| **Root Cause Agent** | Pattern matching (local) | Bedrock Claude (local) |
| **Fix Agent** | Templates (local) | Bedrock Claude (local) |
| **Memory Agent** | Local in-memory | AgentCore Memory (local) |

---

## 🏗️ Lambda vs Runtime Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GATEWAY (MCP)                                   │
│                                                                             │
│   ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐               │
│   │  Parser   │  │ Security  │  │  Context  │  │   Stats   │               │
│   │  Lambda   │  │  Lambda   │  │  Lambda   │  │  Lambda   │               │
│   │           │  │           │  │           │  │           │               │
│   │ Regex +   │  │ Regex +   │  │ GitHub +  │  │ DynamoDB  │               │
│   │ Comprehend│  │ Comprehend│  │ StackOvflw│  │           │               │
│   └───────────┘  └───────────┘  └───────────┘  └───────────┘               │
│         ▲              ▲              ▲              ▲                      │
│         │   MCP Tool Calls via Gateway              │                      │
│         └──────────────┬───────────────┬────────────┘                      │
│                        │               │                                    │
└────────────────────────│───────────────│────────────────────────────────────┘
                         │               │
┌────────────────────────▼───────────────▼────────────────────────────────────┐
│                         AGENTCORE RUNTIME                                    │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                        SUPERVISOR AGENT                              │   │
│   │                  (Orchestrates, calls tools)                         │   │
│   │                                                                      │   │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │   │
│   │   │  Root Cause  │  │     Fix      │  │    Memory    │              │   │
│   │   │    Agent     │  │    Agent     │  │    Agent     │              │   │
│   │   │  (Bedrock)   │  │  (Bedrock)   │  │ (AgentCore)  │              │   │
│   │   │              │  │              │  │              │              │   │
│   │   │  Runs LOCAL  │  │  Runs LOCAL  │  │  Runs LOCAL  │              │   │
│   │   └──────────────┘  └──────────────┘  └──────────────┘              │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Split?

| Location | Agents | Reason |
|----------|--------|--------|
| **Lambda** | Parser, Security, Context, Stats | Fast, stateless, reusable by other systems |
| **Runtime** | Root Cause, Fix | LLM-heavy, needs accumulated context |
| **Runtime** | Memory | Low latency needed for every request |

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           🌐 FRONTEND (S3 + CloudFront)                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  Single Page App (HTML/CSS/JS)  │  config.js (Gateway URL, Runtime ID)  │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │ HTTPS
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     ⚡ AGENTCORE GATEWAY (MCP Protocol)                       │
│                           IAM Authentication                                  │
│  ┌────────────────────────────────┬────────────────────────────────────────┐ │
│  │     🔧 PARSER LAMBDA           │        🔧 SECURITY LAMBDA              │ │
│  │  • Regex stack extraction      │  • Comprehend PII detection            │ │
│  │  • Comprehend language         │  • Regex secret patterns               │ │
│  │  • Error classification        │  • Risk assessment                     │ │
│  └────────────────────────────────┴────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │ Invoke Runtime
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                  🐳 AGENTCORE RUNTIME (Docker Container - ARM64)              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                      👔 SUPERVISOR AGENT (Strands SDK)                   │ │
│  │                    Orchestrates all specialist agents                    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│       │           │           │           │           │           │          │
│       ▼           ▼           ▼           ▼           ▼           ▼          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│  │📋Parser │ │🔒Securi │ │🧠Memory │ │🌐Context│ │🎯Root   │ │🔧Fix    │    │
│  │  Agent  │ │  Agent  │ │  Agent  │ │  Agent  │ │  Cause  │ │  Agent  │    │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘    │
│       │           │           │           │           │           │          │
│  Calls Lambda  Calls Lambda   │       HTTP APIs    Bedrock     Bedrock       │
│  via Gateway   via Gateway    │           │        Claude      Claude        │
│                               ▼           ▼           │           │          │
│                    ┌─────────────────────────────────────────────────────┐   │
│                    │                  📊 STATS AGENT                      │   │
│                    │              Frequency, Trends, Recording            │   │
│                    └─────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
        │                               │                       │
        │ Store/Search                  │ HTTP                  │ InvokeModel
        ▼                               ▼                       ▼
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────────┐
│ 🧠 AGENTCORE       │    │ 🌍 EXTERNAL APIs   │    │ 🤖 AMAZON BEDROCK      │
│    MEMORY          │    │ • GitHub API       │    │ • Claude 3 Sonnet      │
│ ┌────────────────┐ │    │   (code, issues)   │    │ • Root cause analysis  │
│ │ SHORT-TERM     │ │    │ • Stack Overflow   │    │ • Code fix generation  │
│ │ Session: 24h   │ │    │   (Q&A search)     │    │                        │
│ ├────────────────┤ │    └────────────────────┘    └────────────────────────┘
│ │ LONG-TERM      │ │
│ │ Semantic Search│ │    ┌────────────────────┐    ┌────────────────────────┐
│ │ Error Patterns │ │    │ 📝 AMAZON          │    │ 📊 OBSERVABILITY       │
│ └────────────────┘ │    │    COMPREHEND      │    │ • X-Ray Tracing        │
└────────────────────┘    │ • PII Detection    │    │ • CloudWatch Logs      │
                          │ • Language Detect  │    │                        │
                          └────────────────────┘    └────────────────────────┘
```

---

## 📦 What Runs Where

| Component | Runtime | Description |
|-----------|---------|-------------|
| **Frontend** | S3 + CloudFront | Static SPA, calls Gateway via HTTPS |
| **Gateway** | AgentCore Gateway | MCP protocol, IAM auth, routes to Lambda/Runtime |
| **Parser Lambda** | AWS Lambda | Regex extraction, Comprehend language detection |
| **Security Lambda** | AWS Lambda | Comprehend PII, regex secret scanning |
| **Supervisor Agent** | AgentCore Runtime (Docker) | Orchestrates specialists via Strands SDK |
| **Specialist Agents** | AgentCore Runtime (Docker) | Parser, Security, Memory, Context, RootCause, Fix, Stats |
| **Memory** | AgentCore Memory | Session (24h) + Semantic (persistent) storage |
| **LLM** | Amazon Bedrock | Claude 3 Sonnet for reasoning and code generation |

---

## 🔧 Tools by Agent and Where They Run

| Agent | Tools | Runs In | Calls |
|-------|-------|---------|-------|
| **Parser** | `extract_stack_frames`, `detect_language`, `classify_error` | **Lambda** (via Gateway MCP) | Comprehend |
| **Security** | `detect_pii`, `detect_secrets`, `assess_risk` | **Lambda** (via Gateway MCP) | Comprehend |
| **Memory** | `store_session`, `get_session`, `store_pattern`, `search_patterns` | **Runtime** (in-process) | AgentCore Memory API |
| **Context** | `search_github`, `search_stackoverflow`, `fetch_code` | **Runtime** (in-process) | GitHub API, SO API |
| **Root Cause** | `match_patterns`, `analyze_with_llm` | **Runtime** (in-process) | Memory + Bedrock Claude |
| **Fix** | `generate_fix`, `validate_syntax`, `create_issue`, `create_pr` | **Runtime** (in-process) | Bedrock Claude, GitHub API |
| **Stats** | `record_occurrence`, `calculate_frequency`, `detect_trend` | **Runtime** (in-process) | In-memory stats |

---

## 🔄 Request Flow

```
1. User pastes error in Frontend
                │
2. Frontend calls Gateway (/api/debug)
                │
3. Gateway invokes AgentCore Runtime
                │
4. Supervisor Agent orchestrates:
   │
   ├─► Memory Agent: "Have we seen this before?"
   │   └─► AgentCore Memory API (semantic search)
   │
   ├─► Parser Agent: "Extract stack trace"
   │   └─► Gateway → Parser Lambda → Comprehend
   │
   ├─► Security Agent: "Any secrets/PII?"
   │   └─► Gateway → Security Lambda → Comprehend
   │
   ├─► Context Agent: "Find external context"
   │   └─► GitHub API, Stack Overflow API
   │
   ├─► Root Cause Agent: "What's the root cause?"
   │   └─► Memory patterns + Bedrock Claude
   │
   ├─► Fix Agent: "Generate a fix"
   │   └─► Bedrock Claude + syntax validation
   │
   └─► Stats Agent: "Record for trending"
       └─► In-memory statistics
                │
5. Results streamed back to Frontend
                │
6. User can create GitHub Issue/PR (with PAT)
```

---

## 🧠 Memory Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   AGENTCORE MEMORY                          │
├─────────────────────────────────────────────────────────────┤
│  SHORT-TERM (Session Memory)          LONG-TERM (Semantic)  │
│  ┌───────────────────────────┐  ┌───────────────────────┐   │
│  │ • Current error context   │  │ • Error patterns      │   │
│  │ • Hypotheses tried        │  │ • Root cause → fix    │   │
│  │ • User session data       │  │ • Success counts      │   │
│  │                           │  │ • Embeddings search   │   │
│  │ TTL: 24 hours             │  │ TTL: 30+ days         │   │
│  └───────────────────────────┘  └───────────────────────┘   │
│                                                             │
│  API Calls:                                                 │
│  • CreateMemoryEvent (store)                                │
│  • GetMemoryEvents (retrieve session)                       │
│  • SearchMemory (semantic search)                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
error-debugger/
├── .github/workflows/
│   ├── bootstrap.yml        # Create S3/DynamoDB/ECR (run first!)
│   └── deploy.yml           # Build container, deploy infrastructure
│
├── agent/                   # 🐳 AgentCore Runtime (Docker)
│   ├── supervisor.py        # 👔 Supervisor agent
│   ├── agents/
│   │   ├── parser_agent.py  # Calls Parser Lambda via Gateway
│   │   ├── security_agent.py # Calls Security Lambda via Gateway
│   │   ├── memory_agent.py  # AgentCore Memory API (direct)
│   │   ├── context_agent.py # GitHub/SO APIs (direct HTTP)
│   │   ├── rootcause_agent.py # Bedrock Claude (direct)
│   │   ├── fix_agent.py     # Bedrock Claude (direct)
│   │   └── stats_agent.py   # In-memory stats
│   ├── Dockerfile           # ARM64 container for AgentCore
│   └── requirements.txt     # strands-agents, bedrock-agentcore
│
├── app/                     # 🌐 Frontend (S3 + CloudFront)
│   ├── index.html
│   ├── styles.css
│   └── app.js               # Demo mode + GitHub integration
│
├── terraform/agentcore/     # 🏗️ Infrastructure
│   ├── main.tf              # Provider config
│   ├── gateway.tf           # AgentCore Gateway + MCP targets
│   ├── runtime.tf           # AgentCore Runtime + endpoint
│   ├── memory.tf            # AgentCore Memory + KMS
│   ├── tool_lambdas.tf      # Parser + Security Lambdas
│   ├── frontend.tf          # S3, CloudFront, ACM, Route53
│   └── outputs.tf
│
└── docs/
    ├── architecture.mmd     # Mermaid diagram (import to Lucidchart)
    └── architecture-lucidchart.csv  # CSV import for Lucidchart
```

---

## 🚀 Deployment

### 1. Bootstrap (One-time)
```bash
# Run Bootstrap workflow to create:
# - S3 bucket for Terraform state
# - DynamoDB table for state locking
# - ECR repository for agent container
```

### 2. Deploy
```bash
# Push to main branch, or manually trigger Deploy workflow
# Creates: Gateway, Runtime, Memory, Lambdas, Frontend
```

### 3. Required GitHub Variables
| Variable | Description |
|----------|-------------|
| `AWS_ROLE_ARN` | IAM role for OIDC authentication |
| `PROJECT_NAME` | `error-debugger` (optional) |
| `AWS_REGION` | `us-east-1` (optional) |

---

## 🔐 GitHub Integration (PAT)

The app can fetch code from GitHub and create Issues/PRs:

```
┌─────────────────────────────────────────────────────────────┐
│  PAT Storage: Memory only (never persisted)                 │
│  Cleared on: Page unload                                    │
│  Required scopes:                                           │
│  • contents: read/write (fetch code, commit fixes)          │
│  • issues: read/write (create issues)                       │
│  • pull_requests: read/write (create PRs)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Lucidchart Import

Two files are provided in `/docs/`:

1. **`architecture.mmd`** - Mermaid diagram
   - Go to Lucidchart → Import → Select Mermaid
   
2. **`architecture-lucidchart.csv`** - CSV with shapes
   - Go to Lucidchart → File → Import Data → CSV

---

## 🎯 Key AgentCore Features Demonstrated

| Feature | How It's Used |
|---------|---------------|
| **AgentCore Gateway** | MCP protocol, routes to Lambda tools |
| **AgentCore Runtime** | Docker container running Strands agents |
| **AgentCore Memory** | Session + Semantic memory with embeddings |
| **Multi-Agent** | Supervisor orchestrates 7 specialists |
| **Tool Diversity** | Lambda, Bedrock, APIs, regex, in-memory |

---

## 🔍 Sample Errors to Test

```javascript
// TypeError - common React error
TypeError: Cannot read properties of undefined (reading 'map')
    at UserList (src/components/UserList.tsx:15:23)
```

```python
# ImportError - missing package
ImportError: No module named 'pandas'
    at File "/app/analysis.py", line 3
```

```
# ConnectionError - database connection
Error: connect ECONNREFUSED 127.0.0.1:5432
    at TCPConnectWrap.afterConnect
```

---

Built with ❤️ for AWS AgentCore
