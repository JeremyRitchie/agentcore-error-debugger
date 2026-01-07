# Error Debugger Architecture

> Multi-agent error debugging system built on AWS Bedrock AgentCore

---

## System Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                      USER                                                │
│                                        │                                                 │
│                                        ▼                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │                           FRONTEND (CloudFront + S3)                              │   │
│  │  • Static HTML/CSS/JS                                                             │   │
│  │  • Feature-flagged UI (Part 1 vs Part 2)                                          │   │
│  │  • Displays results, logs, architecture visualization                             │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                                 │
│                                        │ POST /analyze                                   │
│                                        ▼                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │                        API PROXY (Lambda Function URL)                            │   │
│  │  • CORS handling for browser requests                                             │   │
│  │  • 15-minute timeout for long analyses                                            │   │
│  │  • Streams AgentCore response, extracts structured data                           │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                                 │
│                                        │ invoke_agent_runtime()                          │
│                                        ▼                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              AWS BEDROCK AGENTCORE                                       │
│                                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │                         RUNTIME (Docker Container)                                │   │
│  │                                                                                   │   │
│  │  ┌─────────────────────────────────────────────────────────────────────────────┐ │   │
│  │  │                      SUPERVISOR AGENT (Strands SDK)                         │ │   │
│  │  │                                                                             │ │   │
│  │  │   System Prompt: Iterative, reflective reasoning                            │ │   │
│  │  │   THINK → ACT → OBSERVE → REFLECT → DECIDE (loop until ≥80% confident)      │ │   │
│  │  │                                                                             │ │   │
│  │  │   Available Tools:                                                          │ │   │
│  │  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │ │   │
│  │  │   │parser_agent  │  │security_agent│  │rootcause_    │  │fix_agent     │    │ │   │
│  │  │   │_tool         │  │_tool         │  │agent_tool    │  │_tool         │    │ │   │
│  │  │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │ │   │
│  │  │          │                 │           (LLM in         (LLM in              │ │   │
│  │  │          │                 │            Runtime)        Runtime)            │ │   │
│  │  │          │                 │                                                │ │   │
│  │  │   ┌──────┴─────────────────┴──────────────────────────────────────────────┐ │ │   │
│  │  │   │                    PART 2 ADDITIONAL TOOLS                            │ │ │   │
│  │  │   │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐  │ │ │   │
│  │  │   │  │context_agent│ │search_memory│ │record_stats │ │read_github_file │  │ │ │   │
│  │  │   │  │_tool        │ │store_pattern│ │get_trend    │ │_tool            │  │ │ │   │
│  │  │   │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └─────────────────┘  │ │ │   │
│  │  │   └─────────┼───────────────┼───────────────┼─────────────────────────────┘ │ │   │
│  │  └─────────────┼───────────────┼───────────────┼───────────────────────────────┘ │   │
│  │                │               │               │                                  │   │
│  └────────────────┼───────────────┼───────────────┼──────────────────────────────────┘   │
│                   │               │               │                                      │
│                   ▼               ▼               ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                        GATEWAY (MCP Protocol Endpoint)                             │ │
│  │                                                                                    │ │
│  │  Routes tool calls to Lambda functions via MCP JSON-RPC                            │ │
│  │                                                                                    │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │ │
│  │  │   Parser    │  │  Security   │  │   Context   │  │    Stats    │               │ │
│  │  │   Target    │  │   Target    │  │   Target    │  │   Target    │               │ │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │ │
│  └─────────┼────────────────┼────────────────┼────────────────┼───────────────────────┘ │
│            │                │                │                │                         │
│            ▼                ▼                ▼                ▼                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                           LAMBDA FUNCTIONS                                       │   │
│  │                                                                                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │   │
│  │  │   Parser    │  │  Security   │  │   Context   │  │    Stats    │             │   │
│  │  │   Lambda    │  │   Lambda    │  │   Lambda    │  │   Lambda    │             │   │
│  │  │             │  │             │  │             │  │             │             │   │
│  │  │ • Language  │  │ • PII scan  │  │ • GitHub    │  │ • DynamoDB  │             │   │
│  │  │   detection │  │ • Secret    │  │   Issues    │  │   writes    │             │   │
│  │  │ • Stack     │  │   detection │  │ • Stack     │  │ • Trend     │             │   │
│  │  │   parsing   │  │ • Risk      │  │   Overflow  │  │   analysis  │             │   │
│  │  │ • Error     │  │   assessment│  │   search    │  │             │             │   │
│  │  │   type      │  │             │  │             │  │             │             │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │   │
│  │         │                │                │                │                     │   │
│  └─────────┼────────────────┼────────────────┼────────────────┼─────────────────────┘   │
│            │                │                │                │                         │
│            ▼                ▼                ▼                ▼                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                           EXTERNAL SERVICES                                      │   │
│  │                                                                                  │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐      │   │
│  │  │ Bedrock   │  │Comprehend │  │  GitHub   │  │  Stack    │  │ DynamoDB  │      │   │
│  │  │ Claude    │  │           │  │   API     │  │ Overflow  │  │           │      │   │
│  │  │           │  │ • Language│  │           │  │   API     │  │ • Error   │      │   │
│  │  │ • LLM     │  │   detect  │  │ • Issues  │  │           │  │   stats   │      │   │
│  │  │   reasoning│ │ • PII     │  │ • Files   │  │ • Search  │  │ • Trends  │      │   │
│  │  │ • Root    │  │   detect  │  │           │  │ • Answers │  │           │      │   │
│  │  │   cause   │  │           │  │           │  │           │  │           │      │   │
│  │  │ • Fix gen │  │           │  │           │  │           │  │           │      │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘      │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │                          MEMORY (Part 2 Only)                                    │   │
│  │                                                                                  │   │
│  │  ┌──────────────────────┐  ┌──────────────────────┐                             │   │
│  │  │   Semantic Memory    │  │   Session Memory     │                             │   │
│  │  │                      │  │                      │                             │   │
│  │  │  • Long-term pattern │  │  • Short-term        │                             │   │
│  │  │    storage           │  │    context           │                             │   │
│  │  │  • Vector similarity │  │  • Per-request state │                             │   │
│  │  │    search            │  │                      │                             │   │
│  │  │  • KMS encrypted     │  │                      │                             │   │
│  │  └──────────────────────┘  └──────────────────────┘                             │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Request Flow

```
1. User → Frontend           User submits error text via web UI
       │
2.     → API Proxy           Lambda Function URL handles CORS, proxies to AgentCore
       │
3.     → Runtime             AgentCore Runtime executes Supervisor agent
       │
4.     → Supervisor Loop     THINK → ACT → OBSERVE → REFLECT → DECIDE
       │    │
       │    ├─→ Gateway      Tool calls routed via MCP protocol
       │    │    │
       │    │    └─→ Lambdas Parser/Security/Context/Stats execute
       │    │
       │    ├─→ Memory       Search/store patterns (Part 2)
       │    │
       │    └─→ Bedrock      LLM reasoning for root cause & fix
       │
5.     ← Structured Result   Final JSON with all agent outputs
       │
6. User ← Frontend           Results displayed in categorized sections
```

---

## Component Purposes

### Frontend (CloudFront + S3)
Static web application that provides the user interface for submitting errors and viewing analysis results. CloudFront ensures global low-latency delivery while S3 provides durable, cost-effective static hosting. Feature flags enable Part 1/Part 2 UI variations without code changes.

### API Proxy (Lambda Function URL)
Bridge between browser and AgentCore that solves two critical problems: CORS (AWS service APIs don't support browser cross-origin requests) and timeout (browsers timeout at 30 seconds, but analysis can take 2+ minutes). The Lambda streams AgentCore responses and extracts structured data for the frontend.

### AgentCore Runtime
Managed container execution environment that runs the Supervisor agent. Handles infrastructure concerns (scaling, networking, IAM) so developers focus on agent logic. The Strands SDK within the container implements the agent's iterative reasoning loop.

### Supervisor Agent
Orchestrator that coordinates all specialist agents using an iterative reasoning pattern. Rather than a fixed pipeline, it thinks, acts, observes, reflects, and decides whether to continue gathering information or produce output—similar to how a senior developer debugs: gather context, form hypothesis, validate, refine.

### AgentCore Gateway
MCP (Model Context Protocol) endpoint that exposes Lambda functions as tools the Supervisor can call. Abstracts the invocation mechanism—agents call tools by name without knowing they're Lambda functions. Handles authentication, routing, and protocol translation.

### Parser Lambda
Extracts structured information from raw error text: programming language, stack frames, file paths, line numbers, and error type. Uses regex patterns and AWS Comprehend for language detection. Outputs the foundation other agents build upon.

### Security Lambda
Scans error text for sensitive data (API keys, passwords, PII) before any storage or external API calls. Uses pattern matching and AWS Comprehend's PII detection. Returns risk assessment and recommendations, enabling safe handling of production errors.

### Context Lambda (Part 2)
Searches external knowledge sources (GitHub Issues, Stack Overflow) for similar errors and solutions. Transforms a user's isolated error into a research query, finding community solutions and related discussions that inform the root cause analysis.

### Stats Lambda (Part 2)
Tracks error occurrences in DynamoDB to identify patterns over time. Enables trend analysis ("this error is increasing") and frequency tracking, helping teams prioritize fixes for recurring issues.

### Root Cause Agent
LLM-powered reasoning engine that synthesizes all gathered context (parsed info, security assessment, external research, memory matches) to determine *why* the error occurred. Uses Claude's reasoning capabilities rather than pattern matching—can explain novel errors it hasn't seen before.

### Fix Agent
Generates concrete, actionable code fixes based on the identified root cause. Produces before/after code snippets, explanations, and prevention tips. The fix must address the specific root cause identified—not generic boilerplate.

### AgentCore Memory (Part 2)
Persistent storage for error patterns and solutions. Semantic memory uses vector embeddings to find similar past errors (even with different wording). When a user encounters an error similar to one solved before, the system can provide instant solutions without re-analysis.

### Bedrock Claude
Foundation model providing the reasoning intelligence. Used by Root Cause Agent for analysis, Fix Agent for code generation, and the Supervisor for orchestration decisions. The "brain" that transforms structured data into insights.

### AWS Comprehend
NLP service used for language detection (is this Python or JavaScript?) and PII detection (does this contain email addresses?). Offloads specialized ML tasks from the main LLM, reducing cost and latency for well-defined classification tasks.

### DynamoDB
NoSQL database storing error statistics for trend analysis. Schema-less design accommodates varying error types without migrations. Provides millisecond response times for the Stats Lambda.

---

## Feature Parts

| Component | Part 1 | Part 2 |
|-----------|--------|--------|
| Frontend | ✅ Core UI | ✅ + Memory panel, GitHub integration |
| API Proxy | ✅ | ✅ |
| Runtime | ✅ | ✅ |
| Supervisor | ✅ 4 tools | ✅ 9 tools |
| Gateway | ✅ 2 targets | ✅ 4 targets |
| Parser Lambda | ✅ | ✅ |
| Security Lambda | ✅ | ✅ |
| Context Lambda | ❌ | ✅ |
| Stats Lambda | ❌ | ✅ |
| Root Cause Agent | ✅ | ✅ |
| Fix Agent | ✅ | ✅ |
| Memory | ❌ | ✅ |
| DynamoDB | ❌ | ✅ |

---

## Key Design Decisions

### Why Lambda Proxy Instead of Direct AgentCore Access?
AWS service APIs don't include CORS headers required for browser requests. A Lambda proxy adds the headers and handles the browser-to-AWS translation. Lambda Function URLs (not API Gateway) are used because they support 15-minute timeouts vs API Gateway's 30-second limit.

### Why MCP Gateway Instead of Direct Lambda Invocation?
The MCP protocol provides a standardized tool interface. Agents call `parser_agent_tool(error_text="...")` without knowing it's a Lambda. This abstraction enables: consistent error handling, automatic retries, centralized authentication, and the ability to swap implementations (Lambda → container → external API) without changing agent code.

### Why Separate Lambda Tools vs All-in-Runtime?
Lambdas provide isolation, independent scaling, and cost efficiency (pay-per-invocation). Parser and Security can run in parallel, while compute-heavy LLM work happens in the Runtime. This hybrid approach optimizes both latency and cost.

### Why Iterative Supervisor vs Fixed Pipeline?
Real debugging is exploratory. A fixed pipeline (parse → analyze → fix) fails when initial assumptions are wrong. The iterative approach lets the Supervisor re-gather context when confidence is low, try different search terms when results are poor, and only produce output when truly confident—mimicking expert human behavior.

