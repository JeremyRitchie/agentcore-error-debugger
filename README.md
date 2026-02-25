# Error Debugger — AWS AgentCore Multi-Agent System

Paste in a stack trace, get back the root cause and a working fix. A Supervisor agent orchestrates specialist agents, each doing one job well.

Built for a two-part blog series:
- [Part 1: Building a Multi-Agent Error Debugger](https://jeremyritchie.com/posts/20) — Parser, Security, Root Cause, Fix
- [Part 2: Memory, Context, and Integrations](https://jeremyritchie.com/posts/21) — AgentCore Memory, GitHub/SO context, stats tracking

## Architecture

```
Frontend (S3 + CloudFront)
    │
    ▼ HTTPS
Lambda Function URL (proxy, handles CORS + timeouts)
    │
    ▼ Invoke
AgentCore Runtime (Docker)
    │
    ├── Supervisor Agent (orchestrates everything)
    │     │
    │     ├── Parser ────── Lambda via Gateway (regex + Comprehend)
    │     ├── Security ──── Lambda via Gateway (PII + secret scanning)
    │     ├── Root Cause ── Bedrock Claude (in-process)
    │     ├── Fix ───────── Bedrock Claude (in-process)
    │     ├── Memory* ───── AgentCore Memory API (in-process)
    │     ├── Context* ──── GitHub + Stack Overflow APIs (in-process)
    │     └── Stats* ────── DynamoDB (in-process)
    │
    * Part 2 only
```

Deterministic work (parsing, secret scanning) runs in Lambda — cheap and fast. LLM reasoning (root cause, fixes) runs in the Runtime. Cost stays low and the expensive stuff only runs when it needs to.

## Feature Flags

Deploy Part 1 or Part 2 with a single parameter:

```bash
# Part 1: core agents only
gh workflow run deploy.yml -f action=deploy -f feature_part=1

# Part 2: adds memory, context, stats, GitHub integration
gh workflow run deploy.yml -f action=deploy -f feature_part=2
```

Terraform conditionally deploys Memory, DynamoDB and extra Lambdas based on the flag. Set it to 1 and there's zero extra cost.

## Project Structure

```
agent/                      # AgentCore Runtime (Docker)
├── supervisor.py           # Supervisor agent
├── agents/
│   ├── parser_agent.py     # Calls Parser Lambda via Gateway
│   ├── security_agent.py   # Calls Security Lambda via Gateway
│   ├── rootcause_agent.py  # Bedrock Claude
│   ├── fix_agent.py        # Bedrock Claude
│   ├── memory_agent.py     # AgentCore Memory (Part 2)
│   ├── context_agent.py    # GitHub/SO APIs (Part 2)
│   └── stats_agent.py      # DynamoDB stats (Part 2)
├── Dockerfile
└── requirements.txt

app/                        # Frontend (S3 + CloudFront)
├── index.html
├── styles.css
└── app.js

terraform/agentcore/        # Infrastructure
├── gateway.tf              # AgentCore Gateway + MCP targets
├── runtime.tf              # AgentCore Runtime
├── memory.tf               # AgentCore Memory + KMS (Part 2)
├── tool_lambdas.tf         # Parser + Security + Context + Stats Lambdas
├── frontend.tf             # S3, CloudFront, ACM, Route53
└── api_proxy.tf            # Lambda Function URL proxy
```

## Deployment

### 1. Bootstrap (one-time)

Run the Bootstrap workflow to create the S3 state bucket, DynamoDB lock table and ECR repository.

### 2. Deploy

Push to `main` or trigger the Deploy workflow manually. Builds the container, runs Terraform, deploys everything.

### Required GitHub Variables

| Variable | Description |
|----------|-------------|
| `AWS_ROLE_ARN` | IAM role for OIDC authentication |
| `PROJECT_NAME` | Project name prefix (default: `error-debugger`) |
| `AWS_REGION` | AWS region (default: `us-east-1`) |

## Demo Mode

For local dev without AWS credentials, set `DEMO_MODE=true`. Uses simulated responses and in-memory storage. Live mode (`DEMO_MODE=false`, the default when deployed) uses real Comprehend, Bedrock, Memory and DynamoDB.

## Sample Errors

```javascript
// TypeError
TypeError: Cannot read properties of undefined (reading 'map')
    at UserList (src/components/UserList.tsx:15:23)
```

```python
# ImportError
ImportError: No module named 'pandas'
    at File "/app/analysis.py", line 3
```

```
# Connection error
Error: connect ECONNREFUSED 127.0.0.1:5432
    at TCPConnectWrap.afterConnect
```
