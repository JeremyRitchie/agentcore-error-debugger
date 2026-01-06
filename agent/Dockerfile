# ============================================================================
# Error Debugger - AgentCore Runtime Container
# Multi-agent system using Strands framework with diverse tools
# ============================================================================

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app

# Configure UV for container environment
ENV UV_SYSTEM_PYTHON=1 UV_COMPILE_BYTECODE=1

# Install dependencies
COPY requirements.txt requirements.txt
RUN uv pip install -r requirements.txt

# AWS configuration
ENV AWS_REGION=us-east-1
ENV AWS_DEFAULT_REGION=us-east-1

# AgentCore runtime configuration
ENV DOCKER_CONTAINER=1

# Create non-root user for security
RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

# Expose AgentCore runtime ports
EXPOSE 8080
EXPOSE 8000

# Copy agent code
COPY . .

# Run the supervisor agent via AgentCore runtime
CMD ["opentelemetry-instrument", "python", "-m", "supervisor"]

