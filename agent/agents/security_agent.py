"""
Security Agent - Detects and redacts sensitive information in errors
Tools: PII detection (Comprehend), secret scanning (regex), redaction
"""
import re
import json
import logging
import boto3
from typing import Dict, Any, List
from strands import Agent, tool

logger = logging.getLogger(__name__)

# Initialize AWS client
try:
    comprehend_client = boto3.client('comprehend')
except Exception:
    comprehend_client = None

# =============================================================================
# SECRET PATTERNS - For detecting hardcoded secrets
# =============================================================================

SECRET_PATTERNS = {
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'(?i)(aws_secret_access_key|secret_key)\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    "github_token": r'ghp_[A-Za-z0-9]{36}',
    "github_oauth": r'gho_[A-Za-z0-9]{36}',
    "slack_token": r'xox[baprs]-[0-9A-Za-z-]{10,}',
    "stripe_key": r'sk_(live|test)_[0-9a-zA-Z]{24,}',
    "openai_key": r'sk-[A-Za-z0-9]{48}',
    "jwt_token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "password_in_url": r'(?i)://[^:]+:([^@]+)@',
    "generic_api_key": r'(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*[\'"]?([A-Za-z0-9_-]{20,})[\'"]?',
    "bearer_token": r'(?i)bearer\s+[A-Za-z0-9_-]{20,}',
    "private_key": r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "connection_string": r'(?i)(mongodb|postgres|mysql|redis)://[^@]+:[^@]+@',
    "env_var_secret": r'(?i)(password|secret|token|key)\s*=\s*[\'"]?[^\s\'"\n]{8,}',
}

# =============================================================================
# TOOLS - Security scanning and PII detection
# =============================================================================

@tool(name="detect_pii")
def detect_pii(text: str) -> str:
    """
    Detect Personally Identifiable Information (PII) using AWS Comprehend.
    Identifies: EMAIL, PHONE, NAME, ADDRESS, SSN, CREDIT_CARD, etc.
    
    Args:
        text: Text to scan for PII
    
    Returns:
        JSON with detected PII entities
    """
    logger.info(f"🔒 Scanning for PII in {len(text)} chars")
    
    if not comprehend_client:
        logger.warning("Comprehend client not available, using regex fallback")
        return _detect_pii_regex(text)
    
    try:
        # Truncate to Comprehend limit
        truncated = text[:5000] if len(text) > 5000 else text
        
        response = comprehend_client.detect_pii_entities(
            Text=truncated,
            LanguageCode='en'
        )
        
        entities = []
        for entity in response.get('Entities', []):
            if entity['Score'] > 0.7:
                entities.append({
                    "type": entity['Type'],
                    "score": round(entity['Score'] * 100, 1),
                    "begin": entity['BeginOffset'],
                    "end": entity['EndOffset'],
                    "text": text[entity['BeginOffset']:entity['EndOffset']][:20] + "..."
                })
        
        result = {
            "pii_found": len(entities) > 0,
            "pii_count": len(entities),
            "entities": entities[:10],  # Limit
            "risk_level": "high" if len(entities) > 3 else "medium" if len(entities) > 0 else "low"
        }
        
        logger.info(f"✅ Found {len(entities)} PII entities")
        return json.dumps(result)
        
    except Exception as e:
        logger.error(f"❌ PII detection error: {str(e)}")
        return _detect_pii_regex(text)


def _detect_pii_regex(text: str) -> str:
    """Fallback PII detection using regex."""
    pii_patterns = {
        "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "PHONE": r'\b(\+?1?[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
        "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        "CREDIT_CARD": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    }
    
    entities = []
    for pii_type, pattern in pii_patterns.items():
        for match in re.finditer(pattern, text):
            entities.append({
                "type": pii_type,
                "score": 80.0,
                "text": match.group(0)[:20] + "..."
            })
    
    return json.dumps({
        "pii_found": len(entities) > 0,
        "pii_count": len(entities),
        "entities": entities[:10],
        "risk_level": "high" if len(entities) > 3 else "medium" if len(entities) > 0 else "low",
        "source": "regex_fallback"
    })


@tool(name="detect_secrets")
def detect_secrets(text: str) -> str:
    """
    Scan for hardcoded secrets, API keys, tokens, and passwords.
    Uses curated regex patterns for common secret formats.
    
    Args:
        text: Text to scan for secrets
    
    Returns:
        JSON with detected secrets (values are redacted)
    """
    logger.info(f"🔑 Scanning for secrets in {len(text)} chars")
    
    findings = []
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            secret_value = match.group(0)
            # Redact the actual secret value
            redacted = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:] if len(secret_value) > 8 else "***"
            
            findings.append({
                "type": secret_type,
                "redacted_value": redacted,
                "position": match.start(),
                "severity": "critical" if secret_type in ["aws_access_key", "private_key", "jwt_token"] else "high"
            })
    
    result = {
        "secrets_found": len(findings) > 0,
        "secret_count": len(findings),
        "findings": findings[:10],  # Limit
        "severity": "critical" if any(f["severity"] == "critical" for f in findings) else "high" if findings else "none"
    }
    
    logger.info(f"✅ Found {len(findings)} potential secrets")
    return json.dumps(result)


@tool(name="redact_sensitive_data")
def redact_sensitive_data(text: str) -> str:
    """
    Redact all detected sensitive information from text.
    Useful for storing errors safely in logs or memory.
    
    Args:
        text: Text with potential sensitive data
    
    Returns:
        JSON with redacted text and summary
    """
    logger.info(f"🔐 Redacting sensitive data from {len(text)} chars")
    
    redacted_text = text
    redaction_count = 0
    
    # Redact secrets
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, redacted_text):
            replacement = f"[REDACTED_{secret_type.upper()}]"
            redacted_text = redacted_text[:match.start()] + replacement + redacted_text[match.end():]
            redaction_count += 1
    
    # Redact common PII patterns
    pii_patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "[REDACTED_EMAIL]"),
        (r'\b\d{3}-\d{2}-\d{4}\b', "[REDACTED_SSN]"),
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', "[REDACTED_CARD]"),
    ]
    
    for pattern, replacement in pii_patterns:
        matches = list(re.finditer(pattern, redacted_text))
        for match in reversed(matches):  # Reverse to maintain positions
            redacted_text = redacted_text[:match.start()] + replacement + redacted_text[match.end():]
            redaction_count += 1
    
    result = {
        "original_length": len(text),
        "redacted_length": len(redacted_text),
        "redaction_count": redaction_count,
        "redacted_text": redacted_text,
        "is_safe": redaction_count == 0
    }
    
    logger.info(f"✅ Applied {redaction_count} redactions")
    return json.dumps(result)


@tool(name="assess_security_risk")
def assess_security_risk(text: str) -> str:
    """
    Provide an overall security risk assessment for the error content.
    Combines PII, secrets, and other risk factors.
    
    Args:
        text: Error text to assess
    
    Returns:
        JSON with risk assessment
    """
    logger.info("🛡️ Assessing security risk")
    
    # Check for secrets
    secret_result = json.loads(detect_secrets(text))
    
    # Check for file path exposure
    path_exposure = bool(re.search(r'/home/\w+|/Users/\w+|C:\\Users\\\w+', text))
    
    # Check for environment variable exposure
    env_exposure = bool(re.search(r'(?i)(DATABASE_URL|API_KEY|SECRET|PASSWORD|TOKEN)\s*=', text))
    
    # Check for internal IP exposure
    internal_ip = bool(re.search(r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b', text))
    
    risk_factors = []
    if secret_result["secrets_found"]:
        risk_factors.append("hardcoded_secrets")
    if path_exposure:
        risk_factors.append("user_path_exposure")
    if env_exposure:
        risk_factors.append("env_var_exposure")
    if internal_ip:
        risk_factors.append("internal_ip_exposure")
    
    # Calculate overall risk
    if "hardcoded_secrets" in risk_factors:
        overall_risk = "critical"
    elif len(risk_factors) >= 2:
        overall_risk = "high"
    elif len(risk_factors) == 1:
        overall_risk = "medium"
    else:
        overall_risk = "low"
    
    result = {
        "overall_risk": overall_risk,
        "risk_factors": risk_factors,
        "recommendations": _get_security_recommendations(risk_factors),
        "safe_to_store": overall_risk in ["low", "medium"],
        "requires_redaction": overall_risk in ["critical", "high"]
    }
    
    logger.info(f"✅ Risk assessment: {overall_risk}")
    return json.dumps(result)


def _get_security_recommendations(risk_factors: List[str]) -> List[str]:
    """Generate security recommendations based on risk factors."""
    recommendations = []
    
    if "hardcoded_secrets" in risk_factors:
        recommendations.append("Remove hardcoded secrets and use environment variables or secret managers")
    if "user_path_exposure" in risk_factors:
        recommendations.append("Sanitize file paths before logging or displaying errors")
    if "env_var_exposure" in risk_factors:
        recommendations.append("Never log environment variables containing secrets")
    if "internal_ip_exposure" in risk_factors:
        recommendations.append("Avoid exposing internal IP addresses in error messages")
    
    if not recommendations:
        recommendations.append("No immediate security concerns detected")
    
    return recommendations


# =============================================================================
# AGENT - Strands Agent with security tools
# =============================================================================

SECURITY_AGENT_PROMPT = """You are a Security Specialist Agent for error analysis.

## YOUR ROLE
Scan error messages for security issues: exposed secrets, PII, sensitive paths.
Provide redacted versions safe for logging and storage.

## YOUR TOOLS
- detect_pii: Find personally identifiable information (AWS Comprehend)
- detect_secrets: Find hardcoded API keys, tokens, passwords (Regex)
- redact_sensitive_data: Create a sanitized version of the error
- assess_security_risk: Overall security risk assessment

## YOUR WORKFLOW
1. Call detect_secrets to find exposed API keys/tokens
2. Call detect_pii to find personal information
3. Call assess_security_risk for overall assessment
4. If risks found, call redact_sensitive_data to create safe version

## OUTPUT FORMAT
Return a JSON object with:
{
    "risk_level": "critical|high|medium|low",
    "secrets_found": N,
    "pii_found": N,
    "risk_factors": ["factor1", "factor2"],
    "recommendations": ["rec1", "rec2"],
    "safe_to_store": true|false,
    "redacted_text": "sanitized error if needed"
}

Always return valid JSON only, no additional text.
"""

security_agent = Agent(
    system_prompt=SECURITY_AGENT_PROMPT,
    tools=[detect_pii, detect_secrets, redact_sensitive_data, assess_security_risk],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def scan(error_text: str) -> Dict[str, Any]:
    """
    Scan an error for security issues using the Security Agent.
    
    Args:
        error_text: Error message to scan
        
    Returns:
        Dict with security assessment
    """
    logger.info(f"🔒 SecurityAgent: Scanning {len(error_text)} chars")
    
    try:
        result = security_agent(f"Scan this error for security issues:\n\n{error_text}")
        response_text = str(result)
        
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ SecurityAgent complete: {parsed.get('risk_level', 'unknown')}")
                return parsed
        except json.JSONDecodeError:
            pass
        
        # Fallback
        return _direct_scan(error_text)
        
    except Exception as e:
        logger.error(f"❌ SecurityAgent error: {str(e)}")
        return _direct_scan(error_text)


def _direct_scan(error_text: str) -> Dict[str, Any]:
    """Direct security scan fallback."""
    try:
        secrets_result = json.loads(detect_secrets(error_text))
        risk_result = json.loads(assess_security_risk(error_text))
        
        return {
            "risk_level": risk_result.get("overall_risk", "unknown"),
            "secrets_found": secrets_result.get("secret_count", 0),
            "pii_found": 0,  # Skip PII in fallback
            "risk_factors": risk_result.get("risk_factors", []),
            "recommendations": risk_result.get("recommendations", []),
            "safe_to_store": risk_result.get("safe_to_store", True)
        }
    except Exception as e:
        return {
            "risk_level": "unknown",
            "secrets_found": 0,
            "pii_found": 0,
            "risk_factors": [],
            "recommendations": [],
            "safe_to_store": True,
            "error": str(e)
        }

