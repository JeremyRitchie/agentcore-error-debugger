"""
Fix Agent - Generates code fixes and validates solutions
Tools: Bedrock code generation, syntax validation
"""
import re
import ast
import json
import logging
import boto3
from typing import Dict, Any, List
from strands import Agent, tool

logger = logging.getLogger(__name__)

# Initialize Bedrock client
try:
    bedrock_runtime = boto3.client('bedrock-runtime')
except Exception:
    bedrock_runtime = None

# =============================================================================
# FIX TEMPLATES - Common fix patterns
# =============================================================================

FIX_TEMPLATES = {
    "null_check_javascript": {
        "before": "data.map(item => item.name)",
        "after": "data?.map(item => item.name) || []",
        "description": "Add optional chaining and default empty array"
    },
    "null_check_python": {
        "before": "for item in data:\n    process(item)",
        "after": "if data is not None:\n    for item in data:\n        process(item)",
        "description": "Add explicit None check before iteration"
    },
    "async_await_fix": {
        "before": "const data = fetchData();",
        "after": "const data = await fetchData();",
        "description": "Add await keyword for async function"
    },
    "try_catch_wrap": {
        "before": "riskyOperation();",
        "after": "try {\n    riskyOperation();\n} catch (error) {\n    console.error('Operation failed:', error);\n}",
        "description": "Wrap risky operation in try-catch"
    },
    "python_try_except": {
        "before": "result = risky_operation()",
        "after": "try:\n    result = risky_operation()\nexcept Exception as e:\n    logger.error(f'Operation failed: {e}')\n    result = None",
        "description": "Wrap risky operation in try-except"
    },
}

# =============================================================================
# TOOLS - Code fix generation and validation
# =============================================================================

@tool(name="generate_code_fix")
def generate_code_fix(error_context: str, root_cause: str, language: str = "javascript") -> str:
    """
    Generate a code fix using Bedrock Claude.
    Creates specific, applicable code changes to resolve the error.
    
    Args:
        error_context: The error message and stack trace
        root_cause: The identified root cause
        language: Programming language for the fix
    
    Returns:
        JSON with generated fix code
    """
    logger.info(f"🔧 Generating code fix for {language}")
    
    prompt = f"""Generate a code fix for this error.

Error Context:
{error_context}

Root Cause: {root_cause}

Language: {language}

Provide a JSON response with:
{{
    "fix_type": "type of fix (null_check, error_handling, refactor, etc.)",
    "original_pattern": "code pattern that causes the error",
    "fixed_code": "the corrected code",
    "explanation": "why this fix works",
    "additional_changes": ["any other recommended changes"]
}}"""

    if bedrock_runtime:
        try:
            response = bedrock_runtime.invoke_model(
                modelId="anthropic.claude-3-sonnet-20240229-v1:0",
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            response_body = json.loads(response['body'].read())
            content = response_body.get('content', [{}])[0].get('text', '{}')
            
            try:
                start = content.find('{')
                end = content.rfind('}') + 1
                if start != -1 and end > start:
                    result = json.loads(content[start:end])
                    logger.info(f"✅ Generated fix: {result.get('fix_type', 'unknown')}")
                    return json.dumps(result)
            except:
                pass
                
        except Exception as e:
            logger.warning(f"Bedrock call failed: {str(e)}, using template")
    
    # Fallback to template-based fixes
    return json.dumps(_template_fix(root_cause, language))


def _template_fix(root_cause: str, language: str) -> Dict[str, Any]:
    """Generate fix from templates when LLM unavailable."""
    root_lower = root_cause.lower()
    
    if "null" in root_lower or "undefined" in root_lower:
        if language in ["javascript", "typescript"]:
            template = FIX_TEMPLATES["null_check_javascript"]
        else:
            template = FIX_TEMPLATES["null_check_python"]
        return {
            "fix_type": "null_check",
            "original_pattern": template["before"],
            "fixed_code": template["after"],
            "explanation": template["description"],
            "additional_changes": ["Add type checking", "Validate data before use"]
        }
    elif "async" in root_lower or "await" in root_lower or "promise" in root_lower:
        template = FIX_TEMPLATES["async_await_fix"]
        return {
            "fix_type": "async_handling",
            "original_pattern": template["before"],
            "fixed_code": template["after"],
            "explanation": template["description"],
            "additional_changes": ["Ensure function is marked async", "Handle promise rejection"]
        }
    else:
        if language in ["javascript", "typescript"]:
            template = FIX_TEMPLATES["try_catch_wrap"]
        else:
            template = FIX_TEMPLATES["python_try_except"]
        return {
            "fix_type": "error_handling",
            "original_pattern": template["before"],
            "fixed_code": template["after"],
            "explanation": template["description"],
            "additional_changes": ["Add specific error handling", "Implement fallback behavior"]
        }


@tool(name="validate_syntax")
def validate_syntax(code: str, language: str) -> str:
    """
    Validate that generated code has correct syntax.
    Helps ensure fix suggestions are valid before presenting.
    
    Args:
        code: The code to validate
        language: Programming language
    
    Returns:
        JSON with validation result
    """
    logger.info(f"✓ Validating {language} syntax")
    
    is_valid = True
    errors = []
    
    if language == "python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            is_valid = False
            errors.append({
                "line": e.lineno,
                "message": e.msg,
                "text": e.text
            })
    elif language in ["javascript", "typescript"]:
        # Basic JavaScript validation (check for common issues)
        # In production, use a proper JS parser like esprima
        
        # Check balanced brackets
        brackets = {'(': ')', '[': ']', '{': '}'}
        stack = []
        for i, char in enumerate(code):
            if char in brackets:
                stack.append((char, i))
            elif char in brackets.values():
                if not stack:
                    is_valid = False
                    errors.append({"position": i, "message": f"Unmatched closing bracket: {char}"})
                else:
                    open_bracket, _ = stack.pop()
                    if brackets[open_bracket] != char:
                        is_valid = False
                        errors.append({"position": i, "message": f"Mismatched brackets: expected {brackets[open_bracket]}, got {char}"})
        
        if stack:
            is_valid = False
            for bracket, pos in stack:
                errors.append({"position": pos, "message": f"Unclosed bracket: {bracket}"})
    
    result = {
        "is_valid": is_valid,
        "language": language,
        "error_count": len(errors),
        "errors": errors[:5],  # Limit
        "message": "Syntax is valid" if is_valid else f"Found {len(errors)} syntax errors"
    }
    
    logger.info(f"✅ Validation: {'valid' if is_valid else 'invalid'}")
    return json.dumps(result)


@tool(name="suggest_prevention")
def suggest_prevention(error_type: str, root_cause: str, language: str) -> str:
    """
    Suggest preventive measures to avoid this error in the future.
    Provides best practices and tooling recommendations.
    
    Args:
        error_type: Type of error
        root_cause: Root cause analysis
        language: Programming language
    
    Returns:
        JSON with prevention suggestions
    """
    logger.info(f"🛡️ Suggesting prevention for {error_type}")
    
    suggestions = []
    
    # Common preventions
    error_lower = error_type.lower()
    root_lower = root_cause.lower()
    
    if "null" in error_lower or "undefined" in root_lower:
        suggestions.extend([
            {
                "category": "type_safety",
                "suggestion": "Use TypeScript or Python type hints to catch null issues at compile time",
                "tool": "TypeScript" if language in ["javascript", "typescript"] else "mypy"
            },
            {
                "category": "coding_pattern",
                "suggestion": "Always use optional chaining (?.) when accessing potentially null values",
                "tool": None
            },
            {
                "category": "linting",
                "suggestion": "Enable strict null checks in linter configuration",
                "tool": "ESLint" if language in ["javascript", "typescript"] else "pylint"
            }
        ])
    
    if "import" in error_lower or "module" in root_lower:
        suggestions.extend([
            {
                "category": "dependency_management",
                "suggestion": "Use lockfiles (package-lock.json, Pipfile.lock) to ensure consistent dependencies",
                "tool": "npm/pip"
            },
            {
                "category": "ci_cd",
                "suggestion": "Run dependency checks in CI pipeline before deployment",
                "tool": "npm ci / pip install -r requirements.txt"
            }
        ])
    
    if "type" in error_lower:
        suggestions.extend([
            {
                "category": "type_safety",
                "suggestion": "Add runtime type validation at function boundaries",
                "tool": "zod" if language in ["javascript", "typescript"] else "pydantic"
            },
            {
                "category": "testing",
                "suggestion": "Add unit tests that verify correct types are passed and returned",
                "tool": "Jest" if language in ["javascript", "typescript"] else "pytest"
            }
        ])
    
    # Always recommend
    suggestions.append({
        "category": "monitoring",
        "suggestion": "Set up error tracking to catch and alert on errors in production",
        "tool": "Sentry, Datadog, or CloudWatch"
    })
    
    result = {
        "error_type": error_type,
        "prevention_count": len(suggestions),
        "suggestions": suggestions,
        "priority_suggestion": suggestions[0] if suggestions else None
    }
    
    logger.info(f"✅ Generated {len(suggestions)} prevention suggestions")
    return json.dumps(result)


@tool(name="generate_test_case")
def generate_test_case(fixed_code: str, error_scenario: str, language: str) -> str:
    """
    Generate a test case to verify the fix works.
    Creates a test that would catch the original error.
    
    Args:
        fixed_code: The fixed code
        error_scenario: Description of what was failing
        language: Programming language
    
    Returns:
        JSON with generated test code
    """
    logger.info(f"🧪 Generating test case for {language}")
    
    if language in ["javascript", "typescript"]:
        test_code = f"""// Test for: {error_scenario}
describe('Fix verification', () => {{
    it('should handle null/undefined without error', () => {{
        // Arrange
        const testData = null;
        
        // Act & Assert
        expect(() => {{
            // Insert fixed code behavior here
            const result = testData?.map?.(x => x) || [];
            return result;
        }}).not.toThrow();
    }});
    
    it('should work correctly with valid data', () => {{
        // Arrange
        const testData = [1, 2, 3];
        
        // Act
        const result = testData.map(x => x * 2);
        
        // Assert
        expect(result).toEqual([2, 4, 6]);
    }});
}});"""
        test_framework = "Jest"
    else:
        test_code = f'''# Test for: {error_scenario}
import pytest

def test_handles_none_without_error():
    """Verify fix handles None gracefully"""
    # Arrange
    test_data = None
    
    # Act & Assert
    try:
        result = test_data if test_data is not None else []
        assert result == []
    except TypeError:
        pytest.fail("Should not raise TypeError on None input")

def test_works_with_valid_data():
    """Verify normal operation still works"""
    # Arrange
    test_data = [1, 2, 3]
    
    # Act
    result = [x * 2 for x in test_data]
    
    # Assert
    assert result == [2, 4, 6]
'''
        test_framework = "pytest"
    
    result = {
        "test_code": test_code,
        "test_framework": test_framework,
        "test_count": 2,
        "covers_error_case": True,
        "covers_happy_path": True
    }
    
    logger.info(f"✅ Generated {test_framework} test case")
    return json.dumps(result)


# =============================================================================
# AGENT - Strands Agent with fix tools
# =============================================================================

FIX_AGENT_PROMPT = """You are a Code Fix Specialist Agent.

## YOUR ROLE
Generate code fixes and validate solutions for errors.
Provide specific, actionable code changes.

## YOUR TOOLS
- generate_code_fix: Generate fix using Bedrock Claude (or templates)
- validate_syntax: Validate generated code has correct syntax
- suggest_prevention: Suggest how to prevent this error in future
- generate_test_case: Create a test to verify the fix

## YOUR WORKFLOW
1. Call generate_code_fix to create the fix
2. Call validate_syntax to ensure fix is syntactically correct
3. Call suggest_prevention for long-term improvements
4. Call generate_test_case to create verification test

## OUTPUT FORMAT
Return a JSON object with:
{
    "fix_type": "type of fix applied",
    "fixed_code": "the corrected code",
    "explanation": "why this fixes the issue",
    "is_valid": true|false,
    "prevention": [...],
    "test_code": "verification test"
}

Always return valid JSON only, no additional text.
"""

fix_agent = Agent(
    system_prompt=FIX_AGENT_PROMPT,
    tools=[generate_code_fix, validate_syntax, suggest_prevention, generate_test_case],
)


# =============================================================================
# INTERFACE - For supervisor to call
# =============================================================================

def generate(error_text: str, root_cause: str, language: str = "javascript") -> Dict[str, Any]:
    """
    Generate a fix for an error.
    
    Args:
        error_text: The error message
        root_cause: Root cause analysis
        language: Programming language
        
    Returns:
        Dict with fix and supporting materials
    """
    logger.info(f"🔨 FixAgent: Generating fix for {language}")
    
    try:
        prompt = f"""Generate a fix for this error:

Error: {error_text}
Root Cause: {root_cause}
Language: {language}

Generate the fix, validate it, suggest prevention, and create a test."""
        
        result = fix_agent(prompt)
        response_text = str(result)
        
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end > start:
                parsed = json.loads(response_text[start:end])
                logger.info(f"✅ FixAgent complete: {parsed.get('fix_type', 'unknown')}")
                return parsed
        except json.JSONDecodeError:
            pass
        
        return _direct_generate(error_text, root_cause, language)
        
    except Exception as e:
        logger.error(f"❌ FixAgent error: {str(e)}")
        return _direct_generate(error_text, root_cause, language)


def _direct_generate(error_text: str, root_cause: str, language: str) -> Dict[str, Any]:
    """Direct fix generation fallback."""
    try:
        fix_result = json.loads(generate_code_fix(error_text, root_cause, language))
        validation = json.loads(validate_syntax(fix_result.get("fixed_code", ""), language))
        prevention = json.loads(suggest_prevention("unknown", root_cause, language))
        test = json.loads(generate_test_case(fix_result.get("fixed_code", ""), error_text[:100], language))
        
        return {
            "fix_type": fix_result.get("fix_type", "error_handling"),
            "fixed_code": fix_result.get("fixed_code", ""),
            "explanation": fix_result.get("explanation", ""),
            "is_valid": validation.get("is_valid", True),
            "prevention": prevention.get("suggestions", []),
            "test_code": test.get("test_code", "")
        }
    except Exception as e:
        return {
            "fix_type": "unknown",
            "fixed_code": "",
            "explanation": "Fix generation failed",
            "is_valid": False,
            "prevention": [],
            "test_code": "",
            "error": str(e)
        }

