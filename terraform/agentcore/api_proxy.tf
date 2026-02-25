# ===== API Proxy for AgentCore =====
# Required because AWS APIs don't support CORS for browser access
# Browser → Lambda Function URL (CORS) → Lambda → AgentCore Runtime
# Using Lambda Function URL instead of API Gateway for 15 min timeout support

# Lambda function to proxy requests to AgentCore
resource "aws_lambda_function" "api_proxy" {
  function_name = "${local.resource_prefix}-api-proxy"
  role          = aws_iam_role.api_proxy.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 900  # 15 minutes max for long agent operations
  memory_size   = 512  # More memory for processing

  filename         = data.archive_file.api_proxy.output_path
  source_code_hash = data.archive_file.api_proxy.output_base64sha256

  environment {
    variables = {
      AGENT_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn
      AWS_REGION_NAME   = local.region
    }
  }

  tags = {
    Name = "${local.resource_prefix}-api-proxy"
  }

  depends_on = [aws_iam_role_policy_attachment.api_proxy]
}

# Lambda code
data "archive_file" "api_proxy" {
  type        = "zip"
  output_path = "${path.module}/lambda_zips/api_proxy.zip"

  source {
    content = <<-PYTHON
import json
import os
import boto3
import logging
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# For Lambda streaming responses
def stream_response(status_code, headers, body_generator):
    """
    Create a streaming response for Lambda Function URL.
    body_generator should yield strings/bytes.
    """
    import awslambdaric.bootstrap as bootstrap
    
    def response_generator():
        for chunk in body_generator:
            if isinstance(chunk, str):
                yield chunk.encode('utf-8')
            else:
                yield chunk
    
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': response_generator(),
        'isBase64Encoded': False
    }

# Get agent runtime ARN (not the endpoint ARN)
# ARN format: arn:aws:bedrock-agentcore:region:account:agent-runtime/runtime_id
AGENT_RUNTIME_ARN = os.environ.get('AGENT_RUNTIME_ARN', '')
REGION = os.environ.get('AWS_REGION_NAME', os.environ.get('AWS_REGION', 'us-east-1'))

logger.info(f"Agent Runtime ARN: {AGENT_RUNTIME_ARN}")
logger.info(f"Region: {REGION}")

# Initialize the bedrock-agentcore client
# Docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-agentcore.html
agentcore_client = None
try:
    agentcore_client = boto3.client('bedrock-agentcore', region_name=REGION)
    logger.info("✅ bedrock-agentcore client initialized")
except Exception as e:
    logger.error(f"Failed to init bedrock-agentcore client: {e}")

def handler(event, context):
    """Proxy requests to AgentCore Runtime via invoke_agent_runtime"""
    
    # Response headers (CORS handled by Lambda Function URL, don't duplicate)
    cors_headers = {
        'Content-Type': 'application/json'
    }
    
    try:
        logger.info(f"Received event: {json.dumps(event)[:500]}")
    except Exception as e:
        logger.info(f"Event logging failed: {e}")
    
    # Handle preflight (Lambda Function URL handles this automatically, but just in case)
    http_method = event.get('requestContext', {}).get('http', {}).get('method', '')
    if not http_method:
        # Try alternative path for Function URL
        http_method = event.get('requestContext', {}).get('httpMethod', 'POST')
    
    logger.info(f"HTTP Method: {http_method}")
    
    if http_method == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors_headers, 'body': ''}
    
    if not agentcore_client:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'error': 'AgentCore client not initialized'})
        }
    
    try:
        # Parse request body
        body = event.get('body', '{}')
        if event.get('isBase64Encoded'):
            import base64
            body = base64.b64decode(body).decode('utf-8')
        
        request = json.loads(body) if isinstance(body, str) else body
        error_text = request.get('error_text', request.get('inputText', ''))
        github_repo = request.get('github_repo', '')
        
        # runtimeSessionId requires minimum 33 characters
        # Generate a proper UUID-based session ID
        client_session = request.get('sessionId', '')
        session_id = f"session-{uuid.uuid4().hex}"  # 40 chars total (8 + 32)
        logger.info(f"Client session: {client_session} -> Runtime session: {session_id}")
        
        if not error_text:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({'error': 'Missing error_text'})
            }
        
        logger.info(f"Invoking AgentCore runtime: {AGENT_RUNTIME_ARN}")
        logger.info(f"Session ID: {session_id}")
        
        # Build the input for the agent supervisor
        # The supervisor expects: prompt (the error text), session_id, mode
        input_payload = json.dumps({
            'prompt': error_text,  # Agent expects "prompt" not "error_text"
            'session_id': session_id,
            'mode': 'comprehensive',
            'github_repo': github_repo
        })
        
        # Call invoke_agent_runtime
        logger.info("Calling invoke_agent_runtime...")
        response = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=AGENT_RUNTIME_ARN,
            payload=input_payload.encode('utf-8'),
            runtimeSessionId=session_id,
            contentType='application/json',
            accept='application/json'
        )
        logger.info("✅ invoke_agent_runtime returned")
        
        # Log the full response structure for debugging
        response_keys = list(response.keys()) if response else []
        logger.info(f"AgentCore response keys: {response_keys}")
        
        content_type = response.get('contentType', '')
        logger.info(f"Content-Type: {content_type}")
        
        # The actual data is in response["response"], not "payload" or "responseStream"
        result_chunks = []
        
        if "text/event-stream" in content_type:
            # Collect all events and extract data from each agent
            logger.info("Processing streaming response...")
            response_body = response.get('response')
            
            if response_body:
                event_count = 0
                final_result = None
                final_message = None
                
                # Track data from each agent
                agent_results = {
                    'parser': None,
                    'security': None,
                    'context': None,
                    'rootcause': None,
                    'fix': None,
                    'memory': None,
                    'stats': None
                }
                agent_activity = []
                current_tool = None
                
                try:
                    sample_events = []  # Capture first few events for debugging
                    
                    for line in response_body.iter_lines(chunk_size=1024):
                        if line:
                            line_text = line.decode('utf-8') if isinstance(line, bytes) else line
                            event_count += 1
                            
                            if line_text.startswith('data: '):
                                data = line_text[6:]
                                
                                # Log sample events for debugging (first 10 and last 10)
                                if event_count <= 10 or '_agentcore_final_result' in data:
                                    sample_events.append(data[:500])
                                # Keep a sliding window of last events
                                if len(sample_events) > 25:
                                    # Keep first 10 and last 15
                                    sample_events = sample_events[:10] + sample_events[-15:]
                                
                                try:
                                    parsed = json.loads(data)
                                    
                                    # Handle double-encoding: AgentCore wraps yields as JSON strings
                                    # So json.loads returns a string that needs to be parsed again
                                    if isinstance(parsed, str):
                                        try:
                                            parsed = json.loads(parsed)
                                        except:
                                            continue  # Not parseable, skip
                                    
                                    # Skip if not a dict
                                    if not isinstance(parsed, dict):
                                        continue
                                    
                                    event_str = str(parsed)
                                    
                                    # FIRST: Check for our final result marker (most important)
                                    # The supervisor yields this with "_agentcore_final_result": True
                                    if parsed.get('_agentcore_final_result') == True:
                                        # This is THE final structured result from supervisor
                                        logger.info("🎯 Found final structured result with marker!")
                                        agents_data = parsed.get('agents', {})
                                        if isinstance(agents_data, dict):
                                            agent_results['parser'] = agents_data.get('parser')
                                            agent_results['security'] = agents_data.get('security')
                                            agent_results['context'] = agents_data.get('context')
                                            agent_results['rootcause'] = agents_data.get('rootcause')
                                            agent_results['fix'] = agents_data.get('fix')
                                            agent_results['memory'] = agents_data.get('memory')
                                            agent_results['stats'] = agents_data.get('stats')
                                            logger.info(f"🎯 Extracted agents: {[k for k, v in agent_results.items() if v]}")
                                        if 'summary' in parsed:
                                            agent_results['summary'] = parsed.get('summary')
                                        final_result = parsed
                                        continue  # Don't process further
                                    
                                    # Capture tool calls - remember which tool is being called
                                    # Look for specific tool use patterns (avoid matching user data)
                                    elif 'toolUse' in event_str or 'tool_use' in event_str:
                                        # Extract tool name using regex (safest approach)
                                        import re
                                        match = re.search(r'"name":\s*"([^"]+)"', event_str)
                                        if match:
                                            tool_name = match.group(1)
                                            # Only accept known tool names (filter out user data like "John")
                                            valid_tool_patterns = ['parser', 'security', 'context', 'rootcause', 'fix', 
                                                                   'memory', 'stats', 'github', 'search', 'analyze',
                                                                   'record', 'store', 'evaluate', 'update', 'generate']
                                            tool_lower = tool_name.lower()
                                            is_valid_tool = any(p in tool_lower for p in valid_tool_patterns)
                                            
                                            if tool_name and is_valid_tool:
                                                current_tool = tool_name
                                                agent_activity.append({
                                                    'type': 'tool_call',
                                                    'tool': tool_name,
                                                    'timestamp': event_count
                                                })
                                                logger.info(f"Found tool call: {tool_name}")
                                    
                                    # Capture tool results - extract the actual data
                                    elif 'toolResult' in event_str:
                                        try:
                                            # Use regex to find JSON content in tool result
                                            import re
                                            # Look for the text content in toolResult
                                            text_match = re.search(r'"text":\s*"((?:[^"\\]|\\.)*)"', event_str)
                                            if text_match:
                                                result_text = text_match.group(1)
                                                # Unescape JSON string
                                                result_text = result_text.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                                                
                                                # Try to parse as JSON
                                                try:
                                                    result_data = json.loads(result_text)
                                                    if not isinstance(result_data, dict):
                                                        result_data = {'raw': str(result_data)[:1000]}
                                                except:
                                                    result_data = {'raw': str(result_text)[:1000]}
                                                
                                                # Map to agent based on current_tool
                                                if current_tool and isinstance(result_data, dict):
                                                    tool_lower = current_tool.lower()
                                                    if 'parse' in tool_lower:
                                                        agent_results['parser'] = result_data
                                                    elif 'security' in tool_lower:
                                                        agent_results['security'] = result_data
                                                    elif 'context' in tool_lower or 'research' in tool_lower:
                                                        agent_results['context'] = result_data
                                                    elif 'root' in tool_lower or 'cause' in tool_lower:
                                                        agent_results['rootcause'] = result_data
                                                    elif 'fix' in tool_lower:
                                                        agent_results['fix'] = result_data
                                                    elif 'memory' in tool_lower:
                                                        agent_results['memory'] = result_data
                                                    elif 'stats' in tool_lower:
                                                        agent_results['stats'] = result_data
                                                
                                                agent_activity.append({
                                                    'type': 'tool_result',
                                                    'tool': current_tool,
                                                    'hasData': True
                                                })
                                        except Exception as te:
                                            logger.warning(f"Failed to parse tool result: {te}")
                                    
                                    # Capture final message
                                    elif 'message' in parsed:
                                        msg = parsed.get('message')
                                        if isinstance(msg, dict) and msg.get('role') == 'assistant':
                                            final_message = parsed
                                        
                                except json.JSONDecodeError:
                                    pass
                                except Exception as parse_err:
                                    # Log but continue processing
                                    pass
                    
                    logger.info(f"Processed {event_count} events")
                    captured = [k for k, v in agent_results.items() if v]
                    logger.info(f"Agent results captured: {captured}")
                    logger.info(f"Agent activity count: {len(agent_activity)}")
                    logger.info(f"Sample events (first 5): {sample_events[:5]}")
                    
                    # Log details about what we captured for debugging
                    if not captured:
                        logger.warning("⚠️ No agent results captured! Looking for '_agentcore_final_result' marker...")
                        # Log last 3 sample events to see what we received
                        logger.warning(f"Last sample events: {sample_events[-3:] if sample_events else 'none'}")
                    else:
                        logger.info(f"✅ Successfully captured {len(captured)} agent results")
                    
                    # Build comprehensive response with all agent data
                    response_data = {
                        'success': True,
                        'eventCount': event_count,
                        'agentActivity': agent_activity,
                        'agents': agent_results,  # Data from each agent
                        'summary': agent_results.get('summary', {}),  # Also at top level for easy access
                    }
                    
                    if final_result and isinstance(final_result, dict):
                        # Use a clean result message, not Python repr
                        result_text = final_result.get('result')
                        if not result_text:
                            # Generate a clean summary from the data
                            summary_data = final_result.get('summary', {})
                            if summary_data:
                                root_cause = summary_data.get('rootCause', '')[:100]
                                confidence = summary_data.get('rootCauseConfidence', 0)
                                result_text = f"Analysis complete: {root_cause} ({confidence}% confidence)"
                            else:
                                result_text = f"Analysis complete ({event_count} events processed)"
                        response_data['result'] = result_text
                        response_data['fullResponse'] = final_result
                        # Ensure summary is at top level
                        if 'summary' in final_result:
                            response_data['summary'] = final_result['summary']
                    elif final_message and isinstance(final_message, dict):
                        msg = final_message.get('message')
                        if isinstance(msg, dict):
                            content = msg.get('content', [])
                            if content and isinstance(content, list):
                                text_parts = []
                                for c in content:
                                    if isinstance(c, dict) and 'text' in c:
                                        text_parts.append(c.get('text', ''))
                                response_data['result'] = '\n'.join(text_parts)
                        response_data['fullResponse'] = final_message
                    else:
                        response_data['result'] = f"Analysis complete ({event_count} events)"
                    
                    result_chunks.append(json.dumps(response_data))
                    
                except Exception as stream_err:
                    logger.error(f"Stream error: {stream_err}")
                    result_chunks.append(json.dumps({'success': False, 'error': str(stream_err)}))
            else:
                result_chunks.append('{"success": false, "error": "No response body"}')
        
        elif content_type == "application/json":
            # Handle standard JSON response
            logger.info("Processing JSON response...")
            response_body = response.get('response')
            if response_body:
                try:
                    for chunk in response_body:
                        chunk_text = chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk
                        result_chunks.append(chunk_text)
                        logger.info(f"JSON chunk: {len(chunk_text)} bytes")
                except Exception as json_err:
                    logger.error(f"Error reading JSON response: {json_err}")
        
        else:
            # Fallback - try to read response directly
            logger.info(f"Unknown content type: {content_type}, trying direct read...")
            response_body = response.get('response', response.get('payload'))
            if response_body:
                if hasattr(response_body, 'read'):
                    data = response_body.read()
                    result_chunks.append(data.decode('utf-8') if isinstance(data, bytes) else str(data))
                elif hasattr(response_body, 'iter_lines'):
                    for line in response_body.iter_lines():
                        if line:
                            line_text = line.decode('utf-8') if isinstance(line, bytes) else line
                            if line_text.startswith('data: '):
                                line_text = line_text[6:]
                            result_chunks.append(line_text)
                elif isinstance(response_body, bytes):
                    result_chunks.append(response_body.decode('utf-8'))
                else:
                    result_chunks.append(str(response_body))
        
        result_text = ''.join(result_chunks)
        
        logger.info(f"Total response length: {len(result_text)}")
        logger.info(f"Response (first 1000 chars): {result_text[:1000]}")
        
        # Check for empty response
        if not result_text or result_text.strip() == '':
            logger.warning("Empty response from AgentCore!")
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': 'Empty response from AgentCore runtime',
                    'debug': {
                        'responseKeys': response_keys,
                        'runtimeArn': AGENT_RUNTIME_ARN,
                        'sessionId': session_id,
                        'inputPayloadLength': len(input_payload)
                    }
                })
            }
        
        # The stream often contains multiple JSON objects or text chunks
        # Try to extract the final result - often the last complete JSON object
        result_json = None
        
        # First try parsing the whole thing as JSON
        try:
            result_json = json.loads(result_text)
            logger.info(f"Parsed as single JSON: {list(result_json.keys()) if isinstance(result_json, dict) else 'not a dict'}")
        except json.JSONDecodeError:
            # Try to find JSON objects in the streamed text
            # The agent often yields multiple JSON objects or text lines
            logger.info("Not single JSON, looking for embedded JSON...")
            
            # Split by newlines and look for JSON
            for line in result_text.strip().split('\n'):
                line = line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try:
                        candidate = json.loads(line)
                        # Keep the last/most complete JSON
                        if isinstance(candidate, dict):
                            if 'result' in candidate or 'parsed_info' in candidate or 'root_cause' in candidate:
                                result_json = candidate
                                logger.info(f"Found result JSON: {list(candidate.keys())}")
                    except:
                        pass
            
            if not result_json:
                # Just wrap the raw text
                result_json = {'rawResult': result_text}
        
        # Return the full response for debugging
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'success': True,
                'result': result_json.get('result', result_json) if isinstance(result_json, dict) else result_text,
                'fullResponse': result_json,
                'rawText': result_text[:5000],  # First 5000 chars for debugging
                'chunkCount': len(result_chunks),
                'traces': result_json.get('traces', []) if isinstance(result_json, dict) else [],
                'sessionId': session_id
            })
        }
        
    except agentcore_client.exceptions.ValidationException as ve:
        logger.error(f"Validation error: {ve}")
        return {
            'statusCode': 400,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': f"Validation error: {str(ve)}",
                'runtimeArn': AGENT_RUNTIME_ARN
            })
        }
    except Exception as e:
        logger.error(f"Error invoking AgentCore: {e}", exc_info=True)
        try:
            return {
                'statusCode': 500,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': str(e),
                    'message': 'Failed to invoke AgentCore Runtime',
                    'runtimeArn': AGENT_RUNTIME_ARN
                })
            }
        except Exception as json_err:
            # Last resort - return plain text error
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'text/plain'},
                'body': f'Error: {str(e)}'
            }
PYTHON
    filename = "index.py"
  }
}

# IAM Role for API Proxy Lambda
resource "aws_iam_role" "api_proxy" {
  name = "${local.resource_prefix}-api-proxy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${local.resource_prefix}-api-proxy-role"
  }
}

# IAM Policy for API Proxy
resource "aws_iam_policy" "api_proxy" {
  name = "${local.resource_prefix}-api-proxy-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Sid    = "InvokeAgentCore"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeAgent",
          "bedrock:InvokeAgentWithResponseStream",
          "bedrock-agentcore:InvokeAgentRuntime",
          "bedrock-agentcore:InvokeAgentRuntimeWithResponseStream"
        ]
        Resource = [
          aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn,
          aws_bedrockagentcore_agent_runtime_endpoint.main.agent_runtime_endpoint_arn,
          "${aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_proxy" {
  role       = aws_iam_role.api_proxy.name
  policy_arn = aws_iam_policy.api_proxy.arn
}

# Lambda Function URL - supports up to 15 min timeout
resource "aws_lambda_function_url" "api_proxy" {
  function_name      = aws_lambda_function.api_proxy.function_name
  authorization_type = "NONE"  # Public access
  invoke_mode        = "BUFFERED"  # Collect full response (Python doesn't support streaming easily)

  cors {
    allow_origins     = ["*"]
    allow_methods     = ["POST"]
    allow_headers     = ["content-type", "authorization"]
    allow_credentials = false
    max_age           = 300
  }
}

# Output the Lambda Function URL
output "api_endpoint" {
  value       = trimsuffix(aws_lambda_function_url.api_proxy.function_url, "/")
  description = "Lambda Function URL for AgentCore proxy (15 min timeout)"
}

