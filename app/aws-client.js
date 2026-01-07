/**
 * AWS Client for Error Debugger
 * 
 * Handles:
 * - Getting temporary credentials from Cognito Identity Pool
 * - Calling AgentCore Runtime directly with signed requests
 * 
 * Uses fetch + SigV4 signing (no SDK dependency for smaller bundle)
 */

// AWS SigV4 Signing implementation for browser
class AWSClient {
    constructor(config) {
        this.region = config.region || 'us-east-1';
        this.identityPoolId = config.identityPoolId;
        this.runtimeEndpointArn = config.runtimeEndpointArn;
        this.credentials = null;
        this.credentialsExpiry = null;
    }

    /**
     * Get temporary credentials from Cognito Identity Pool
     */
    async getCredentials() {
        // Check if we have valid cached credentials
        if (this.credentials && this.credentialsExpiry && Date.now() < this.credentialsExpiry) {
            return this.credentials;
        }

        console.log('🔑 Getting credentials from Cognito...');

        // Step 1: Get Identity ID
        const getIdResponse = await fetch(
            `https://cognito-identity.${this.region}.amazonaws.com/`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityService.GetId',
                },
                body: JSON.stringify({
                    IdentityPoolId: this.identityPoolId,
                }),
            }
        );

        if (!getIdResponse.ok) {
            const error = await getIdResponse.text();
            throw new Error(`Failed to get Cognito Identity ID: ${error}`);
        }

        const { IdentityId } = await getIdResponse.json();
        console.log('📋 Got Identity ID:', IdentityId);

        // Step 2: Get credentials for the identity
        const getCredsResponse = await fetch(
            `https://cognito-identity.${this.region}.amazonaws.com/`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
                },
                body: JSON.stringify({
                    IdentityId: IdentityId,
                }),
            }
        );

        if (!getCredsResponse.ok) {
            const error = await getCredsResponse.text();
            throw new Error(`Failed to get Cognito credentials: ${error}`);
        }

        const { Credentials } = await getCredsResponse.json();
        
        this.credentials = {
            accessKeyId: Credentials.AccessKeyId,
            secretAccessKey: Credentials.SecretKey,
            sessionToken: Credentials.SessionToken,
        };
        
        // Set expiry 5 minutes before actual expiry for safety
        this.credentialsExpiry = Credentials.Expiration * 1000 - (5 * 60 * 1000);
        
        console.log('✅ Got temporary credentials');
        return this.credentials;
    }

    /**
     * Sign a request using AWS SigV4
     */
    async signRequest(method, url, headers, body, service) {
        const creds = await this.getCredentials();
        
        const urlObj = new URL(url);
        const datetime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
        const date = datetime.slice(0, 8);
        
        // Canonical headers
        const signedHeaders = 'content-type;host;x-amz-date;x-amz-security-token';
        const canonicalHeaders = [
            `content-type:${headers['Content-Type'] || 'application/json'}`,
            `host:${urlObj.host}`,
            `x-amz-date:${datetime}`,
            `x-amz-security-token:${creds.sessionToken}`,
        ].join('\n') + '\n';
        
        // Canonical request
        const payloadHash = await this.sha256(body || '');
        const canonicalRequest = [
            method,
            urlObj.pathname,
            urlObj.search.slice(1), // query string without ?
            canonicalHeaders,
            signedHeaders,
            payloadHash,
        ].join('\n');
        
        // String to sign
        const credentialScope = `${date}/${this.region}/${service}/aws4_request`;
        const stringToSign = [
            'AWS4-HMAC-SHA256',
            datetime,
            credentialScope,
            await this.sha256(canonicalRequest),
        ].join('\n');
        
        // Calculate signature
        const kDate = await this.hmac(`AWS4${creds.secretAccessKey}`, date);
        const kRegion = await this.hmac(kDate, this.region);
        const kService = await this.hmac(kRegion, service);
        const kSigning = await this.hmac(kService, 'aws4_request');
        const signature = await this.hmacHex(kSigning, stringToSign);
        
        // Authorization header
        const authorization = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
        
        return {
            ...headers,
            'X-Amz-Date': datetime,
            'X-Amz-Security-Token': creds.sessionToken,
            'Authorization': authorization,
        };
    }

    /**
     * Invoke AgentCore Runtime
     */
    async invokeAgentCore(inputText, sessionId = 'default') {
        console.log('🚀 Invoking AgentCore Runtime...');
        
        if (!this.runtimeEndpointArn) {
            throw new Error('No runtime endpoint ARN configured');
        }
        
        // Parse the endpoint ARN to construct URL
        // ARN format: arn:aws:bedrock-agentcore:region:account:agent-runtime-endpoint/id
        const arnParts = this.runtimeEndpointArn.split('/');
        const endpointId = arnParts[arnParts.length - 1];
        
        // Construct the API URL
        const url = `https://bedrock-agentcore.${this.region}.amazonaws.com/runtime-endpoints/${endpointId}/invoke`;
        
        console.log('📍 Endpoint URL:', url);
        console.log('📍 Endpoint ID:', endpointId);
        
        const body = JSON.stringify({
            inputText: inputText,
            sessionId: sessionId,
            enableTrace: true,
        });
        
        const headers = await this.signRequest(
            'POST',
            url,
            { 'Content-Type': 'application/json' },
            body,
            'bedrock-agentcore'
        );
        
        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: body,
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`AgentCore error ${response.status}: ${errorText}`);
        }
        
        return response;
    }

    /**
     * Invoke AgentCore with streaming
     */
    async invokeAgentCoreStreaming(inputText, sessionId, onChunk) {
        const response = await this.invokeAgentCore(inputText, sessionId);
        
        const reader = response.body?.getReader();
        const decoder = new TextDecoder();
        let fullText = '';
        
        if (reader) {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                const chunk = decoder.decode(value, { stream: true });
                fullText += chunk;
                
                if (onChunk) {
                    onChunk(chunk, fullText);
                }
            }
        } else {
            fullText = await response.text();
            if (onChunk) {
                onChunk(fullText, fullText);
            }
        }
        
        return fullText;
    }

    // Crypto helpers using Web Crypto API
    async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async hmac(key, message) {
        const keyBuffer = typeof key === 'string' 
            ? new TextEncoder().encode(key) 
            : key;
        const msgBuffer = new TextEncoder().encode(message);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgBuffer);
        return new Uint8Array(signature);
    }

    async hmacHex(key, message) {
        const signature = await this.hmac(key, message);
        return Array.from(signature)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// Export for use in app.js
window.AWSClient = AWSClient;

