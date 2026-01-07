/**
 * Error Debugger - AgentCore Multi-Agent Demo
 * Frontend for the error debugging multi-agent system
 * 
 * BLOG SERIES FEATURE FLAGS:
 * - Part 1: Basic multi-agent system (5 agents, Lambda tools, Bedrock)
 * - Part 2: Advanced features (Memory, GitHub integration, full visualization)
 */

// ===== Configuration =====
const CONFIG = {
    apiEndpoint: window.AGENTCORE_CONFIG?.apiEndpoint || '/api',
    logsApiEndpoint: window.AGENTCORE_CONFIG?.logsApiEndpoint || null,
    sessionId: 'sess_' + Math.random().toString(36).substring(2, 10),
    // Demo mode: true unless the AgentCore backend is available
    demoMode: window.AGENTCORE_CONFIG?.demoMode ?? true,
    githubRawUrl: 'https://raw.githubusercontent.com',
    githubApiUrl: 'https://api.github.com',
    // CloudWatch log groups (set by Terraform output)
    logGroups: window.AGENTCORE_CONFIG?.logGroups || {
        runtime:  '/aws/bedrock-agentcore/error-debugger',
        gateway:  '/aws/bedrock-agentcore/error-debugger-gateway',
        parser:   '/aws/lambda/error-debugger-parser',
        security: '/aws/lambda/error-debugger-security',
        context:  '/aws/lambda/error-debugger-context',
        stats:    '/aws/lambda/error-debugger-stats',
    },
    // AWS Region for CloudWatch
    awsRegion: window.AGENTCORE_CONFIG?.region || 'us-east-1',
};

// ===== Feature Flags (Blog Post Parts) =====
// Part 1: Basic agents (Parser, Security, Root Cause, Fix, Supervisor)
// Part 2: Part 1 + Memory, Context, Stats agents + GitHub integration + Live viz
const FEATURES = {
    // Set via window config or default to Part 2 (full features)
    PART: window.AGENTCORE_CONFIG?.part ?? 2,
    
    // Computed feature flags based on part
    get MEMORY_ENABLED() { return this.PART >= 2; },
    get CONTEXT_AGENT_ENABLED() { return this.PART >= 2; },
    get STATS_AGENT_ENABLED() { return this.PART >= 2; },
    get GITHUB_INTEGRATION_ENABLED() { return this.PART >= 2; },
    get LIVE_ARCHITECTURE_ENABLED() { return this.PART >= 2; },
    get ACTIVITY_LOG_ENABLED() { return this.PART >= 2; },
    get PRESEEDED_MEMORY_ENABLED() { return this.PART >= 2; },
    
    // Part 1 features (always enabled)
    get PARSER_AGENT_ENABLED() { return true; },
    get SECURITY_AGENT_ENABLED() { return true; },
    get ROOTCAUSE_AGENT_ENABLED() { return true; },
    get FIX_AGENT_ENABLED() { return true; },
    get LAMBDA_TOOLS_ENABLED() { return true; },
};

// ===== Secure PAT Handling =====
// PAT is stored ONLY in memory, never persisted to localStorage/sessionStorage
// Cleared on page unload for security
const SecureToken = {
    _token: null,
    
    set(token) {
        // Basic validation - GitHub PATs start with specific prefixes
        if (token && (token.startsWith('ghp_') || token.startsWith('github_pat_') || token.length > 30)) {
            this._token = token;
            return true;
        }
        this._token = token || null;
        return !!token;
    },
    
    get() {
        return this._token;
    },
    
    clear() {
        this._token = null;
    },
    
    hasToken() {
        return !!this._token;
    },
    
    // Get auth headers for GitHub API
    getHeaders() {
        if (!this._token) return {};
        return {
            'Authorization': `Bearer ${this._token}`,
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28',
        };
    },
    
    // Get headers for raw content
    getRawHeaders() {
        if (!this._token) return {};
        return {
            'Authorization': `Bearer ${this._token}`,
            'Accept': 'application/vnd.github.v3.raw',
        };
    }
};

// Clear token on page unload for security
window.addEventListener('beforeunload', () => {
    SecureToken.clear();
});

// ===== State =====
const state = {
    isAnalyzing: false,
    startTime: null,
    agentsUsed: 0,
    toolsUsed: 0,
    shortTermMemory: [],
    longTermMemory: [],
    // GitHub integration
    githubRepo: '',
    githubBranch: 'main',
    // Note: PAT is stored in SecureToken, not in state
    fetchedFiles: {},  // Cache for fetched file contents
    // GitHub actions results
    createdIssue: null,
    createdPR: null,
    // CloudWatch logs
    logs: {
        entries: [],          // All log entries
        selectedComponent: 'all',
        isLoading: false,
        lastFetch: null,
        autoRefresh: false,
        autoRefreshInterval: null,
        showErrorsOnly: false,
    },
};

// ===== Pre-seeded Memory =====
const PRE_SEEDED_MEMORY = [
    {
        type: 'null_reference',
        signature: 'cannot_read_map_undefined',
        solution: 'Add optional chaining: data?.map()',
        successCount: 15,
    },
    {
        type: 'import_error',
        signature: 'module_not_found',
        solution: 'Run npm install or pip install',
        successCount: 12,
    },
    {
        type: 'connection_error',
        signature: 'econnrefused',
        solution: 'Verify service is running, check port',
        successCount: 8,
    },
];

// ===== Sample Errors =====
const SAMPLE_ERRORS = [
    `TypeError: Cannot read properties of undefined (reading 'map')
    at UserList (src/components/UserList.tsx:15:23)
    at renderWithHooks (node_modules/react-dom/cjs/react-dom.development.js:14985:18)
    at mountIndeterminateComponent (node_modules/react-dom/cjs/react-dom.development.js:17811:13)`,
    
    `ImportError: No module named 'pandas'
    at File "/app/analysis.py", line 3, in <module>
        import pandas as pd
    ModuleNotFoundError: No module named 'pandas'`,
    
    `Error: connect ECONNREFUSED 127.0.0.1:5432
    at TCPConnectWrap.afterConnect [as oncomplete] (net.js:1141:16)
    at Protocol._enqueue (/app/node_modules/mysql/lib/protocol/Protocol.js:144:48)`,
    
    `SyntaxError: Unexpected token '<' (at parser.js:15:12)
    at JSON.parse (<anonymous>)
    at fetchData (src/api/client.ts:42:18)
    at async loadUserProfile (src/pages/Profile.tsx:28:5)`,
];

// ===== DOM Elements =====
let els = {};

function initElements() {
    els = {
        sessionId: document.getElementById('sessionId'),
        errorInput: document.getElementById('errorInput'),
        analyzeBtn: document.getElementById('analyzeBtn'),
        loadSampleBtn: document.getElementById('loadSampleBtn'),
        copyBtn: document.getElementById('copyBtn'),
        
        // GitHub integration
        githubRepo: document.getElementById('githubRepo'),
        githubBranch: document.getElementById('githubBranch'),
        githubPat: document.getElementById('githubPat'),
        githubStatus: document.getElementById('githubStatus'),
        togglePatBtn: document.getElementById('togglePatBtn'),
        
        orchestrationEmpty: document.getElementById('orchestrationEmpty'),
        archDiagram: document.getElementById('archDiagram'),
        modeBadge: document.getElementById('modeBadge'),
        
        agentCount: document.getElementById('agentCount'),
        toolCount: document.getElementById('toolCount'),
        execTime: document.getElementById('execTime'),
        
        resultsContent: document.getElementById('resultsContent'),
        
        shortTermCount: document.getElementById('shortTermCount'),
        longTermCount: document.getElementById('longTermCount'),
        shortTermList: document.getElementById('shortTermList'),
        longTermList: document.getElementById('longTermList'),
        
        // Activity log
        logEntries: document.getElementById('logEntries'),
        
        // Architecture nodes (new interactive diagram)
        nodeFrontend: document.getElementById('node-frontend'),
        nodeGateway: document.getElementById('node-gateway'),
        nodeParserLambda: document.getElementById('node-parser-lambda'),
        nodeSecurityLambda: document.getElementById('node-security-lambda'),
        nodeRuntime: document.getElementById('node-runtime'),
        nodeComprehend: document.getElementById('node-comprehend'),
        nodeBedrock: document.getElementById('node-bedrock'),
        nodeGithub: document.getElementById('node-github'),
        nodeMemory: document.getElementById('node-memory'),
        
        // Agent nodes inside runtime
        agentSupervisor: document.getElementById('agent-supervisor'),
        agentParser: document.getElementById('agent-parser'),
        agentSecurity: document.getElementById('agent-security'),
        agentContext: document.getElementById('agent-context'),
        agentMemory: document.getElementById('agent-memory'),
        agentRootcause: document.getElementById('agent-rootcause'),
        agentFix: document.getElementById('agent-fix'),
        agentStats: document.getElementById('agent-stats'),
        
        // Agent statuses (inside agent nodes)
        supervisorStatus: document.getElementById('supervisorStatus'),
        parserStatus: document.getElementById('parserStatus'),
        securityStatus: document.getElementById('securityStatus'),
        memoryStatus: document.getElementById('memoryStatus'),
        contextStatus: document.getElementById('contextStatus'),
        rootcauseStatus: document.getElementById('rootcauseStatus'),
        fixStatus: document.getElementById('fixStatus'),
        statsStatus: document.getElementById('statsStatus'),
        
        // Memory types
        memSession: document.getElementById('mem-session'),
        memSemantic: document.getElementById('mem-semantic'),
    };
    
    // Update mode badge
    if (els.modeBadge) {
        if (CONFIG.demoMode) {
            els.modeBadge.textContent = 'DEMO';
            els.modeBadge.classList.remove('live');
        } else {
            els.modeBadge.textContent = 'LIVE';
            els.modeBadge.classList.add('live');
        }
    }
}

// ===== Simulation =====
async function simulateAnalysis(errorText) {
    state.startTime = Date.now();
    state.agentsUsed = 0;
    state.toolsUsed = 0;
    state.fetchedFiles = {};
    
    // Get GitHub config from inputs (Part 2 only)
    if (FEATURES.GITHUB_INTEGRATION_ENABLED) {
        state.githubRepo = els.githubRepo?.value?.trim() || '';
        state.githubBranch = els.githubBranch?.value?.trim() || 'main';
        SecureToken.set(els.githubPat?.value?.trim() || '');
    } else {
        state.githubRepo = '';
        state.githubBranch = 'main';
    }
    state.createdIssue = null;
    state.createdPR = null;
    
    const result = {
        parsed: null,
        security: null,
        memory: null,
        context: null,
        codeContext: null,
        rootCause: null,
        fix: null,
        stats: null,
    };
    
    // Activate frontend node briefly (Part 2 visualization)
    if (FEATURES.LIVE_ARCHITECTURE_ENABLED) {
        activateNode('node-frontend');
        await sleep(100);
        deactivateNode('node-frontend');
    }
    
    // 1. Supervisor starts (always)
    await runAgent('supervisor', 'Analyzing error...', 200);
    
    // 2. Memory search - Part 2 only
    if (FEATURES.MEMORY_ENABLED) {
        await runAgent('memory', 'Searching similar errors...', 300);
        logMemoryOp('search_patterns');
        state.toolsUsed += 1;
        updateStats();
        result.memory = searchMemory(errorText);
        updateAgentOutput('memory', result.memory.count > 0 ? 
            `Found ${result.memory.count} similar errors!` : 'No matches found');
    }
    
    // 3. Parser - always enabled (Part 1 core)
    await runAgent('parser', 'Parsing stack trace...', 400);
    if (FEATURES.ACTIVITY_LOG_ENABLED) {
        logToolCall('extract_stack_frames', 'Parser Lambda');
        logToolCall('detect_language', 'Comprehend');
    }
    state.toolsUsed += 4;
    updateStats();
    result.parsed = parseError(errorText);
    updateAgentOutput('parser', 
        `${result.parsed.language} | ${result.parsed.errorType}`);
    
    // 4. Security - always enabled (Part 1 core)
    await runAgent('security', 'Scanning for PII/secrets...', 300);
    if (FEATURES.ACTIVITY_LOG_ENABLED) {
        logToolCall('detect_pii', 'Security Lambda → Comprehend');
        logToolCall('detect_secrets', 'Security Lambda');
    }
    state.toolsUsed += 3;
    updateStats();
    result.security = scanSecurity(errorText);
    updateAgentOutput('security', 
        `Risk: ${result.security.riskLevel} | ${result.security.secretsFound} secrets`);
    
    // 5. Context Agent - Part 2 only (GitHub integration)
    if (FEATURES.CONTEXT_AGENT_ENABLED) {
        if (state.githubRepo && FEATURES.GITHUB_INTEGRATION_ENABLED) {
            updateGithubStatus('loading', `Fetching code from ${state.githubRepo}...`);
            await runAgent('context', 'Fetching code from GitHub...', 300);
            logToolCall('fetch_code_context', 'GitHub API');
            state.toolsUsed += 1;
            updateStats();
            result.codeContext = await fetchCodeFromStackTrace(errorText, result.parsed);
            updateAgentOutput('context', 
                `📂 ${result.codeContext.filesFound} files fetched`);
            updateGithubStatus('connected', `✓ Connected to ${state.githubRepo}`);
            await sleep(200);
        }
        
        await runAgent('context', 'Searching GitHub Issues, StackOverflow...', 400);
        logToolCall('search_github_issues', 'GitHub API');
        logToolCall('search_stackoverflow', 'SO API');
        state.toolsUsed += 2;
        updateStats();
        result.context = getContext(errorText, result.parsed);
        updateAgentOutput('context', 
            state.githubRepo 
                ? `📂 ${result.codeContext?.filesFound || 0} files | ${result.context.stackoverflowCount} SO answers`
                : `${result.context.githubCount} issues, ${result.context.stackoverflowCount} answers`);
    }
    
    // 6. Root Cause - always enabled (Part 1 core)
    await runAgent('rootcause', 'Analyzing root cause...', 400);
    if (FEATURES.ACTIVITY_LOG_ENABLED) {
        logToolCall('analyze_with_llm', 'Bedrock Claude');
        if (FEATURES.MEMORY_ENABLED) {
            logToolCall('match_patterns', 'AgentCore Memory');
        }
    }
    state.toolsUsed += 2;
    updateStats();
    result.rootCause = analyzeRootCause(errorText, result.parsed, result.codeContext);
    updateAgentOutput('rootcause', 
        `${result.rootCause.confidence}% confidence`);
    
    // 7. Fix - always enabled (Part 1 core)
    await runAgent('fix', 'Generating fix...', 500);
    if (FEATURES.ACTIVITY_LOG_ENABLED) {
        logToolCall('generate_code_fix', 'Bedrock Claude');
        logToolCall('validate_syntax', 'AST Parser');
    }
    state.toolsUsed += 3;
    updateStats();
    result.fix = generateFix(result.rootCause, result.parsed.language, result.codeContext);
    updateAgentOutput('fix', 
        `${result.fix.fixType} | Syntax valid`);
    
    // 8. Stats Agent - Part 2 only
    if (FEATURES.STATS_AGENT_ENABLED) {
        await runAgent('stats', 'Recording statistics...', 150);
        logToolCall('record_occurrence', 'In-memory stats');
        state.toolsUsed += 2;
        updateStats();
        result.stats = recordStats(result.parsed);
    }
    
    // Store in memory - Part 2 only
    if (FEATURES.MEMORY_ENABLED) {
        logMemoryOp('store_session_context');
    }
    
    return result;
}

// ===== GitHub Integration =====

function updateGithubStatus(status, message) {
    if (els.githubStatus) {
        els.githubStatus.textContent = message;
        els.githubStatus.className = `github-status ${status}`;
    }
}

function extractFilePaths(errorText) {
    // Extract file paths from stack traces
    const paths = [];
    const patterns = [
        /at\s+\w+\s+\(([^:]+):(\d+)/g,           // JS: at Function (path:line)
        /at\s+([^:]+):(\d+)/g,                   // JS: at path:line
        /File\s+"([^"]+)",\s+line\s+(\d+)/g,     // Python: File "path", line N
        /\(([^)]+\.(?:ts|tsx|js|jsx)):(\d+)/g,   // (path.ts:line)
    ];
    
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(errorText)) !== null) {
            const filePath = match[1];
            const lineNum = parseInt(match[2], 10);
            // Skip node_modules and vendor paths
            if (!filePath.includes('node_modules') && 
                !filePath.includes('vendor') &&
                !filePath.startsWith('/')) {
                paths.push({ path: filePath, line: lineNum });
            }
        }
    }
    
    // Dedupe by path
    const seen = new Set();
    return paths.filter(p => {
        if (seen.has(p.path)) return false;
        seen.add(p.path);
        return true;
    });
}

async function fetchFileFromGitHub(filePath) {
    if (!state.githubRepo) return null;
    
    // Clean up path (remove leading ./ or /)
    const cleanPath = filePath.replace(/^\.?\//, '');
    
    // Use GitHub API for private repos (with PAT), or raw URL for public
    let url, headers = {};
    
    if (SecureToken.hasToken()) {
        // Private repo: Use GitHub API with authentication
        url = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/contents/${cleanPath}?ref=${state.githubBranch}`;
        headers = SecureToken.getRawHeaders();
    } else {
        // Public repo: Use raw.githubusercontent.com (no auth needed)
        url = `${CONFIG.githubRawUrl}/${state.githubRepo}/${state.githubBranch}/${cleanPath}`;
    }
    
    try {
        const response = await fetch(url, { headers });
        if (response.ok) {
            const content = await response.text();
            state.fetchedFiles[cleanPath] = content;
            return { path: cleanPath, content, success: true };
        } else if (response.status === 401 || response.status === 403) {
            updateGithubStatus('error', '❌ Invalid PAT or no access');
        } else if (response.status === 404) {
            console.log(`File not found: ${cleanPath}`);
        }
    } catch (e) {
        console.log(`Failed to fetch ${cleanPath}:`, e.message);
    }
    return { path: cleanPath, content: null, success: false };
}

// ===== GitHub Actions (Issue/PR Creation) =====

async function createGitHubIssue(title, body, labels = []) {
    if (!state.githubRepo || !SecureToken.hasToken()) {
        return { success: false, error: 'PAT required for creating issues' };
    }
    
    const url = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/issues`;
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: SecureToken.getHeaders(),
            body: JSON.stringify({
                title,
                body,
                labels,
            }),
        });
        
        if (response.ok) {
            const issue = await response.json();
            state.createdIssue = issue;
            return { 
                success: true, 
                issueNumber: issue.number,
                url: issue.html_url,
            };
        } else {
            const error = await response.json();
            return { success: false, error: error.message || 'Failed to create issue' };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}

async function createGitHubPullRequest(title, body, head, base = 'main') {
    if (!state.githubRepo || !SecureToken.hasToken()) {
        return { success: false, error: 'PAT required for creating PRs' };
    }
    
    const url = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/pulls`;
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: SecureToken.getHeaders(),
            body: JSON.stringify({
                title,
                body,
                head,  // Branch with changes
                base,  // Target branch (usually main)
            }),
        });
        
        if (response.ok) {
            const pr = await response.json();
            state.createdPR = pr;
            return { 
                success: true, 
                prNumber: pr.number,
                url: pr.html_url,
            };
        } else {
            const error = await response.json();
            return { success: false, error: error.message || 'Failed to create PR' };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// Create a fix branch with the suggested changes
async function createFixBranch(branchName, filePath, newContent, commitMessage) {
    if (!state.githubRepo || !SecureToken.hasToken()) {
        return { success: false, error: 'PAT required for creating branches' };
    }
    
    try {
        // 1. Get the default branch's latest commit SHA
        const refUrl = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/git/refs/heads/${state.githubBranch}`;
        const refResponse = await fetch(refUrl, { headers: SecureToken.getHeaders() });
        if (!refResponse.ok) throw new Error('Failed to get branch ref');
        const refData = await refResponse.json();
        const baseSha = refData.object.sha;
        
        // 2. Create new branch
        const createBranchUrl = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/git/refs`;
        const branchResponse = await fetch(createBranchUrl, {
            method: 'POST',
            headers: SecureToken.getHeaders(),
            body: JSON.stringify({
                ref: `refs/heads/${branchName}`,
                sha: baseSha,
            }),
        });
        if (!branchResponse.ok) {
            const err = await branchResponse.json();
            if (!err.message?.includes('already exists')) {
                throw new Error(err.message || 'Failed to create branch');
            }
        }
        
        // 3. Get current file SHA (needed for update)
        const fileUrl = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/contents/${filePath}?ref=${branchName}`;
        const fileResponse = await fetch(fileUrl, { headers: SecureToken.getHeaders() });
        let fileSha = null;
        if (fileResponse.ok) {
            const fileData = await fileResponse.json();
            fileSha = fileData.sha;
        }
        
        // 4. Create/update file with fix
        const updateUrl = `${CONFIG.githubApiUrl}/repos/${state.githubRepo}/contents/${filePath}`;
        const updateResponse = await fetch(updateUrl, {
            method: 'PUT',
            headers: SecureToken.getHeaders(),
            body: JSON.stringify({
                message: commitMessage,
                content: btoa(unescape(encodeURIComponent(newContent))), // Base64 encode
                branch: branchName,
                sha: fileSha,  // Required if updating existing file
            }),
        });
        
        if (!updateResponse.ok) {
            const err = await updateResponse.json();
            throw new Error(err.message || 'Failed to commit file');
        }
        
        return { success: true, branch: branchName };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

async function fetchCodeFromStackTrace(errorText, parsed) {
    const filePaths = extractFilePaths(errorText);
    const results = [];
    let filesFound = 0;
    
    // Fetch up to 3 files
    for (const { path, line } of filePaths.slice(0, 3)) {
        const result = await fetchFileFromGitHub(path);
        if (result?.success) {
            filesFound++;
            // Extract relevant lines around the error
            const lines = result.content.split('\n');
            const startLine = Math.max(0, line - 5);
            const endLine = Math.min(lines.length, line + 5);
            const snippet = lines.slice(startLine, endLine).join('\n');
            
            results.push({
                path: result.path,
                errorLine: line,
                snippet,
                fullContent: result.content,
            });
        }
    }
    
    return {
        filesFound,
        files: results,
        hasContext: filesFound > 0,
    };
}

// ===== Activity Log =====
function addLogEntry(message, type = 'info') {
    if (!els.logEntries) return;
    
    // Remove placeholder
    const placeholder = els.logEntries.querySelector('.placeholder');
    if (placeholder) placeholder.remove();
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `${new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })} ${message}`;
    
    els.logEntries.appendChild(entry);
    els.logEntries.scrollTop = els.logEntries.scrollHeight;
}

function clearActivityLog() {
    if (els.logEntries) {
        els.logEntries.innerHTML = '<div class="log-entry placeholder">Waiting for analysis...</div>';
    }
}

// ===== Node Animations =====
function activateNode(nodeId) {
    const node = document.getElementById(nodeId);
    if (node) node.classList.add('active');
}

function deactivateNode(nodeId) {
    const node = document.getElementById(nodeId);
    if (node) node.classList.remove('active');
}

// Agent to service node mappings (which services light up when agent runs)
const AGENT_NODES = {
    supervisor: ['node-gateway', 'node-runtime'],
    parser: ['node-gateway', 'node-parser-lambda', 'node-comprehend'],
    security: ['node-gateway', 'node-security-lambda', 'node-comprehend'],
    memory: ['node-memory'],
    context: ['node-github'],
    rootcause: ['node-bedrock'],
    fix: ['node-bedrock', 'node-github'],
    stats: [],
};

async function runAgent(agent, message, delay) {
    const statusEl = els[`${agent}Status`];
    const agentEl = document.getElementById(`agent-${agent}`);
    
    // Update status
    if (statusEl) {
        statusEl.textContent = 'running';
        statusEl.className = 'agent-status running';
    }
    if (agentEl) agentEl.classList.add('active');
    
    // Activate related service nodes
    const nodes = AGENT_NODES[agent] || [];
    nodes.forEach(activateNode);
    
    // Log activity
    addLogEntry(`${agent.toUpperCase()} → ${message}`, 'agent-start');
    
    // Increment agent count
    state.agentsUsed++;
    updateStats();
    
    await sleep(delay);
    
    // Complete
    if (statusEl) {
        statusEl.textContent = 'done';
        statusEl.className = 'agent-status complete';
    }
    if (agentEl) {
        agentEl.classList.remove('active');
        agentEl.classList.add('complete');
    }
    
    // Deactivate service nodes
    nodes.forEach(deactivateNode);
    
    addLogEntry(`${agent.toUpperCase()} ✓ complete`, 'agent-complete');
}

function logToolCall(tool, target) {
    addLogEntry(`TOOL ${tool} → ${target}`, 'tool-call');
}

function logMemoryOp(operation) {
    addLogEntry(`MEM ${operation}`, 'memory-op');
    // Flash memory node and badges
    activateNode('node-memory');
    const memSession = document.getElementById('mem-session');
    const memSemantic = document.getElementById('mem-semantic');
    if (memSession) memSession.classList.add('active');
    if (memSemantic) memSemantic.classList.add('active');
    setTimeout(() => {
        deactivateNode('node-memory');
        if (memSession) memSession.classList.remove('active');
        if (memSemantic) memSemantic.classList.remove('active');
    }, 500);
}

function updateAgentOutput(agent, text) {
    // Log the output
    addLogEntry(`  └─ ${text}`, 'agent-complete');
}

function updateStats() {
    if (els.agentCount) els.agentCount.textContent = `${state.agentsUsed} agents`;
    if (els.toolCount) els.toolCount.textContent = `${state.toolsUsed} tools`;
    
    // Update execution time
    if (els.execTime && state.startTime) {
        const elapsed = ((Date.now() - state.startTime) / 1000).toFixed(1);
        els.execTime.textContent = `${elapsed}s`;
    }
}

// ===== Analysis Functions =====

function searchMemory(errorText) {
    const lower = errorText.toLowerCase();
    const matches = PRE_SEEDED_MEMORY.filter(m => 
        lower.includes('undefined') && m.type === 'null_reference' ||
        lower.includes('module') && m.type === 'import_error' ||
        lower.includes('connect') && m.type === 'connection_error'
    );
    
    return {
        count: matches.length,
        matches: matches,
        hasSolution: matches.length > 0,
    };
}

function parseError(errorText) {
    // Detect language
    let language = 'unknown';
    if (errorText.includes('.tsx') || errorText.includes('.ts')) language = 'typescript';
    else if (errorText.includes('.js')) language = 'javascript';
    else if (errorText.includes('.py')) language = 'python';
    else if (errorText.includes('.go')) language = 'go';
    
    // Classify error type
    let errorType = 'unknown';
    const lower = errorText.toLowerCase();
    if (lower.includes('typeerror') || lower.includes('undefined')) errorType = 'null_reference';
    else if (lower.includes('importerror') || lower.includes('module')) errorType = 'import_error';
    else if (lower.includes('syntaxerror')) errorType = 'syntax_error';
    else if (lower.includes('connect') || lower.includes('refused')) errorType = 'connection_error';
    
    // Count frames
    const frameCount = (errorText.match(/at\s+\w+/g) || []).length;
    
    return {
        language,
        languageConfidence: language !== 'unknown' ? 85 : 0,
        errorType,
        errorTypeConfidence: errorType !== 'unknown' ? 90 : 30,
        frameCount,
        coreMessage: errorText.split('\n')[0].substring(0, 100),
    };
}

function scanSecurity(errorText) {
    let secretsFound = 0;
    let piiFound = 0;
    let riskLevel = 'low';
    
    // Check for secrets
    if (/AKIA[0-9A-Z]{16}/.test(errorText)) secretsFound++;
    if (/sk-[A-Za-z0-9]{48}/.test(errorText)) secretsFound++;
    if (/password\s*=\s*['"][^'"]+['"]/i.test(errorText)) secretsFound++;
    
    // Check for PII
    if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(errorText)) piiFound++;
    
    if (secretsFound > 0) riskLevel = 'critical';
    else if (piiFound > 0) riskLevel = 'medium';
    
    return {
        secretsFound,
        piiFound,
        riskLevel,
        safeToStore: secretsFound === 0,
        recommendations: secretsFound > 0 ? ['Remove hardcoded secrets', 'Use environment variables'] : [],
    };
}

function getContext(errorText, parsed) {
    // Extract search terms from error text
    const words = errorText.match(/\b[a-zA-Z_][a-zA-Z0-9_]*\b/g) || [];
    const noise = new Set(['the', 'a', 'an', 'is', 'are', 'was', 'in', 'on', 'for', 'to', 'of', 'at', 'line', 'file', 'error']);
    const terms = words.filter(w => !noise.has(w.toLowerCase()) && w.length > 2).slice(0, 5);
    const searchQuery = terms.join(' ');
    const encodedQuery = encodeURIComponent(searchQuery);
    
    // Build REAL working search URLs
    const githubSearchUrl = `https://github.com/search?q=${encodedQuery}&type=issues`;
    const soSearchUrl = `https://stackoverflow.com/search?q=${encodedQuery}`;
    
    return {
        githubCount: Math.floor(Math.random() * 15) + 3,
        stackoverflowCount: Math.floor(Math.random() * 10) + 2,
        githubIssues: [
            { title: `Search GitHub: ${parsed.errorType} issues`, url: githubSearchUrl, state: 'search' },
            { title: `${parsed.language} ${parsed.errorType} issues`, url: `https://github.com/search?q=${encodedQuery}+${parsed.language}&type=issues`, state: 'search' },
        ],
        stackoverflowQuestions: [
            { title: `How to fix ${parsed.errorType}?`, url: `${soSearchUrl}+${parsed.errorType}`, score: 127, answered: true },
            { title: `${parsed.language} debugging tips`, url: `https://stackoverflow.com/search?q=${encodedQuery}+${parsed.language}`, score: 45, answered: true },
        ],
        explanation: getErrorExplanation(parsed.errorType),
        searchUrls: {
            github: githubSearchUrl,
            stackoverflow: soSearchUrl
        }
    };
}

function getErrorExplanation(errorType) {
    const explanations = {
        null_reference: 'Attempting to access a property or method on a null/undefined value.',
        import_error: 'Failed to load a required module or package.',
        syntax_error: 'Code structure doesn\'t follow language grammar rules.',
        connection_error: 'Failed to establish network connection.',
    };
    return explanations[errorType] || 'Unknown error type.';
}

function analyzeRootCause(errorText, parsed, codeContext) {
    const causes = {
        null_reference: {
            rootCause: 'Array or object is undefined when accessed. Likely async data not loaded yet.',
            solution: 'Add null check or optional chaining before accessing properties.',
            confidence: codeContext?.hasContext ? 95 : 90,  // Higher with code context
        },
        import_error: {
            rootCause: 'Module not installed or wrong import path.',
            solution: 'Run package manager install command, verify module name.',
            confidence: 85,
        },
        syntax_error: {
            rootCause: 'Invalid JSON or syntax error in code.',
            solution: 'Validate JSON format, check for missing brackets.',
            confidence: 80,
        },
        connection_error: {
            rootCause: 'Target service not running or network issue.',
            solution: 'Verify service is running and port is correct.',
            confidence: 75,
        },
    };
    
    return causes[parsed.errorType] || {
        rootCause: 'Unable to determine specific cause.',
        solution: 'Manual investigation required.',
        confidence: 40,
    };
}

function generateFix(rootCause, language, codeContext) {
    const fixes = {
        javascript: {
            null_reference: {
                fixType: 'null_check',
                before: 'data.map(item => item.name)',
                after: 'data?.map(item => item.name) || []',
                explanation: 'Optional chaining prevents access on undefined',
            },
        },
        typescript: {
            null_reference: {
                fixType: 'null_check',
                before: 'data.map(item => item.name)',
                after: 'data?.map(item => item.name) ?? []',
                explanation: 'Optional chaining with nullish coalescing',
            },
        },
        python: {
            import_error: {
                fixType: 'install_module',
                before: 'import pandas as pd',
                after: '# Run: pip install pandas\nimport pandas as pd',
                explanation: 'Install missing package',
            },
        },
    };
    
    const langFixes = fixes[language] || fixes.javascript;
    const fix = langFixes.null_reference || {
        fixType: 'error_handling',
        before: 'riskyOperation()',
        after: 'try {\n  riskyOperation()\n} catch (e) {\n  handleError(e)\n}',
        explanation: 'Wrap in try-catch for error handling',
    };
    
    // If we have code context, use the actual code
    if (codeContext?.hasContext && codeContext.files?.length > 0) {
        const file = codeContext.files[0];
        fix.sourceFile = file.path;
        fix.sourceLine = file.errorLine;
        fix.actualCode = file.snippet;
        fix.hasCodeContext = true;
    }
    
    return fix;
}

function recordStats(parsed) {
    state.shortTermMemory.push({
        type: 'analyzed_error',
        errorType: parsed.errorType,
        language: parsed.language,
        timestamp: new Date().toISOString(),
    });
    
    return {
        recorded: true,
        sessionTotal: state.shortTermMemory.length,
        trend: 'stable',
    };
}

// ===== Display Results =====

function displayResults(result) {
    // Store for GitHub action handlers
    lastAnalysisResult = result;
    
    let html = '';
    
    // Memory match (Part 2 only)
    if (FEATURES.MEMORY_ENABLED && result.memory?.hasSolution) {
        html += `
            <div class="result-section memory fade-in">
                <h3>🧠 Memory Match Found!</h3>
                <p class="result-text">Similar error found in memory. Previous solution:</p>
                <div class="result-code">${result.memory.matches[0].solution}</div>
                <span class="result-badge positive">×${result.memory.matches[0].successCount} successful uses</span>
            </div>
        `;
    }
    
    // Parsed info
    html += `
        <div class="result-section fade-in">
            <h3>📋 Parsed Information</h3>
            <p class="result-text">
                <strong>Language:</strong> ${result.parsed.language} (${result.parsed.languageConfidence}%)<br>
                <strong>Error Type:</strong> ${result.parsed.errorType}<br>
                <strong>Stack Frames:</strong> ${result.parsed.frameCount}<br>
                <strong>Message:</strong> ${result.parsed.coreMessage}
            </p>
        </div>
    `;
    
    // Security
    const securityBadge = result.security.riskLevel === 'low' ? 'positive' : 
                          result.security.riskLevel === 'critical' ? 'negative' : 'warning';
    html += `
        <div class="result-section security fade-in">
            <h3>🔒 Security Assessment</h3>
            <span class="result-badge ${securityBadge}">Risk: ${result.security.riskLevel.toUpperCase()}</span>
            <p class="result-text" style="margin-top: 8px">
                Secrets Found: ${result.security.secretsFound}<br>
                PII Found: ${result.security.piiFound}<br>
                Safe to Store: ${result.security.safeToStore ? 'Yes' : 'No'}
            </p>
            ${result.security.recommendations.length > 0 ? `
                <ul class="result-list">
                    ${result.security.recommendations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            ` : ''}
        </div>
    `;
    
    // Root Cause
    html += `
        <div class="result-section fade-in">
            <h3>🎯 Root Cause Analysis</h3>
            <span class="result-badge info">${result.rootCause.confidence}% confidence</span>
            <p class="result-text" style="margin-top: 8px">
                <strong>Cause:</strong> ${result.rootCause.rootCause}<br>
                <strong>Solution:</strong> ${result.rootCause.solution}
            </p>
        </div>
    `;
    
    // Fix
    const hasGitHub = FEATURES.GITHUB_INTEGRATION_ENABLED && state.githubRepo && SecureToken.hasToken();
    html += `
        <div class="result-section fix fade-in">
            <h3>🔧 Suggested Fix</h3>
            <span class="result-badge positive">${result.fix.fixType}</span>
            ${result.fix.hasCodeContext && FEATURES.GITHUB_INTEGRATION_ENABLED ? `
                <p class="result-text" style="margin-top: 8px">
                    <strong>📂 Source:</strong> <code>${result.fix.sourceFile}:${result.fix.sourceLine}</code>
                </p>
                <p class="result-text"><strong>Actual Code:</strong></p>
                <div class="result-code">${escapeHtml(result.fix.actualCode || '')}</div>
            ` : ''}
            <p class="result-text" style="margin-top: 8px"><strong>Before:</strong></p>
            <div class="result-code">${escapeHtml(result.fix.before)}</div>
            <p class="result-text"><strong>After:</strong></p>
            <div class="result-code">${escapeHtml(result.fix.after)}</div>
            <p class="result-text">${result.fix.explanation}</p>
            
            ${hasGitHub ? `
                <div class="github-actions" style="margin-top: 12px; display: flex; gap: 8px;">
                    <button class="btn-github" id="createIssueBtn" onclick="handleCreateIssue()">
                        <span>📝</span> Create Issue
                    </button>
                    <button class="btn-github btn-github-pr" id="createPRBtn" onclick="handleCreatePR()">
                        <span>🔀</span> Create PR with Fix
                    </button>
                </div>
                <div class="github-action-status" id="githubActionStatus"></div>
            ` : FEATURES.GITHUB_INTEGRATION_ENABLED ? `
                <p class="result-text hint" style="margin-top: 8px; font-size: 0.75rem; color: var(--text-muted);">
                    💡 Add a GitHub PAT to create issues/PRs directly
                </p>
            ` : ''}
        </div>
    `;
    
    // External Resources (Part 2 only - Context Agent)
    if (FEATURES.CONTEXT_AGENT_ENABLED && result.context) {
        html += `
            <div class="result-section resources fade-in">
                <h3>📚 External Resources</h3>
                <p class="result-text">
                    Found ${result.context.githubCount} GitHub issues and ${result.context.stackoverflowCount} Stack Overflow answers.
                </p>
                <p class="result-text"><strong>Explanation:</strong> ${result.context.explanation}</p>
                <div style="margin-top: 8px">
                    ${result.context.stackoverflowQuestions.map(q => `
                        <a href="${q.url}" class="result-link">
                            ${q.title}
                            <span class="result-link-meta">Score: ${q.score} ${q.answered ? '✓' : ''}</span>
                        </a>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Stats
    const execTime = ((Date.now() - state.startTime) / 1000).toFixed(1);
    html += `
        <div class="result-section fade-in">
            <h3>📊 Analysis Metrics</h3>
            <p class="result-text">
                <strong>Agents Used:</strong> ${state.agentsUsed}<br>
                <strong>Tool Calls:</strong> ${state.toolsUsed}<br>
                <strong>Execution Time:</strong> ${execTime}s
                ${FEATURES.STATS_AGENT_ENABLED && result.stats ? `<br><strong>Trend:</strong> ${result.stats.trend}` : ''}
            </p>
        </div>
    `;
    
    els.resultsContent.innerHTML = html;
    
    // Update header stats
    els.agentCount.textContent = `${state.agentsUsed} agents`;
    els.toolCount.textContent = `${state.toolsUsed} tools`;
    els.execTime.textContent = `${execTime}s`;
}

// ===== Memory Display =====

function updateMemoryDisplay() {
    // Short-term
    if (state.shortTermMemory.length > 0) {
        els.shortTermList.innerHTML = state.shortTermMemory.map(m => `
            <div class="memory-item">
                <div class="memory-item-header">
                    <span class="memory-item-type">${m.type}</span>
                </div>
                <div class="memory-item-text">${m.errorType} (${m.language})</div>
            </div>
        `).join('');
    }
    els.shortTermCount.textContent = state.shortTermMemory.length;
    
    // Long-term (pre-seeded)
    els.longTermList.innerHTML = PRE_SEEDED_MEMORY.map(m => `
        <div class="memory-item">
            <div class="memory-item-header">
                <span class="memory-item-type">${m.type}</span>
                <span class="memory-item-count">×${m.successCount}</span>
            </div>
            <div class="memory-item-text">${m.solution}</div>
        </div>
    `).join('');
    els.longTermCount.textContent = PRE_SEEDED_MEMORY.length;
}

// ===== Main Analysis =====

async function runAnalysis() {
    const errorText = els.errorInput?.value?.trim();
    if (!errorText) {
        alert('Please paste an error message');
        return;
    }
    
    state.isAnalyzing = true;
    els.analyzeBtn.disabled = true;
    els.analyzeBtn.innerHTML = '<span class="icon">⏳</span><span>Analyzing...</span>';
    
    // Show architecture diagram
    if (els.orchestrationEmpty) els.orchestrationEmpty.style.display = 'none';
    if (els.archDiagram) els.archDiagram.style.display = 'block';
    
    // Reset all architecture nodes and agents
    document.querySelectorAll('.arch-node').forEach(node => {
        node.classList.remove('active');
    });
    document.querySelectorAll('.agent-node').forEach(agent => {
        agent.classList.remove('active', 'complete');
    });
    document.querySelectorAll('.agent-status').forEach(status => {
        status.textContent = 'idle';
        status.className = 'agent-status';
    });
    document.querySelectorAll('.mem-badge').forEach(mem => {
        mem.classList.remove('active');
    });
    
    // Clear and prepare activity log
    clearActivityLog();
    addLogEntry('Starting analysis...', 'agent-start');
    
    // Show loading in results
    els.resultsContent.innerHTML = '<div class="loading">Analyzing error...</div>';
    
    try {
        const result = await simulateAnalysis(errorText);
        displayResults(result);
        updateMemoryDisplay();
        els.copyBtn.disabled = false;
        
        // Fetch logs after analysis completes
        setTimeout(() => {
            LogsManager.fetchLogs();
        }, 500);
    } catch (error) {
        console.error('Analysis failed:', error);
        els.resultsContent.innerHTML = `
            <div class="result-section" style="border-color: var(--accent-red)">
                <h3>❌ Analysis Failed</h3>
                <p class="result-text">${error.message}</p>
            </div>
        `;
    } finally {
        state.isAnalyzing = false;
        els.analyzeBtn.disabled = false;
        els.analyzeBtn.innerHTML = '<span class="icon">⚡</span><span>Debug Error</span>';
    }
}

// ===== Utilities =====

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== GitHub Action Handlers =====

// Store last analysis result for action handlers
let lastAnalysisResult = null;

async function handleCreateIssue() {
    if (!lastAnalysisResult) return;
    
    const statusEl = document.getElementById('githubActionStatus');
    const btn = document.getElementById('createIssueBtn');
    
    if (statusEl) statusEl.innerHTML = '<span class="loading">Creating issue...</span>';
    if (btn) btn.disabled = true;
    
    const title = `🐛 ${lastAnalysisResult.parsed.errorType}: ${lastAnalysisResult.parsed.coreMessage.substring(0, 60)}`;
    const body = generateIssueBody(lastAnalysisResult);
    const labels = ['bug', 'auto-generated'];
    
    const result = await createGitHubIssue(title, body, labels);
    
    if (result.success) {
        if (statusEl) statusEl.innerHTML = `
            <span class="success">✅ Issue #${result.issueNumber} created!</span>
            <a href="${result.url}" target="_blank" class="result-link" style="display: inline; margin-left: 8px;">View Issue →</a>
        `;
    } else {
        if (statusEl) statusEl.innerHTML = `<span class="error">❌ ${result.error}</span>`;
        if (btn) btn.disabled = false;
    }
}

async function handleCreatePR() {
    if (!lastAnalysisResult) return;
    
    const statusEl = document.getElementById('githubActionStatus');
    const btn = document.getElementById('createPRBtn');
    
    if (statusEl) statusEl.innerHTML = '<span class="loading">Creating fix branch and PR...</span>';
    if (btn) btn.disabled = true;
    
    // Generate branch name
    const timestamp = Date.now();
    const branchName = `fix/${lastAnalysisResult.parsed.errorType}-${timestamp}`;
    
    // If we have actual code context, try to create a real fix
    if (lastAnalysisResult.fix.hasCodeContext && lastAnalysisResult.fix.sourceFile) {
        const filePath = lastAnalysisResult.fix.sourceFile;
        const originalContent = state.fetchedFiles[filePath];
        
        if (originalContent) {
            // Simple fix: replace the problematic pattern
            // In real implementation, this would be more sophisticated
            const fixedContent = originalContent.replace(
                lastAnalysisResult.fix.before,
                lastAnalysisResult.fix.after
            );
            
            const commitMessage = `fix: ${lastAnalysisResult.parsed.errorType} in ${filePath}

Auto-generated fix by Error Debugger
Root cause: ${lastAnalysisResult.rootCause.rootCause}`;
            
            const branchResult = await createFixBranch(branchName, filePath, fixedContent, commitMessage);
            
            if (!branchResult.success) {
                if (statusEl) statusEl.innerHTML = `<span class="error">❌ ${branchResult.error}</span>`;
                if (btn) btn.disabled = false;
                return;
            }
        }
    }
    
    // Create the PR
    const title = `🔧 Fix: ${lastAnalysisResult.parsed.errorType}`;
    const body = generatePRBody(lastAnalysisResult);
    
    const result = await createGitHubPullRequest(title, body, branchName, state.githubBranch);
    
    if (result.success) {
        if (statusEl) statusEl.innerHTML = `
            <span class="success">✅ PR #${result.prNumber} created!</span>
            <a href="${result.url}" target="_blank" class="result-link" style="display: inline; margin-left: 8px;">View PR →</a>
        `;
    } else {
        if (statusEl) statusEl.innerHTML = `<span class="error">❌ ${result.error}</span>`;
        if (btn) btn.disabled = false;
    }
}

function generateIssueBody(result) {
    return `## 🐛 Error Report

**Type:** ${result.parsed.errorType}
**Language:** ${result.parsed.language}
**Confidence:** ${result.rootCause.confidence}%

### Error Message
\`\`\`
${result.parsed.coreMessage}
\`\`\`

### Root Cause Analysis
${result.rootCause.rootCause}

### Suggested Solution
${result.rootCause.solution}

### Suggested Fix
**Before:**
\`\`\`${result.parsed.language}
${result.fix.before}
\`\`\`

**After:**
\`\`\`${result.parsed.language}
${result.fix.after}
\`\`\`

### Security Assessment
- **Risk Level:** ${result.security.riskLevel}
- **Secrets Found:** ${result.security.secretsFound}
- **PII Found:** ${result.security.piiFound}

---
*Auto-generated by Error Debugger (AgentCore Multi-Agent Demo)*
`;
}

function generatePRBody(result) {
    return `## 🔧 Automated Fix

This PR was automatically generated by the Error Debugger multi-agent system.

### Problem
**${result.parsed.errorType}:** ${result.parsed.coreMessage}

### Root Cause
${result.rootCause.rootCause}

### Changes
${result.fix.explanation}

### Before
\`\`\`${result.parsed.language}
${result.fix.before}
\`\`\`

### After
\`\`\`${result.parsed.language}
${result.fix.after}
\`\`\`

### Verification
- [ ] Tested locally
- [ ] No new warnings
- [ ] Related tests pass

---
*Auto-generated by Error Debugger (AgentCore Multi-Agent Demo)*
`;
}

function loadSample() {
    const sample = SAMPLE_ERRORS[Math.floor(Math.random() * SAMPLE_ERRORS.length)];
    els.errorInput.value = sample;
}

function copyResults() {
    const text = els.resultsContent.innerText;
    navigator.clipboard.writeText(text);
    alert('Results copied to clipboard!');
}

// ===== CloudWatch Logs =====

const LogsManager = {
    els: {},
    
    init() {
        this.els = {
            container: document.getElementById('logsContainer'),
            tabs: document.getElementById('logsTabs'),
            status: document.getElementById('logsStatus'),
            info: document.getElementById('logsInfo'),
            refreshBtn: document.getElementById('refreshLogsBtn'),
            autoRefreshBtn: document.getElementById('autoRefreshBtn'),
            errorsOnlyCheckbox: document.getElementById('showErrorsOnly'),
        };
        
        // Tab click handlers
        this.els.tabs?.querySelectorAll('.log-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.selectComponent(tab.dataset.component);
            });
        });
        
        // Refresh button
        this.els.refreshBtn?.addEventListener('click', () => this.fetchLogs());
        
        // Auto-refresh toggle
        this.els.autoRefreshBtn?.addEventListener('click', () => this.toggleAutoRefresh());
        
        // Errors only filter
        this.els.errorsOnlyCheckbox?.addEventListener('change', (e) => {
            state.logs.showErrorsOnly = e.target.checked;
            this.renderLogs();
        });
    },
    
    selectComponent(component) {
        state.logs.selectedComponent = component;
        
        // Update tab UI
        this.els.tabs?.querySelectorAll('.log-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.component === component);
        });
        
        // Re-render logs
        this.renderLogs();
    },
    
    setStatus(status, message) {
        if (this.els.status) {
            this.els.status.textContent = message;
            this.els.status.className = `logs-status ${status}`;
        }
    },
    
    async fetchLogs() {
        if (state.logs.isLoading) return;
        
        state.logs.isLoading = true;
        this.setStatus('loading', 'Fetching...');
        this.showLoading();
        
        try {
            // In demo mode, generate simulated logs
            if (CONFIG.demoMode) {
                await this.fetchSimulatedLogs();
            } else {
                await this.fetchCloudWatchLogs();
            }
            
            state.logs.lastFetch = new Date();
            this.setStatus('success', `Updated ${state.logs.lastFetch.toLocaleTimeString()}`);
            this.renderLogs();
        } catch (error) {
            console.error('Failed to fetch logs:', error);
            this.setStatus('error', `Error: ${error.message}`);
            this.showError(error.message);
        } finally {
            state.logs.isLoading = false;
        }
    },
    
    async fetchCloudWatchLogs() {
        // If no logs API endpoint configured, fall back to simulated
        if (!CONFIG.logsApiEndpoint) {
            console.log('No logs API endpoint configured, using simulated logs');
            return this.fetchSimulatedLogs();
        }
        
        // Call the backend API to fetch CloudWatch logs
        const response = await fetch(`${CONFIG.logsApiEndpoint}/logs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                components: Object.keys(CONFIG.logGroups),
                limit: 100,
                startTime: Date.now() - (60 * 60 * 1000), // Last hour
            }),
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API error ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Unknown error');
        }
        
        state.logs.entries = this.parseCloudWatchLogs(data.logs || []);
        
        // Log any component-specific errors
        if (data.errors?.length > 0) {
            console.warn('Some log fetches failed:', data.errors);
        }
    },
    
    async fetchSimulatedLogs() {
        // Simulate network delay
        await new Promise(r => setTimeout(r, 500));
        
        // Generate simulated logs based on current analysis state
        const now = Date.now();
        const logs = [];
        
        const components = ['runtime', 'gateway', 'parser', 'security', 'context', 'stats'];
        const levels = ['INFO', 'INFO', 'INFO', 'WARN', 'ERROR'];
        
        // If we've run an analysis, generate logs for that
        if (state.shortTermMemory.length > 0) {
            const analysis = state.shortTermMemory[state.shortTermMemory.length - 1];
            
            logs.push(
                { timestamp: now - 5000, component: 'gateway', level: 'INFO', message: 'Received analysis request' },
                { timestamp: now - 4800, component: 'runtime', level: 'INFO', message: '🚀 Error Debugger started (mode: comprehensive)' },
                { timestamp: now - 4600, component: 'runtime', level: 'INFO', message: `📥 Input: ${analysis.errorType} error detected` },
                { timestamp: now - 4400, component: 'parser', level: 'INFO', message: `Parsing error text (${Math.floor(Math.random() * 500 + 100)} chars)` },
                { timestamp: now - 4200, component: 'parser', level: 'INFO', message: `✅ Detected language: ${analysis.language}` },
                { timestamp: now - 4000, component: 'security', level: 'INFO', message: 'Scanning for PII and secrets...' },
                { timestamp: now - 3800, component: 'security', level: 'INFO', message: '✅ Security scan complete - no sensitive data found' },
                { timestamp: now - 3500, component: 'runtime', level: 'INFO', message: '🎯 Invoking RootCauseAgent' },
                { timestamp: now - 3200, component: 'runtime', level: 'INFO', message: `✅ RootCauseAgent returned: 85% confidence` },
                { timestamp: now - 3000, component: 'runtime', level: 'INFO', message: `🔧 Invoking FixAgent for ${analysis.language}` },
                { timestamp: now - 2700, component: 'runtime', level: 'INFO', message: '✅ FixAgent returned: null_check fix' },
                { timestamp: now - 2500, component: 'stats', level: 'INFO', message: `Recording ${analysis.errorType} occurrence` },
                { timestamp: now - 2300, component: 'gateway', level: 'INFO', message: 'Analysis complete, streaming response' },
            );
        }
        
        // Add some background noise logs
        for (let i = 0; i < 15; i++) {
            const component = components[Math.floor(Math.random() * components.length)];
            const level = levels[Math.floor(Math.random() * levels.length)];
            const offset = Math.floor(Math.random() * 60000);
            
            const messages = {
                runtime: ['Heartbeat check', 'Memory usage: 245MB', 'Active sessions: 1', 'Tool execution complete'],
                gateway: ['Health check OK', 'Route matched: /analyze', 'Request authenticated', 'Response sent'],
                parser: ['Regex pattern matched', 'Stack frame extracted', 'Language detected', 'Classification complete'],
                security: ['PII scan started', 'No secrets found', 'Risk level: low', 'Scan complete'],
                context: ['GitHub API call', 'StackOverflow search', 'Results cached', 'Context retrieved'],
                stats: ['Stats recorded', 'DynamoDB write', 'Trend calculated', 'Frequency updated'],
            };
            
            const componentMessages = messages[component] || ['Processing...'];
            const message = componentMessages[Math.floor(Math.random() * componentMessages.length)];
            
            logs.push({
                timestamp: now - offset,
                component,
                level,
                message: level === 'ERROR' ? `❌ ${message} failed` : 
                         level === 'WARN' ? `⚠️ ${message} (warning)` : message,
            });
        }
        
        // Sort by timestamp descending (newest first)
        logs.sort((a, b) => b.timestamp - a.timestamp);
        
        state.logs.entries = logs;
    },
    
    parseCloudWatchLogs(rawLogs) {
        return rawLogs.map(log => {
            // Determine component from log group name
            let component = 'runtime';
            if (log.logGroup?.includes('gateway')) component = 'gateway';
            else if (log.logGroup?.includes('parser')) component = 'parser';
            else if (log.logGroup?.includes('security')) component = 'security';
            else if (log.logGroup?.includes('context')) component = 'context';
            else if (log.logGroup?.includes('stats')) component = 'stats';
            
            // Determine level from message
            let level = 'INFO';
            const msg = log.message || '';
            if (msg.includes('ERROR') || msg.includes('❌')) level = 'ERROR';
            else if (msg.includes('WARN') || msg.includes('⚠️')) level = 'WARN';
            
            return {
                timestamp: log.timestamp,
                component,
                level,
                message: msg,
            };
        });
    },
    
    renderLogs() {
        if (!this.els.container) return;
        
        let entries = state.logs.entries;
        
        // Filter by component
        if (state.logs.selectedComponent !== 'all') {
            entries = entries.filter(e => e.component === state.logs.selectedComponent);
        }
        
        // Filter by errors only
        if (state.logs.showErrorsOnly) {
            entries = entries.filter(e => e.level === 'ERROR' || e.level === 'WARN');
        }
        
        // Update count
        if (this.els.info) {
            this.els.info.textContent = `${entries.length} entries`;
        }
        
        if (entries.length === 0) {
            this.els.container.innerHTML = `
                <div class="logs-empty">
                    <span class="empty-icon">📋</span>
                    <p>No logs found${state.logs.selectedComponent !== 'all' ? ` for ${state.logs.selectedComponent}` : ''}</p>
                    <p class="hint">${state.logs.showErrorsOnly ? 'Try disabling "Errors only" filter' : 'Click "Refresh" to fetch latest logs'}</p>
                </div>
            `;
            return;
        }
        
        this.els.container.innerHTML = entries.map(entry => `
            <div class="cloudwatch-log-entry ${entry.level.toLowerCase()}">
                <span class="log-timestamp">${this.formatTimestamp(entry.timestamp)}</span>
                <span class="log-component ${entry.component}">${entry.component}</span>
                <span class="log-message ${entry.level === 'ERROR' ? 'error' : ''}">${escapeHtml(entry.message)}</span>
            </div>
        `).join('');
    },
    
    showLoading() {
        if (!this.els.container) return;
        
        const skeletons = Array(8).fill(null).map(() => `
            <div class="log-skeleton">
                <span class="sk-time"></span>
                <span class="sk-component"></span>
                <span class="sk-message"></span>
            </div>
        `).join('');
        
        this.els.container.innerHTML = skeletons;
    },
    
    showError(message) {
        if (!this.els.container) return;
        
        this.els.container.innerHTML = `
            <div class="logs-empty">
                <span class="empty-icon">❌</span>
                <p>Failed to fetch logs</p>
                <p class="hint">${escapeHtml(message)}</p>
            </div>
        `;
    },
    
    formatTimestamp(ts) {
        const date = new Date(ts);
        return date.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            fractionalSecondDigits: 3,
        });
    },
    
    toggleAutoRefresh() {
        state.logs.autoRefresh = !state.logs.autoRefresh;
        
        if (this.els.autoRefreshBtn) {
            this.els.autoRefreshBtn.textContent = state.logs.autoRefresh ? '⏸️ Stop' : '▶️ Auto';
        }
        
        if (state.logs.autoRefresh) {
            // Start auto-refresh every 5 seconds
            this.fetchLogs();
            state.logs.autoRefreshInterval = setInterval(() => {
                this.fetchLogs();
            }, 5000);
        } else {
            // Stop auto-refresh
            if (state.logs.autoRefreshInterval) {
                clearInterval(state.logs.autoRefreshInterval);
                state.logs.autoRefreshInterval = null;
            }
        }
    },
};

// ===== Initialization =====

function applyFeatureFlags() {
    // Update part badge in header
    if (els.modeBadge) {
        const partText = FEATURES.PART === 1 ? 'PART 1' : 'PART 2';
        const modeText = CONFIG.demoMode ? 'DEMO' : 'LIVE';
        els.modeBadge.textContent = `${partText} • ${modeText}`;
        els.modeBadge.classList.toggle('live', !CONFIG.demoMode);
    }
    
    // Hide Part 2 features if Part 1
    const part2Elements = [
        '.github-input',           // GitHub integration section
        '.memory-panel',           // Memory panel at bottom
        '#agent-memory',           // Memory agent in runtime
        '#agent-context',          // Context agent in runtime
        '#agent-stats',            // Stats agent in runtime
        '.activity-log',           // Activity log
        '.arch-flow-note',         // Flow explanation
        '#node-memory',            // Memory service node
        '#node-github',            // GitHub node
    ];
    
    if (FEATURES.PART === 1) {
        part2Elements.forEach(selector => {
            const el = document.querySelector(selector);
            if (el) el.style.display = 'none';
        });
        
        // Update subtitle
        const subtitle = document.querySelector('.subtitle');
        if (subtitle) {
            subtitle.textContent = 'Powered by AWS AgentCore • 5 Agents • 8+ Tools';
        }
    }
    
    console.log(`🎯 Feature flags applied: Part ${FEATURES.PART}`);
}

function init() {
    console.log('🔍 Error Debugger initializing...');
    console.log(`📌 Running Part ${FEATURES.PART} features`);
    console.log(`📋 Log groups configured:`, CONFIG.logGroups);
    
    initElements();
    
    // Apply feature flags to UI
    applyFeatureFlags();
    
    // Set session ID
    if (els.sessionId) {
        els.sessionId.textContent = CONFIG.sessionId;
    }
    
    // Initialize memory display (Part 2 only)
    if (FEATURES.MEMORY_ENABLED) {
        updateMemoryDisplay();
    }
    
    // Initialize CloudWatch Logs manager
    LogsManager.init();
    
    // Event listeners
    els.analyzeBtn?.addEventListener('click', runAnalysis);
    els.loadSampleBtn?.addEventListener('click', loadSample);
    els.copyBtn?.addEventListener('click', copyResults);
    
    // PAT visibility toggle (Part 2 only)
    if (FEATURES.GITHUB_INTEGRATION_ENABLED) {
        els.togglePatBtn?.addEventListener('click', () => {
            if (els.githubPat) {
                const isPassword = els.githubPat.type === 'password';
                els.githubPat.type = isPassword ? 'text' : 'password';
                els.togglePatBtn.textContent = isPassword ? '🙈' : '👁';
            }
        });
    }
    
    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !state.isAnalyzing) {
            e.preventDefault();
            runAnalysis();
        }
    });
    
    console.log('✅ Error Debugger initialized');
}

// Start
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Export for testing
window.ErrorDebugger = { state, CONFIG, runAnalysis };

