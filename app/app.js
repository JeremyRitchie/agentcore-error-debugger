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
    // API endpoint (Lambda proxy with CORS - from Terraform output)
    apiEndpoint: window.AGENTCORE_CONFIG?.apiEndpoint || null,
    
    // Logs API endpoint
    logsApiEndpoint: window.AGENTCORE_CONFIG?.logsApiEndpoint || null,
    
    sessionId: 'sess_' + Math.random().toString(36).substring(2, 10),
    // Demo mode: true unless API endpoint is configured
    demoMode: window.AGENTCORE_CONFIG?.demoMode ?? true,
    githubRawUrl: 'https://raw.githubusercontent.com',
    githubApiUrl: 'https://api.github.com',
    // CloudWatch log groups (set by Terraform output)
    logGroups: window.AGENTCORE_CONFIG?.logGroups || {
        runtime:  '/aws/bedrock-agentcore/error-debugger',
        gateway:  '/aws/bedrock-agentcore/error-debugger-gateway',
        memory:   '/aws/bedrock-agentcore/error-debugger-memory',
        parser:   '/aws/lambda/error-debugger-parser',
        security: '/aws/lambda/error-debugger-security',
        context:  '/aws/lambda/error-debugger-context',
        stats:    '/aws/lambda/error-debugger-stats',
    },
    // AWS Region
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
    get PRESEEDED_MEMORY_ENABLED() { return false; },  // Disabled - no static patterns
    
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
// REMOVED: No static pre-seeded patterns
// Memory should only contain patterns stored from actual successful debugging sessions
// The backend memory agent handles this - frontend just displays what backend returns
const PRE_SEEDED_MEMORY = [];  // Empty - no fake data

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
        `${result.parsed.language} detected`);
    
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
    // DEMO MODE ONLY: Return empty - real memory search is done by backend
    // No static pattern matching - the backend LLM handles this
    return {
        count: 0,
        matches: [],
        hasSolution: false,
        note: 'Demo mode: Memory search handled by backend in live mode'
    };
}

function parseError(errorText) {
    // DEMO MODE ONLY: Basic structural extraction
    // NO static error type classification - the backend LLM handles this
    
    // Detect language from file extensions (structural, not semantic)
    let language = 'unknown';
    if (errorText.includes('.tsx') || errorText.includes('.ts')) language = 'typescript';
    else if (errorText.includes('.js')) language = 'javascript';
    else if (errorText.includes('.py')) language = 'python';
    else if (errorText.includes('.go')) language = 'go';
    else if (errorText.includes('.tf')) language = 'terraform';
    
    // Count frames (structural extraction only)
    const frameCount = (errorText.match(/at\s+\w+/g) || []).length;
    
    return {
        language,
        languageConfidence: language !== 'unknown' ? 85 : 0,
        // NO errorType - LLM will analyze this
        frameCount,
        coreMessage: errorText.split('\n')[0].substring(0, 100),
        rawError: errorText.substring(0, 1000),
        note: 'Demo mode: Full parsing done by backend in live mode'
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
    
    // Generate relevant resources based on error type
    const resources = generateRelevantResources(parsed.errorType, parsed.language, encodedQuery, searchQuery);
    
    return {
        githubCount: resources.github.length,
        stackoverflowCount: resources.stackoverflow.length,
        githubIssues: resources.github,
        stackoverflowQuestions: resources.stackoverflow,
        allResources: resources.all,  // Combined and ranked
        explanation: getErrorExplanation(parsed.errorType),
        searchUrls: {
            github: githubSearchUrl,
            stackoverflow: soSearchUrl
        }
    };
}

function generateRelevantResources(errorType, language, encodedQuery, searchQuery) {
    const github = [];
    const stackoverflow = [];
    
    // DEMO MODE ONLY: Generate search links based on error text
    // NO static error type mapping - just create search URLs from the actual error
    // Real search is done by backend context agent
    
    // Use the searchQuery passed in (already extracted from error)
    const displayQuery = searchQuery.substring(0, 50);
    
    // GitHub search link
    github.push({
        title: `Search GitHub for: "${displayQuery}..."`,
        url: `https://github.com/search?q=${encodedQuery}&type=issues`,
        relevance: 80,
        tags: ['search'],
        source: 'github',
        note: 'Demo mode: Real search done by backend'
    });
    
    // Add language-specific search if detected
    if (language && language !== 'unknown') {
        github.push({
            title: `${language} issues matching this error`,
            url: `https://github.com/search?q=${encodedQuery}+language:${language}&type=issues`,
            relevance: 75,
            tags: ['language-specific'],
            source: 'github',
        });
    }
    
    // Stack Overflow search link
    stackoverflow.push({
        title: `Search Stack Overflow for: "${displayQuery}..."`,
        url: `https://stackoverflow.com/search?q=${encodedQuery}`,
        score: 0,
        answers: 0,
        accepted: false,
        relevance: 80,
        source: 'stackoverflow',
        note: 'Demo mode: Real search done by backend'
    });
    
    // Combine
    const all = [...github, ...stackoverflow].sort((a, b) => b.relevance - a.relevance);
    
    return { github, stackoverflow, all, note: 'Demo mode: Actual resources fetched by backend' };
}

function getErrorExplanation(errorType) {
    // DEMO MODE ONLY: Return generic message
    // Real explanation is generated by backend LLM
    return 'Analysis pending - the backend will provide detailed explanation.';
}

function analyzeRootCause(errorText, parsed, codeContext) {
    // DEMO MODE ONLY: Return placeholder
    // Real root cause analysis is done by backend LLM - no static patterns
    return {
        rootCause: 'Root cause analysis pending - the backend LLM will analyze this error.',
        solution: 'Solution will be generated by the backend.',
        confidence: 0,
        note: 'Demo mode: Actual analysis done by backend rootcause agent'
    };
}

function generateFix(rootCause, language, codeContext) {
    // DEMO MODE ONLY: Return placeholder
    // Real fix generation is done by backend LLM - no static templates
    const fix = {
        fixType: 'pending',
        before: '// Original code',
        after: '// Fix will be generated by backend LLM',
        explanation: 'Fix generation pending - the backend will analyze the error and generate a specific fix.',
        note: 'Demo mode: Actual fix generated by backend fix agent'
    };
    
    // If we have code context, include it for display
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
        const allResources = result.context.allResources || [];
        
        html += `
            <div class="result-section resources fade-in">
                <h3>📚 External Resources</h3>
                <p class="result-text"><strong>What this error means:</strong> ${result.context.explanation}</p>
                
                <div class="resources-list">
                    ${allResources.map((r, i) => `
                        <a href="${r.url}" target="_blank" class="resource-item ${r.source}">
                            <span class="resource-rank">#${i + 1}</span>
                            <span class="resource-icon">${r.source === 'github' ? '🐙' : '📖'}</span>
                            <span class="resource-content">
                                <span class="resource-title">${escapeHtml(r.title)}</span>
                                <span class="resource-meta">
                                    ${r.source === 'stackoverflow' 
                                        ? `<span class="so-score">▲ ${r.score}</span> <span class="so-answers">${r.answers} answers</span> ${r.accepted ? '<span class="so-accepted">✓ Accepted</span>' : ''}`
                                        : `<span class="gh-tags">${(r.tags || []).map(t => `<span class="gh-tag">${t}</span>`).join('')}</span>`
                                    }
                                </span>
                            </span>
                            <span class="resource-relevance" title="Relevance score">
                                <span class="relevance-bar" style="width: ${r.relevance}%"></span>
                                <span class="relevance-text">${r.relevance}%</span>
                            </span>
                        </a>
                    `).join('')}
                </div>
                
                <div class="resources-footer">
                    <a href="${result.context.searchUrls.github}" target="_blank" class="search-more-link">
                        🔍 Search more on GitHub
                    </a>
                    <a href="${result.context.searchUrls.stackoverflow}" target="_blank" class="search-more-link">
                        🔍 Search more on Stack Overflow
                    </a>
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
                <div class="memory-item-text">${m.language} error analyzed</div>
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
        let result;
        
        if (CONFIG.demoMode) {
            // Demo mode: run local simulation
            addLogEntry('Running in DEMO mode (local simulation)', 'info');
            result = await simulateAnalysis(errorText);
        } else {
            // Live mode: call real AgentCore backend
            addLogEntry('Calling AgentCore backend...', 'agent-start');
            result = await callAgentCoreBackend(errorText);
        }
        
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
                <p class="result-text">${escapeHtml(error.message)}</p>
                <p class="result-text hint" style="margin-top: 8px; font-size: 0.75rem;">
                    ${CONFIG.demoMode ? 'Running in demo mode.' : 'Check the CloudWatch logs for more details.'}
                </p>
            </div>
        `;
    } finally {
        state.isAnalyzing = false;
        els.analyzeBtn.disabled = false;
        els.analyzeBtn.innerHTML = '<span class="icon">⚡</span><span>Debug Error</span>';
    }
}

// ===== Live Backend Call =====

async function callAgentCoreBackend(errorText) {
    if (!CONFIG.apiEndpoint) {
        throw new Error('API not configured. Set apiEndpoint in config.');
    }
    
    state.startTime = Date.now();
    state.agentsUsed = 0;
    state.toolsUsed = 0;
    
    // Activate supervisor
    activateNode('node-runtime');
    updateAgentStatus('supervisor', 'running');
    addLogEntry('SUPERVISOR → Connecting to AgentCore...', 'agent-start');
    
    const githubRepo = document.getElementById('githubRepo')?.value?.trim() || '';
    
    // Initialize result structure
    let result = {
        parsed: { language: 'unknown', languageConfidence: 0, frameCount: 0, coreMessage: '' },
        security: { riskLevel: 'low', secretsFound: 0, piiFound: 0, safeToStore: true, recommendations: [] },
        memory: { count: 0, matches: [], hasSolution: false },
        context: { githubCount: 0, stackoverflowCount: 0, allResources: [], explanation: '', searchUrls: {} },
        rootCause: { rootCause: '', confidence: 0, solution: '' },
        fix: { fixType: '', before: '', after: '', explanation: '' },
        stats: { recorded: true, trend: 'stable' },
    };
    
    try {
        // Build request payload
        const payload = {
            error_text: errorText,
            github_repo: githubRepo,
            sessionId: CONFIG.sessionId,
        };
        
        addLogEntry('🚀 Streaming from AgentCore...', 'agent-start');
        
        // Call the API proxy with streaming
        const response = await fetch(`${CONFIG.apiEndpoint}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });
        
        if (!response.ok) {
            const errorData = await response.text();
            throw new Error(`API error ${response.status}: ${errorData}`);
        }
        
        // Parse JSON response (Lambda collects stream and returns structured data)
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Unknown error from AgentCore');
        }
        
        console.log('📥 AgentCore Response:', {
            eventCount: data.eventCount,
            agentActivity: data.agentActivity,
            agents: data.agents,
            result: data.result?.substring?.(0, 500) || data.result
        });
        
        // Process agent activity for UI updates
        if (data.agentActivity) {
            for (const activity of data.agentActivity) {
                if (activity.type === 'tool_call') {
                    addLogEntry(`🔧 ${activity.tool}`, 'tool');
                    if (state) state.toolsUsed++;
                } else if (activity.type === 'tool_result') {
                    addLogEntry(`✅ ${activity.tool} complete`, 'tool-result');
                }
            }
        }
        
        // Use structured agent data if available
        if (data.agents) {
            if (data.agents.parser) {
                result.parsed = {
                    language: data.agents.parser.language || 'unknown',
                    languageConfidence: data.agents.parser.confidence || data.agents.parser.language_confidence || 0,
                    frameCount: data.agents.parser.stack_frames?.length || data.agents.parser.frame_count || 0,
                    // Support multiple field names for core message
                    coreMessage: data.agents.parser.core_message || data.agents.parser.core_error || data.agents.parser.error_message || '',
                    errorType: data.agents.parser.error_type || 'unknown',
                    filePaths: data.agents.parser.file_paths || [],
                    filePath: data.agents.parser.file_path || '',
                    lineNumber: data.agents.parser.line_number || 0,
                    rawData: data.agents.parser
                };
                updateAgentStatus('parser', 'complete');
            }
            
            if (data.agents.security) {
                // Support both count and boolean formats
                const secretsFound = data.agents.security.secrets_found || 
                                     (data.agents.security.secrets_detected ? 1 : 0);
                const piiFound = data.agents.security.pii_found || 
                                 (Array.isArray(data.agents.security.pii_found) ? data.agents.security.pii_found.length : 0) ||
                                 (data.agents.security.pii_detected ? 1 : 0);
                
                result.security = {
                    riskLevel: data.agents.security.risk_level || 'low',
                    secretsFound: secretsFound,
                    piiFound: piiFound,
                    safeToStore: data.agents.security.safe_to_store !== false,
                    recommendations: data.agents.security.recommendations || [],
                    analysis: data.agents.security.analysis || '',
                    rawData: data.agents.security
                };
                updateAgentStatus('security', 'complete');
            }
            
            if (data.agents.context) {
                // Context returns stackoverflow_questions and/or stackoverflow_answers
                const soData = data.agents.context.stackoverflow_answers || data.agents.context.stackoverflow_questions || [];
                const ghData = data.agents.context.github_issues || [];
                
                // Normalize resources with source field for display
                const allResources = [
                    ...ghData.map((r, i) => ({
                        ...r,
                        source: 'github',
                        relevance: r.relevance || (100 - i * 10),
                        tags: r.labels || [],
                    })),
                    ...soData.map((r, i) => ({
                        ...r,
                        source: 'stackoverflow',
                        relevance: r.relevance || (90 - i * 10),
                        answers: r.answer_count || 0,
                        accepted: r.is_answered || false,
                    }))
                ];
                
                // Generate search URLs from the error text
                const searchQuery = encodeURIComponent(els.errorInput?.value?.substring(0, 100) || 'error');
                
                result.context = {
                    githubCount: ghData.length,
                    stackoverflowCount: soData.length,
                    allResources: allResources,
                    explanation: data.agents.context.summary?.recommended_approach || 
                                 data.agents.context.explanation || 
                                 (allResources.length > 0 ? `Found ${allResources.length} relevant resources` : 'No external resources found'),
                    searchUrls: {
                        github: `https://github.com/search?q=${searchQuery}&type=issues`,
                        stackoverflow: `https://stackoverflow.com/search?q=${searchQuery}`
                    },
                    rawData: data.agents.context
                };
                updateAgentStatus('context', 'complete');
            }
            
            if (data.agents.rootcause) {
                result.rootCause = {
                    rootCause: data.agents.rootcause.root_cause || data.agents.rootcause.cause || '',
                    confidence: data.agents.rootcause.confidence || 0,
                    // Use solution field, fallback to explanation
                    solution: data.agents.rootcause.solution || data.agents.rootcause.explanation || '',
                    explanation: data.agents.rootcause.explanation || '',
                    category: data.agents.rootcause.category || '',
                    contributingFactors: data.agents.rootcause.contributing_factors || [],
                    rawData: data.agents.rootcause
                };
                updateAgentStatus('rootcause', 'complete');
            }
            
            if (data.agents.fix) {
                result.fix = {
                    fixType: data.agents.fix.fix_type || '',
                    // Fix agent uses original_pattern/fixed_code, but also support before/after
                    before: data.agents.fix.before || data.agents.fix.original_pattern || '',
                    after: data.agents.fix.after || data.agents.fix.fixed_code || '',
                    explanation: data.agents.fix.explanation || '',
                    // Support both additional_changes and prevention arrays
                    additionalChanges: data.agents.fix.additional_changes || data.agents.fix.prevention || [],
                    isValid: data.agents.fix.is_valid !== false,
                    testCode: data.agents.fix.test_code || '',
                    rawData: data.agents.fix
                };
                updateAgentStatus('fix', 'complete');
            }
            
            if (data.agents.memory) {
                const matches = data.agents.memory.matches || data.agents.memory.similar_errors || [];
                result.memory = {
                    count: matches.length,
                    matches: matches,
                    hasSolution: data.agents.memory.has_solution || false,
                    analysis: data.agents.memory.analysis || '',
                    rawData: data.agents.memory
                };
            }
            
            if (data.agents.stats) {
                result.stats = {
                    recorded: data.agents.stats.recorded !== false,
                    trend: data.agents.stats.trend || 'stable',
                    rawData: data.agents.stats
                };
            }
            
            // Use summary for comprehensive display
            if (data.agents.summary) {
                const summary = data.agents.summary;
                result.summary = summary;
                
                // Override with summary data if available (more reliable)
                if (summary.language && summary.language !== 'unknown') {
                    result.parsed.language = summary.language;
                    result.parsed.languageConfidence = summary.languageConfidence || 0;
                }
                if (summary.errorType && summary.errorType !== 'unknown') {
                    result.parsed.errorType = summary.errorType;
                }
                if (summary.coreMessage) {
                    result.parsed.coreMessage = summary.coreMessage;
                }
                if (summary.rootCause) {
                    result.rootCause.rootCause = summary.rootCause;
                    result.rootCause.confidence = summary.rootCauseConfidence || 0;
                    result.rootCause.solution = summary.solution || '';
                }
                if (summary.fixAfter) {
                    result.fix.fixType = summary.fixType || '';
                    result.fix.before = summary.fixBefore || '';
                    result.fix.after = summary.fixAfter || '';
                    result.fix.explanation = summary.fixExplanation || '';
                }
                if (summary.riskLevel) {
                    result.security.riskLevel = summary.riskLevel;
                }
                
                console.log('📋 Summary applied:', summary);
            }
        }
        
        // Also parse the final result text for any additional info
        if (data.result && typeof data.result === 'string') {
            result = parseAgentResponse(data.result, result);
        }
        
        // Store raw response for debugging
        result.rawResponse = data;
        
        // Mark supervisor complete
        updateAgentStatus('supervisor', 'complete');
        deactivateNode('node-runtime');
        addLogEntry('✅ Analysis complete!', 'agent-complete');
        
        return result;
        
    } catch (error) {
        console.error('AgentCore error:', error);
        updateAgentStatus('supervisor', 'error');
        deactivateNode('node-runtime');
        addLogEntry(`❌ Error: ${error.message}`, 'error');
        throw error;
    }
}

// Helper to extract tool name from event (kept for compatibility)
function extractToolName(event) {
    if (event.event?.contentBlockStart?.start?.toolUse?.name) {
        return event.event.contentBlockStart.start.toolUse.name;
    }
    if (event.toolUse?.name) return event.toolUse.name;
    if (event.tool_use?.name) return event.tool_use.name;
    if (event.name) return event.name;
    if (event.tool) return event.tool;
    return null;
}

function processTrace(trace) {
    // Process AgentCore trace data to update UI
    if (trace.orchestrationTrace) {
        const orch = trace.orchestrationTrace;
        if (orch.invocationInput?.actionGroupInvocationInput) {
            const action = orch.invocationInput.actionGroupInvocationInput;
            addLogEntry(`🔧 Tool: ${action.function || 'unknown'}`, 'tool');
        }
    }
}

function handleStatusUpdate(status) {
    const { component, status: state, message, error } = status;
    
    // Map component to agent
    const agentMap = {
        parser: 'parser',
        security: 'security',
        context: 'context',
        rootcause: 'rootcause',
        fix: 'fix',
        memory: 'memory',
        stats: 'stats',
        github_file: 'context',
    };
    
    const agent = agentMap[component];
    if (!agent) return;
    
    if (state === 'running') {
        updateAgentStatus(agent, 'running');
        addLogEntry(`${component.toUpperCase()} → ${message || 'Processing...'}`, 'agent-start');
        if (window.state) window.state.agentsUsed++;
    } else if (state === 'success') {
        updateAgentStatus(agent, 'complete');
        addLogEntry(`${component.toUpperCase()} ✓ ${message || 'Complete'}`, 'agent-complete');
        if (window.state) window.state.toolsUsed++;
    } else if (state === 'error') {
        updateAgentStatus(agent, 'error');
        addLogEntry(`${component.toUpperCase()} ❌ ${error || 'Failed'}`, 'error');
    }
    
    updateStats();
}

function updateAgentStatus(agent, status) {
    const statusEl = document.getElementById(`${agent}Status`);
    const agentEl = document.getElementById(`agent-${agent}`);
    
    if (statusEl) {
        statusEl.textContent = status === 'running' ? 'running' : status === 'complete' ? 'done' : status === 'error' ? 'error' : 'idle';
        statusEl.className = `agent-status ${status === 'running' ? 'running' : status === 'complete' ? 'complete' : status === 'error' ? 'error' : ''}`;
    }
    
    if (agentEl) {
        agentEl.classList.remove('active', 'complete', 'error');
        if (status === 'running') agentEl.classList.add('active');
        else if (status === 'complete') agentEl.classList.add('complete');
        else if (status === 'error') agentEl.classList.add('error');
    }
}

function updateStreamingResults(content) {
    // Show streaming markdown content
    if (els.resultsContent) {
        // Remove status markers for display
        const cleanContent = content.replace(/\[\[STATUS:.*?\]\]/g, '');
        
        if (cleanContent.trim()) {
            els.resultsContent.innerHTML = `
                <div class="result-section streaming fade-in">
                    <h3>📡 Live Response</h3>
                    <pre class="streaming-content">${escapeHtml(cleanContent)}</pre>
                </div>
            `;
        }
    }
}

function parseAgentResponse(responseText, defaultResult) {
    // Remove status markers
    const cleanResponse = responseText.replace(/\[\[STATUS:.*?\]\]/g, '');
    
    // Try to extract structured data from the response
    const result = { ...defaultResult };
    
    // Extract language
    const langMatch = cleanResponse.match(/\*\*Language\*\*:\s*(\w+)/i) || 
                      cleanResponse.match(/Language:\s*(\w+)/i);
    if (langMatch) {
        result.parsed.language = langMatch[1].toLowerCase();
        result.parsed.languageConfidence = 85;
    }
    
    // Extract error type
    const typeMatch = cleanResponse.match(/\*\*Error Type\*\*:\s*(\w+)/i) ||
                      cleanResponse.match(/Error Type:\s*(\w+)/i) ||
                      cleanResponse.match(/\*\*Type\*\*:\s*(\w+)/i);
    if (typeMatch) {
        result.parsed.errorType = typeMatch[1].toLowerCase();
    }
    
    // Extract confidence
    const confMatch = cleanResponse.match(/\*\*Confidence\*\*:\s*(\d+)/i) ||
                      cleanResponse.match(/Confidence:\s*(\d+)/i);
    if (confMatch) {
        result.rootCause.confidence = parseInt(confMatch[1]);
    }
    
    // Extract root cause
    const rootCauseMatch = cleanResponse.match(/### 🎯 Root Cause\s*\n([\s\S]*?)(?=\n###|\n##|$)/i) ||
                           cleanResponse.match(/\*\*Root Cause\*\*:\s*([^\n]+)/i);
    if (rootCauseMatch) {
        result.rootCause.rootCause = rootCauseMatch[1].trim();
    }
    
    // Extract fix code
    const fixMatch = cleanResponse.match(/```(\w+)?\n([\s\S]*?)```/);
    if (fixMatch) {
        result.fix.after = fixMatch[2].trim();
        result.fix.fixType = 'code_fix';
    }
    
    // Store the raw response for display
    result.rawResponse = cleanResponse;
    
    return result;
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
        
        const components = ['runtime', 'gateway', 'memory', 'parser', 'security', 'context', 'stats'];
        const levels = ['INFO', 'INFO', 'INFO', 'WARN', 'ERROR'];
        
        // If we've run an analysis, generate logs for that
        if (state.shortTermMemory.length > 0) {
            const analysis = state.shortTermMemory[state.shortTermMemory.length - 1];
            
            logs.push(
                { timestamp: now - 5000, component: 'runtime', level: 'INFO', message: 'Received analysis request' },
                { timestamp: now - 4800, component: 'runtime', level: 'INFO', message: '🚀 Error Debugger started (mode: comprehensive)' },
                { timestamp: now - 4600, component: 'runtime', level: 'INFO', message: `📥 Input: ${analysis.language} error received` },
                { timestamp: now - 4400, component: 'parser', level: 'INFO', message: `Parsing error text (${Math.floor(Math.random() * 500 + 100)} chars)` },
                { timestamp: now - 4200, component: 'parser', level: 'INFO', message: `✅ Detected language: ${analysis.language}` },
                { timestamp: now - 4000, component: 'security', level: 'INFO', message: 'Scanning for PII and secrets...' },
                { timestamp: now - 3800, component: 'security', level: 'INFO', message: '✅ Security scan complete - no sensitive data found' },
                { timestamp: now - 3500, component: 'runtime', level: 'INFO', message: '🎯 Invoking RootCauseAgent' },
                { timestamp: now - 3200, component: 'runtime', level: 'INFO', message: `✅ RootCauseAgent returned: 85% confidence` },
                { timestamp: now - 3000, component: 'runtime', level: 'INFO', message: `🔧 Invoking FixAgent for ${analysis.language}` },
                { timestamp: now - 2700, component: 'runtime', level: 'INFO', message: '✅ FixAgent returned fix' },
                { timestamp: now - 2500, component: 'stats', level: 'INFO', message: `Recording ${analysis.language} error occurrence` },
                { timestamp: now - 2300, component: 'runtime', level: 'INFO', message: 'Analysis complete, streaming response' },
            );
        }
        
        // Add some background noise logs
        for (let i = 0; i < 15; i++) {
            const component = components[Math.floor(Math.random() * components.length)];
            const level = levels[Math.floor(Math.random() * levels.length)];
            const offset = Math.floor(Math.random() * 60000);
            
            const messages = {
                runtime: ['Heartbeat check', 'Memory usage: 245MB', 'Active sessions: 1', 'Tool execution complete'],
                gateway: ['MCP request received', 'Routing to Lambda', 'Tool invocation complete', 'Response streaming'],
                memory: ['Semantic search initiated', 'Found 3 matching patterns', 'Context stored', 'Session updated'],
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
            // Determine component from log group name or component field
            let component = log.component || 'runtime';
            if (!log.component && log.logGroup) {
                if (log.logGroup.includes('parser')) component = 'parser';
                else if (log.logGroup.includes('security')) component = 'security';
                else if (log.logGroup.includes('context')) component = 'context';
                else if (log.logGroup.includes('stats')) component = 'stats';
                else component = 'runtime';
            }
            
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

