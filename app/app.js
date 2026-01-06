/**
 * Error Debugger - AgentCore Multi-Agent Demo
 * Frontend for the error debugging multi-agent system
 */

// ===== Configuration =====
const CONFIG = {
    apiEndpoint: window.AGENTCORE_CONFIG?.apiEndpoint || '/api',
    sessionId: 'sess_' + Math.random().toString(36).substring(2, 10),
    demoMode: true, // Always use simulation for demo
};

// ===== State =====
const state = {
    isAnalyzing: false,
    startTime: null,
    agentsUsed: 0,
    toolsUsed: 0,
    shortTermMemory: [],
    longTermMemory: [],
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
        
        orchestrationEmpty: document.getElementById('orchestrationEmpty'),
        orchestrationFlow: document.getElementById('orchestrationFlow'),
        
        agentCount: document.getElementById('agentCount'),
        toolCount: document.getElementById('toolCount'),
        execTime: document.getElementById('execTime'),
        
        resultsContent: document.getElementById('resultsContent'),
        
        shortTermCount: document.getElementById('shortTermCount'),
        longTermCount: document.getElementById('longTermCount'),
        shortTermList: document.getElementById('shortTermList'),
        longTermList: document.getElementById('longTermList'),
        
        // Agent cards
        supervisorCard: document.getElementById('supervisorCard'),
        parserCard: document.getElementById('parserCard'),
        securityCard: document.getElementById('securityCard'),
        memoryCard: document.getElementById('memoryCard'),
        contextCard: document.getElementById('contextCard'),
        rootcauseCard: document.getElementById('rootcauseCard'),
        fixCard: document.getElementById('fixCard'),
        statsCard: document.getElementById('statsCard'),
        
        // Agent statuses
        supervisorStatus: document.getElementById('supervisorStatus'),
        parserStatus: document.getElementById('parserStatus'),
        securityStatus: document.getElementById('securityStatus'),
        memoryStatus: document.getElementById('memoryStatus'),
        contextStatus: document.getElementById('contextStatus'),
        rootcauseStatus: document.getElementById('rootcauseStatus'),
        fixStatus: document.getElementById('fixStatus'),
        statsStatus: document.getElementById('statsStatus'),
        
        // Agent outputs
        parserOutput: document.getElementById('parserOutput'),
        securityOutput: document.getElementById('securityOutput'),
        memoryOutput: document.getElementById('memoryOutput'),
        contextOutput: document.getElementById('contextOutput'),
        rootcauseOutput: document.getElementById('rootcauseOutput'),
        fixOutput: document.getElementById('fixOutput'),
    };
}

// ===== Simulation =====
async function simulateAnalysis(errorText) {
    state.startTime = Date.now();
    state.agentsUsed = 0;
    state.toolsUsed = 0;
    
    const result = {
        parsed: null,
        security: null,
        memory: null,
        context: null,
        rootCause: null,
        fix: null,
        stats: null,
    };
    
    // 1. Supervisor starts
    await runAgent('supervisor', 'Analyzing error...', 200);
    
    // 2. Memory search (first!)
    await runAgent('memory', 'Searching similar errors...', 300);
    state.toolsUsed += 1;
    result.memory = searchMemory(errorText);
    updateAgentOutput('memory', result.memory.count > 0 ? 
        `Found ${result.memory.count} similar errors!` : 'No matches found');
    
    // 3. Parser
    await runAgent('parser', 'Parsing stack trace...', 400);
    state.toolsUsed += 4; // regex, AST, comprehend, classify
    result.parsed = parseError(errorText);
    updateAgentOutput('parser', 
        `${result.parsed.language} | ${result.parsed.errorType}`);
    
    // 4. Security
    await runAgent('security', 'Scanning for PII/secrets...', 300);
    state.toolsUsed += 3; // PII, secrets, redact
    result.security = scanSecurity(errorText);
    updateAgentOutput('security', 
        `Risk: ${result.security.riskLevel} | ${result.security.secretsFound} secrets`);
    
    // 5. Context (external APIs)
    await runAgent('context', 'Searching GitHub, StackOverflow...', 500);
    state.toolsUsed += 3; // github, stackoverflow, docs
    result.context = getContext(errorText, result.parsed);
    updateAgentOutput('context', 
        `${result.context.githubCount} issues, ${result.context.stackoverflowCount} answers`);
    
    // 6. Root Cause
    await runAgent('rootcause', 'Analyzing root cause...', 400);
    state.toolsUsed += 2; // patterns, LLM
    result.rootCause = analyzeRootCause(errorText, result.parsed);
    updateAgentOutput('rootcause', 
        `${result.rootCause.confidence}% confidence`);
    
    // 7. Fix
    await runAgent('fix', 'Generating fix...', 500);
    state.toolsUsed += 3; // generate, validate, test
    result.fix = generateFix(result.rootCause, result.parsed.language);
    updateAgentOutput('fix', 
        `${result.fix.fixType} | Syntax valid`);
    
    // 8. Stats
    await runAgent('stats', 'Recording statistics...', 150);
    state.toolsUsed += 2; // record, trend
    result.stats = recordStats(result.parsed);
    
    state.agentsUsed = 7;
    
    return result;
}

async function runAgent(agent, message, delay) {
    const statusEl = els[`${agent}Status`];
    const cardEl = els[`${agent}Card`];
    
    if (statusEl) statusEl.textContent = 'running';
    if (statusEl) statusEl.className = 'agent-status running';
    if (cardEl) cardEl.classList.add('running');
    
    await sleep(delay);
    
    if (statusEl) statusEl.textContent = 'done';
    if (statusEl) statusEl.className = 'agent-status complete';
    if (cardEl) cardEl.classList.remove('running');
    if (cardEl) cardEl.classList.add('complete');
}

function updateAgentOutput(agent, text) {
    const outputEl = els[`${agent}Output`];
    if (outputEl) {
        outputEl.textContent = text;
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
    // Simulated external API results
    return {
        githubCount: Math.floor(Math.random() * 15) + 3,
        stackoverflowCount: Math.floor(Math.random() * 10) + 2,
        githubIssues: [
            { title: `Similar ${parsed.errorType} issue`, url: '#', state: 'closed' },
            { title: 'Related error handling', url: '#', state: 'open' },
        ],
        stackoverflowQuestions: [
            { title: `How to fix ${parsed.errorType}?`, url: '#', score: 127, answered: true },
            { title: 'Debugging tips', url: '#', score: 45, answered: true },
        ],
        explanation: getErrorExplanation(parsed.errorType),
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

function analyzeRootCause(errorText, parsed) {
    const causes = {
        null_reference: {
            rootCause: 'Array or object is undefined when accessed. Likely async data not loaded yet.',
            solution: 'Add null check or optional chaining before accessing properties.',
            confidence: 90,
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

function generateFix(rootCause, language) {
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
    return langFixes.null_reference || {
        fixType: 'error_handling',
        before: 'riskyOperation()',
        after: 'try {\n  riskyOperation()\n} catch (e) {\n  handleError(e)\n}',
        explanation: 'Wrap in try-catch for error handling',
    };
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
    let html = '';
    
    // Memory match (if found)
    if (result.memory.hasSolution) {
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
    html += `
        <div class="result-section fix fade-in">
            <h3>🔧 Suggested Fix</h3>
            <span class="result-badge positive">${result.fix.fixType}</span>
            <p class="result-text" style="margin-top: 8px"><strong>Before:</strong></p>
            <div class="result-code">${result.fix.before}</div>
            <p class="result-text"><strong>After:</strong></p>
            <div class="result-code">${result.fix.after}</div>
            <p class="result-text">${result.fix.explanation}</p>
        </div>
    `;
    
    // External Resources
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
    
    // Stats
    const execTime = ((Date.now() - state.startTime) / 1000).toFixed(1);
    html += `
        <div class="result-section fade-in">
            <h3>📊 Analysis Metrics</h3>
            <p class="result-text">
                <strong>Agents Used:</strong> ${state.agentsUsed}<br>
                <strong>Tool Calls:</strong> ${state.toolsUsed}<br>
                <strong>Execution Time:</strong> ${execTime}s<br>
                <strong>Trend:</strong> ${result.stats.trend}
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
    
    // Show orchestration flow
    els.orchestrationEmpty.style.display = 'none';
    els.orchestrationFlow.style.display = 'flex';
    
    // Reset agent cards
    document.querySelectorAll('.agent-card').forEach(card => {
        card.classList.remove('running', 'complete');
    });
    document.querySelectorAll('.agent-status').forEach(status => {
        status.textContent = 'idle';
        status.className = 'agent-status';
    });
    document.querySelectorAll('.agent-output').forEach(output => {
        output.textContent = '';
    });
    
    // Show loading in results
    els.resultsContent.innerHTML = '<div class="loading">Analyzing error...</div>';
    
    try {
        const result = await simulateAnalysis(errorText);
        displayResults(result);
        updateMemoryDisplay();
        els.copyBtn.disabled = false;
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

function loadSample() {
    const sample = SAMPLE_ERRORS[Math.floor(Math.random() * SAMPLE_ERRORS.length)];
    els.errorInput.value = sample;
}

function copyResults() {
    const text = els.resultsContent.innerText;
    navigator.clipboard.writeText(text);
    alert('Results copied to clipboard!');
}

// ===== Initialization =====

function init() {
    console.log('🔍 Error Debugger initializing...');
    
    initElements();
    
    // Set session ID
    if (els.sessionId) {
        els.sessionId.textContent = CONFIG.sessionId;
    }
    
    // Initialize memory display
    updateMemoryDisplay();
    
    // Event listeners
    els.analyzeBtn?.addEventListener('click', runAnalysis);
    els.loadSampleBtn?.addEventListener('click', loadSample);
    els.copyBtn?.addEventListener('click', copyResults);
    
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

