/**
 * NoLangX Static Code Analyzer
 * Slither-like pattern matching for Solidity vulnerability detection
 * Outputs risk score 0-100 and detailed issue list
 */

export interface AuditIssue {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'reentrancy' | 'overflow' | 'access_control' | 'initialization' | 'other';
  line: number;
  pattern: string;
  description: string;
  recommendation: string;
}

export interface AuditReport {
  code: string;
  riskScore: number; // 0-100
  issues: AuditIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  passed: boolean;
  timestamp: number;
}

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0
};

/**
 * Check for reentrancy vulnerabilities
 * Pattern: external calls before state updates (checks-effects-interactions violation)
 */
function checkReentrancy(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Track state variables and external calls
  const stateVarPattern = /(?:public|private|internal)?\s*(?:uint|address|bool|mapping|struct)\s+\w+\s*;/g;
  const externalCallPattern = /(?:call|send|transfer|staticcall|delegatecall)\s*\(/g;
  const stateWritePattern = /(?:\w+\s*=|\+\+=|\-\-=|\*\*=|\/\/=|%\%=)/g;
  
  let inFunction = false;
  let functionStartLine = 0;
  let hasStateWrite = false;
  let hasExternalCall = false;
  let externalCallLine = 0;
  let lastStateWriteLine = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    // Detect function start
    if (/function\s+\w+\s*\(/.test(line)) {
      inFunction = true;
      functionStartLine = lineNum;
      hasStateWrite = false;
      hasExternalCall = false;
    }
    
    // Detect function end
    if (inFunction && /^\s*\}\s*$/.test(line)) {
      // Check if external call happened before state update
      if (hasExternalCall && hasStateWrite && externalCallLine < lastStateWriteLine) {
        issues.push({
          severity: 'critical',
          category: 'reentrancy',
          line: externalCallLine,
          pattern: 'external-call-before-state-update',
          description: 'External call made before state variable update - potential reentrancy vulnerability',
          recommendation: 'Follow checks-effects-interactions pattern: update state before making external calls'
        });
      }
      inFunction = false;
    }
    
    if (inFunction) {
      if (stateWritePattern.test(line)) {
        hasStateWrite = true;
        lastStateWriteLine = lineNum;
      }
      if (externalCallPattern.test(line)) {
        hasExternalCall = true;
        externalCallLine = lineNum;
      }
    }
  }
  
  // Check for .call() without reentrancy guard
  const callWithoutGuard = /\.call\s*\(/g;
  let match;
  while ((match = callWithoutGuard.exec(code)) !== null) {
    const beforeCall = code.substring(0, match.index);
    if (!/nonReentrant|ReentrancyGuard|mutex/.test(beforeCall)) {
      const lineNum = (beforeCall.match(/\n/g) || []).length + 1;
      issues.push({
        severity: 'high',
        category: 'reentrancy',
        line: lineNum,
        pattern: 'call-without-reentrancy-guard',
        description: 'Low-level .call() used without reentrancy protection',
        recommendation: 'Use OpenZeppelin ReentrancyGuard or implement mutex lock'
      });
    }
  }
  
  return issues;
}

/**
 * Check for arithmetic overflow/underflow
 * Pattern: uint256 arithmetic without SafeMath or Solidity 0.8+ checked arithmetic
 */
function checkOverflow(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check pragma version
  const pragmaMatch = code.match(/pragma\s+solidity\s+\^?([0-9]+)\.([0-9]+)\.([0-9]+)/);
  const hasSafeVersion = pragmaMatch && (
    parseInt(pragmaMatch[1]) > 0 || 
    (parseInt(pragmaMatch[1]) === 0 && parseInt(pragmaMatch[2]) >= 8)
  );
  
  // Check for SafeMath import
  const hasSafeMath = /import.*SafeMath|using\s+SafeMath/.test(code);
  
  // If Solidity 0.8+ or SafeMath, overflow is handled
  if (hasSafeVersion || hasSafeMath) {
    return issues;
  }
  
  // Check for unsafe arithmetic operations on uint256
  const unsafeOps = [
    { pattern: /uint256\s+\w+\s*=\s*\w+\s*\+\s*\w+/g, op: 'addition' },
    { pattern: /uint256\s+\w+\s*=\s*\w+\s*-\s*\w+/g, op: 'subtraction' },
    { pattern: /uint256\s+\w+\s*=\s*\w+\s*\*\s*\w+/g, op: 'multiplication' },
    { pattern: /\+\+=|\-\-=|\*\*=/g, op: 'compound' }
  ];
  
  for (const { pattern, op } of unsafeOps) {
    let match;
    while ((match = pattern.exec(code)) !== null) {
      const beforeMatch = code.substring(0, match.index);
      const lineNum = (beforeMatch.match(/\n/g) || []).length + 1;
      issues.push({
        severity: 'high',
        category: 'overflow',
        line: lineNum,
        pattern: `unsafe-${op}`,
        description: `Arithmetic ${op} on uint256 without overflow protection (Solidity <0.8.0 without SafeMath)`,
        recommendation: 'Upgrade to Solidity 0.8+ or use OpenZeppelin SafeMath library'
      });
    }
  }
  
  // Check for unchecked blocks in 0.8+
  const uncheckedPattern = /unchecked\s*\{/g;
  let uncheckedMatch;
  while ((uncheckedMatch = uncheckedPattern.exec(code)) !== null) {
    const beforeUncheck = code.substring(0, uncheckedMatch.index);
    const lineNum = (beforeUncheck.match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'medium',
      category: 'overflow',
      line: lineNum,
      pattern: 'unchecked-block',
      description: 'Unchecked arithmetic block - overflow/underflow not caught',
      recommendation: 'Ensure unchecked block is intentional and values are bounded'
    });
  }
  
  return issues;
}

/**
 * Check for access control vulnerabilities
 * Pattern: sensitive functions missing onlyOwner or role-based access
 */
function checkAccessControl(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check for Ownable import
  const hasOwnable = /import.*Ownable|is\s+Ownable/.test(code);
  
  // Sensitive function patterns that should have access control
  const sensitivePatterns = [
    /function\s+(withdraw|transferOwnership|pause|unpause|mint|burn|set)/,
    /function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^}]*\{[^}]*(?:balanceOf|onlyOwner|msg\.sender)/
  ];
  
  let inFunction = false;
  let functionName = '';
  let functionLine = 0;
  let hasAccessControl = false;
  let functionBody = '';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    // Detect function start with sensitive names
    const funcMatch = line.match(/function\s+(\w+)\s*\([^)]*\)\s*(external|public|internal|private)?/);
    if (funcMatch) {
      inFunction = true;
      functionName = funcMatch[1];
      functionLine = lineNum;
      hasAccessControl = /onlyOwner|onlyRole|accessControl|require\s*\([^,]*sender/.test(line);
      functionBody = '';
    }
    
    if (inFunction) {
      functionBody += line + '\n';
      
      // Check for access control modifiers in function body
      if (/onlyOwner|onlyRole|modifier/.test(line)) {
        hasAccessControl = true;
      }
      
      // Check for require sender checks
      if (/require\s*\([^)]*msg\.sender/.test(line)) {
        hasAccessControl = true;
      }
      
      // Detect function end
      if (/^\s*\}\s*$/.test(line) && functionBody.split('\n').length > 1) {
        // Check if function is sensitive and lacks access control
        const isSensitive = sensitivePatterns.some(p => p.test(`function ${functionName}`));
        const isExternalPublic = /external|public/.test(functionBody);
        const modifiesState = /[=+\-*/%]=|\+\+|--/.test(functionBody);
        
        if (isSensitive && isExternalPublic && modifiesState && !hasAccessControl) {
          issues.push({
            severity: 'critical',
            category: 'access_control',
            line: functionLine,
            pattern: 'missing-access-control',
            description: `Function '${functionName}' modifies state but lacks access control modifier`,
            recommendation: 'Add onlyOwner modifier or implement role-based access control'
          });
        }
        
        inFunction = false;
      }
    }
  }
  
  // Check for owner variable without protection
  if (/address\s+owner\s*=/.test(code) && !/onlyOwner/.test(code)) {
    issues.push({
      severity: 'high',
      category: 'access_control',
      line: 1,
      pattern: 'unprotected-owner',
      description: 'Owner variable defined but no access control enforcement found',
      recommendation: 'Use OpenZeppelin Ownable contract for standardized access control'
    });
  }
  
  return issues;
}

/**
 * Check for initialization vulnerabilities
 * Pattern: missing constructor initialization, uninitialized proxies
 */
function checkInitialization(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check if contract uses proxy pattern (has initializer)
  const isProxy = /initializer|Initializable/.test(code);
  
  // Check for constructor
  const hasConstructor = /constructor\s*\(/.test(code);
  
  // Check for critical state variables
  const criticalVars = [
    { pattern: /address\s+(owner|admin|treasury)/, name: 'owner/admin' },
    { pattern: /uint256\s+(totalSupply|maxSupply)/, name: 'supply' },
    { pattern: /bool\s+(initialized|paused)/, name: 'state flag' }
  ];
  
  let constructorBody = '';
  let inConstructor = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (/constructor\s*\(/.test(line)) {
      inConstructor = true;
      constructorBody = '';
    }
    
    if (inConstructor) {
      constructorBody += line + '\n';
      if (/^\s*\}\s*$/.test(line)) {
        inConstructor = false;
      }
    }
  }
  
  // Check for uninitialized critical variables
  for (const { pattern, name } of criticalVars) {
    const varMatch = code.match(pattern);
    if (varMatch) {
      const varName = varMatch[0].match(/(owner|admin|treasury|totalSupply|maxSupply|initialized|paused)/)?.[0];
      if (varName) {
        // Check if initialized in constructor
        const initPattern = new RegExp(`${varName}\\s*=`);
        if (!initPattern.test(constructorBody) && !initPattern.test(code.substring(0, code.indexOf('constructor')))) {
          const lineNum = (code.substring(0, varMatch.index).match(/\n/g) || []).length + 1;
          issues.push({
            severity: 'high',
            category: 'initialization',
            line: lineNum,
            pattern: 'uninitialized-critical-var',
            description: `Critical variable '${varName}' may not be properly initialized`,
            recommendation: 'Initialize all critical state variables in constructor or initializer function'
          });
        }
      }
    }
  }
  
  // Check for proxy initialization pattern
  if (isProxy && !/function\s+initialize\s*\(/.test(code)) {
    issues.push({
      severity: 'critical',
      category: 'initialization',
      line: 1,
      pattern: 'missing-proxy-initializer',
      description: 'Proxy-compatible contract missing initialize() function',
      recommendation: 'Implement initialize() function with initializer modifier for upgradeable contracts'
    });
  }
  
  // Check for constructor with no parameters but state variables exist
  const stateVars = code.match(/(?:uint|address|bool|mapping)\s+\w+\s*;/g) || [];
  if (hasConstructor && stateVars.length > 0 && !/\(.*\)/.test(code.match(/constructor\s*\([^)]*\)/)?.[0] || '')) {
    // Constructor exists but may not initialize all vars
    const initCount = (constructorBody.match(/=\s*[^;]+;/g) || []).length;
    if (initCount < stateVars.length / 2) {
      issues.push({
        severity: 'medium',
        category: 'initialization',
        line: 1,
        pattern: 'partial-initialization',
        description: 'Constructor may not initialize all state variables',
        recommendation: 'Ensure all state variables are explicitly initialized in constructor'
      });
    }
  }
  
  return issues;
}

/**
 * Additional Mythril-inspired heuristics
 */
function checkHeuristics(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  
  // Check for tx.origin usage (phishing vulnerability)
  if (/tx\.origin/.test(code)) {
    const lineNum = (code.substring(0, code.indexOf('tx.origin')).match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'critical',
      category: 'access_control',
      line: lineNum,
      pattern: 'tx-origin-usage',
      description: 'tx.origin used for authentication - vulnerable to phishing attacks',
      recommendation: 'Use msg.sender instead of tx.origin for access control'
    });
  }
  
  // Check for block.timestamp usage in critical logic
  if (/block\.(timestamp|number)/.test(code)) {
    const lineNum = (code.substring(0, code.indexOf('block.')).match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'medium',
      category: 'other',
      line: lineNum,
      pattern: 'timestamp-dependency',
      description: 'Contract logic depends on block.timestamp - miners can manipulate',
      recommendation: 'Avoid using block.timestamp for critical randomness or timing'
    });
  }
  
  // Check for low-level calls without validation
  if (/\.call\s*\(.*\)\s*;/g.test(code) && !/success.*=.*\.call/.test(code)) {
    const lineNum = (code.substring(0, code.indexOf('.call')).match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'high',
      category: 'other',
      line: lineNum,
      pattern: 'unchecked-call-return',
      description: 'Low-level call return value not checked',
      recommendation: 'Always check the return value of .call() and handle failures'
    });
  }
  
  // Check for selfdestruct
  if (/selfdestruct\(/.test(code)) {
    const lineNum = (code.substring(0, code.indexOf('selfdestruct')).match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'high',
      category: 'other',
      line: lineNum,
      pattern: 'selfdestruct-usage',
      description: 'selfdestruct used - contract can be forcibly terminated',
      recommendation: 'Ensure selfdestruct is protected and intentional'
    });
  }
  
  // Check for delegatecall to external address
  if (/delegatecall\(/.test(code)) {
    const lineNum = (code.substring(0, code.indexOf('delegatecall')).match(/\n/g) || []).length + 1;
    issues.push({
      severity: 'critical',
      category: 'other',
      line: lineNum,
      pattern: 'delegatecall-usage',
      description: 'delegatecall to potentially untrusted address - storage corruption risk',
      recommendation: 'Whitelist delegatecall targets and validate addresses'
    });
  }
  
  return issues;
}

/**
 * Calculate risk score based on issues found
 */
function calculateRiskScore(issues: AuditIssue[]): number {
  let score = 0;
  for (const issue of issues) {
    score += SEVERITY_WEIGHTS[issue.severity];
  }
  return Math.min(100, score);
}

/**
 * Generate summary counts by severity
 */
function generateSummary(issues: AuditIssue[]): AuditReport['summary'] {
  return {
    critical: issues.filter(i => i.severity === 'critical').length,
    high: issues.filter(i => i.severity === 'high').length,
    medium: issues.filter(i => i.severity === 'medium').length,
    low: issues.filter(i => i.severity === 'low').length,
    info: issues.filter(i => i.severity === 'info').length
  };
}

/**
 * Main audit function - analyzes Solidity code and returns audit report
 * @param code - Solidity source code to analyze
 * @returns AuditReport with risk score and issues list
 */
export function auditContract(code: string): AuditReport {
  // Run all checks
  const reentrancyIssues = checkReentrancy(code);
  const overflowIssues = checkOverflow(code);
  const accessControlIssues = checkAccessControl(code);
  const initializationIssues = checkInitialization(code);
  const heuristicIssues = checkHeuristics(code);
  
  // Combine all issues
  const allIssues = [
    ...reentrancyIssues,
    ...overflowIssues,
    ...accessControlIssues,
    ...initializationIssues,
    ...heuristicIssues
  ];
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  // Calculate metrics
  const riskScore = calculateRiskScore(allIssues);
  const summary = generateSummary(allIssues);
  
  return {
    code,
    riskScore,
    issues: allIssues,
    summary,
    passed: riskScore < 25, // Pass if risk score is low
    timestamp: Date.now()
  };
}

/**
 * Format audit report as human-readable string
 */
export function formatAuditReport(report: AuditReport): string {
  const status = report.passed ? '✅ PASSED' : '❌ FAILED';
  let output = `\n=== NoLangX Audit Report ===\n`;
  output += `Status: ${status}\n`;
  output += `Risk Score: ${report.riskScore}/100\n`;
  output += `Issues Found: ${report.issues.length}\n`;
  output += `  Critical: ${report.summary.critical}\n`;
  output += `  High: ${report.summary.high}\n`;
  output += `  Medium: ${report.summary.medium}\n`;
  output += `  Low: ${report.summary.low}\n`;
  output += `\n--- Detailed Issues ---\n`;
  
  if (report.issues.length === 0) {
    output += 'No issues detected.\n';
  } else {
    for (const issue of report.issues) {
      output += `\n[${issue.severity.toUpperCase()}] ${issue.category}\n`;
      output += `  Line ${issue.line}: ${issue.description}\n`;
      output += `  Pattern: ${issue.pattern}\n`;
      output += `  Fix: ${issue.recommendation}\n`;
    }
  }
  
  return output;
}

export default { auditContract, formatAuditReport };
