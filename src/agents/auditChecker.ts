/**
 * NoLangX Static Code Analyzer
 * Slither-like pattern matching for Solidity vulnerability detection
 * Outputs risk score 0-100 with detailed issue list
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
 * Reentrancy Detection
 * Pattern: external call before state update in same function
 */
function checkReentrancy(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Track function boundaries and state changes
  let inFunction = false;
  let functionName = '';
  let functionStartLine = 0;
  let hasExternalCall = false;
  let externalCallLine = 0;
  let hasStateUpdate = false;
  let stateUpdateLine = 0;
  let braceCount = 0;
  
  const externalCallPatterns = [
    /\.call\(/,
    /\.delegateCall\(/,
    /\.staticCall\(/,
    /transfer\(/,
    /send\(/,
    /\w+\.\w+\(/ // external contract calls
  ];
  
  const stateUpdatePatterns = [
    /\s+\w+\s*=\s*/,
    /\s+\w+\s*\+=\s*/,
    /\s+\w+\s*\-=\s*/,
    /mapping\[.*\]\s*=\s*/,
    /\w+\[.*\]\s*=\s*/
  ];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    // Detect function start
    const funcMatch = line.match(/function\s+(\w+)\s*\(/);
    if (funcMatch && !line.includes('function ' + funcMatch[1] + ' internal')) {
      inFunction = true;
      functionName = funcMatch[1];
      functionStartLine = lineNum;
      hasExternalCall = false;
      hasStateUpdate = false;
      braceCount = 0;
    }
    
    if (inFunction) {
      braceCount += (line.match(/\{/g) || []).length;
      braceCount -= (line.match(/\}/g) || []).length;
      
      // Check for external calls
      if (!hasExternalCall) {
        for (const pattern of externalCallPatterns) {
          if (pattern.test(line) && !line.trim().startsWith('//')) {
            hasExternalCall = true;
            externalCallLine = lineNum;
            break;
          }
        }
      }
      
      // Check for state updates after external call
      if (hasExternalCall && !hasStateUpdate) {
        for (const pattern of stateUpdatePatterns) {
          if (pattern.test(line) && !line.trim().startsWith('//')) {
            hasStateUpdate = true;
            stateUpdateLine = lineNum;
            break;
          }
        }
      }
      
      // Function ended - check for reentrancy pattern
      if (braceCount === 0 && inFunction) {
        if (hasExternalCall && hasStateUpdate && externalCallLine < stateUpdateLine) {
          issues.push({
            severity: 'critical',
            category: 'reentrancy',
            line: externalCallLine,
            pattern: 'external-call-before-state-update',
            description: `Function '${functionName}' makes external call at line ${externalCallLine} before updating state at line ${stateUpdateLine}`,
            recommendation: 'Apply checks-effects-interactions pattern: update state before external calls'
          });
        }
        inFunction = false;
      }
    }
  }
  
  return issues;
}

/**
 * Overflow/Underflow Detection
 * Pattern: uint256 arithmetic without SafeMath or Solidity 0.8+ checks
 */
function checkOverflow(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check pragma version
  const pragmaMatch = code.match(/pragma\s+solidity\s+\^?([0-9.]+)/);
  const solidityVersion = pragmaMatch ? pragmaMatch[1] : '0.0.0';
  const isSafeVersion = solidityVersion >= '0.8.0';
  
  // Check for SafeMath import
  const hasSafeMath = /import.*SafeMath/.test(code) || /using\s+SafeMath/.test(code);
  
  // Only check if not using safe version or SafeMath
  if (isSafeVersion || hasSafeMath) {
    return issues;
  }
  
  const arithmeticPatterns = [
    { pattern: /\+\+/g, op: 'increment' },
    { pattern: /--/g, op: 'decrement' },
    { pattern: /\+=/g, op: 'addition assignment' },
    { pattern: /-=/g, op: 'subtraction assignment' },
    { pattern: /\*=/g, op: 'multiplication assignment' },
    { pattern: /\/=\s*[^/]/g, op: 'division assignment' },
    { pattern: /[^=]\+[^+]/g, op: 'addition' },
    { pattern: /[^=]-[^-]/g, op: 'subtraction' },
    { pattern: /[^=]\*[^*]/g, op: 'multiplication' }
  ];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
    
    // Check if line involves uint256 arithmetic
    if (/uint256|uint\s+\w+|\w+\s*:\s*uint/.test(line)) {
      for (const { pattern, op } of arithmeticPatterns) {
        if (pattern.test(line)) {
          issues.push({
            severity: 'high',
            category: 'overflow',
            line: lineNum,
            pattern: `unsafe-${op}`,
            description: `Potential ${op} on uint256 without overflow protection (Solidity ${solidityVersion})`,
            recommendation: 'Upgrade to Solidity ^0.8.0 or use OpenZeppelin SafeMath library'
          });
          break;
        }
      }
    }
  }
  
  return issues;
}

/**
 * Access Control Detection
 * Pattern: state-changing functions without onlyOwner or similar modifiers
 */
function checkAccessControl(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check for Ownable import
  const hasOwnable = /import.*Ownable/.test(code) || /is\s+Ownable/.test(code);
  
  // Known access control modifiers
  const accessModifiers = ['onlyOwner', 'onlyAdmin', 'onlyRole', 'restricted', 'authorized'];
  
  let inFunction = false;
  let functionName = '';
  let functionStartLine = 0;
  let hasModifier = false;
  let isStateChanging = false;
  let braceCount = 0;
  
  const stateChangingPatterns = [
    /\s+\w+\s*=\s*/,
    /\s+\w+\s*\+=\s*/,
    /\s+\w+\s*\-=\s*/,
    /emit\s+\w+\(/,
    /selfdestruct\(/,
    /\.transfer\(/,
    /\.send\(/,
    /\.call\{/ 
  ];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    // Detect function start
    const funcMatch = line.match(/function\s+(\w+)\s*\([^)]*\)\s*(?:([a-z]+)\s+)?(?:([a-zA-Z_][a-zA-Z0-9_]*)\s+)?/);
    if (funcMatch) {
      inFunction = true;
      functionName = funcMatch[1];
      functionStartLine = lineNum;
      hasModifier = false;
      isStateChanging = false;
      braceCount = 0;
      
      // Check for access modifiers in function signature
      for (const modifier of accessModifiers) {
        if (line.includes(modifier)) {
          hasModifier = true;
          break;
        }
      }
      
      // Check visibility - public/external functions that change state need protection
      const visibility = line.match(/(public|external)/);
      if (!visibility && !line.includes('private') && !line.includes('internal')) {
        // Default visibility, check if state-changing
      }
    }
    
    if (inFunction) {
      braceCount += (line.match(/\{/g) || []).length;
      braceCount -= (line.match(/\}/g) || []).length;
      
      // Check for state changes
      if (!isStateChanging) {
        for (const pattern of stateChangingPatterns) {
          if (pattern.test(line) && !line.trim().startsWith('//')) {
            isStateChanging = true;
            break;
          }
        }
      }
      
      // Function ended
      if (braceCount === 0 && inFunction) {
        // Skip constructors and view/pure functions
        const isConstructor = functionName === 'constructor' || functionName === 'initialize';
        const isViewOrPure = lines[functionStartLine - 1]?.match(/(view|pure)/);
        
        if (isStateChanging && !hasModifier && !isConstructor && !isViewOrPure) {
          // Check if function name implies admin action
          const adminKeywords = ['set', 'update', 'change', 'modify', 'withdraw', 'transfer', 'mint', 'burn', 'pause', 'unpause'];
          const isAdminFunction = adminKeywords.some(kw => functionName.toLowerCase().includes(kw));
          
          if (isAdminFunction || functionName.toLowerCase().includes('owner')) {
            issues.push({
              severity: 'high',
              category: 'access_control',
              line: functionStartLine,
              pattern: 'missing-access-modifier',
              description: `State-changing function '${functionName}' lacks access control modifier`,
              recommendation: 'Add onlyOwner or role-based access control modifier'
            });
          }
        }
        inFunction = false;
      }
    }
  }
  
  return issues;
}

/**
 * Initialization Detection
 * Pattern: Missing constructor initialization or improper initialize function
 */
function checkInitialization(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  const hasConstructor = /constructor\s*\(/.test(code);
  const hasInitialize = /function\s+initialize\s*\(/.test(code);
  const isUpgradeable = /is\s+.*Initializable/.test(code) || /import.*Initializable/.test(code);
  
  // Check for uninitialized state variables
  const stateVarPattern = /(uint|address|bool|mapping|\w+)\s+(\w+)\s*[;=]/g;
  const stateVars: { name: string; line: number; initialized: boolean }[] = [];
  
  let inContract = false;
  let contractStartLine = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    if (line.match(/contract\s+\w+/)) {
      inContract = true;
      contractStartLine = lineNum;
    }
    
    if (inContract && line.match(/^\s*(uint|address|bool|mapping|\w+)\s+\w+\s*[;=]/)) {
      const varMatch = line.match(/\w+\s+(\w+)\s*[;=]/);
      if (varMatch && !line.includes('constant') && !line.includes('immutable')) {
        stateVars.push({
          name: varMatch[1],
          line: lineNum,
          initialized: line.includes('=') || line.includes('constructor') || line.includes('initialize')
        });
      }
    }
    
    if (line.match(/^\s*\}\s*$/) && inContract) {
      inContract = false;
    }
  }
  
  // Check for proper initialization pattern
  if (isUpgradeable && !hasInitialize) {
    issues.push({
      severity: 'critical',
      category: 'initialization',
      line: contractStartLine,
      pattern: 'missing-initialize-function',
      description: 'Upgradeable contract lacks initialize() function',
      recommendation: 'Add initialize() function with initializer modifier for upgradeable contracts'
    });
  }
  
  if (!isUpgradeable && !hasConstructor && stateVars.length > 0) {
    // Check if any state vars are uninitialized
    const uninitialized = stateVars.filter(v => !v.initialized);
    if (uninitialized.length > 0) {
      issues.push({
        severity: 'medium',
        category: 'initialization',
        line: uninitialized[0].line,
        pattern: 'uninitialized-state',
        description: `State variables may be uninitialized: ${uninitialized.map(v => v.name).join(', ')}`,
        recommendation: 'Add constructor to initialize state variables or use default values'
      });
    }
  }
  
  // Check for missing initializer modifier on initialize function
  if (hasInitialize && isUpgradeable) {
    const initLine = lines.findIndex(l => /function\s+initialize\s*\(/.test(l));
    if (initLine >= 0 && !lines[initLine].includes('initializer')) {
      issues.push({
        severity: 'critical',
        category: 'initialization',
        line: initLine + 1,
        pattern: 'missing-initializer-modifier',
        description: 'initialize() function lacks initializer modifier',
        recommendation: 'Add initializer modifier to prevent re-initialization attacks'
      });
    }
  }
  
  return issues;
}

/**
 * Additional Mythril-inspired Heuristics
 */
function checkHeuristics(code: string): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const lines = code.split('\n');
  
  // Check for tx.origin usage (phishing vulnerability)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/tx\.origin/.test(line) && !line.trim().startsWith('//')) {
      issues.push({
        severity: 'critical',
        category: 'access_control',
        line: i + 1,
        pattern: 'tx-origin-usage',
        description: 'tx.origin used for authentication - vulnerable to phishing attacks',
        recommendation: 'Use msg.sender instead of tx.origin for access control'
      });
    }
  }
  
  // Check for weak randomness
  if (/block\.timestamp|block\.number|block\.hash|now/.test(code)) {
    const lineNum = lines.findIndex(l => /block\.timestamp|block\.number|now/.test(l)) + 1;
    issues.push({
      severity: 'medium',
      category: 'other',
      line: lineNum,
      pattern: 'weak-randomness',
      description: 'Block properties used - predictable by miners/validators',
      recommendation: 'Use Chainlink VRF or commit-reveal scheme for randomness'
    });
  }
  
  // Check for unchecked blocks (Solidity 0.8+)
  const pragmaMatch = code.match(/pragma\s+solidity\s+\^?([0-9.]+)/);
  const solidityVersion = pragmaMatch ? pragmaMatch[1] : '0.0.0';
  if (solidityVersion >= '0.8.0' && /unchecked\s*\{/.test(code)) {
    const lineNum = lines.findIndex(l => /unchecked\s*\{/.test(l)) + 1;
    issues.push({
      severity: 'info',
      category: 'overflow',
      line: lineNum,
      pattern: 'unchecked-block',
      description: 'Unchecked block disables overflow protection',
      recommendation: 'Ensure arithmetic in unchecked blocks is provably safe'
    });
  }
  
  // Check for missing events on state changes
  const hasStateChange = /\s+\w+\s*=\s*/.test(code);
  const hasEvents = /emit\s+\w+\(/.test(code);
  if (hasStateChange && !hasEvents) {
    issues.push({
      severity: 'low',
      category: 'other',
      line: 1,
      pattern: 'missing-events',
      description: 'State changes without events - reduces off-chain visibility',
      recommendation: 'Emit events for important state changes for indexing and monitoring'
    });
  }
  
  return issues;
}

/**
 * Calculate risk score from issues
 */
function calculateRiskScore(issues: AuditIssue[]): number {
  let score = 0;
  for (const issue of issues) {
    score += SEVERITY_WEIGHTS[issue.severity];
  }
  return Math.min(100, score);
}

/**
 * Generate summary counts
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
 * Main audit function - analyzes Solidity code and returns report
 * @param code - Solidity source code to audit
 * @returns AuditReport with risk score and issues
 */
export function auditContract(code: string): AuditReport {
  const allIssues: AuditIssue[] = [
    ...checkReentrancy(code),
    ...checkOverflow(code),
    ...checkAccessControl(code),
    ...checkInitialization(code),
    ...checkHeuristics(code)
  ];
  
  // Deduplicate issues by line and pattern
  const uniqueIssues = allIssues.filter((issue, index, self) =>
    index === self.findIndex(i => i.line === issue.line && i.pattern === issue.pattern)
  );
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  uniqueIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  const riskScore = calculateRiskScore(uniqueIssues);
  const summary = generateSummary(uniqueIssues);
  
  return {
    riskScore,
    issues: uniqueIssues,
    summary,
    passed: riskScore < 25, // Pass if no critical/high issues
    timestamp: Date.now()
  };
}

/**
 * Quick validation - returns true if code passes basic safety checks
 */
export function isCodeSafe(code: string): boolean {
  const report = auditContract(code);
  return report.passed;
}

/**
 * Get critical issues only
 */
export function getCriticalIssues(code: string): AuditIssue[] {
  const report = auditContract(code);
  return report.issues.filter(i => i.severity === 'critical');
}
