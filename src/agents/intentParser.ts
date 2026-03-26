import { ChatOpenAI } from '@langchain/openai';
import { PromptTemplate } from '@langchain/core/prompts';
import { StringOutputParser } from '@langchain/core/output_parsers';

// Contract specification interface
export interface ContractSpec {
  type: 'staking' | 'swap' | 'escrow' | 'dao';
  params: Record<string, unknown>;
  chain: string;
  constraints: {
    maxGas?: number;
    deadline?: number;
    slippage?: number;
  };
  rawIntent: string;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

// System prompt for contract classification
const SYSTEM_PROMPT = `You are a smart contract intent parser for NoLangX. Your job is to:
1. Classify the user's intent into one of four contract types
2. Extract structured parameters from natural language
3. Validate the intent is feasible

Contract types:
- staking: Yield generation pools with APY, lock periods, token acceptance
- swap: DEX trading with input/output tokens, amounts, slippage tolerance
- escrow: Trustless third-party holding with release conditions, timeouts
- dao: Decentralized governance with voting periods, quorum, proposal types

Always respond with valid JSON matching the ContractSpec schema.`;

// Base classification prompt - uses {{input}} to avoid template variable conflict
const classificationPrompt = PromptTemplate.fromTemplate(`
Classify this smart contract request and extract parameters.

Request: {{input}}

Respond with ONLY this JSON (no markdown, no explanation):
{
  "type": "staking" | "swap" | "escrow" | "dao",
  "params": { /* type-specific parameters */ },
  "chain": "ethereum" | "polygon" | "arbitrum" | "base" | "optimism",
  "constraints": {
    "maxGas": number | null,
    "deadline": number | null,
    "slippage": number | null
  }
}
`);

// Type-specific prompt templates
const stakingPrompt = PromptTemplate.fromTemplate(`
Extract staking pool parameters from: {{input}}

Respond with ONLY this JSON:
{
  "type": "staking",
  "params": {
    "rewardToken": string,
    "stakingToken": string,
    "apy": number,
    "lockPeriodDays": number,
    "minStake": number,
    "maxStake": number | null,
    "rewardDistribution": "linear" | "exponential" | "instant"
  },
  "chain": "ethereum" | "polygon" | "arbitrum" | "base" | "optimism",
  "constraints": {
    "maxGas": number | null,
    "deadline": number | null,
    "slippage": null
  }
}
`);

const swapPrompt = PromptTemplate.fromTemplate(`
Extract token swap parameters from: {{input}}

Respond with ONLY this JSON:
{
  "type": "swap",
  "params": {
    "tokenIn": string,
    "tokenOut": string,
    "amountIn": number,
    "amountOutMin": number | null,
    "dex": "uniswap" | "sushiswap" | "curve" | "balancer" | "any"
  },
  "chain": "ethereum" | "polygon" | "arbitrum" | "base" | "optimism",
  "constraints": {
    "maxGas": number | null,
    "deadline": number | null,
    "slippage": number
  }
}
`);

const escrowPrompt = PromptTemplate.fromTemplate(`
Extract escrow contract parameters from: {{input}}

Respond with ONLY this JSON:
{
  "type": "escrow",
  "params": {
    "token": string,
    "amount": number,
    "beneficiary": string,
    "arbiter": string,
    "releaseConditions": "time-based" | "condition-met" | "multi-sig" | "oracle-fed",
    "timeoutDays": number
  },
  "chain": "ethereum" | "polygon" | "arbitrum" | "base" | "optimism",
  "constraints": {
    "maxGas": number | null,
    "deadline": number | null,
    "slippage": null
  }
}
`);

const daoPrompt = PromptTemplate.fromTemplate(`
Extract DAO governance parameters from: {{input}}

Respond with ONLY this JSON:
{
  "type": "dao",
  "params": {
    "proposalType": "treasury" | "parameter" | "membership" | "plugin" | "upgrade",
    "title": string,
    "description": string,
    "votingPeriodDays": number,
    "quorum": number,
    "approvalThreshold": number,
    "executionDelayDays": number
  },
  "chain": "ethereum" | "polygon" | "arbitrum" | "base" | "optimism",
  "constraints": {
    "maxGas": number | null,
    "deadline": number | null,
    "slippage": null
  }
}
`);

// Validation layer
const VALID_CHAINS = ['ethereum', 'polygon', 'arbitrum', 'base', 'optimism'];
const VALID_TYPES = ['staking', 'swap', 'escrow', 'dao'];

function validateSpec(spec: Partial<ContractSpec>): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Type validation
  if (!spec.type || !VALID_TYPES.includes(spec.type)) {
    errors.push(`Invalid contract type: ${spec.type}. Must be one of: ${VALID_TYPES.join(', ')}`);
  }

  // Chain validation
  if (!spec.chain || !VALID_CHAINS.includes(spec.chain)) {
    errors.push(`Invalid chain: ${spec.chain}. Must be one of: ${VALID_CHAINS.join(', ')}`);
  }

  // Type-specific validation
  if (spec.type === 'staking') {
    const params = spec.params as { apy?: number; lockPeriodDays?: number };
    if (params.apy !== undefined && (params.apy < 0 || params.apy > 1000)) {
      warnings.push(`APY of ${params.apy}% is unusually high. Verify this is intentional.`);
    }
    if (params.lockPeriodDays !== undefined && params.lockPeriodDays < 1) {
      errors.push('Lock period must be at least 1 day');
    }
  }

  if (spec.type === 'swap') {
    const params = spec.params as { amountIn?: number; slippage?: number };
    if (params.amountIn !== undefined && params.amountIn <= 0) {
      errors.push('Swap amount must be positive');
    }
    if (params.slippage !== undefined && (params.slippage < 0 || params.slippage > 50)) {
      warnings.push(`Slippage of ${params.slippage}% is extreme. Consider 0.5-2% range.`);
    }
  }

  if (spec.type === 'escrow') {
    const params = spec.params as { amount?: number; timeoutDays?: number };
    if (params.amount !== undefined && params.amount <= 0) {
      errors.push('Escrow amount must be positive');
    }
    if (params.timeoutDays !== undefined && params.timeoutDays < 1) {
      errors.push('Timeout must be at least 1 day');
    }
  }

  if (spec.type === 'dao') {
    const params = spec.params as { quorum?: number; approvalThreshold?: number };
    if (params.quorum !== undefined && (params.quorum < 1 || params.quorum > 100)) {
      errors.push('Quorum must be between 1% and 100%');
    }
    if (params.approvalThreshold !== undefined && (params.approvalThreshold < 51 || params.approvalThreshold > 100)) {
      errors.push('Approval threshold must be between 51% and 100%');
    }
  }

  // Constraint validation
  if (spec.constraints) {
    if (spec.constraints.maxGas !== null && spec.constraints.maxGas !== undefined && spec.constraints.maxGas < 100000) {
      warnings.push('Gas limit seems low. Consider 200000+ for complex contracts.');
    }
    if (spec.constraints.deadline !== undefined && spec.constraints.deadline < Math.floor(Date.now() / 1000)) {
      errors.push('Deadline must be in the future');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

// Main parser class
class IntentParser {
  private llm: ChatOpenAI;
  private outputParser: StringOutputParser;

  constructor(apiKey?: string) {
    this.llm = new ChatOpenAI({
      modelName: 'gpt-4-turbo',
      temperature: 0.1,
      openAIApiKey: apiKey || process.env.OPENAI_API_KEY,
      configuration: { baseURL: process.env.OPENAI_BASE_URL }
    });
    this.outputParser = new StringOutputParser();
  }

  async classify(text: string): Promise<{ type: string; confidence: number }> {
    const chain = classificationPrompt.pipe(this.llm).pipe(this.outputParser);
    const result = await chain.invoke({ input: text });
    
    try {
      const parsed = JSON.parse(result.trim());
      return { type: parsed.type, confidence: 0.9 };
    } catch {
      // Fallback classification based on keywords
      const lowerText = text.toLowerCase();
      if (lowerText.includes('stake') || lowerText.includes('apy') || lowerText.includes('yield')) {
        return { type: 'staking', confidence: 0.6 };
      }
      if (lowerText.includes('swap') || lowerText.includes('exchange') || lowerText.includes('trade')) {
        return { type: 'swap', confidence: 0.6 };
      }
      if (lowerText.includes('escrow') || lowerText.includes('hold') || lowerText.includes('release')) {
        return { type: 'escrow', confidence: 0.6 };
      }
      if (lowerText.includes('vote') || lowerText.includes('proposal') || lowerText.includes('govern')) {
        return { type: 'dao', confidence: 0.6 };
      }
      return { type: 'unknown', confidence: 0 };
    }
  }

  async parseWithTemplate(text: string, type: string): Promise<Partial<ContractSpec>> {
    let prompt: PromptTemplate;
    
    switch (type) {
      case 'staking':
        prompt = stakingPrompt;
        break;
      case 'swap':
        prompt = swapPrompt;
        break;
      case 'escrow':
        prompt = escrowPrompt;
        break;
      case 'dao':
        prompt = daoPrompt;
        break;
      default:
        prompt = classificationPrompt;
    }

    const chain = prompt.pipe(this.llm).pipe(this.outputParser);
    const result = await chain.invoke({ input: text });
    
    try {
      return JSON.parse(result.trim());
    } catch (parseError) {
      throw new Error(`Failed to parse LLM response: ${result}`);
    }
  }

  async parse(text: string): Promise<ContractSpec> {
    // Step 1: Classify intent type
    const { type, confidence } = await this.classify(text);
    
    if (type === 'unknown' || confidence < 0.3) {
      throw new Error(`Could not classify intent: "${text}". Try specifying staking, swap, escrow, or DAO.`);
    }

    // Step 2: Parse with type-specific template
    const parsed = await this.parseWithTemplate(text, type);

    // Step 3: Build full spec
    const spec: ContractSpec = {
      type: parsed.type as ContractSpec['type'],
      params: parsed.params || {},
      chain: parsed.chain || 'ethereum',
      constraints: {
        maxGas: parsed.constraints?.maxGas ?? null,
        deadline: parsed.constraints?.deadline ?? null,
        slippage: parsed.constraints?.slippage ?? null
      },
      rawIntent: text
    };

    // Step 4: Validate
    const validation = validateSpec(spec);
    if (!validation.valid) {
      throw new Error(`Validation failed: ${validation.errors.join('; ')}`);
    }

    if (validation.warnings.length > 0) {
      console.warn('NoLangX Validation Warnings:', validation.warnings.join('; '));
    }

    return spec;
  }
}

// Singleton instance
let parserInstance: IntentParser | null = null;

export function getIntentParser(apiKey?: string): IntentParser {
  if (!parserInstance) {
    parserInstance = new IntentParser(apiKey);
  }
  return parserInstance;
}

// Main exported function - primary entry point
export async function parseIntent(text: string): Promise<ContractSpec> {
  const parser = getIntentParser();
  return parser.parse(text);
}

export { IntentParser, ContractSpec, ValidationResult };
