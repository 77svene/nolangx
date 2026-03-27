# 🤖 NoLangX: Natural Language Smart Contract Agent

> **Deploy audited, ZK-verified smart contracts with a single sentence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-orange.svg)](https://soliditylang.org/)
[![Built for Microsoft AI Agents Hackathon](https://img.shields.io/badge/Microsoft%20AI%20Agents%20Hackathon-2026-green.svg)](https://devpost.com)

---

## 🎯 One-Line Pitch

NoLangX lets anyone deploy secure, audited smart contracts by describing what they want in plain English — no Solidity knowledge required.

---

## 🔥 The Problem

Deploying smart contracts requires deep Solidity expertise, security auditing skills, and multi-chain knowledge. 99% of people with a valid use case can't access this technology. Existing solutions either require coding or sacrifice security.

## 💡 The Solution

NoLangX is an autonomous AI agent pipeline:

```
"Create a staking pool with 12% APY that accepts USDC"
        ↓
  IntentParser (LangChain + GPT-4)
        ↓
  SolGenerator (Solidity templates + LLM refinement)
        ↓
  AuditChecker (static analysis: reentrancy, overflow, access control)
        ↓
  ZK Prover (snarkjs/circom — proof of correctness without revealing logic)
        ↓
  Deployer (Polygon / Arbitrum / Base / Optimism)
        ↓
  Live contract address + verification URL
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NoLangX API (Express)                 │
│                    POST /deploy                          │
└──────────────────────────┬──────────────────────────────┘
                           │
           ┌───────────────▼───────────────┐
           │         IntentParser           │
           │  LangChain + GPT-4o           │
           │  → ContractSpec (type, params) │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │         SolGenerator           │
           │  Template library + LLM        │
           │  → Auditable Solidity code     │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │         AuditChecker           │
           │  Static pattern analysis       │
           │  Risk score 0-100             │
           │  Reentrancy / overflow / ACL   │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │           ZK Prover            │
           │  snarkjs + Circom circuits     │
           │  Poseidon hash + groth16       │
           │  Proof: code is correct        │
           │  without revealing source      │
           └───────────────┬───────────────┘
                           │
           ┌───────────────▼───────────────┐
           │           Deployer             │
           │  ethers.js v6                  │
           │  Polygon / Arbitrum / Base /   │
           │  Optimism + fallback RPCs      │
           │  Gas oracle + auto-retry       │
           └───────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/77svene/nolangx.git
cd nolangx

# Install
npm install

# Configure
cp .env.example .env
# Add: OPENAI_API_KEY, DEPLOYER_PRIVATE_KEY, ALCHEMY_API_KEY

# Run
npm run dev

# Deploy a contract
curl -X POST http://localhost:3000/deploy \
  -H "Content-Type: application/json" \
  -d '{"intent": "Create a staking pool with 12% APY accepting USDC", "chain": "polygon"}'
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/deploy` | Parse intent → audit → prove → deploy |
| `POST` | `/audit` | Static analysis only (no deployment) |
| `POST` | `/prove` | Generate ZK proof for contract code |
| `GET` | `/deployment/:txHash` | Check deployment status |
| `GET` | `/health` | Health check + wallet balance |

### Example Request
```json
{
  "intent": "Create an escrow contract that releases funds after 7 days",
  "chain": "arbitrum",
  "options": { "maxGas": 500000 }
}
```

### Example Response
```json
{
  "contractAddress": "0x1234...abcd",
  "txHash": "0xabcd...1234",
  "chain": "arbitrum",
  "explorerUrl": "https://arbiscan.io/address/0x1234...abcd",
  "auditScore": 92,
  "zkProof": { "verified": true, "circuitHash": "0x..." },
  "gasUsed": "245000"
}
```

---

## 🔐 Supported Contract Types

| Type | Natural Language Examples |
|------|--------------------------|
| **Staking Pool** | "12% APY staking pool accepting USDC with 30-day lock" |
| **Token Swap** | "Swap 1 ETH for max USDC with 0.5% slippage on Uniswap" |
| **Escrow** | "Hold 5 ETH until both parties confirm, 14-day timeout" |
| **DAO** | "Governance with 48h voting, 10% quorum, token-weighted" |

---

## 🛡️ Security Pipeline

Every generated contract goes through:

1. **Reentrancy Detection** — checks-effects-interactions pattern enforcement
2. **Overflow Protection** — validates SafeMath usage or Solidity 0.8+ overflow
3. **Access Control Audit** — owner/admin function gating verification
4. **Initialization Check** — constructor parameter validation
5. **ZK Proof Generation** — Poseidon-hashed code commitment via groth16 circuit
6. **Risk Score** — 0-100 score; contracts below 70 are rejected

---

## 🌐 Supported Chains

| Chain | Chain ID | Explorer |
|-------|----------|---------|
| Polygon | 137 | polygonscan.com |
| Arbitrum One | 42161 | arbiscan.io |
| Base | 8453 | basescan.org |
| Optimism | 10 | optimistic.etherscan.io |

---

## 🧰 Tech Stack

- **Runtime**: Node.js 18 + TypeScript
- **AI**: LangChain + OpenAI GPT-4o (intent parsing + code generation)
- **Smart Contracts**: Solidity 0.8.24 + Hardhat + OpenZeppelin
- **ZK**: snarkjs + circomlibjs (Poseidon hash) + groth16 proofs
- **Deployment**: ethers.js v6 + viem + Alchemy
- **API**: Express 4 + rate limiting

---

## 🏆 Hackathon

Built for the **Microsoft AI Agents Hackathon (April 8-30 2026)** — $50K+ AI Agents Track.

NoLangX demonstrates autonomous AI agents operating across the full smart contract lifecycle: from natural language understanding → code generation → security verification → ZK attestation → on-chain deployment — without human intervention.

---

## 🤝 Team

Built by **VARAKH BUILDER** — an autonomous AI agent system that researches, codes, and ships projects autonomously.

---

## 📄 License

MIT — see [LICENSE](LICENSE)
