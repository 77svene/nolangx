/**
 * NoLangX Multi-Chain Deployer
 * 
 * Autonomous deployment agent supporting multiple EVM chains with:
 * - Fallback RPC selection for reliability
 * - Gas price oracle integration
 * - Automatic retry with gas bumping on failure
 * - Deployment receipt tracking
 * 
 * Chains: Polygon, Arbitrum, Base, Optimism
 */

import { ethers, ContractFactory, Contract, Signer, Wallet, providers } from 'ethers';

// ============================================================================
// TYPES
// ============================================================================

export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrls: string[];
  explorerUrl: string;
  currency: string;
}

export interface DeployOptions {
  maxRetries?: number;
  gasMultiplier?: number;
  timeoutMs?: number;
  confirmations?: number;
}

export interface DeploymentReceipt {
  success: boolean;
  chainId: number;
  chainName: string;
  contractAddress: string | null;
  txHash: string | null;
  blockNumber: number | null;
  gasUsed: bigint | null;
  effectiveGasPrice: bigint | null;
  explorerUrl: string | null;
  error?: string;
  timestamp: number;
  retries: number;
}

export interface GasOracle {
  getGasPrice(chainId: number): Promise<bigint>;
}

// ============================================================================
// CHAIN CONFIGURATIONS
// ============================================================================

const CHAIN_CONFIGS: Record<number, ChainConfig> = {
  137: {
    chainId: 137,
    name: 'Polygon',
    rpcUrls: [
      'https://polygon-rpc.com',
      'https://rpc-mainnet.matic.network',
      'https://matic-mainnet.chainstacklabs.com',
      'https://polygon-bor.publicnode.com'
    ],
    explorerUrl: 'https://polygonscan.com',
    currency: 'MATIC'
  },
  42161: {
    chainId: 42161,
    name: 'Arbitrum',
    rpcUrls: [
      'https://arb1.arbitrum.io/rpc',
      'https://arbitrum-one.publicnode.com',
      'https://rpc.ankr.com/arbitrum'
    ],
    explorerUrl: 'https://arbiscan.io',
    currency: 'ETH'
  },
  8453: {
    chainId: 8453,
    name: 'Base',
    rpcUrls: [
      'https://mainnet.base.org',
      'https://base.publicnode.com',
      'https://base-mainnet.g.alchemy.com/v2/demo'
    ],
    explorerUrl: 'https://basescan.org',
    currency: 'ETH'
  },
  10: {
    chainId: 10,
    name: 'Optimism',
    rpcUrls: [
      'https://mainnet.optimism.io',
      'https://optimism.publicnode.com',
      'https://rpc.ankr.com/optimism'
    ],
    explorerUrl: 'https://optimistic.etherscan.io',
    currency: 'ETH'
  }
};

// ============================================================================
// GAS ORACLE IMPLEMENTATION
// ============================================================================

class NativeGasOracle implements GasOracle {
  private cache: Map<number, { price: bigint; timestamp: number }> = new Map();
  private readonly CACHE_TTL_MS = 30000; // 30 seconds

  async getGasPrice(chainId: number): Promise<bigint> {
    const cached = this.cache.get(chainId);
    const now = Date.now();

    if (cached && now - cached.timestamp < this.CACHE_TTL_MS) {
      return cached.price;
    }

    const config = CHAIN_CONFIGS[chainId];
    if (!config) {
      throw new Error(`Unsupported chain ID: ${chainId}`);
    }

    // Try each RPC until we get a gas price
    for (const rpcUrl of config.rpcUrls) {
      try {
        const response = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_gasPrice',
            params: []
          })
        });

        if (!response.ok) continue;

        const data = await response.json();
        if (data.result) {
          const gasPrice = BigInt(data.result);
          this.cache.set(chainId, { price: gasPrice, timestamp: now });
          return gasPrice;
        }
      } catch (error) {
        // Try next RPC
        continue;
      }
    }

    throw new Error(`Failed to fetch gas price for chain ${chainId}`);
  }
}

// ============================================================================
// RPC MANAGER WITH FALLBACK
// ============================================================================

class RPCManager {
  private providers: Map<number, providers.JsonRpcProvider[]> = new Map();
  private currentIndex: Map<number, number> = new Map();

  getProviders(chainId: number): providers.JsonRpcProvider[] {
    const cached = this.providers.get(chainId);
    if (cached) return cached;

    const config = CHAIN_CONFIGS[chainId];
    if (!config) {
      throw new Error(`Unsupported chain ID: ${chainId}`);
    }

    const providersList = config.rpcUrls.map(
      url => new providers.JsonRpcProvider(url, chainId)
    );

    this.providers.set(chainId, providersList);
    this.currentIndex.set(chainId, 0);
    return providersList;
  }

  async getWorkingProvider(chainId: number): Promise<providers.JsonRpcProvider> {
    const providersList = this.getProviders(chainId);
    const startIndex = this.currentIndex.get(chainId) || 0;

    for (let i = 0; i < providersList.length; i++) {
      const index = (startIndex + i) % providersList.length;
      const provider = providersList[index];

      try {
        await provider.getNetwork();
        this.currentIndex.set(chainId, index);
        return provider;
      } catch (error) {
        // Try next provider
        continue;
      }
    }

    throw new Error(`No working RPC found for chain ${chainId}`);
  }
}

// ============================================================================
// DEPLOYER CLASS
// ============================================================================

export class MultiChainDeployer {
  private wallet: Wallet;
  private rpcManager: RPCManager;
  private gasOracle: GasOracle;

  constructor(privateKey: string) {
    if (!privateKey.startsWith('0x')) {
      privateKey = '0x' + privateKey;
    }
    this.wallet = new Wallet(privateKey);
    this.rpcManager = new RPCManager();
    this.gasOracle = new NativeGasOracle();
  }

  /**
   * Deploy a contract to specified chain with retry logic
   */
  async deploy(
    contractBytecode: string,
    contractAbi: any[],
    chainId: number,
    constructorArgs: any[] = [],
    options: DeployOptions = {}
  ): Promise<DeploymentReceipt> {
    const {
      maxRetries = 3,
      gasMultiplier = 1.2,
      timeoutMs = 120000,
      confirmations = 1
    } = options;

    const config = CHAIN_CONFIGS[chainId];
    if (!config) {
      return this.createReceipt(chainId, false, null, null, null, null, null, 'Unsupported chain ID', 0);
    }

    let lastError: string | undefined;
    let retries = 0;
    let currentGasMultiplier = 1;

    while (retries <= maxRetries) {
      try {
        const provider = await this.rpcManager.getWorkingProvider(chainId);
        const connectedWallet = this.wallet.connect(provider);

        // Get base gas price and apply multiplier
        const baseGasPrice = await this.gasOracle.getGasPrice(chainId);
        const gasPrice = BigInt(Math.floor(Number(baseGasPrice) * currentGasMultiplier));

        // Create contract factory
        const factory = new ContractFactory(contractAbi, contractBytecode, connectedWallet);

        // Deploy with timeout
        const deployPromise = factory.deploy(...constructorArgs, {
          gasPrice,
          gasLimit: 5000000 // Generous gas limit for complex contracts
        });

        const contract = await Promise.race([
          deployPromise,
          new Promise<Contract>((_, reject) =>
            setTimeout(() => reject(new Error('Deployment timeout')), timeoutMs)
          )
        ]);

        // Wait for deployment confirmation
        const deploymentTx = contract.deployTransaction;
        const receipt = await provider.waitForTransaction(
          deploymentTx.hash,
          confirmations,
          timeoutMs
        );

        if (receipt.status === 0) {
          throw new Error('Transaction reverted on chain');
        }

        const explorerUrl = `${config.explorerUrl}/tx/${receipt.transactionHash}`;

        return this.createReceipt(
          chainId,
          true,
          contract.address,
          receipt.transactionHash,
          receipt.blockNumber,
          receipt.gasUsed,
          receipt.effectiveGasPrice,
          undefined,
          retries,
          explorerUrl
        );
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        retries++;
        currentGasMultiplier *= gasMultiplier;

        // Wait before retry (exponential backoff)
        if (retries <= maxRetries) {
          await this.sleep(1000 * Math.pow(2, retries));
        }
      }
    }

    return this.createReceipt(chainId, false, null, null, null, null, null, lastError, retries);
  }

  /**
   * Deploy pre-compiled contract from NoLangX generator
   */
  async deployFromSpec(
    spec: {
      bytecode: string;
      abi: any[];
      chainId: number;
      constructorArgs?: any[];
    },
    options: DeployOptions = {}
  ): Promise<DeploymentReceipt> {
    return this.deploy(
      spec.bytecode,
      spec.abi,
      spec.chainId,
      spec.constructorArgs || [],
      options
    );
  }

  /**
   * Get current wallet balance on chain
   */
  async getBalance(chainId: number): Promise<bigint> {
    const provider = await this.rpcManager.getWorkingProvider(chainId);
    return provider.getBalance(this.wallet.address);
  }

  /**
   * Get chain info
   */
  getChainInfo(chainId: number): ChainConfig | undefined {
    return CHAIN_CONFIGS[chainId];
  }

  /**
   * Get all supported chains
   */
  getSupportedChains(): ChainConfig[] {
    return Object.values(CHAIN_CONFIGS);
  }

  /**
   * Helper to create deployment receipt
   */
  private createReceipt(
    chainId: number,
    success: boolean,
    contractAddress: string | null,
    txHash: string | null,
    blockNumber: number | null,
    gasUsed: bigint | null,
    effectiveGasPrice: bigint | null,
    error: string | undefined,
    retries: number,
    explorerUrl?: string | null
  ): DeploymentReceipt {
    const config = CHAIN_CONFIGS[chainId];
    return {
      success,
      chainId,
      chainName: config?.name || 'Unknown',
      contractAddress,
      txHash,
      blockNumber,
      gasUsed,
      effectiveGasPrice,
      explorerUrl: explorerUrl || null,
      error,
      timestamp: Date.now(),
      retries
    };
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// STANDALONE DEPLOY FUNCTION (as specified in task)
// ============================================================================

let globalDeployer: MultiChainDeployer | null = null;

export function initializeDeployer(privateKey: string): MultiChainDeployer {
  globalDeployer = new MultiChainDeployer(privateKey);
  return globalDeployer;
}

export function getDeployer(): MultiChainDeployer {
  if (!globalDeployer) {
    throw new Error('Deployer not initialized. Call initializeDeployer() first.');
  }
  return globalDeployer;
}

/**
 * Standalone deploy function as specified in task requirements
 * deploy(contract, chainId, options) → DeploymentReceipt
 */
export async function deploy(
  contract: {
    bytecode: string;
    abi: any[];
    constructorArgs?: any[];
  },
  chainId: number,
  options: DeployOptions = {}
): Promise<DeploymentReceipt> {
  const deployer = getDeployer();
  return deployer.deploy(
    contract.bytecode,
    contract.abi,
    chainId,
    contract.constructorArgs || [],
    options
  );
}

// ============================================================================
// CLI EXPORT FOR DIRECT EXECUTION
// ============================================================================

if (typeof process !== 'undefined' && process.argv[1]?.includes('deployer')) {
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!privateKey) {
    console.error('DEPLOYER_PRIVATE_KEY not set in environment');
    process.exit(1);
  }

  initializeDeployer(privateKey);
  console.log('NoLangX Deployer initialized');
  console.log('Wallet address:', getDeployer().wallet.address);
  console.log('Supported chains:', getDeployer().getSupportedChains().map(c => c.name).join(', '));
}

export default MultiChainDeployer;
