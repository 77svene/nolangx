import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { logger } from './utils/logger';
import { intentParser } from './agents/intentParser';
import { generateContract } from './agents/solGenerator';
import { auditContract } from './agents/auditChecker';
import { proveCorrectness } from './zk/prover';
import { deployContract } from './agents/deployer';

const app = express();
const PORT = process.env.PORT || 3000;
const TRUST_PROXY = parseInt(process.env.TRUST_PROXY || '1', 10);

app.set('trust proxy', TRUST_PROXY);
app.use(express.json({ limit: '10mb' }));

const deployLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many deployment requests, please try again in a minute',
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Too many requests, please slow down',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

interface DeploymentState {
  txHash: string;
  status: 'pending' | 'confirmed' | 'failed';
  contractAddress?: string;
  chainId: number;
  timestamp: number;
}

const deploymentCache = new Map<string, DeploymentState>();
const auditCache = new Map<string, { score: number; issues: string[]; timestamp: number }>();

async function checkWalletBalance(): Promise<{ balance: string; sufficient: boolean }> {
  const { deployer } = await import('./agents/deployer');
  try {
    const balance = await deployer.getBalance();
    const minBalance = BigInt('100000000000000000');
    return {
      balance: balance.toString(),
      sufficient: balance >= minBalance,
    };
  } catch {
    return { balance: '0', sufficient: false };
  }
}

app.post('/api/deploy', deployLimiter, async (req: Request, res: Response) => {
  try {
    const { intent, chainId = 1 } = req.body;

    if (!intent || typeof intent !== 'string') {
      res.status(400).json({ error: 'Natural language intent is required' });
      return;
    }

    const balanceCheck = await checkWalletBalance();
    if (!balanceCheck.sufficient) {
      res.status(402).json({
        error: 'Insufficient wallet balance for deployment',
        balance: balanceCheck.balance,
      });
      return;
    }

    const parsedIntent = await intentParser(intent);
    if (!parsedIntent.valid) {
      res.status(400).json({ error: 'Invalid intent', details: parsedIntent.errors });
      return;
    }

    const contractCode = await generateContract(parsedIntent.spec);
    if (!contractCode) {
      res.status(500).json({ error: 'Failed to generate contract code' });
      return;
    }

    const auditResult = await auditContract(contractCode);
    if (auditResult.score < 70) {
      res.status(400).json({
        error: 'Contract failed security audit',
        score: auditResult.score,
        issues: auditResult.issues,
      });
      return;
    }

    const proof = await proveCorrectness(contractCode);

    const deployment = await deployContract(contractCode, chainId);

    const txHash = deployment.txHash;
    deploymentCache.set(txHash, {
      txHash,
      status: 'pending',
      chainId,
      timestamp: Date.now(),
    });

    res.status(202).json({
      success: true,
      txHash,
      status: 'pending',
      chainId,
      auditScore: auditResult.score,
      proofGenerated: !!proof,
      message: 'Deployment initiated, monitor status via /api/status/:txHash',
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Deployment failed', details: errorMessage });
  }
});

app.get('/api/status/:txHash', async (req: Request, res: Response) => {
  try {
    const { txHash } = req.params;

    if (!txHash || !txHash.startsWith('0x')) {
      res.status(400).json({ error: 'Valid transaction hash required' });
      return;
    }

    const cached = deploymentCache.get(txHash);
    if (cached) {
      const elapsed = Date.now() - cached.timestamp;
      if (elapsed > 300000) {
        deploymentCache.delete(txHash);
      } else {
        res.json({
          txHash,
          status: cached.status,
          contractAddress: cached.contractAddress,
          chainId: cached.chainId,
          cached: true,
        });
        return;
      }
    }

    const { deployer } = await import('./agents/deployer');
    const receipt = await deployer.getTransactionReceipt(txHash);

    if (!receipt) {
      res.json({
        txHash,
        status: 'pending',
        message: 'Transaction still pending confirmation',
      });
      return;
    }

    const status = receipt.status === 1 ? 'confirmed' : 'failed';
    const updatedState: DeploymentState = {
      txHash,
      status,
      contractAddress: receipt.contractAddress,
      chainId: receipt.chainId,
      timestamp: Date.now(),
    };
    deploymentCache.set(txHash, updatedState);

    res.json({
      txHash,
      status,
      contractAddress: receipt.contractAddress,
      chainId: receipt.chainId,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Status check failed', details: errorMessage });
  }
});

app.get('/api/audit/:contractAddress', async (req: Request, res: Response) => {
  try {
    const { contractAddress } = req.params;

    if (!contractAddress || !contractAddress.startsWith('0x')) {
      res.status(400).json({ error: 'Valid contract address required' });
      return;
    }

    const cached = auditCache.get(contractAddress);
    if (cached) {
      const elapsed = Date.now() - cached.timestamp;
      if (elapsed < 3600000) {
        res.json({
          contractAddress,
          score: cached.score,
          issues: cached.issues,
          cached: true,
        });
        return;
      }
    }

    const { deployer } = await import('./agents/deployer');
    const bytecode = await deployer.getCode(contractAddress);

    if (!bytecode || bytecode === '0x') {
      res.status(404).json({ error: 'Contract not found or has no code' });
      return;
    }

    const auditResult = await auditContract(bytecode);

    auditCache.set(contractAddress, {
      score: auditResult.score,
      issues: auditResult.issues,
      timestamp: Date.now(),
    });

    res.json({
      contractAddress,
      score: auditResult.score,
      issues: auditResult.issues,
      recommendations: auditResult.recommendations,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Audit failed', details: errorMessage });
  }
});

app.post('/api/verify-proof', async (req: Request, res: Response) => {
  try {
    const { proof, publicInputs, contractAddress } = req.body;

    if (!proof || !publicInputs) {
      res.status(400).json({ error: 'Proof and public inputs are required' });
      return;
    }

    const { verifyProof } = await import('./zk/prover');
    const isValid = await verifyProof(proof, publicInputs);

    res.json({
      valid: isValid,
      contractAddress,
      timestamp: new Date().toISOString(),
      message: isValid ? 'ZK proof verified successfully' : 'ZK proof verification failed',
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Proof verification failed', details: errorMessage });
  }
});

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

app.get('/api/balance', async (_req: Request, res: Response) => {
  try {
    const balanceCheck = await checkWalletBalance();
    res.json({
      balance: balanceCheck.balance,
      sufficient: balanceCheck.sufficient,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Balance check failed', details: errorMessage });
  }
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

let server: ReturnType<typeof app.listen> | null = null;

function startServer(): void {
  server = app.listen(PORT, () => {
    logger.info(`NoLangX API server running on port ${PORT}`);
    logger.info(`Trust proxy level: ${TRUST_PROXY}`);
  });
}

function gracefulShutdown(signal: string): void {
  logger.info(`Received ${signal}, shutting down gracefully...`);

  if (server) {
    server.close((err) => {
      if (err) {
        logger.error('Error during server close:', err);
        process.exit(1);
      }

      logger.info('Server closed, all connections terminated');

      const handles = setInterval(() => {
        const activeHandles = process._getActiveHandles();
        const activeRequests = process._getActiveRequests();

        if (activeHandles.length === 0 && activeRequests.length === 0) {
          clearInterval(handles);
          logger.info('All handles cleared, exiting process');
          process.exit(0);
        }
      }, 100);

      setTimeout(() => {
        clearInterval(handles);
        logger.info('Forced shutdown after timeout');
        process.exit(1);
      }, 10000);
    });
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error(`Unhandled rejection at: ${promise} reason: ${reason}`);
  gracefulShutdown('unhandledRejection');
});

startServer();

export { app };
