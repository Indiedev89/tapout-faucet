// server.ts - Updated with Redis for persistent rate limiting
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { createClient } from 'redis';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Interfaces
interface ClaimRequest {
  userAddress: string;
  timestamp?: number;
  captchaToken: string;
}

interface UserClaimData {
  totalClaimed: number;
  lastClaimTime: number;
  firstClaimTime: number;
}

// reCAPTCHA v2 response interface
interface RecaptchaResponse {
  success: boolean;
  challenge_ts: string;
  hostname: string;
  'error-codes'?: string[];
}

// Configuration
const CONFIG = {
  PRIVATE_KEY: process.env.TREASURY_PRIVATE_KEY!,
  RPC_URL: process.env.RPC_URL!,
  TOKEN_CONTRACT_ADDRESS: process.env.TOKEN_CONTRACT_ADDRESS!,
  RECAPTCHA_SECRET_KEY: process.env.RECAPTCHA_SECRET_KEY!,

  // Rate limiting settings
  DEFAULT_CLAIM_AMOUNT: '100000',
  MAX_TOKENS_PER_24H: '100000',
  MIN_CLAIM_INTERVAL: 5 * 60 * 1000, // 5 minutes
  RATE_LIMIT_WINDOW: 24 * 60 * 60 * 1000, // 24 hours

  TOKEN_DECIMALS: 18,
  CHAIN_ID: 6342
};

// Redis client setup
let redis: any = null;

async function initRedis() {
  try {
    const redisUrl = process.env.REDIS_URL || process.env.REDIS_PRIVATE_URL;

    if (!redisUrl) {
      console.warn(
        '⚠️  No Redis URL found. Using in-memory storage (not recommended for production)'
      );
      return null;
    }

    redis = createClient({
      url: redisUrl,
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 500),
        connectTimeout: 10000
      }
    });

    redis.on('error', (err) => {
      console.error('Redis Client Error:', err);
    });

    redis.on('connect', () => {
      console.log('✅ Connected to Redis');
    });

    redis.on('ready', () => {
      console.log('✅ Redis is ready');
    });

    redis.on('end', () => {
      console.log('❌ Redis connection ended');
    });

    await redis.connect();
    return redis;
  } catch (error) {
    console.error('❌ Failed to connect to Redis:', error);
    return null;
  }
}

// Fallback in-memory storage (only used if Redis is unavailable)
const memoryStorage = new Map<string, UserClaimData>();

// Storage functions that work with both Redis and memory
async function getUserClaimData(
  userAddress: string
): Promise<UserClaimData | null> {
  try {
    if (redis) {
      const data = await redis.get(`claims:${userAddress}`);
      return data ? JSON.parse(data) : null;
    } else {
      return memoryStorage.get(userAddress) || null;
    }
  } catch (error) {
    console.error('Error getting user claim data:', error);
    return memoryStorage.get(userAddress) || null;
  }
}

async function setUserClaimData(
  userAddress: string,
  data: UserClaimData
): Promise<void> {
  try {
    if (redis) {
      // Set with 25-hour expiry (slightly longer than 24h window for safety)
      await redis.setEx(
        `claims:${userAddress}`,
        25 * 60 * 60,
        JSON.stringify(data)
      );
    } else {
      memoryStorage.set(userAddress, data);
    }
  } catch (error) {
    console.error('Error setting user claim data:', error);
    // Fallback to memory storage
    memoryStorage.set(userAddress, data);
  }
}

async function deleteUserClaimData(userAddress: string): Promise<void> {
  try {
    if (redis) {
      await redis.del(`claims:${userAddress}`);
    } else {
      memoryStorage.delete(userAddress);
    }
  } catch (error) {
    console.error('Error deleting user claim data:', error);
    memoryStorage.delete(userAddress);
  }
}

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://your-domain.vercel.app',
    'https://your-custom-domain.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

// ERC20 ABI
const ERC20_ABI = [
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address account) view returns (uint256)',
  'function decimals() view returns (uint8)'
];

// Verify Google reCAPTCHA v2 token
async function verifyCaptcha(
  token: string,
  userIP: string
): Promise<{ success: boolean; error?: string }> {
  // For test key, skip verification
  if (
    CONFIG.RECAPTCHA_SECRET_KEY === '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
  ) {
    console.log('Using test reCAPTCHA key - auto-approving');
    return { success: true };
  }

  if (!CONFIG.RECAPTCHA_SECRET_KEY) {
    console.warn(
      'RECAPTCHA_SECRET_KEY not configured, skipping captcha verification'
    );
    return { success: true };
  }

  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return { success: false, error: 'Invalid captcha token provided' };
  }

  try {
    const formData = new URLSearchParams();
    formData.append('secret', CONFIG.RECAPTCHA_SECRET_KEY);
    formData.append('response', token);
    if (userIP && userIP !== '127.0.0.1') {
      formData.append('remoteip', userIP);
    }

    const response = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData.toString()
      }
    );

    if (!response.ok) {
      console.error(
        'reCAPTCHA verification request failed:',
        response.status,
        response.statusText
      );
      return {
        success: false,
        error: 'Captcha verification service unavailable'
      };
    }

    const result = (await response.json()) as Partial<RecaptchaResponse>;
    if (
      typeof result.success !== 'boolean' ||
      typeof result.challenge_ts !== 'string' ||
      typeof result.hostname !== 'string'
    ) {
      console.error('Invalid reCAPTCHA response structure:', result);
      return {
        success: false,
        error: 'Invalid captcha verification response from server'
      };
    }
    console.log('reCAPTCHA v2 verification result:', {
      success: result.success,
      hostname: result.hostname,
      errorCodes: result['error-codes']
    });

    if (!result.success) {
      const errorCodes = result['error-codes'] || [];
      if (errorCodes.includes('timeout-or-duplicate')) {
        return {
          success: false,
          error: 'Captcha token expired or already used. Please try again.'
        };
      } else if (errorCodes.includes('invalid-input-response')) {
        return {
          success: false,
          error: 'Invalid captcha response. Please try again.'
        };
      } else {
        return {
          success: false,
          error: 'Captcha verification failed. Please try again.'
        };
      }
    }

    console.log('reCAPTCHA v2 verification successful');
    return { success: true };
  } catch (error) {
    console.error('Captcha verification error:', error);
    return {
      success: false,
      error: 'Captcha verification service temporarily unavailable'
    };
  }
}

// Check if user has exceeded rate limits
async function checkRateLimit(userAddress: string): Promise<{
  allowed: boolean;
  remainingTokens: number;
  nextClaimTime: number; // Timestamp when next claim is possible. 0 if allowed now.
  error?: string;
}> {
  const now = Date.now();
  const userData = await getUserClaimData(userAddress);
  const maxTokens = parseInt(CONFIG.MAX_TOKENS_PER_24H);
  const claimAmount = parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT);

  if (!userData) {
    return {
      allowed: true,
      remainingTokens: maxTokens,
      nextClaimTime: 0
    };
  }

  const { totalClaimed, lastClaimTime, firstClaimTime } = userData;

  // Reset if 24 hours have passed since the first claim
  const windowResetTime = firstClaimTime + CONFIG.RATE_LIMIT_WINDOW;
  if (now >= windowResetTime) {
    await deleteUserClaimData(userAddress);
    return {
      allowed: true,
      remainingTokens: maxTokens,
      nextClaimTime: 0
    };
  }

  const remainingTokens = maxTokens - totalClaimed;

  // Check 24-hour token limit. A user can't claim if they don't have enough allowance for one claim.
  if (remainingTokens < claimAmount) {
    const hoursUntilReset = Math.ceil(
      (windowResetTime - now) / 1000 / 60 / 60
    );
    return {
      allowed: false,
      remainingTokens: remainingTokens,
      nextClaimTime: windowResetTime,
      error: `Daily limit reached. You have ${remainingTokens} tokens remaining. Resets in ${hoursUntilReset} hours`
    };
  }

  // Check minimum time between claims
  const cooldownEndTime = lastClaimTime + CONFIG.MIN_CLAIM_INTERVAL;
  if (now < cooldownEndTime) {
    const remainingWait = Math.ceil((cooldownEndTime - now) / 1000 / 60);
    return {
      allowed: false,
      remainingTokens: remainingTokens,
      nextClaimTime: cooldownEndTime,
      error: `Please wait ${remainingWait} minutes before claiming again`
    };
  }

  // If all checks pass, user can claim
  return {
    allowed: true,
    remainingTokens: remainingTokens,
    nextClaimTime: 0 // Can claim now
  };
}

// Update user claim data
async function updateUserClaims(
  userAddress: string,
  amount: number
): Promise<void> {
  const now = Date.now();
  const userData = await getUserClaimData(userAddress);

  if (!userData) {
    await setUserClaimData(userAddress, {
      totalClaimed: amount,
      lastClaimTime: now,
      firstClaimTime: now
    });
  } else {
    await setUserClaimData(userAddress, {
      ...userData,
      totalClaimed: userData.totalClaimed + amount,
      lastClaimTime: now
    });
  }
}

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Validate environment variables
    if (!process.env.RPC_URL || !process.env.TOKEN_CONTRACT_ADDRESS) {
      throw new Error('Missing required environment variables');
    }

    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    const network = await provider.getNetwork();

    // Check Redis connection
    let redisStatus = 'not_configured';
    if (redis) {
      try {
        await redis.ping();
        redisStatus = 'connected';
      } catch (error) {
        redisStatus = 'error';
      }
    }

    return res.json({
      status: 'healthy',
      network: {
        chainId: network.chainId.toString(),
        name: network.name
      },
      config: {
        rpcConfigured: !!process.env.RPC_URL,
        tokenConfigured: !!process.env.TOKEN_CONTRACT_ADDRESS,
        recaptchaConfigured: !!process.env.RECAPTCHA_SECRET_KEY,
        redisStatus
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    return res.status(500).json({
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    });
  }
});

// CHANGED: Added /api prefix for consistency
app.get('/api/claim-status/:address', async (req, res) => {
  try {
    const { address } = req.params;

    if (!address || !ethers.isAddress(address)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid address'
      });
    }

    const rateLimitCheck = await checkRateLimit(address);

    return res.json({
      success: true,
      remainingTokens: rateLimitCheck.remainingTokens,
      nextClaimTime: rateLimitCheck.nextClaimTime,
      canClaim: rateLimitCheck.allowed,
      maxTokensPerDay: parseInt(CONFIG.MAX_TOKENS_PER_24H),
      claimAmount: parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT),
      cooldownMinutes: CONFIG.MIN_CLAIM_INTERVAL / (1000 * 60)
    });
  } catch (error) {
    console.error('Error getting claim status:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to get claim status'
    });
  }
});

// CHANGED: Added /api prefix for consistency
app.post('/api/claim-tokens', async (req, res) => {
  try {
    console.log('Claim request received at:', new Date().toISOString());

    // Validate environment variables
    const missingEnvVars = [];
    if (!process.env.TREASURY_PRIVATE_KEY)
      missingEnvVars.push('TREASURY_PRIVATE_KEY');
    if (!process.env.RPC_URL) missingEnvVars.push('RPC_URL');
    if (!process.env.TOKEN_CONTRACT_ADDRESS)
      missingEnvVars.push('TOKEN_CONTRACT_ADDRESS');

    if (missingEnvVars.length > 0) {
      console.error('Missing environment variables:', missingEnvVars);
      return res.status(500).json({
        success: false,
        error: 'Server configuration error: Missing environment variables'
      });
    }

    const { userAddress, captchaToken }: ClaimRequest = req.body;

    // Basic validation
    if (!userAddress || !ethers.isAddress(userAddress)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid recipient address'
      });
    }

    if (!captchaToken) {
      return res.status(400).json({
        success: false,
        error: 'Captcha verification required'
      });
    }

    // Get user IP for captcha verification
    const userIP =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (req.headers['x-real-ip'] as string) ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      '127.0.0.1';

    console.log('User IP:', userIP);

    // Verify captcha with reCAPTCHA v2
    const captchaResult = await verifyCaptcha(captchaToken, userIP);
    if (!captchaResult.success) {
      return res.status(400).json({
        success: false,
        error:
          captchaResult.error || 'Bot verification failed. Please try again.'
      });
    }

    // Check rate limits
    const rateLimitCheck = await checkRateLimit(userAddress);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: rateLimitCheck.error,
        remainingTokens: rateLimitCheck.remainingTokens,
        nextClaimTime: rateLimitCheck.nextClaimTime
      });
    }

    console.log(
      `Processing claim for ${userAddress}: ${CONFIG.DEFAULT_CLAIM_AMOUNT} tokens (${rateLimitCheck.remainingTokens} remaining today)`
    );

    // Setup ethers with error handling
    let provider;
    try {
      provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
      // Test connection
      await provider.getNetwork();
    } catch (error) {
      console.error('RPC connection error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to connect to blockchain network'
      });
    }

    // Clean and validate private key
    let privateKey = CONFIG.PRIVATE_KEY;
    if (!privateKey.startsWith('0x')) {
      privateKey = '0x' + privateKey;
    }

    let wallet;
    try {
      wallet = new ethers.Wallet(privateKey, provider);
      console.log('Treasury wallet address:', wallet.address);
    } catch (error) {
      console.error('Wallet creation error:', error);
      return res.status(500).json({
        success: false,
        error: 'Server configuration error: Invalid wallet configuration'
      });
    }

    // Get token contract
    const tokenContract = new ethers.Contract(
      CONFIG.TOKEN_CONTRACT_ADDRESS,
      ERC20_ABI,
      wallet
    );

    // Parse amount
    const amountInWei = ethers.parseUnits(
      CONFIG.DEFAULT_CLAIM_AMOUNT,
      CONFIG.TOKEN_DECIMALS
    );

    // Check treasury balance
    let treasuryBalance;
    try {
      treasuryBalance = await tokenContract.balanceOf(wallet.address);
      console.log(
        'Treasury balance:',
        ethers.formatUnits(treasuryBalance, CONFIG.TOKEN_DECIMALS)
      );
    } catch (error) {
      console.error('Balance check error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to check treasury balance'
      });
    }

    if (treasuryBalance < amountInWei) {
      return res.status(500).json({
        success: false,
        error: 'Insufficient treasury balance'
      });
    }

    // Send the transfer transaction with retry logic
    let tx;
    let retries = 3;

    while (retries > 0) {
      try {
        // Get gas price with buffer
        const gasPrice = await provider.getFeeData();
        tx = await tokenContract.transfer(userAddress, amountInWei, {
          gasLimit: 150000,
          gasPrice: gasPrice.gasPrice
            ? (gasPrice.gasPrice * 110n) / 100n
            : undefined
        });

        console.log(`Transaction sent: ${tx.hash}`);

        const receipt = await tx.wait(1);
        console.log(`Transaction confirmed in block: ${receipt.blockNumber}`);

        break; // Exit the loop but continue execution
      } catch (error) {
        retries--;
        console.error(`Transaction attempt failed (${3 - retries}/3):`, error);

        if (retries === 0) {
          throw error; // Only throw after all retries exhausted
        }

        // Wait a bit before retrying
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    if (!tx) {
      return res.status(500).json({
        success: false,
        error: 'Failed to send transaction after multiple attempts'
      });
    }

    // Wait for confirmation with timeout
    let receipt;
    try {
      receipt = await Promise.race([
        tx.wait(1),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Transaction timeout')), 30000)
        )
      ]);
    } catch (error) {
      console.error('Transaction confirmation error:', error);
      // Transaction was sent but confirmation timed out
      // Still update user claims as the transaction may succeed
      await updateUserClaims(
        userAddress,
        parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT)
      );

      // Get updated remaining tokens after the claim
      const updatedRateLimitCheckTimeout = await checkRateLimit(userAddress);

      return res.status(200).json({
        success: true,
        txHash: tx.hash,
        amount: CONFIG.DEFAULT_CLAIM_AMOUNT,
        token: 'TAP',
        remainingTokens: updatedRateLimitCheckTimeout.remainingTokens, // This is now correct
        nextClaimTime: updatedRateLimitCheckTimeout.nextClaimTime,
        maxTokensPerDay: parseInt(CONFIG.MAX_TOKENS_PER_24H),
        warning: 'Transaction sent but confirmation is pending'
      });
    }

    console.log(`Transaction confirmed in block: ${receipt.blockNumber}`);

    // Update user claim data
    await updateUserClaims(userAddress, parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT));

    const updatedRateLimitCheck = await checkRateLimit(userAddress);

    // Send success response
    return res.json({
      success: true,
      txHash: tx.hash,
      amount: CONFIG.DEFAULT_CLAIM_AMOUNT,
      token: 'TAP',
      remainingTokens: updatedRateLimitCheck.remainingTokens, // This is now correct
      nextClaimTime: updatedRateLimitCheck.nextClaimTime,
      maxTokensPerDay: parseInt(CONFIG.MAX_TOKENS_PER_24H)
    });
  } catch (error) {
    console.error('Claim processing error:', error);

    let errorMessage = 'Transaction failed';
    if (error instanceof Error) {
      console.error('Error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name
      });

      if (error.message.includes('insufficient funds')) {
        errorMessage = 'Insufficient gas or treasury funds';
      } else if (error.message.includes('execution reverted')) {
        errorMessage = 'Transaction was reverted - check token balance';
      } else if (error.message.includes('invalid private key')) {
        errorMessage = 'Server configuration error: Invalid private key';
      } else if (error.message.includes('could not detect network')) {
        errorMessage = 'Network connection error';
      } else if (error.message.includes('timeout')) {
        errorMessage = 'Transaction timeout - please try again';
      } else if (error.message.includes('nonce')) {
        errorMessage = 'Transaction nonce error - please try again';
      } else {
        errorMessage = error.message.substring(0, 100); // Limit error message length
      }
    }

    return res.status(500).json({
      success: false,
      error: errorMessage
    });
  }
});

// Initialize server
async function startServer() {
  // Initialize Redis connection
  await initRedis();

  // Start server
  app.listen(PORT, () => {
    console.log(`🚀 Token Faucet Server running on port ${PORT}`);
    // CHANGED: Updated logs to show full, correct paths
    console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
    console.log(`📊 Status endpoint: http://localhost:${PORT}/api/claim-status/:address`);
    console.log(`🪙 Claim endpoint: http://localhost:${PORT}/api/claim-tokens`);

    // Validate environment on startup
    const requiredEnvVars = [
      'TREASURY_PRIVATE_KEY',
      'RPC_URL',
      'TOKEN_CONTRACT_ADDRESS',
      'RECAPTCHA_SECRET_KEY'
    ];

    const missing = requiredEnvVars.filter((key) => !process.env[key]);
    if (missing.length > 0) {
      console.warn('⚠️  Missing environment variables:', missing);
    } else {
      console.log('✅ All environment variables configured');
    }

    if (redis) {
      console.log('✅ Redis connected - persistent rate limiting enabled');
    } else {
      console.warn(
        '⚠️  Redis not available - using in-memory storage (not recommended for production)'
      );
    }
  });
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (redis) {
    await redis.quit();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  if (redis) {
    await redis.quit();
  }
  process.exit(0);
});

// Start the server
startServer().catch(console.error);