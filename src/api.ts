// server.ts - COMPLETE & SECURED with dual Wallet + IP Address rate limiting (TypeScript fix applied)
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { createClient, RedisClientType } from 'redis';

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// --- TYPE DEFINITIONS ---

interface ClaimRequest {
  userAddress: string;
  captchaToken: string;
  proof: {
    contractAddress: string;
    chainId: number;
  };
}

interface ClaimData {
  totalClaims: number;
  lastClaimTime: number;
  firstClaimTime: number;
}

interface RecaptchaResponse {
  success: boolean;
  challenge_ts: string;
  hostname: string;
  'error-codes'?: string[];
}

// --- CONFIGURATION ---

const CONFIG = {
  PRIVATE_KEY: process.env.TREASURY_PRIVATE_KEY!,
  RPC_URLS: {
    '6342': process.env.RPC_URL!, // Megaeth Testnet
    '1': process.env.ETH_RPC_URL! // Ethereum Mainnet
  },
  TOKEN_CONTRACT_ADDRESS: process.env.TOKEN_CONTRACT_ADDRESS!,
  RECAPTCHA_SECRET_KEY: process.env.RECAPTCHA_SECRET_KEY!,
  DEFAULT_CLAIM_AMOUNT: '100000',
  MAX_TOKENS_PER_WALLET_24H: 100000,
  MAX_CLAIMS_PER_IP_24H: 1,
  MIN_CLAIM_INTERVAL: 5 * 60 * 1000, // 5 minutes (for wallets)
  RATE_LIMIT_WINDOW: 24 * 60 * 60 * 1000, // 24 hours
  TOKEN_DECIMALS: 18,
  ALLOWED_NFT_CONTRACTS: {
    '6342': [
      (
        process.env.NFT_CONTRACT_ADDRESS ||
        '0x375886CA380b56F3bF5ac75A5d3d2c87954E1b9b'
      ).toLowerCase(),
      '0x8bd9de927dccb375df08a747a0e42b90a5758eba'
    ],
    '1': [
      '0xbdb13add477e76c1df52192d4f5f4dd67f6a40d8',
      '0x4e502ab1bb313b3c1311eb0d11b31a6b62988b86',
      '0x851b728e568c9e10ab8007f27a525fbbed29b259'
    ]
  }
};

// --- REDIS & STORAGE ---

let redis: RedisClientType | null = null;
const memoryStorage = new Map<string, ClaimData>();
async function initRedis() {
  try {
    const redisUrl = process.env.REDIS_URL || process.env.REDIS_PRIVATE_URL;
    if (!redisUrl) {
      console.warn('⚠️  No Redis URL found. Using in-memory storage.');
      return null;
    }
    redis = createClient({
      url: redisUrl,
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 500),
        connectTimeout: 10000
      }
    });
    redis.on('error', (err: unknown) =>
      console.error('Redis Client Error:', err)
    );
    redis.on('connect', () => console.log('✅ Connected to Redis'));
    await redis.connect();
    return redis;
  } catch (error) {
    console.error('❌ Failed to connect to Redis:', error);
    return null;
  }
}
async function getClaimData(key: string): Promise<ClaimData | null> {
  try {
    if (redis) {
      const data = await redis.get(key);
      if (typeof data === 'string') {
        return JSON.parse(data) as ClaimData;
      }
      return null;
    }
    return memoryStorage.get(key) || null;
  } catch (error) {
    console.error(`Error getting claim data for key ${key}:`, error);
    return memoryStorage.get(key) || null;
  }
}
async function setClaimData(key: string, data: ClaimData): Promise<void> {
  try {
    if (redis) {
      await redis.setEx(key, 25 * 60 * 60, JSON.stringify(data));
    } else {
      memoryStorage.set(key, data);
    }
  } catch (error) {
    console.error(`Error setting claim data for key ${key}:`, error);
    memoryStorage.set(key, data);
  }
}
app.use(
  cors({
    origin: (origin, callback) => {
      const whitelist = [
        'http://localhost:3000',
        'http://localhost:8080',
        'http://localhost:5173',
        'https://www.tapout.pro'
      ];
      if (
        !origin ||
        whitelist.includes(origin) ||
        origin.endsWith('.vercel.app')
      ) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  })
);
app.use(express.json());
const ERC20_ABI = [
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address account) view returns (uint256)'
];
const ERC721_ABI = ['function balanceOf(address owner) view returns (uint256)'];
async function verifyCaptcha(
  token: string,
  userIP: string
): Promise<{ success: boolean; error?: string }> {
  if (!CONFIG.RECAPTCHA_SECRET_KEY) return { success: true };
  if (!token) return { success: false, error: 'Invalid captcha token.' };
  try {
    const response = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: CONFIG.RECAPTCHA_SECRET_KEY,
          response: token,
          remoteip: userIP
        })
      }
    );
    const result = (await response.json()) as RecaptchaResponse;
    if (!result.success)
      return {
        success: false,
        error: `Captcha failed: ${result['error-codes']?.join(', ')}`
      };
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Captcha service unavailable.' };
  }
}
async function verifyNFTOwnership(
  userAddress: string,
  proof: { contractAddress: string; chainId: number }
): Promise<{ success: boolean; error?: string }> {
  const { contractAddress, chainId } = proof;
  const chainIdStr = String(chainId);
  const allowedContracts =
    CONFIG.ALLOWED_NFT_CONTRACTS[
      chainIdStr as keyof typeof CONFIG.ALLOWED_NFT_CONTRACTS
    ];
  if (
    !allowedContracts ||
    !allowedContracts.includes(contractAddress.toLowerCase())
  ) {
    return { success: false, error: 'Unsupported NFT contract.' };
  }
  const rpcUrl = CONFIG.RPC_URLS[chainIdStr as keyof typeof CONFIG.RPC_URLS];
  if (!rpcUrl)
    return { success: false, error: 'Server misconfiguration for chain.' };
  try {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const nftContract = new ethers.Contract(
      contractAddress,
      ERC721_ABI,
      provider
    );
    const balance = await nftContract.balanceOf(userAddress);
    if (balance > 0n) return { success: true };
    return { success: false, error: 'Account does not own the required NFT.' };
  } catch (error) {
    return { success: false, error: 'Failed to verify NFT ownership.' };
  }
}
async function checkWalletRateLimit(
  userAddress: string
): Promise<{
  allowed: boolean;
  remainingTokens: number;
  nextClaimTime: number;
  error?: string;
}> {
  const key = `claims_wallet:${userAddress}`;
  const now = Date.now();
  const userData = await getClaimData(key);
  const maxTokens = CONFIG.MAX_TOKENS_PER_WALLET_24H;
  if (!userData) {
    return { allowed: true, remainingTokens: maxTokens, nextClaimTime: 0 };
  }
  const windowResetTime = userData.firstClaimTime + CONFIG.RATE_LIMIT_WINDOW;
  if (now >= windowResetTime) {
    return { allowed: true, remainingTokens: maxTokens, nextClaimTime: 0 };
  }
  const remainingTokens =
    maxTokens - userData.totalClaims * parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT);
  if (remainingTokens < parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT)) {
    return {
      allowed: false,
      remainingTokens,
      nextClaimTime: windowResetTime,
      error: 'Daily token limit for this wallet has been reached.'
    };
  }
  const cooldownEndTime = userData.lastClaimTime + CONFIG.MIN_CLAIM_INTERVAL;
  if (now < cooldownEndTime) {
    return {
      allowed: false,
      remainingTokens,
      nextClaimTime: cooldownEndTime,
      error: 'Please wait before claiming again with this wallet.'
    };
  }
  return { allowed: true, remainingTokens, nextClaimTime: 0 };
}
async function checkIpRateLimit(
  ip: string
): Promise<{ allowed: boolean; error?: string }> {
  const key = `claims_ip:${ip}`;
  const now = Date.now();
  const ipData = await getClaimData(key);
  if (!ipData) return { allowed: true };
  if (now >= ipData.firstClaimTime + CONFIG.RATE_LIMIT_WINDOW) {
    return { allowed: true };
  }
  if (ipData.totalClaims >= CONFIG.MAX_CLAIMS_PER_IP_24H) {
    return {
      allowed: false,
      error: 'The daily claim limit for your network has been reached.'
    };
  }
  return { allowed: true };
}
async function updateClaimData(key: string): Promise<void> {
  const now = Date.now();
  const existingData = await getClaimData(key);
  let data: ClaimData;
  if (
    !existingData ||
    now >= existingData.firstClaimTime + CONFIG.RATE_LIMIT_WINDOW
  ) {
    data = { totalClaims: 1, lastClaimTime: now, firstClaimTime: now };
  } else {
    data = {
      ...existingData,
      totalClaims: existingData.totalClaims + 1,
      lastClaimTime: now
    };
  }
  await setClaimData(key, data);
}
app.get('/api/health', (req, res) => res.json({ status: 'healthy' }));

// --- SERVER CHANGE ---
// This endpoint is now reverted to provide the detailed data the original UI needs.
app.get('/api/claim-status/:address', async (req, res) => {
  try {
    const { address } = req.params;
    if (!address || !ethers.isAddress(address)) {
      return res.status(400).json({ success: false, error: 'Invalid address' });
    }
    // We only need to check the wallet limit here for UI purposes
    const walletLimit = await checkWalletRateLimit(address);
    return res.json({
      success: true,
      canClaim: walletLimit.allowed,
      remainingTokens: walletLimit.remainingTokens,
      nextClaimTime: walletLimit.nextClaimTime,
      claimAmount: parseInt(CONFIG.DEFAULT_CLAIM_AMOUNT),
      error: walletLimit.error
    });
  } catch (error) {
    console.error('Error in /api/claim-status:', error);
    return res
      .status(500)
      .json({ success: false, error: 'An internal server error occurred.' });
  }
});

app.post('/api/claim-tokens', async (req, res) => {
  try {
    if (
      !CONFIG.PRIVATE_KEY ||
      !CONFIG.TOKEN_CONTRACT_ADDRESS ||
      !CONFIG.RPC_URLS['6342']
    ) {
      return res
        .status(500)
        .json({ success: false, error: 'Server configuration error.' });
    }
    const { userAddress, captchaToken, proof }: ClaimRequest = req.body;
    if (
      !userAddress ||
      !ethers.isAddress(userAddress) ||
      !captchaToken ||
      !proof?.contractAddress ||
      !proof?.chainId
    ) {
      return res
        .status(400)
        .json({ success: false, error: 'Invalid or incomplete request.' });
    }
    const userIP =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress;
    if (!userIP) {
      return res
        .status(400)
        .json({
          success: false,
          error: 'Could not identify client IP address.'
        });
    }
    const captchaResult = await verifyCaptcha(captchaToken, userIP);
    if (!captchaResult.success)
      return res
        .status(400)
        .json({ success: false, error: captchaResult.error });
    const ipLimit = await checkIpRateLimit(userIP);
    if (!ipLimit.allowed)
      return res.status(429).json({ success: false, error: ipLimit.error });
    const walletLimit = await checkWalletRateLimit(userAddress);
    if (!walletLimit.allowed)
      return res.status(429).json({ success: false, error: walletLimit.error });
    const nftCheck = await verifyNFTOwnership(userAddress, proof);
    if (!nftCheck.success)
      return res.status(403).json({ success: false, error: nftCheck.error });
    const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URLS['6342']);
    const wallet = new ethers.Wallet(CONFIG.PRIVATE_KEY, provider);
    const tokenContract = new ethers.Contract(
      CONFIG.TOKEN_CONTRACT_ADDRESS,
      ERC20_ABI,
      wallet
    );
    const amountInWei = ethers.parseUnits(
      CONFIG.DEFAULT_CLAIM_AMOUNT,
      CONFIG.TOKEN_DECIMALS
    );
    const faucetBalance = await tokenContract.balanceOf(wallet.address);
    if (faucetBalance < amountInWei) {
      return res
        .status(503)
        .json({ success: false, error: 'Faucet is currently empty.' });
    }
    const tx = await tokenContract.transfer(userAddress, amountInWei);
    console.log(
      `Transaction sent: ${tx.hash} for wallet ${userAddress} from IP ${userIP}`
    );
    await updateClaimData(`claims_wallet:${userAddress}`);
    await updateClaimData(`claims_ip:${userIP}`);
    // Also return the new status after claiming
    const newStatus = await checkWalletRateLimit(userAddress);
    return res.json({
      success: true,
      txHash: tx.hash,
      amount: CONFIG.DEFAULT_CLAIM_AMOUNT,
      remainingTokens: newStatus.remainingTokens,
      nextClaimTime: newStatus.nextClaimTime
    });
  } catch (error) {
    console.error('Unhandled claim processing error:', error);
    return res
      .status(500)
      .json({ success: false, error: 'An unexpected server error occurred.' });
  }
});

async function startServer() {
  await initRedis();
  app.listen(PORT, () =>
    console.log(`🚀 Faucet Server running on port ${PORT}`)
  );
}
startServer().catch((err) => console.error('Failed to start server:', err));
