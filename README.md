# ExpressJS ERC-20 Token Faucet API

This project is a TypeScript-based [ExpressJS](https://expressjs.com/) API server that acts as a secure ERC-20 token faucet. It allows users to claim a limited amount of tokens per day, with rate limiting, Google reCAPTCHA v2 bot protection, and persistent storage using Redis (with in-memory fallback for development).

## ✨ Features

- ExpressJS API written in TypeScript
- ERC-20 token faucet: send tokens to user addresses
- Rate limiting per user (tokens per 24h, cooldown between claims)
- Google reCAPTCHA v2 verification for anti-bot protection
- Redis-based persistent storage for rate limiting (with in-memory fallback)
- Health check and status endpoints

## 🛠️ Endpoints

- `GET /api/health` — Health check and environment status
- `GET /api/claim-status/:address` — Get claim status, rate limit info, and next claim time for a user address
- `POST /api/claim-tokens` — Claim tokens (requires `{ userAddress, captchaToken }` in body)

## 🧑‍💻 How to use

1. Install dependencies:
   ```sh
   yarn
   ```
2. Set up your `.env` file with the following variables:
   - `TREASURY_PRIVATE_KEY` — Private key of the wallet sending tokens
   - `RPC_URL` — RPC endpoint for your blockchain
   - `TOKEN_CONTRACT_ADDRESS` — ERC-20 token contract address
   - `RECAPTCHA_SECRET_KEY` — Google reCAPTCHA v2 secret key
   - `REDIS_URL` (optional) — Redis connection string for persistent storage
3. Start the development server:
   ```sh
   yarn dev
   ```

## 📝 Notes

- The faucet enforces a daily token limit and a cooldown between claims per address.
- If Redis is not configured, in-memory storage is used (not recommended for production).
- The `/api/claim-tokens` endpoint requires a valid Google reCAPTCHA v2 token.
- All configuration is done via environment variables.

## 👏 Thanks

- [Faraz Patankar](https://github.com/FarazPatankar) / Railway team for the [original template](https://github.com/railwayapp-templates/expressjs)
