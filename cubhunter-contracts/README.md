# cubhunter-contracts

Smart contracts for the CubHunter SecureVault system — deployed on Base network.

## Contracts

- **SecureVault.sol** — UUPS upgradeable vault with state machine, EIP-712 recovery, quarantine mechanism and reentrancy protection.

## Setup

```bash
npm install
cp .env.example .env
# Fill in your PRIVATE_KEY and API keys in .env
```

## Commands

```bash
# Compile
npm run compile

# Run tests
npm test

# Deploy to local hardhat node
npm run deploy:local

# Deploy to Base Sepolia testnet
npm run deploy:testnet

# Deploy to Base Mainnet
npm run deploy:mainnet
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PRIVATE_KEY` | Deployer wallet private key |
| `BASE_SEPOLIA_URL` | Base Sepolia RPC URL |
| `BASESCAN_API_KEY` | For contract verification on BaseScan |

## Networks

| Network | Chain ID |
|---------|----------|
| Base Sepolia (testnet) | 84532 |
| Base Mainnet | 8453 |

Get testnet ETH: https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet
