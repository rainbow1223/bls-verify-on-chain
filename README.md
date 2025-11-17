# BLS12-381 Verification with Hash-to-Curve

This Foundry project contains a Solidity implementation of BLS12-381 signature verification with on-chain hash-to-curve functionality using EIP-2537 precompiles.

## Overview

The contract `BLSVerifyWithHashToCurve` implements:
- BLS12-381 signature verification using pairing checks
- Hash-to-curve (G2) using XMD:SHA-256 with SSWU mapping
- EIP-2537 precompile integration for BLS operations

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed (for Solidity tests)
- [Node.js](https://nodejs.org/) and npm (for TypeScript tests)
- A network that supports EIP-2537 precompiles (e.g., some testnets or custom networks)

## Project Structure

```
.
├── src/
│   └── BLSVerifyWithHashToCurve.sol    # Main contract
├── test/
│   ├── BLSVerifyWithHashToCurve.t.sol  # Solidity test suite (Foundry)
│   ├── BLSVerify.test.ts               # TypeScript test suite (Hardhat)
│   ├── bls-verify.test.ts              # Alternative TypeScript tests
│   └── bls-utils.ts                    # BLS utility functions
├── scripts/
│   └── deploy.ts                       # Deployment script
├── foundry.toml                         # Foundry configuration
├── hardhat.config.ts                   # Hardhat configuration
├── tsconfig.json                        # TypeScript configuration
└── README.md                            # This file
```

## Installation

1. Install Foundry (if not already installed):
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. Clone or navigate to this directory

3. Install forge-std (required for Solidity tests):
   ```bash
   forge install foundry-rs/forge-std --no-commit
   ```

4. Install Node.js dependencies (required for TypeScript tests):
   ```bash
   npm install
   ```

## Testing

### Solidity Tests (Foundry)

Run all Solidity tests:
```bash
forge test
```

Run tests with verbose output:
```bash
forge test -vvv
```

Run a specific test:
```bash
forge test --match-test test_HashToCurveG2_Deterministic
```

Run fuzz tests:
```bash
forge test --match-test testFuzz
```

### TypeScript Tests (Hardhat)

The TypeScript tests use `@chainsafe/bls` to generate real BLS signatures and verify them on-chain.

1. Compile the contracts:
   ```bash
   npx hardhat compile
   ```

2. Run TypeScript tests:
   ```bash
   npx hardhat test
   ```

   Or run a specific test file:
   ```bash
   npx hardhat test test/BLSVerify.test.ts
   ```

3. Deploy the contract (optional, tests deploy automatically to local network):
   
   **Setup for deployment:**
   
   a. Create a `.env` file in the project root:
   ```bash
   cp .env.example .env
   ```
   
   b. Edit `.env` and add your credentials for the network you want to deploy to:
   ```env
   # For Sepolia testnet
   SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY
   
   # For Mainnet (use with caution!)
   MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY
   
   # For other networks, add their RPC URLs
   PRIVATE_KEY=your_private_key_without_0x_prefix
   ETHERSCAN_API_KEY=your_etherscan_api_key  # Optional, for verification
   ```
   
   c. Make sure your wallet has ETH for gas fees on the target network
   
   d. Deploy to your chosen network:
   ```bash
   # Deploy to Sepolia
   npx hardhat run scripts/deploy.ts --network sepolia
   
   # Deploy to Mainnet (be careful!)
   npx hardhat run scripts/deploy.ts --network mainnet
   
   # Deploy to Holesky
   npx hardhat run scripts/deploy.ts --network holesky
   
   # Deploy to Goerli (deprecated)
   npx hardhat run scripts/deploy.ts --network goerli
   ```
   
   **Available networks:**
   - `hardhat` - Local Hardhat network (default, no --network flag needed)
   - `sepolia` - Sepolia testnet (Chain ID: 11155111)
   - `mainnet` - Ethereum mainnet (Chain ID: 1)
   - `goerli` - Goerli testnet (Chain ID: 5, deprecated)
   - `holesky` - Holesky testnet (Chain ID: 17000)
   
   To add a custom network, edit `hardhat.config.ts` and add it to the `networks` object.

**Note:** TypeScript tests require EIP-2537 precompiles to be available. If running on Hardhat's default network, some tests may be skipped with a warning. For full functionality, deploy to a network that supports EIP-2537 precompiles or use a Hardhat fork of such a network.

**Important:** Sepolia testnet may not support EIP-2537 precompiles. The contract will deploy but BLS operations may fail. Consider deploying to a network that supports EIP-2537 precompiles (check network documentation).

## Contract Functions

### `verifyWithHashToCurveG2`
Verifies a BLS signature with on-chain hash-to-curve computation.

**Parameters:**
- `pkG1_128`: Public key in G1 (128 bytes, uncompressed EIP-2537 encoding)
- `sigG2_256`: Signature in G2 (256 bytes, uncompressed EIP-2537 encoding)
- `msg_`: Message to verify (arbitrary length)
- `dst`: Domain separation tag (≤ 255 bytes)

**Returns:** `bool` - `true` if signature is valid

### `hashToCurveG2`
Maps a message to a point on the G2 curve using hash-to-curve.

**Parameters:**
- `message`: Message to hash (arbitrary length)
- `dst`: Domain separation tag (≤ 255 bytes)

**Returns:** `G2Point` - Point on G2 curve

### `hashToCurve`
Convenience function that returns the packed G2 point.

**Parameters:**
- `message`: Message to hash
- `dst`: Domain separation tag

**Returns:** `bytes` - 256-byte packed G2 point

## EIP-2537 Precompiles

This contract uses the following EIP-2537 precompiles:
- `0x0d`: G2_ADD - G2 point addition
- `0x0f`: PAIRING - Bilinear pairing check
- `0x11`: MAP_FP2_TO_G2 - Map Fp2 element to G2 point

**Note:** These precompiles must be available on the network where the contract is deployed.

## Testing with Real BLS Data

The TypeScript test suite (`test/BLSVerify.test.ts`) automatically generates BLS key pairs and signatures using the `@noble/curves` library and verifies them on-chain.

### TypeScript Tests Include:

- **BLS Key Generation**: Tests key pair generation
- **Off-Chain Verification**: Verifies signatures using the BLS library
- **On-Chain Verification**: Verifies signatures using the contract
- **Hash-to-Curve**: Tests deterministic message hashing
- **Input Validation**: Tests contract input validation
- **Edge Cases**: Tests empty messages, long messages, etc.

### Format Conversion

The contract expects uncompressed EIP-2537 format:
- **G1 Public Key**: 128 bytes (64 bytes x || 64 bytes y)
- **G2 Signature**: 256 bytes (64 bytes x_im || 64 bytes x_re || 64 bytes y_im || 64 bytes y_re)

The `@noble/curves` library provides compressed format by default. The test utilities (`test/bls-utils.ts`) include conversion functions, though for production use you may need to use the contract's EIP-2537 precompiles to properly decompress points.

### Example TypeScript Test

```typescript
import { bls12_381 as bls } from "@noble/curves/bls12-381";

// Generate key pair
const privateKey = bls.utils.randomPrivateKey();
const publicKey = bls.getPublicKey(privateKey);

// Sign message
const message = "Hello, BLS!";
const messageBytes = new TextEncoder().encode(message);
const signature = bls.sign(messageBytes, privateKey);

// Verify on-chain
const isValid = await blsVerifier.verifyWithHashToCurveG2(
  g1PublicKeyToEIP2537(publicKey),
  g2SignatureToEIP2537(signature),
  ethers.toUtf8Bytes(message),
  dstToHexArray(BLS_SIG_DST)
);
```

## Standard DST

The default domain separation tag (DST) used in tests is:
```
BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
```

This is the standard DST for BLS signatures as specified in the BLS signature standard.

## Gas Considerations

- Hash-to-curve operations are computationally expensive
- Pairing checks require significant gas
- Consider using this contract only when on-chain verification is necessary
- For off-chain verification, use native BLS libraries
