# sample-contract: Multi-Token Escrow Smart Contract

This project implements a secure Multi-Token Escrow system on the Core blockchain, allowing users to create and manage escrow transactions with multiple token types. The contract has been audited and enhanced with advanced security features.

##  Security Features

- **Audited & Secure**: All high-severity vulnerabilities have been addressed
- **SafeERC20 Integration**: Handles non-standard ERC-20 tokens safely
- **Per-user Nonce System**: Prevents replay attacks and front-running
- **EIP-712 Signatures**: Supports gasless transactions with cryptographic verification
- **Token Whitelisting**: Only approved tokens can be used in the escrow
- **Batch Size Limits**: Prevents out-of-gas errors during settlements
- **Forced ETH Protection**: Detects and handles malicious ETH deposits

##  Key Improvements

- **O(1) Token Lookups**: Efficient mapping-based token balance storage
- **Per-user Deposit Tracking**: Transparent deposit history for each user
- **Graceful Failure Handling**: Failed transfers don't revert entire batches
- **Enhanced Error Messages**: Detailed error context for debugging
- **Gas Optimizations**: Reduced gas costs through efficient data structures

## Prerequisites

- Node.js (v16+ recommended)
- npm or yarn
- A wallet with some test CORE tokens for deployment and interaction

## Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd eth-multi-token-escrow
```

2. Install dependencies:
```bash
npm install
```

3. Create a `secret.json` file in the root directory with your private key:
```json
{
    "PrivateKey": "your-private-key-here"
}
```

 **Never commit your `secret.json` file or expose your private key!**

4. Configure environment variables by creating a `.env` file (if needed)

## Compilation

Compile the smart contracts with optimization enabled:
```bash
npx hardhat compile --optimizer
```

For contracts with complex functions, you may need to use the IR optimizer:
```bash
npx hardhat compile --via-ir
```

## Deployment

### Testnet Deployment
To deploy the contract to Core Testnet:
```bash
npx hardhat run scripts/deploy.ts --network coreTestnet2
```

### Mainnet Deployment
To deploy the contract to Core Mainnet:
```bash
npx hardhat run scripts/deploy.ts --network coreMainnet
```

Make sure to save the deployed contract address that will be output in the console.

## Contract Interaction

### Basic Operations

#### 1. Whitelist a Token (Owner only)
```bash
npx hardhat run scripts/whitelist-token.ts --network coreTestnet2
```

#### 2. Participate in Escrow
```bash
npx hardhat run scripts/participate.ts --network coreTestnet2
```

#### 3. Settle Challenge (Owner only)
```bash
npx hardhat run scripts/settle.ts --network coreTestnet2
```

### Advanced Features

#### EIP-712 Signature Participation
The contract supports gasless transactions using EIP-712 signatures:
```bash
npx hardhat run scripts/participate-with-signature.ts --network coreTestnet2
```

#### Handle Forced ETH (Owner only)
Detect and manage forced ETH deposits:
```bash
npx hardhat run scripts/handle-forced-eth.ts --network coreTestnet2
```

### Testnet Interaction
To interact with the deployed contract on testnet:
```bash
npx hardhat run scripts/interact.ts --network coreTestnet2
```

### Mainnet Interaction
To interact with the deployed contract on mainnet:
```bash
npx hardhat run scripts/interact.ts --network coreMainnet
```

## Network Configuration

### Core Testnet
- Network Name: Core Testnet 2
- RPC URL: https://rpc.test2.btcs.network
- Chain ID: 1114
- Explorer: https://scan.test2.btcs.network

### Core Mainnet
- Network Name: Core Mainnet
- RPC URL: https://rpc.coredao.org
- Chain ID: 1116
- Explorer: https://scan.coredao.org

## Contract Architecture

### Core Components

- **Multi-Token Support**: Handle ETH and multiple ERC-20 tokens
- **Participation Types**: Support for SideBet and JoinChallenge
- **User Deposit Tracking**: Per-user, per-token deposit history
- **Batch Settlements**: Efficient distribution to multiple winners
- **Token Management**: Whitelist-based token support

### Key Functions

- `participate()`: Standard participation with tokens
- `participateWithSignature()`: Gasless participation using EIP-712
- `settleChallenge()`: Distribute winnings to participants
- `falseSettlement()`: Refund users in case of disputes
- `whitelistToken()`: Add new tokens to the escrow
- `handleForcedEth()`: Manage unexpected ETH deposits

## Security Considerations

1. **Always use the latest version** of the contract
2. **Verify token addresses** before whitelisting
3. **Monitor forced ETH deposits** regularly
4. **Use multi-signature wallets** for owner operations
5. **Test thoroughly** on testnet before mainnet deployment

## Development

The project uses:
- Hardhat as the development environment
- TypeScript for type safety
- Solidity version 0.8.24
- OpenZeppelin contracts for security
- Core blockchain network

## Testing

Run the test suite:
```bash
npx hardhat test
```

Run tests with gas reporting:
```bash
npx hardhat test --gas-report
```

## Troubleshooting

### Common Issues

1. **Stack too deep error**: Use `--via-ir` flag during compilation
2. **Gas estimation failed**: Check token balances and allowances
3. **Nonce mismatch**: Ensure you're using the correct user nonce for signatures
4. **Token not whitelisted**: Whitelist tokens before use

### Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the contract events for detailed error information
3. Verify network configuration and gas settings

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Audit Status

**Audited**: All high-severity vulnerabilities have been addressed
- Global nonce DoS vulnerability fixed
- Linear storage scan optimization implemented
- ERC-20 compatibility issues resolved
- Unbounded loop risks mitigated
- Forced ETH protection added

## Development

The project uses:
- Hardhat as the development environment
- TypeScript for type safety
- Solidity version 0.8.24
- Core blockchain network
