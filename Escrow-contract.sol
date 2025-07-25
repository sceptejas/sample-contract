// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MultiTokenEscrow is Ownable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;
    
    // Equivalent to ParticipationType in the Solana contract
    enum ParticipationType { SideBet, JoinChallenge }

    // Settler role for operational functions
    address public settler;
    
    // Events for role changes
    event SettlerChanged(address indexed previousSettler, address indexed newSettler);

    // Main state variables
    mapping(address => uint256) public tokenBalances;
    mapping(address => mapping(address => uint256)) public userDeposits; // user => token => amount
    mapping(address => bool) public whitelistedTokens;
    
    address[] public supportedTokens;
    uint256 public coreBalance;
    uint256 public coreLiabilities;
    
    // WCORE contract address
    address public constant WCORE = 0x00789Cfb69499c65ac9A3a68fb4917c9b4FcA2a7;
    
    // Per-user nonces for EIP-712 signatures
    mapping(address => uint256) public userNonces;
    
    // Batch settlement parameters
    uint256 public constant MAX_BATCH_SIZE = 100;
    
    // EIP-712 type hash for participation
    bytes32 public constant PARTICIPATE_TYPEHASH = keccak256(
        "Participate(address user,uint256 amount,uint256 challengeId,uint256 playerId,uint8 participationType,bool isNative,address tokenAddress,uint256 nonce)"
    );

    // Events
    event ParticipateEvent(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 challengeId,
        uint256 playerId,
        ParticipationType participationType,
        bool isNative,
        uint256 nonce
    );

    event SettleChallengeEvent(
        address indexed token,
        uint256[] amounts,
        uint256 challengeId,
        address[] winners,
        bool isNative
    );

    event FalseSettlementEvent(
        address indexed user,
        address indexed token,
        uint256 amount,
        string txnId,
        bool isNative
    );

    event SendEvent(
        address indexed to,
        address indexed token,
        uint256 amount,
        bool isNative
    );

    event TokenWhitelisted(address indexed token);
    event TokenRemoved(address indexed token);
    event ForcedCoreDetected(uint256 amount);
    event TransferFailedEvent(address indexed token, address indexed to, uint256 amount);

    // Custom errors with context
    error Unauthorized();
    error InsufficientFunds(address token, uint256 requested, uint256 available);
    error UnsupportedCurrency(address token);
    error TransferFailed(address token, address to, uint256 amount);
    error InvalidInput();
    error InvalidAmount();
    error TokenNotFound(address token);
    error BatchSizeExceeded(uint256 requested, uint256 maxAllowed);
    error InvalidSignature();
    error DirectCoreNotAllowed();
    error TokenAlreadyWhitelisted(address token);
    error TokenHasBalance(address token, uint256 balance);
    error NotSettler();

    // Modifiers
    modifier onlySettler() {
        if (msg.sender != settler) {
            revert NotSettler();
        }
        _;
    }

    modifier onlyOwnerOrSettler() {
        if (msg.sender != owner() && msg.sender != settler) {
            revert Unauthorized();
        }
        _;
    }

    constructor() 
        Ownable(msg.sender) 
        EIP712("MultiTokenEscrow", "1") 
    {
        // Native CORE is implicitly supported
        whitelistedTokens[address(0)] = true;
        
        // Auto-whitelist WCORE
        whitelistedTokens[WCORE] = true;
        supportedTokens.push(WCORE);
        
        // Set initial settler to deployer
        settler = msg.sender;
    }

    /**
     * @notice Set the settler address (only owner can call)
     * @param newSettler Address of the new settler
     */
    function setSettler(address newSettler) external onlyOwner {
        address previousSettler = settler;
        settler = newSettler;
        emit SettlerChanged(previousSettler, newSettler);
    }

    /**
     * @notice Whitelist a token for use in the escrow
     * @param tokenAddress Address of the token to whitelist
     */
    function whitelistToken(address tokenAddress) external onlyOwner {
        if (whitelistedTokens[tokenAddress]) {
            revert TokenAlreadyWhitelisted(tokenAddress);
        }
        
        whitelistedTokens[tokenAddress] = true;
        supportedTokens.push(tokenAddress);
        
        emit TokenWhitelisted(tokenAddress);
    }

    /**
     * @notice Allows users to participate by sending tokens to the escrow
     * @param amount Amount of tokens to send
     * @param challengeId ID of the challenge
     * @param playerId Optional ID of the player
     * @param participationType Type of participation (SideBet or JoinChallenge)
     * @param isNative Whether the token is native CORE
     * @param tokenAddress Address of the token (ignored if isNative is true)
     */
    function participate(
        uint256 amount,
        uint256 challengeId,
        uint256 playerId,
        ParticipationType participationType,
        bool isNative,
        address tokenAddress
    ) external payable nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }

        address effectiveTokenAddress = isNative ? address(0) : tokenAddress;
        
        if (!whitelistedTokens[effectiveTokenAddress]) {
            revert UnsupportedCurrency(effectiveTokenAddress);
        }

        if (isNative) {
            if (msg.value != amount) {
                revert InvalidAmount();
            }
            coreBalance += amount;
            coreLiabilities += amount;
            userDeposits[msg.sender][address(0)] += amount;
        } else {
            IERC20 token = IERC20(tokenAddress);
            
            // SafeERC20 handles the transfer and reverts on failure
            token.safeTransferFrom(msg.sender, address(this), amount);
            
            tokenBalances[tokenAddress] += amount;
            userDeposits[msg.sender][tokenAddress] += amount;
        }

        uint256 currentNonce = userNonces[msg.sender]++;
        
        emit ParticipateEvent(
            msg.sender,
            effectiveTokenAddress,
            amount,
            challengeId,
            playerId,
            participationType,
            isNative,
            currentNonce
        );
    }

    /**
     * @notice Participate with EIP-712 signature (for gasless transactions)
     * @param user The user participating
     * @param amount Amount of tokens to send
     * @param challengeId ID of the challenge
     * @param playerId Optional ID of the player
     * @param participationType Type of participation
     * @param isNative Whether the token is native CORE
     * @param tokenAddress Address of the token
     * @param nonce User's nonce for this signature
     * @param signature EIP-712 signature
     */
    function participateWithSignature(
        address user,
        uint256 amount,
        uint256 challengeId,
        uint256 playerId,
        ParticipationType participationType,
        bool isNative,
        address tokenAddress,
        uint256 nonce,
        bytes calldata signature
    ) external payable nonReentrant {
        _verifySignature(user, amount, challengeId, playerId, participationType, isNative, tokenAddress, nonce, signature);
        _executeParticipation(user, amount, challengeId, playerId, participationType, isNative, tokenAddress, nonce);
    }

    /**
     * @notice Internal function to verify EIP-712 signature
     */
    function _verifySignature(
        address user,
        uint256 amount,
        uint256 challengeId,
        uint256 playerId,
        ParticipationType participationType,
        bool isNative,
        address tokenAddress,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userNonces[user]) {
            revert InvalidSignature();
        }

        bytes32 structHash = keccak256(abi.encode(
            PARTICIPATE_TYPEHASH,
            user,
            amount,
            challengeId,
            playerId,
            participationType,
            isNative,
            tokenAddress,
            nonce
        ));

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        
        if (signer != user) {
            revert InvalidSignature();
        }
    }

    /**
     * @notice Internal function to execute participation logic
     */
    function _executeParticipation(
        address user,
        uint256 amount,
        uint256 challengeId,
        uint256 playerId,
        ParticipationType participationType,
        bool isNative,
        address tokenAddress,
        uint256 nonce
    ) internal {
        if (amount == 0) {
            revert InvalidAmount();
        }

        address effectiveTokenAddress = isNative ? address(0) : tokenAddress;
        
        if (!whitelistedTokens[effectiveTokenAddress]) {
            revert UnsupportedCurrency(effectiveTokenAddress);
        }

        if (isNative) {
            if (msg.value != amount) {
                revert InvalidAmount();
            }
            coreBalance += amount;
            coreLiabilities += amount;
            userDeposits[user][address(0)] += amount;
        } else {
            IERC20(tokenAddress).safeTransferFrom(user, address(this), amount);
            tokenBalances[tokenAddress] += amount;
            userDeposits[user][tokenAddress] += amount;
        }

        userNonces[user]++;
        
        emit ParticipateEvent(
            user,
            effectiveTokenAddress,
            amount,
            challengeId,
            playerId,
            participationType,
            isNative,
            nonce
        );
    }

    /**
     * @notice Handles false settlements by transferring tokens back to users
     * @param amount Amount to transfer
     * @param txnId Transaction ID for reference
     * @param isNative Whether it's native CORE
     * @param user User address to refund
     * @param tokenAddress Address of the token being refunded
     */
    function falseSettlement(
        uint256 amount,
        string calldata txnId,
        bool isNative,
        address payable user,
        address tokenAddress
    ) external onlySettler nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }

        address effectiveTokenAddress = isNative ? address(0) : tokenAddress;

        if (isNative) {
            if (coreLiabilities < amount) {
                revert InsufficientFunds(address(0), amount, coreLiabilities);
            }
            
            coreBalance -= amount;
            coreLiabilities -= amount;
            userDeposits[user][address(0)] -= amount;
            
            (bool success, ) = user.call{value: amount}("");
            if (!success) {
                revert TransferFailed(address(0), user, amount);
            }
        } else {
            if (tokenBalances[tokenAddress] < amount) {
                revert InsufficientFunds(tokenAddress, amount, tokenBalances[tokenAddress]);
            }
            
            tokenBalances[tokenAddress] -= amount;
            userDeposits[user][tokenAddress] -= amount;
            
            IERC20 token = IERC20(tokenAddress);
            token.safeTransfer(user, amount);
        }

        emit FalseSettlementEvent(
            user,
            effectiveTokenAddress,
            amount,
            txnId,
            isNative
        );
    }

    /**
     * @notice Sends tokens from the escrow to an admin account
     * @param amount Amount to transfer
     * @param isNative Whether it's native CORE
     * @param adminAccount Address of the admin
     * @param tokenAddress Address of the token being sent
     */
    function send(
        uint256 amount,
        bool isNative,
        address payable adminAccount,
        address tokenAddress
    ) external onlySettler nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }

        address effectiveTokenAddress = isNative ? address(0) : tokenAddress;

        if (isNative) {
            if (coreBalance < amount) {
                revert InsufficientFunds(address(0), amount, coreBalance);
            }
            
            coreBalance -= amount;
            (bool success, ) = adminAccount.call{value: amount}("");
            if (!success) {
                revert TransferFailed(address(0), adminAccount, amount);
            }
        } else {
            if (tokenBalances[tokenAddress] < amount) {
                revert InsufficientFunds(tokenAddress, amount, tokenBalances[tokenAddress]);
            }
            
            tokenBalances[tokenAddress] -= amount;
            IERC20 token = IERC20(tokenAddress);
            token.safeTransfer(adminAccount, amount);
        }

        emit SendEvent(
            adminAccount,
            effectiveTokenAddress,
            amount,
            isNative
        );
    }

    /**
     * @notice Settles a challenge by distributing tokens to winners (with batch size limit)
     * @param amounts Array of amounts to distribute
     * @param challengeId ID of the challenge
     * @param isNative Whether it's native CORE
     * @param winners Array of winner addresses
     * @param tokenAddress Address of the token being distributed
     */
    function settleChallenge(
        uint256[] calldata amounts,
        uint256 challengeId,
        bool isNative,
        address payable[] calldata winners,
        address tokenAddress
    ) external onlySettler nonReentrant {
        if (winners.length != amounts.length) {
            revert InvalidInput();
        }
        
        if (winners.length > MAX_BATCH_SIZE) {
            revert BatchSizeExceeded(winners.length, MAX_BATCH_SIZE);
        }

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] == 0) {
                revert InvalidAmount();
            }
            totalAmount += amounts[i];
        }

        address effectiveTokenAddress = isNative ? address(0) : tokenAddress;

        if (isNative) {
            if (coreLiabilities < totalAmount) {
                revert InsufficientFunds(address(0), totalAmount, coreLiabilities);
            }
            coreBalance -= totalAmount;
            coreLiabilities -= totalAmount;

            // Use try-catch to handle failed transfers without reverting the entire batch
            uint256 successfulTransfers = 0;
            for (uint256 i = 0; i < winners.length; i++) {
                (bool success, ) = winners[i].call{value: amounts[i]}("");
                if (success) {
                    successfulTransfers++;
                } else {
                    // Log failed transfer but don't revert
                    emit TransferFailedEvent(address(0), winners[i], amounts[i]);
                    // Refund the failed amount back to balances
                    coreBalance += amounts[i];
                    coreLiabilities += amounts[i];
                }
            }
        } else {
            if (tokenBalances[tokenAddress] < totalAmount) {
                revert InsufficientFunds(tokenAddress, totalAmount, tokenBalances[tokenAddress]);
            }
            
            tokenBalances[tokenAddress] -= totalAmount;
            IERC20 token = IERC20(tokenAddress);

            uint256 successfulTransfers = 0;
            for (uint256 i = 0; i < winners.length; i++) {
                try token.transfer(winners[i], amounts[i]) returns (bool success) {
                    if (success) {
                        successfulTransfers++;
                    } else {
                        // Refund failed transfer
                        tokenBalances[tokenAddress] += amounts[i];
                    }
                } catch {
                    // Refund failed transfer
                    tokenBalances[tokenAddress] += amounts[i];
                }
            }
        }

        // Convert address payable[] to address[] for the event
        address[] memory winnerAddresses = new address[](winners.length);
        for (uint256 i = 0; i < winners.length; i++) {
            winnerAddresses[i] = winners[i];
        }

        emit SettleChallengeEvent(
            effectiveTokenAddress,
            amounts,
            challengeId,
            winnerAddresses,
            isNative
        );
    }

    /**
     * @notice Removes a token from the whitelist (only if balance is zero)
     * @param tokenToRemove Address of the token to remove
     */
    function removeToken(address tokenToRemove) external onlyOwner {
        if (!whitelistedTokens[tokenToRemove]) {
            revert TokenNotFound(tokenToRemove);
        }
        
        if (tokenBalances[tokenToRemove] > 0) {
            revert TokenHasBalance(tokenToRemove, tokenBalances[tokenToRemove]);
        }
        
        whitelistedTokens[tokenToRemove] = false;
        
        // Remove from supportedTokens array
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == tokenToRemove) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(tokenToRemove);
    }

    /**
     * @notice Returns the number of different tokens supported by the contract
     */
    function getSupportedTokenCount() external view returns (uint256) {
        return supportedTokens.length;
    }

    /**
     * @notice Get supported token by index
     */
    function getSupportedToken(uint256 index) external view returns (address) {
        return supportedTokens[index];
    }

    /**
     * @notice Get user's deposit amount for a specific token
     */
    function getUserDeposit(address user, address token) external view returns (uint256) {
        return userDeposits[user][token];
    }

    /**
     * @notice Detect and handle forced CORE (e.g., from selfdestruct)
     */
    function handleForcedCore() external onlyOwner {
        uint256 actualBalance = address(this).balance;
        if (actualBalance > coreBalance) {
            uint256 forcedAmount = actualBalance - coreBalance;
            coreBalance = actualBalance;
            emit ForcedCoreDetected(forcedAmount);
        }
    }

    /**
     * @notice Emergency function to withdraw forced CORE
     */
    function withdrawForcedCore() external onlyOwner {
        uint256 forcedAmount = coreBalance - coreLiabilities;
        if (forcedAmount > 0) {
            coreBalance -= forcedAmount;
            (bool success, ) = payable(owner()).call{value: forcedAmount}("");
            if (!success) {
                revert TransferFailed(address(0), owner(), forcedAmount);
            }
        }
    }

    /**
     * @notice Rejects direct CORE transfers
     */
    receive() external payable {
        revert DirectCoreNotAllowed();
    }

    /**
     * @notice Fallback function also rejects CORE
     */
    fallback() external payable {
        revert DirectCoreNotAllowed();
    }
}
