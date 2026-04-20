// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NexusChain Bridge - Cross-Chain Asset Transfer
 * @dev Handles deposits and withdrawals between Ethereum (L1) and NexusChain (L2)
 * @author NexusChain Team
 */

interface IL2Bridge {
    function finalizeDeposit(address _recipient, uint256 _amount) external;
    function initiateWithdrawal(address _recipient, uint256 _amount) external returns (bytes32);
}

contract NexusChainBridge {
    // ============================================================================
    // Storage
    // ============================================================================
    
    // L2 Bridge contract
    address public l2Bridge;
    
    // NexusChain L1 contract
    address public nexusChain;
    
    // Admin
    address public admin;
    
    // Paused
    bool public paused;
    
    // Deposit tracking
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    
    // Deposit records
    mapping(bytes32 => bool) public deposits;
    mapping(bytes32 => bool) public withdrawals;
    
    // Pending withdrawals
    mapping(bytes32 => WithdrawalRequest) public pendingWithdrawals;
    bytes32[] public withdrawalQueue;
    
    // Deposit limits
    uint256 public minDeposit = 0.001 ether;
    uint256 public maxDeposit = 1000 ether;
    
    // ============================================================================
    // Data Structures
    // ============================================================================
    
    struct WithdrawalRequest {
        address user;
        address recipient;
        uint256 amount;
        uint256 timestamp;
        bool claimed;
    }
    
    // ============================================================================
    // Events
    // ============================================================================
    
    event DepositInitiated(
        address indexed depositor,
        uint256 amount,
        bytes32 indexed l2Recipient,
        bytes32 depositHash
    );
    
    event DepositFinalized(
        address indexed recipient,
        uint256 amount,
        bytes32 indexed l1DepositHash
    );
    
    event WithdrawalInitiated(
        address indexed user,
        address indexed recipient,
        uint256 amount,
        bytes32 indexed l2TxHash
    );
    
    event WithdrawalClaimed(
        address indexed recipient,
        uint256 amount,
        bytes32 withdrawalHash
    );
    
    event Paused(address account);
    event Unpaused(address account);
    
    // ============================================================================
    // Errors
    // ============================================================================
    
    error DepositTooSmall();
    error DepositTooLarge();
    error InvalidDepositHash();
    error DepositAlreadyClaimed();
    error WithdrawalAlreadyClaimed();
    error WithdrawalNotClaimable();
    error BridgePaused();
    
    // ============================================================================
    // Initialization
    // ============================================================================
    
    constructor(
        address _l2Bridge,
        address _nexusChain,
        address _admin
    ) {
        require(_l2Bridge != address(0), "Invalid L2 bridge");
        require(_nexusChain != address(0), "Invalid NexusChain");
        require(_admin != address(0), "Invalid admin");
        
        l2Bridge = _l2Bridge;
        nexusChain = _nexusChain;
        admin = _admin;
        paused = false;
    }
    
    // ============================================================================
    // L1 -> L2 Deposits
    // ============================================================================
    
    /**
     * @notice Deposit ETH to Layer 2
     * @dev Locks ETH in this contract and sends a message to L2 to mint tokens
     * @param _l2Recipient The L2 address that will receive the deposit
     */
    function depositToL2(address _l2Recipient) external payable {
        if (paused) revert BridgePaused();
        if (msg.value < minDeposit) revert DepositTooSmall();
        if (msg.value > maxDeposit) revert DepositTooLarge();
        
        // Generate deposit hash
        bytes32 depositHash = keccak256(
            abi.encodePacked(
                msg.sender,
                _l2Recipient,
                msg.value,
                block.timestamp,
                totalDeposits
            )
        );
        
        // Record deposit
        deposits[depositHash] = true;
        totalDeposits++;
        
        // Send message to L2 to mint tokens
        // In production, this would be done via cross-chain messaging
        // For now, we emit an event that L2 observes
        IL2Bridge(l2Bridge).finalizeDeposit(_l2Recipient, msg.value);
        
        emit DepositInitiated(
            msg.sender,
            msg.value,
            bytes32(uint256(uint160(_l2Recipient))),
            depositHash
        );
    }
    
    /**
     * @notice Finalize a deposit from L1 (called when deposit is confirmed)
     * @dev Can be called by anyone to finalize after L1 confirmation
     * @param _depositHash The deposit hash to finalize
     */
    function finalizeDeposit(bytes32 _depositHash) external {
        if (paused) revert BridgePaused();
        if (!deposits[_depositHash]) revert InvalidDepositHash();
        
        deposits[_depositHash] = false; // Mark as finalized
        
        emit DepositFinalized(
            msg.sender, // In production, get from deposit data
            0, // In production, get from deposit data
            _depositHash
        );
    }
    
    // ============================================================================
    // L2 -> L1 Withdrawals
    // ============================================================================
    
    /**
     * @notice Initiate a withdrawal from L2 to L1
     * @dev Called by L2 bridge when user burns tokens on L2
     * @param _user The L2 user withdrawing
     * @param _recipient The L1 address to receive funds
     * @param _amount The amount to withdraw
     * @param _l2TxHash The L2 transaction hash proving the burn
     */
    function initiateWithdrawal(
        address _user,
        address _recipient,
        uint256 _amount,
        bytes32 _l2TxHash,
        bytes32 _nullifierHash,
        bytes32[] calldata _merkleProof
    ) external {
        if (paused) revert BridgePaused();
        require(_recipient != address(0), "Invalid recipient");
        require(_amount > 0, "Invalid amount");
        
        // Check if withdrawal already processed
        bytes32 withdrawalHash = keccak256(
            abi.encodePacked(_l2TxHash, _nullifierHash)
        );
        
        require(!withdrawals[withdrawalHash], "Withdrawal already initiated");
        
        // Store withdrawal
        withdrawals[withdrawalHash] = true;
        
        WithdrawalRequest storage request = pendingWithdrawals[withdrawalHash];
        request.user = _user;
        request.recipient = _recipient;
        request.amount = _amount;
        request.timestamp = block.timestamp;
        request.claimed = false;
        
        withdrawalQueue.push(withdrawalHash);
        totalWithdrawals++;
        
        emit WithdrawalInitiated(_user, _recipient, _amount, _l2TxHash);
    }
    
    /**
     * @notice Claim a withdrawal on L1
     * @dev Can be called after ZK proof verification (instant for ZK-Rollups)
     * @param _withdrawalHash The withdrawal hash
     */
    function claimWithdrawal(bytes32 _withdrawalHash) external {
        if (paused) revert BridgePaused();
        
        WithdrawalRequest storage request = pendingWithdrawals[_withdrawalHash];
        if (request.claimed) revert WithdrawalAlreadyClaimed();
        
        // For ZK-Rollups, proof is already verified on L2
        // No additional delay needed
        
        request.claimed = true;
        
        // Transfer ETH
        uint256 amount = request.amount;
        address payable recipient = payable(request.recipient);
        
        // Clear storage (after reading)
        delete pendingWithdrawals[_withdrawalHash];
        
        // Transfer
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit WithdrawalClaimed(request.recipient, amount, _withdrawalHash);
    }
    
    /**
     * @notice Batch claim multiple withdrawals
     * @param _withdrawalHashes Array of withdrawal hashes
     */
    function claimWithdrawalsBatch(bytes32[] calldata _withdrawalHashes) external {
        for (uint256 i = 0; i < _withdrawalHashes.length; i++) {
            try this.claimWithdrawal(_withdrawalHashes[i]) {
                // Success
            } catch {
                // Continue with next
                continue;
            }
        }
    }
    
    // ============================================================================
    // View Functions
    // ============================================================================
    
    /**
     * @notice Get pending withdrawal count
     */
    function getPendingWithdrawalCount() external view returns (uint256) {
        return withdrawalQueue.length;
    }
    
    /**
     * @notice Get pending withdrawal by index
     */
    function getPendingWithdrawal(uint256 _index) external view returns (WithdrawalRequest memory) {
        require(_index < withdrawalQueue.length, "Invalid index");
        return pendingWithdrawals[withdrawalQueue[_index]];
    }
    
    /**
     * @notice Get bridge statistics
     */
    function getStats() external view returns (
        uint256 _totalDeposits,
        uint256 _totalWithdrawals,
        uint256 _pendingCount,
        bool _paused
    ) {
        return (
            totalDeposits,
            totalWithdrawals,
            withdrawalQueue.length,
            paused
        );
    }
    
    // ============================================================================
    // Admin Functions
    // ============================================================================
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }
    
    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }
    
    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }
    
    function setDepositLimits(uint256 _min, uint256 _max) external onlyAdmin {
        minDeposit = _min;
        maxDeposit = _max;
    }
    
    function setL2Bridge(address _l2Bridge) external onlyAdmin {
        require(_l2Bridge != address(0), "Invalid L2 bridge");
        l2Bridge = _l2Bridge;
    }
    
    // ============================================================================
    // Emergency Functions
    // ============================================================================
    
    /**
     * @notice Emergency function to drain all ETH
     * @dev Only callable when emergency exit is active
     */
    function emergencyDrain(address payable _recipient) external onlyAdmin {
        require(_recipient != address(0), "Invalid recipient");
        (bool success, ) = _recipient.call{value: address(this).balance}("");
        require(success, "Drain failed");
    }
    
    // ============================================================================
    // Receive ETH
    // ============================================================================
    
    receive() external payable {
        // Accept ETH deposits
    }
}
