// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NexusChain - Layer 2 ZK-Rollup Contract
 * @dev Main contract for NexusChain Layer 2 on Ethereum
 * @author NexusChain Team
 */

contract NexusChain {
    // ============================================================================
    // Storage
    // ============================================================================
    
    // Current state root (Merkle root of L2 state)
    bytes32 public stateRoot;
    
    // Block number
    uint256 public blockNumber;
    
    // Verifier contract address
    address public verifier;
    
    // Bridge contract address
    address public bridge;
    
    // Admin address
    address public admin;
    
    // Pending state root (not yet finalized)
    bytes32 public pendingStateRoot;
    uint256 public pendingBlockNumber;
    
    // Batch tracking
    uint256 public totalBatches;
    mapping(uint256 => Batch) public batches;
    
    // Block tracking
    mapping(uint256 => bytes32) public blockRoots;
    
    // Emergency exit flag
    bool public emergencyExitActive;
    
    // Paused flag
    bool public paused;
    
    // ============================================================================
    // Data Structures
    // ============================================================================
    
    struct Batch {
        uint256 batchNumber;
        bytes32 stateRootBefore;
        bytes32 stateRootAfter;
        uint256 timestamp;
        uint256 transactionCount;
        address sequencer;
        bytes proof;  // ZK proof
        bool proven;
        bool finalized;
    }
    
    struct BlockData {
        bytes32 previousBlockHash;
        uint256 timestamp;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        uint256 gasUsed;
        address proposer;
    }
    
    // ============================================================================
    // Events
    // ============================================================================
    
    event NewBatch(
        uint256 indexed batchNumber,
        bytes32 stateRootBefore,
        bytes32 stateRootAfter,
        uint256 transactionCount,
        address indexed sequencer
    );
    
    event BatchFinalized(
        uint256 indexed batchNumber,
        bytes32 stateRoot
    );
    
    event ProofVerified(
        uint256 indexed batchNumber,
        bool success
    );
    
    event EmergencyExitInitiated(
        address indexed initiator,
        bytes32[] merkleProof,
        address recipient,
        uint256 amount
    );
    
    event EmergencyExitCompleted(
        address indexed recipient,
        uint256 amount
    );
    
    event Paused(address account);
    event Unpaused(address account);
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    
    // ============================================================================
    // Access Control Roles
    // ============================================================================
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant Sequencer_ROLE = keccak256("SEQUENCER_ROLE");
    
    mapping(bytes32 => mapping(address => bool)) public roles;
    
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "AccessControl: insufficient permissions");
        _;
    }
    
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }
    
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        roles[role][account] = true;
        emit RoleGranted(role, account);
    }
    
    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        roles[role][account] = false;
        emit RoleRevoked(role, account);
    }
    
    // ============================================================================
    // Initialization
    // ============================================================================
    
    constructor(
        address _verifier,
        address _bridge,
        address _admin
    ) {
        require(_verifier != address(0), "Invalid verifier address");
        require(_bridge != address(0), "Invalid bridge address");
        require(_admin != address(0), "Invalid admin address");
        
        verifier = _verifier;
        bridge = _bridge;
        admin = _admin;
        stateRoot = bytes32(0);
        blockNumber = 0;
        totalBatches = 0;
        emergencyExitActive = false;
        paused = false;
        
        // Grant admin role to deployer
        roles[ADMIN_ROLE][_admin] = true;
    }
    
    // ============================================================================
    // Batch Submission
    // ============================================================================
    
    /**
     * @notice Submit a new batch of transactions
     * @dev Called by the sequencer
     * @param _stateRootBefore State root before the batch
     * @param _stateRootAfter State root after the batch
     * @param _transactionCount Number of transactions in the batch
     */
    function submitBatch(
        bytes32 _stateRootBefore,
        bytes32 _stateRootAfter,
        uint256 _transactionCount
    ) external onlyRole(Sequencer_ROLE) whenNotPaused {
        require(
            _stateRootBefore == stateRoot || stateRoot == bytes32(0),
            "Invalid previous state root"
        );
        require(
            _transactionCount > 0,
            "Empty batch"
        );
        
        totalBatches++;
        
        Batch storage batch = batches[totalBatches];
        batch.batchNumber = totalBatches;
        batch.stateRootBefore = _stateRootBefore;
        batch.stateRootAfter = _stateRootAfter;
        batch.timestamp = block.timestamp;
        batch.transactionCount = _transactionCount;
        batch.sequencer = msg.sender;
        
        pendingStateRoot = _stateRootAfter;
        pendingBlockNumber = totalBatches;
        
        emit NewBatch(
            totalBatches,
            _stateRootBefore,
            _stateRootAfter,
            _transactionCount,
            msg.sender
        );
    }
    
    // ============================================================================
    // Proof Verification
    // ============================================================================
    
    /**
     * @notice Submit and verify a ZK proof for a batch
     * @dev Called by the prover
     * @param _batchNumber Batch number to prove
     * @param _proof ZK proof data
     * @param _pubSignals Public inputs for the proof
     */
    function submitProof(
        uint256 _batchNumber,
        bytes calldata _proof,
        uint256[] calldata _pubSignals
    ) external onlyRole(PROVER_ROLE) whenNotPaused {
        require(
            _batchNumber > 0 && _batchNumber <= totalBatches,
            "Invalid batch number"
        );
        
        Batch storage batch = batches[_batchNumber];
        require(
            !batch.proven,
            "Batch already proven"
        );
        
        // Store proof
        batch.proof = _proof;
        
        // Verify proof using verifier contract
        // In production, this would call the actual verifier
        bool verified = verifyProofOnChain(_proof, _pubSignals);
        
        batch.proven = true;
        
        emit ProofVerified(_batchNumber, verified);
        
        // Auto-finalize if verified
        if (verified) {
            _finalizeBatch(_batchNumber);
        }
    }
    
    /**
     * @notice Verify ZK proof on-chain
     * @dev This is a placeholder - actual verification would use a verifier contract
     */
    function verifyProofOnChain(
        bytes calldata _proof,
        uint256[] calldata _pubSignals
    ) internal returns (bool) {
        // In production, call the verifier contract:
        // IVerifier(verifier).verifyProof(_proof, _pubSignals);
        
        // For simulation, always return true
        return true;
    }
    
    // ============================================================================
    // Batch Finalization
    // ============================================================================
    
    /**
     * @notice Finalize a batch after proof verification
     * @param _batchNumber Batch number to finalize
     */
    function finalizeBatch(uint256 _batchNumber) external onlyRole(ADMIN_ROLE) {
        _finalizeBatch(_batchNumber);
    }
    
    function _finalizeBatch(uint256 _batchNumber) internal {
        Batch storage batch = batches[_batchNumber];
        
        require(
            batch.proven || emergencyExitActive,
            "Batch not proven"
        );
        require(
            !batch.finalized,
            "Batch already finalized"
        );
        
        batch.finalized = true;
        stateRoot = batch.stateRootAfter;
        
        emit BatchFinalized(_batchNumber, batch.stateRootAfter);
    }
    
    // ============================================================================
    // Block Management
    // ============================================================================
    
    /**
     * @notice Register a new block
     * @param _blockNumber Block number
     * @param _blockData Block data
     */
    function registerBlock(
        uint256 _blockNumber,
        BlockData calldata _blockData
    ) external onlyRole(Sequencer_ROLE) whenNotPaused {
        require(
            _blockNumber == blockNumber + 1,
            "Invalid block number"
        );
        
        blockRoots[_blockNumber] = _blockData.stateRoot;
        blockNumber++;
    }
    
    // ============================================================================
    // Emergency Exit
    // ============================================================================
    
    /**
     * @notice Initiate emergency exit
     * @dev Allows users to exit if the protocol is stuck
     * @param _merkleProof Merkle proof of the user's balance
     * @param _recipient Address to receive funds
     * @param _amount Amount to withdraw
     */
    function emergencyExit(
        bytes32[] calldata _merkleProof,
        address _recipient,
        uint256 _amount
    ) external whenEmergencyExitActive {
        require(
            _recipient != address(0),
            "Invalid recipient"
        );
        require(
            _amount > 0,
            "Invalid amount"
        );
        
        // Verify Merkle proof
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, _amount));
        require(
            verifyMerkleProof(_merkleProof, stateRoot, leaf),
            "Invalid proof"
        );
        
        emit EmergencyExitInitiated(msg.sender, _merkleProof, _recipient, _amount);
        
        // Transfer funds (in production, this would use the bridge)
        // payable(_recipient).transfer(_amount);
        
        emit EmergencyExitCompleted(_recipient, _amount);
    }
    
    /**
     * @notice Verify a Merkle proof
     */
    function verifyMerkleProof(
        bytes32[] calldata _proof,
        bytes32 _root,
        bytes32 _leaf
    ) public pure returns (bool) {
        bytes32 currentHash = _leaf;
        
        for (uint256 i = 0; i < _proof.length; i++) {
            if (i % 2 == 0) {
                currentHash = keccak256(abi.encodePacked(currentHash, _proof[i]));
            } else {
                currentHash = keccak256(abi.encodePacked(_proof[i], currentHash));
            }
        }
        
        return currentHash == _root;
    }
    
    /**
     * @notice Activate emergency exit mode
     */
    function activateEmergencyExit() external onlyRole(ADMIN_ROLE) {
        emergencyExitActive = true;
    }
    
    /**
     * @notice Deactivate emergency exit mode
     */
    function deactivateEmergencyExit() external onlyRole(ADMIN_ROLE) {
        emergencyExitActive = false;
    }
    
    // ============================================================================
    // Pause/Unpause
    // ============================================================================
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    modifier whenEmergencyExitActive() {
        require(emergencyExitActive, "Emergency exit not active");
        _;
    }
    
    function pause() external onlyRole(ADMIN_ROLE) {
        paused = true;
        emit Paused(msg.sender);
    }
    
    function unpause() external onlyRole(ADMIN_ROLE) {
        paused = false;
        emit Unpaused(msg.sender);
    }
    
    // ============================================================================
    // View Functions
    // ============================================================================
    
    /**
     * @notice Get batch information
     */
    function getBatch(uint256 _batchNumber) external view returns (Batch memory) {
        return batches[_batchNumber];
    }
    
    /**
     * @notice Get current state
     */
    function getState() external view returns (
        bytes32 _stateRoot,
        uint256 _blockNumber,
        uint256 _totalBatches,
        bool _paused,
        bool _emergencyExitActive
    ) {
        return (stateRoot, blockNumber, totalBatches, paused, emergencyExitActive);
    }
}
