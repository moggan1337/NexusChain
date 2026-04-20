"""
NexusChain - Layer 2 ZK-Rollup Blockchain

A high-performance Layer 2 scaling solution for Ethereum using Zero-Knowledge Proofs.
"""

__version__ = "0.1.0"
__author__ = "NexusChain Team"

from .zk_rollup.types import (
    Transaction, TransactionType, Block, BlockHeader, Account,
    Batch, ZKProof, StateDiff, WithdrawalProof,
    Deposit, Withdrawal
)

from .zk_rollup.circuit import (
    Circuit, TransferCircuit, BatchCircuit,
    CircuitLibrary, CircuitType, TrustedSetup
)

from .zk_rollup.proof import (
    ProofSystem, Groth16Prover, PlonkProver, ProofGenerator
)

from .state.merkle import (
    SparseMerkleTree, MultiMerkleTree, ZKStateTree, MerkleProof
)

from .sequencer.block import (
    Sequencer, SequencerConfig, SequencerState
)

from .txpool.pool import (
    TransactionPool, TransactionPool, TxPoolConfig
)

from .bridge.bridge import (
    BridgeManager, L1Bridge, L2Bridge, BridgeConfig
)

from .evm.interpreter import (
    EVMInterpreter, ExecutionEnvironment, ExecutionResult
)

from .rpc.server import RPCServer, RPCHandler

__all__ = [
    # Version
    "__version__",
    
    # Types
    "Transaction",
    "TransactionType", 
    "Block",
    "BlockHeader",
    "Account",
    "Batch",
    "ZKProof",
    "StateDiff",
    "WithdrawalProof",
    "Deposit",
    "Withdrawal",
    
    # Circuits
    "Circuit",
    "TransferCircuit",
    "BatchCircuit",
    "CircuitLibrary",
    "CircuitType",
    "TrustedSetup",
    
    # Proofs
    "ProofSystem",
    "Groth16Prover",
    "PlonkProver",
    "ProofGenerator",
    
    # State
    "SparseMerkleTree",
    "MultiMerkleTree",
    "ZKStateTree",
    "MerkleProof",
    
    # Sequencer
    "Sequencer",
    "SequencerConfig",
    "SequencerState",
    
    # Transaction Pool
    "TransactionPool",
    "TxPoolConfig",
    
    # Bridge
    "BridgeManager",
    "L1Bridge",
    "L2Bridge",
    "BridgeConfig",
    
    # EVM
    "EVMInterpreter",
    "ExecutionEnvironment",
    "ExecutionResult",
    
    # RPC
    "RPCServer",
    "RPCHandler",
]
