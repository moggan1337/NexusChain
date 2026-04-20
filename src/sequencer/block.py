"""
NexusChain - Sequencer Implementation

The sequencer is responsible for:
- Transaction ordering and execution
- Block production
- State updates
- Batch submission to prover
"""

from __future__ import annotations
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set
from enum import Enum
from collections import defaultdict
import threading
import logging

from ..zk_rollup.types import (
    Transaction, TransactionType, Block, BlockHeader, TransactionReceipt,
    Account, StateDiff, Batch, Address, Amount, Nonce, Hash, HashlibHasher,
    BlockNumber, Gas, GasPrice, Timestamp
)
from ..state.merkle import SparseMerkleTree, ZKStateTree
from ..txpool.pool import TransactionPool


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Transaction execution status"""
    SUCCESS = "success"
    FAILURE = "failure"
    REVERTED = "reverted"
    OUT_OF_GAS = "out_of_gas"
    INVALID_NONCE = "invalid_nonce"
    INSUFFICIENT_BALANCE = "insufficient_balance"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass
class ExecutionResult:
    """Result of transaction execution"""
    status: ExecutionStatus
    gas_used: Gas
    return_data: bytes = b""
    error_message: Optional[str] = None
    logs: List[Dict[str, Any]] = field(default_factory=list)
    state_diff: Optional[StateDiff] = None


@dataclass
class SequencerConfig:
    """Sequencer configuration"""
    block_gas_limit: Gas = 8000000
    max_txs_per_block: int = 1000
    block_time: float = 1.0  # Target block time in seconds
    fee_recipient: Address = b"\x00" * 20
    max_batch_size: int = 100  # Max transactions per proof batch
    force_batch_interval: float = 30.0  # Force batch after this many seconds


@dataclass
class SequencerState:
    """Current state of the sequencer"""
    current_block_number: BlockNumber = 0
    current_timestamp: Timestamp = 0
    state_root: Hash = b"\x00" * 32
    pending_batch_size: int = 0
    last_batch_time: Timestamp = 0
    
    # Metrics
    total_transactions: int = 0
    total_blocks_produced: int = 0
    total_gas_used: Gas = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "blockNumber": self.current_block_number,
            "timestamp": self.current_timestamp,
            "stateRoot": self.state_root.hex(),
            "pendingBatchSize": self.pending_batch_size,
            "totalTransactions": self.total_transactions,
            "totalBlocksProduced": self.total_blocks_produced,
            "totalGasUsed": self.total_gas_used
        }


class EVMState:
    """
    EVM execution state
    
    Simplified EVM state for Layer 2 execution
    """
    
    def __init__(self, state_tree: ZKStateTree):
        self.state_tree = state_tree
        self.contracts: Dict[Address, bytes] = {}  # address -> bytecode
        self.contract_storage: Dict[Address, Dict[Hash, Hash]] = defaultdict(dict)
        self.call_depth_limit = 1024
    
    def get_account(self, address: Address) -> Account:
        """Get account from state tree"""
        # In a real implementation, this would fetch from the merkle tree
        return Account(address=address)
    
    def get_balance(self, address: Address) -> Amount:
        """Get account balance"""
        account = self.get_account(address)
        return account.balance
    
    def set_balance(self, address: Address, balance: Amount):
        """Set account balance"""
        account = self.get_account(address)
        account.balance = balance
        self.state_tree.update_account(address, account)
    
    def get_nonce(self, address: Address) -> Nonce:
        """Get account nonce"""
        account = self.get_account(address)
        return account.nonce
    
    def set_nonce(self, address: Address, nonce: Nonce):
        """Set account nonce"""
        account = self.get_account(address)
        account.nonce = nonce
        self.state_tree.update_account(address, account)
    
    def get_code(self, address: Address) -> bytes:
        """Get contract bytecode"""
        return self.contracts.get(address, b"")
    
    def get_storage(self, address: Address, slot: Hash) -> Hash:
        """Get storage value"""
        return self.contract_storage[address].get(slot, b"\x00" * 32)
    
    def set_storage(self, address: Address, slot: Hash, value: Hash):
        """Set storage value"""
        self.contract_storage[address][slot] = value


class Sequencer:
    """
    Main sequencer class
    
    Responsible for:
    - Accepting transactions from the mempool
    - Executing transactions and updating state
    - Producing blocks
    - Creating batches for proof generation
    """
    
    def __init__(
        self,
        txpool: TransactionPool,
        config: Optional[SequencerConfig] = None
    ):
        self.config = config or SequencerConfig()
        self.txpool = txpool
        
        # State management
        self.state_tree = ZKStateTree(depth=32)
        self.evm_state = EVMState(self.state_tree)
        
        # Sequencer state
        self.state = SequencerState()
        
        # Pending blocks and batches
        self.pending_blocks: List[Block] = []
        self.pending_txs: List[Tuple[Transaction, ExecutionResult]] = []
        self.processed_txs: Set[Hash] = set()
        
        # Fee recipients per block
        self.fee_recipients: List[Address] = []
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Callbacks
        self.on_block_produced: Optional[callable] = None
        self.on_batch_ready: Optional[callable] = None
        
        logger.info("Sequencer initialized")
    
    def start(self):
        """Start the sequencer loop"""
        logger.info("Starting sequencer...")
        
        # Start block production loop
        self._run_block_producer()
    
    def _run_block_producer(self):
        """Run the block production loop"""
        while True:
            try:
                self._produce_next_block()
                time.sleep(self.config.block_time)
            except Exception as e:
                logger.error(f"Error in block production: {e}")
                time.sleep(1)
    
    def _produce_next_block(self):
        """Produce the next block"""
        with self.lock:
            self.state.current_block_number += 1
            self.state.current_timestamp = int(time.time())
            
            # Get transactions from pool
            txs = self.txpool.get_batch(self.config.max_txs_per_block)
            
            if not txs:
                # Produce empty block
                block = self._create_empty_block()
                self.pending_blocks.append(block)
                return block
            
            # Execute transactions
            block = self._execute_transactions(txs)
            
            # Finalize block
            block.header.state_root = self.state_tree.get_roots()["stateRoot"]
            block.header.gas_used = sum(r.gas_used for r in block.receipts)
            
            # Store block
            self.pending_blocks.append(block)
            
            # Update state
            self.state.total_blocks_produced += 1
            self.state.total_transactions += len(block.transactions)
            
            # Update metrics
            self.state.pending_batch_size += len(block.transactions)
            
            # Check if we should create a batch
            if self._should_create_batch():
                self._create_batch()
            
            logger.info(
                f"Block {self.state.current_block_number} produced: "
                f"{len(block.transactions)} txs, {block.header.gas_used} gas"
            )
            
            # Trigger callback
            if self.on_block_produced:
                self.on_block_produced(block)
            
            return block
    
    def _create_empty_block(self) -> Block:
        """Create an empty block"""
        header = BlockHeader(
            parent_hash=self.state.state_root,
            block_number=self.state.current_block_number,
            timestamp=self.state.current_timestamp,
            state_root=self.state_tree.get_roots()["stateRoot"],
            tx_root=b"\x00" * 32,
            receipt_root=b"\x00" * 32,
            gas_used=0,
            gas_limit=self.config.block_gas_limit,
            proposer=self.config.fee_recipient,
            batch_hash=b"\x00" * 32,
            proof_hash=b"\x00" * 32
        )
        return Block(header=header)
    
    def _execute_transactions(self, txs: List[Transaction]) -> Block:
        """Execute a list of transactions and create a block"""
        
        header = BlockHeader(
            parent_hash=self.state.state_root,
            block_number=self.state.current_block_number,
            timestamp=self.state.current_timestamp,
            state_root=b"\x00" * 32,  # Will be updated
            tx_root=b"\x00" * 32,
            receipt_root=b"\x00" * 32,
            gas_used=0,
            gas_limit=self.config.block_gas_limit,
            proposer=self.config.fee_recipient,
            batch_hash=b"\x00" * 32,
            proof_hash=b"\x00" * 32
        )
        
        block = Block(header=header)
        gas_used = 0
        
        for tx in txs:
            # Skip if already processed
            if tx.hash in self.processed_txs:
                continue
            
            # Execute transaction
            result = self._execute_transaction(tx)
            
            # Create receipt
            receipt = TransactionReceipt(
                transaction_hash=tx.hash,
                block_number=self.state.current_block_number,
                status=result.status == ExecutionStatus.SUCCESS,
                gas_used=result.gas_used,
                logs=result.logs,
                bloom_filter=self._compute_bloom(result.logs)
            )
            
            block.add_transaction(tx, receipt)
            gas_used += result.gas_used
            
            # Mark as processed
            self.processed_txs.add(tx.hash)
            
            # Track pending for batch
            if result.status == ExecutionStatus.SUCCESS:
                self.pending_txs.append((tx, result))
        
        block.header.gas_used = gas_used
        
        return block
    
    def _execute_transaction(self, tx: Transaction) -> ExecutionResult:
        """
        Execute a single transaction
        
        Handles different transaction types:
        - TRANSFER: Simple balance transfer
        - DEPLOY_CONTRACT: Contract deployment
        - CALL_CONTRACT: Contract call
        - BRIDGE_DEPOSIT: Bridge deposit
        - BRIDGE_WITHDRAW: Bridge withdrawal
        """
        
        # Validate transaction
        if not tx.verify_signature():
            return ExecutionResult(
                status=ExecutionStatus.INVALID_SIGNATURE,
                gas_used=0,
                error_message="Invalid signature"
            )
        
        # Check nonce
        sender_nonce = self.evm_state.get_nonce(tx.sender)
        if tx.nonce != sender_nonce:
            return ExecutionResult(
                status=ExecutionStatus.INVALID_NONCE,
                gas_used=0,
                error_message=f"Invalid nonce: expected {sender_nonce}, got {tx.nonce}"
            )
        
        # Check balance
        sender_balance = self.evm_state.get_balance(tx.sender)
        total_cost = tx.amount + tx.fee
        if sender_balance < total_cost:
            return ExecutionResult(
                status=ExecutionStatus.INSUFFICIENT_BALANCE,
                gas_used=0,
                error_message=f"Insufficient balance: have {sender_balance}, need {total_cost}"
            )
        
        # Execute based on type
        if tx.transaction_type == TransactionType.TRANSFER:
            return self._execute_transfer(tx)
        elif tx.transaction_type == TransactionType.DEPLOY_CONTRACT:
            return self._execute_deploy(tx)
        elif tx.transaction_type == TransactionType.CALL_CONTRACT:
            return self._execute_call(tx)
        elif tx.transaction_type == TransactionType.BRIDGE_DEPOSIT:
            return self._execute_bridge_deposit(tx)
        elif tx.transaction_type == TransactionType.BRIDGE_WITHDRAW:
            return self._execute_bridge_withdraw(tx)
        else:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                gas_used=21000,
                error_message=f"Unknown transaction type: {tx.transaction_type}"
            )
    
    def _execute_transfer(self, tx: Transaction) -> ExecutionResult:
        """Execute a simple transfer transaction"""
        gas_used = 21000  # Base gas for transfer
        
        # Get old balances
        old_sender_balance = self.evm_state.get_balance(tx.sender)
        old_recipient_balance = self.evm_state.get_balance(tx.recipient)
        old_sender_nonce = self.evm_state.get_nonce(tx.sender)
        
        # Update balances
        self.evm_state.set_balance(tx.sender, old_sender_balance - tx.amount - tx.fee)
        self.evm_state.set_balance(tx.recipient, old_recipient_balance + tx.amount)
        
        # Increment sender nonce
        self.evm_state.set_nonce(tx.sender, old_sender_nonce + 1)
        
        # Create state diff
        state_diff = StateDiff(
            account=tx.sender,
            old_balance=old_sender_balance,
            new_balance=old_sender_balance - tx.amount - tx.fee,
            old_nonce=old_sender_nonce,
            new_nonce=old_sender_nonce + 1,
            storage_changes={}
        )
        
        # Create nullifier to prevent double-spending
        self.state_tree.add_nullifier(tx.hash)
        
        logger.debug(
            f"Transfer: {tx.sender.hex()[:8]} -> {tx.recipient.hex()[:8]} "
            f"amount={tx.amount} fee={tx.fee}"
        )
        
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            gas_used=gas_used,
            state_diff=state_diff
        )
    
    def _execute_deploy(self, tx: Transaction) -> ExecutionResult:
        """Execute a contract deployment transaction"""
        gas_used = 21000 + 32000  # Base + deployment gas
        
        # Compute new contract address
        sender_nonce = self.evm_state.get_nonce(tx.sender)
        contract_address = self._compute_contract_address(tx.sender, sender_nonce)
        
        # Store bytecode
        self.evm_state.contracts[contract_address] = tx.data
        
        # Initialize contract storage root (empty)
        # ...
        
        # Increment nonce
        self.evm_state.set_nonce(tx.sender, sender_nonce + 1)
        
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            gas_used=gas_used,
            return_data=contract_address,
            state_diff=StateDiff(
                account=tx.sender,
                old_balance=0,
                new_balance=0,
                old_nonce=sender_nonce,
                new_nonce=sender_nonce + 1,
                storage_changes={}
            )
        )
    
    def _execute_call(self, tx: Transaction) -> ExecutionResult:
        """Execute a contract call transaction"""
        gas_used = 21000  # Base gas
        
        # Check if contract exists
        if tx.recipient not in self.evm_state.contracts:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                gas_used=gas_used,
                error_message="Contract does not exist"
            )
        
        # Simplified: just record the call
        # Real implementation would execute EVM bytecode
        
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            gas_used=gas_used,
            return_data=b"",
            logs=[{
                "address": tx.recipient.hex(),
                "topics": [],
                "data": tx.data.hex()
            }]
        )
    
    def _execute_bridge_deposit(self, tx: Transaction) -> ExecutionResult:
        """Execute a bridge deposit (L1 to L2)"""
        # This would verify the L1 deposit event
        # For now, just mint the tokens
        
        gas_used = 21000
        
        # Update recipient balance
        old_balance = self.evm_state.get_balance(tx.recipient)
        self.evm_state.set_balance(tx.recipient, old_balance + tx.amount)
        
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            gas_used=gas_used,
            state_diff=StateDiff(
                account=tx.recipient,
                old_balance=old_balance,
                new_balance=old_balance + tx.amount,
                old_nonce=0,
                new_nonce=0,
                storage_changes={}
            )
        )
    
    def _execute_bridge_withdraw(self, tx: Transaction) -> ExecutionResult:
        """Execute a bridge withdrawal (L2 to L1)"""
        gas_used = 21000
        
        # Check balance
        sender_balance = self.evm_state.get_balance(tx.sender)
        if sender_balance < tx.amount:
            return ExecutionResult(
                status=ExecutionStatus.INSUFFICIENT_BALANCE,
                gas_used=gas_used,
                error_message="Insufficient balance for withdrawal"
            )
        
        # Burn tokens
        self.evm_state.set_balance(tx.sender, sender_balance - tx.amount)
        
        # Mark as withdrawn (would trigger L1 withdrawal)
        
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            gas_used=gas_used,
            logs=[{
                "address": tx.sender.hex(),
                "topics": ["withdraw"],
                "data": tx.amount.to_bytes(32, "big").hex()
            }]
        )
    
    def _compute_contract_address(self, deployer: Address, nonce: Nonce) -> Address:
        """Compute contract address from deployer and nonce"""
        data = deployer + nonce.to_bytes(8, "big")
        address_hash = HashlibHasher.keccak256(data)
        return address_hash[:20]
    
    def _compute_bloom(self, logs: List[Dict]) -> bytes:
        """Compute bloom filter from logs"""
        # Simplified bloom filter
        bloom = b"\x00" * 256
        
        for log in logs:
            address = bytes.fromhex(log.get("address", "0" * 40))
            for i in range(3):
                idx = int.from_bytes(address[i*4:(i+1)*4], "big") % 2048
                bloom = self._set_bit(bloom, idx)
        
        return bloom
    
    def _set_bit(self, data: bytes, index: int) -> bytes:
        """Set a bit in byte array"""
        data = bytearray(data)
        data[index // 8] |= (1 << (index % 8))
        return bytes(data)
    
    def _should_create_batch(self) -> bool:
        """Check if we should create a proof batch"""
        if self.state.pending_batch_size >= self.config.max_batch_size:
            return True
        
        time_since_last = time.time() - self.state.last_batch_time
        if (time_since_last >= self.config.force_batch_interval and 
            self.state.pending_batch_size > 0):
            return True
        
        return False
    
    def _create_batch(self) -> Batch:
        """Create a batch for proof generation"""
        with self.lock:
            batch = Batch(
                batch_number=self.state.current_block_number,
                old_state_root=self.state.state_root,
                new_state_root=self.state_tree.get_roots()["stateRoot"]
            )
            
            # Add all pending blocks
            for block in self.pending_blocks:
                batch.add_block(block)
                
                # Add state diffs
                for tx, result in self.pending_txs:
                    if result.state_diff:
                        batch.add_state_diff(result.state_diff)
            
            batch.finalize()
            
            # Reset pending state
            self.pending_blocks = []
            self.pending_txs = []
            self.state.pending_batch_size = 0
            self.state.last_batch_time = int(time.time())
            
            logger.info(f"Created batch {batch.batch_number}: {len(batch.blocks)} blocks")
            
            # Trigger callback
            if self.on_batch_ready:
                self.on_batch_ready(batch)
            
            return batch
    
    def get_state(self) -> SequencerState:
        """Get current sequencer state"""
        return self.state
    
    def get_pending_batch(self) -> Optional[Batch]:
        """Get pending batch if any transactions are waiting"""
        with self.lock:
            if not self.pending_blocks:
                return None
            
            return Batch(
                batch_number=self.state.current_block_number,
                blocks=self.pending_blocks,
                old_state_root=self.state.state_root,
                new_state_root=self.state_tree.get_roots()["stateRoot"]
            )
    
    def submit_transaction(self, tx: Transaction) -> bool:
        """
        Submit a transaction to the sequencer
        
        Called by the RPC layer
        """
        # Validate transaction
        if not tx.verify_signature():
            logger.warning(f"Invalid signature for transaction {tx.hash.hex()}")
            return False
        
        # Add to pool
        return self.txpool.add_transaction(tx)
    
    def get_account_info(self, address: Address) -> Dict[str, Any]:
        """Get account information"""
        account = self.evm_state.get_account(address)
        return {
            "address": address.hex(),
            "balance": str(account.balance),
            "nonce": account.nonce,
            "codeHash": account.code_hash.hex(),
            "stateRoot": self.state_tree.get_roots()["stateRoot"].hex()
        }


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for sequencer"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NexusChain Sequencer")
    parser.add_argument("--rpc-url", default="http://localhost:8545", help="L1 RPC URL")
    parser.add_argument("--port", type=int, default=8546, help="Sequencer RPC port")
    parser.add_argument("--block-gas-limit", type=int, default=8000000, help="Block gas limit")
    parser.add_argument("--max-txs", type=int, default=1000, help="Max transactions per block")
    parser.add_argument("--max-batch-size", type=int, default=100, help="Max transactions per batch")
    
    args = parser.parse_args()
    
    # Create sequencer
    txpool = TransactionPool()
    config = SequencerConfig(
        block_gas_limit=args.block_gas_limit,
        max_txs_per_block=args.max_txs,
        max_batch_size=args.max_batch_size
    )
    
    sequencer = Sequencer(txpool, config)
    
    print(f"Starting sequencer on port {args.port}...")
    print(f"Block gas limit: {args.block_gas_limit}")
    print(f"Max batch size: {args.max_batch_size}")
    
    # Start sequencer
    sequencer.start()


if __name__ == "__main__":
    main()
