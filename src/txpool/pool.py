"""
NexusChain - Transaction Pool Implementation

Manages pending transactions for Layer 2 processing.
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict
import heapq
import threading
import logging
from enum import Enum

from ..zk_rollup.types import (
    Transaction, TransactionType, Address, Amount, Nonce, 
    Hash, GasPrice, HashlibHasher
)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PoolStatus(Enum):
    """Transaction pool status"""
    OK = "ok"
    FULL = "full"
    DUPLICATE = "duplicate"
    INVALID = "invalid"
    NONCE_TOO_LOW = "nonce_too_low"
    NONCE_TOO_HIGH = "nonce_too_high"


@dataclass(order=True)
class PendingTransaction:
    """Wrapper for transaction with ordering"""
    priority: Tuple[int, int]  # (gas_price, nonce) - higher gas = higher priority
    transaction: Transaction = field(compare=False)
    arrival_time: float = field(compare=False, default_factory=time.time)
    local_marker: int = field(compare=False, default=0)
    
    def __lt__(self, other):
        # Higher gas price = higher priority (we negate for max-heap behavior)
        if self.priority != other.priority:
            return self.priority > other.priority  # Max heap by gas price
        return self.arrival_time < other.arrival_time  # FIFO by arrival


@dataclass
class TxPoolConfig:
    """Transaction pool configuration"""
    max_size: int = 10000
    max_per_sender: int = 100
    min_gas_price: int = 0
    eviction_age: int = 300  # seconds
    
    # Price bids
    min_bid: int = 1000000  # 0.001 ETH in wei
    max_bid: int = 100000000000  # 0.1 ETH in wei
    
    # Nonce window
    nonce_window: int = 100  # Allow nonces within this window


class TransactionPool:
    """
    Layer 2 Transaction Pool
    
    Features:
    - Priority queue by gas price
    - Per-sender nonce management
    - Transaction deduplication
    - Size limits and eviction
    - Spam protection
    
    Transactions are ordered by:
    1. Gas price (higher first)
    2. Nonce (lower first)
    3. Arrival time (earlier first)
    """
    
    def __init__(self, config: Optional[TxPoolConfig] = None):
        self.config = config or TxPoolConfig()
        
        # Priority queue of pending transactions
        self.pending: List[PendingTransaction] = []
        
        # Transactions by hash
        self.by_hash: Dict[Hash, Transaction] = {}
        
        # Transactions by sender (for nonce management)
        self.by_sender: Dict[Address, Dict[Nonce, Transaction]] = defaultdict(dict)
        
        # Lowest nonce per sender (for next transaction)
        self.next_nonce: Dict[Address, Nonce] = defaultdict(int)
        
        # Highest nonce per sender (for validation)
        self.highest_nonce: Dict[Address, Nonce] = defaultdict(int)
        
        # Metadata
        self.total_received: int = 0
        self.total_rejected: int = 0
        self.total_evicted: int = 0
        
        # Lock for thread safety
        self.lock = threading.RLock()
        
        logger.info(f"Transaction pool initialized: max_size={self.config.max_size}")
    
    def add_transaction(self, tx: Transaction) -> bool:
        """
        Add a transaction to the pool
        
        Returns:
            True if added, False if rejected
        """
        with self.lock:
            self.total_received += 1
            
            # Validate transaction
            status, reason = self._validate_transaction(tx)
            if status != PoolStatus.OK:
                self.total_rejected += 1
                logger.debug(f"Transaction rejected: {reason}")
                return False
            
            # Check size limit
            if len(self.by_hash) >= self.config.max_size:
                if not self._try_evict():
                    self.total_rejected += 1
                    logger.warning("Pool full, cannot evict")
                    return False
            
            # Create pending transaction wrapper
            pending_tx = PendingTransaction(
                priority=(tx.fee, tx.nonce),
                transaction=tx,
                local_marker=self.total_received
            )
            
            # Add to pool
            heapq.heappush(self.pending, pending_tx)
            self.by_hash[tx.hash] = tx
            self.by_sender[tx.sender][tx.nonce] = tx
            
            # Update nonce tracking
            if tx.nonce >= self.next_nonce[tx.sender]:
                self.next_nonce[tx.sender] = tx.nonce + 1
            if tx.nonce > self.highest_nonce[tx.sender]:
                self.highest_nonce[tx.sender] = tx.nonce
            
            logger.debug(
                f"Transaction added: hash={tx.hash.hex()[:16]}... "
                f"sender={tx.sender.hex()[:8]}... fee={tx.fee}"
            )
            
            return True
    
    def _validate_transaction(self, tx: Transaction) -> Tuple[PoolStatus, str]:
        """Validate a transaction before adding"""
        
        # Check for duplicate
        if tx.hash in self.by_hash:
            return PoolStatus.DUPLICATE, f"Duplicate transaction {tx.hash.hex()}"
        
        # Check sender limit
        if len(self.by_sender[tx.sender]) >= self.config.max_per_sender:
            return PoolStatus.FULL, f"Sender {tx.sender.hex()} has too many pending txs"
        
        # Check gas price
        if tx.fee < self.config.min_gas_price:
            return PoolStatus.INVALID, f"Gas price {tx.fee} below minimum {self.config.min_gas_price}"
        
        # Check nonce is within window
        next_nonce = self.next_nonce[tx.sender]
        if tx.nonce < next_nonce:
            return PoolStatus.NONCE_TOO_LOW, f"Nonce {tx.nonce} too low (expected >= {next_nonce})"
        
        if tx.nonce > next_nonce + self.config.nonce_window:
            return PoolStatus.NONCE_TOO_HIGH, f"Nonce {tx.nonce} too high (expected <= {next_nonce + self.config.nonce_window})"
        
        return PoolStatus.OK, "OK"
    
    def _try_evict(self) -> bool:
        """Try to evict a transaction to make room"""
        if not self.pending:
            return False
        
        # Try to evict lowest priority transaction
        while self.pending:
            pending_tx = heapq.heappop(self.pending)
            tx = pending_tx.transaction
            
            # Skip if already removed
            if tx.hash not in self.by_hash:
                continue
            
            # Remove transaction
            self._remove_transaction(tx)
            self.total_evicted += 1
            logger.debug(f"Evicted transaction: {tx.hash.hex()[:16]}...")
            return True
        
        return False
    
    def _remove_transaction(self, tx: Transaction):
        """Remove a transaction from all tracking structures"""
        del self.by_hash[tx.hash]
        
        if tx.nonce in self.by_sender[tx.sender]:
            del self.by_sender[tx.sender][tx.nonce]
        
        # Clean up empty sender entry
        if not self.by_sender[tx.sender]:
            del self.by_sender[tx.sender]
    
    def get_transaction(self, tx_hash: Hash) -> Optional[Transaction]:
        """Get a transaction by hash"""
        return self.by_hash.get(tx_hash)
    
    def get_sender_transactions(self, sender: Address) -> List[Transaction]:
        """Get all pending transactions from a sender"""
        with self.lock:
            return list(self.by_sender.get(sender, {}).values())
    
    def get_next_nonce(self, sender: Address) -> Nonce:
        """Get the next valid nonce for a sender"""
        return self.next_nonce[sender]
    
    def get_batch(self, batch_size: int) -> List[Transaction]:
        """
        Get next batch of transactions for sequencing
        
        Returns transactions ordered by:
        1. Gas price (highest first)
        2. Nonce (lowest first)
        """
        with self.lock:
            batch = []
            seen = set()
            
            # We need to handle nonces carefully
            # For each sender, we want to include consecutive nonces starting from next_nonce
            
            # Build list of eligible transactions by sender
            eligible_by_sender: Dict[Address, List[Transaction]] = defaultdict(list)
            
            for pending_tx in self.pending:
                tx = pending_tx.transaction
                
                # Skip if we already have too many from this sender
                if len(eligible_by_sender[tx.sender]) >= self.config.max_per_sender:
                    continue
                
                # Check if nonce is eligible
                next_nonce = self.next_nonce[tx.sender]
                if tx.nonce >= next_nonce and tx.nonce <= next_nonce + self.config.nonce_window:
                    eligible_by_sender[tx.sender].append(tx)
            
            # Build batch ensuring nonce ordering per sender
            for sender, txs in eligible_by_sender.items():
                # Sort by nonce
                txs.sort(key=lambda t: t.nonce)
                
                # Add consecutive nonces from next_nonce
                expected_nonce = self.next_nonce[sender]
                for tx in txs:
                    if len(batch) >= batch_size:
                        break
                    
                    if tx.nonce == expected_nonce:
                        batch.append(tx)
                        expected_nonce += 1
                        # Remove from pending tracking
                        self._mark_processed(tx)
            
            return batch
    
    def _mark_processed(self, tx: Transaction):
        """Mark a transaction as processed (removed from pool)"""
        # Remove from pending heap
        self._remove_transaction(tx)
    
    def remove_processed(self, txs: List[Transaction]):
        """Remove multiple processed transactions"""
        with self.lock:
            for tx in txs:
                if tx.hash in self.by_hash:
                    self._remove_transaction(tx)
    
    def get_pending_count(self) -> int:
        """Get number of pending transactions"""
        return len(self.by_hash)
    
    def get_sender_count(self, sender: Address) -> int:
        """Get number of pending transactions from a sender"""
        return len(self.by_sender.get(sender, {}))
    
    def get_gas_price_stats(self) -> Dict[str, int]:
        """Get gas price statistics"""
        if not self.by_hash:
            return {"min": 0, "max": 0, "avg": 0, "median": 0}
        
        prices = [tx.fee for tx in self.by_hash.values()]
        prices.sort()
        
        return {
            "min": prices[0],
            "max": prices[-1],
            "avg": sum(prices) // len(prices),
            "median": prices[len(prices) // 2]
        }
    
    def get_pending_by_gas_price(self, min_price: GasPrice) -> List[Transaction]:
        """Get all pending transactions above a minimum gas price"""
        with self.lock:
            return [
                tx for tx in self.by_hash.values()
                if tx.fee >= min_price
            ]
    
    def clear(self):
        """Clear all pending transactions"""
        with self.lock:
            self.pending.clear()
            self.by_hash.clear()
            self.by_sender.clear()
            self.next_nonce.clear()
            self.highest_nonce.clear()
            logger.info("Transaction pool cleared")
    
    def get_status(self) -> Dict:
        """Get pool status for monitoring"""
        with self.lock:
            return {
                "pending_count": len(self.by_hash),
                "sender_count": len(self.by_sender),
                "max_size": self.config.max_size,
                "utilization": len(self.by_hash) / self.config.max_size,
                "total_received": self.total_received,
                "total_rejected": self.total_rejected,
                "total_evicted": self.total_evicted,
                "gas_price_stats": self.get_gas_price_stats()
            }
    
    def update_next_nonce(self, sender: Address, nonce: Nonce):
        """Update the next expected nonce for a sender"""
        self.next_nonce[sender] = nonce
    
    def is_empty(self) -> bool:
        """Check if pool is empty"""
        return len(self.by_hash) == 0
    
    def get_all_hashes(self) -> List[Hash]:
        """Get all transaction hashes in the pool"""
        return list(self.by_hash.keys())


# ============================================================================
# Transaction Validator
# ============================================================================

class TransactionValidator:
    """
    Validates transactions before adding to pool
    
    Checks:
    - Signature validity
    - Chain ID
    - Gas parameters
    - Data size limits
    """
    
    MAX_DATA_SIZE = 128 * 1024  # 128 KB
    MAX_GAS_LIMIT = 8000000
    
    def __init__(self, chain_id: int = 1337):
        self.chain_id = chain_id
    
    def validate(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate a transaction"""
        
        # Check chain ID
        if tx.chain_id != self.chain_id:
            return False, f"Wrong chain ID: expected {self.chain_id}, got {tx.chain_id}"
        
        # Check signature
        if not tx.verify_signature():
            return False, "Invalid signature"
        
        # Check gas limit
        if tx.fee > self.MAX_GAS_LIMIT:
            return False, f"Gas limit too high: {tx.fee}"
        
        # Check data size
        if len(tx.data) > self.MAX_DATA_SIZE:
            return False, f"Data too large: {len(tx.data)} bytes"
        
        # Check amounts are non-negative
        if tx.amount < 0 or tx.fee < 0:
            return False, "Negative amount or fee"
        
        # Check addresses are valid
        if len(tx.sender) != 20 or len(tx.recipient) != 20:
            return False, "Invalid address length"
        
        # Check sender is not zero address
        if tx.sender == b"\x00" * 20:
            return False, "Sender cannot be zero address"
        
        return True, "OK"


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NexusChain Transaction Pool")
    parser.add_argument("--max-size", type=int, default=10000, help="Max pool size")
    parser.add_argument("--test-txs", type=int, default=100, help="Number of test transactions")
    
    args = parser.parse_args()
    
    # Create pool
    config = TxPoolConfig(max_size=args.max_size)
    pool = TransactionPool(config)
    validator = TransactionValidator()
    
    # Generate test transactions
    from ..zk_rollup.types import Transaction, TransactionType, Address
    
    print(f"Adding {args.test_txs} test transactions...")
    
    for i in range(args.test_txs):
        sender = bytes([i % 256] * 20)
        recipient = bytes([(i + 1) % 256] * 20)
        
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=sender,
            recipient=recipient,
            amount=i * 100,
            fee=1000000 + i * 1000,
            nonce=i,
            data=b""
        )
        
        # Sign (simplified)
        tx.sign(bytes([1] * 32))
        
        if validator.validate(tx)[0]:
            pool.add_transaction(tx)
    
    # Get batch
    print(f"\nPool status: {pool.get_status()}")
    print(f"\nGas price stats: {pool.get_gas_price_stats()}")
    
    batch = pool.get_batch(10)
    print(f"\nFirst batch ({len(batch)} transactions):")
    for tx in batch:
        print(f"  {tx.hash.hex()[:16]}... nonce={tx.nonce} fee={tx.fee}")


if __name__ == "__main__":
    main()
