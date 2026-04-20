"""
NexusChain - Cross-Chain Bridge

Manages asset transfers between Ethereum (L1) and NexusChain (L2).
"""

from __future__ import annotations
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass
import threading
import logging

from ..zk_rollup.types import (
    Address, Amount, Hash, Deposit, Withdrawal, WithdrawalProof,
    Transaction, TransactionType, Block, HashlibHasher
)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BridgeStatus(Enum):
    """Bridge operation status"""
    PENDING = "pending"
    FINALIZED = "finalized"
    FAILED = "failed"
    DISPUTED = "disputed"


@dataclass
class BridgeConfig:
    """Bridge configuration"""
    l1_bridge_address: Address = b"\x00" * 20
    l2_bridge_address: Address = b"\x00" * 20
    min_deposit: Amount = 0
    max_deposit: Amount = 10**18 * 1000  # 1000 ETH
    withdrawal_delay: float = 0.0  # 0 for ZK-Rollups (no delay)
    challenge_period: float = 0.0  # ZK proofs don't need challenge period
    
    # Security
    emergency_exit_enabled: bool = True
    paused: bool = False


@dataclass
class BridgeState:
    """Bridge state tracking"""
    total_deposits: int = 0
    total_withdrawals: int = 0
    total_volume_deposited: Amount = 0
    total_volume_withdrawn: Amount = 0
    
    pending_deposits: List[Deposit] = field(default_factory=list)
    pending_withdrawals: List[Withdrawal] = field(default_factory=list)
    finalized_deposits: List[Deposit] = field(default_factory=list)
    finalized_withdrawals: List[Withdrawal] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "totalDeposits": self.total_deposits,
            "totalWithdrawals": self.total_withdrawals,
            "totalVolumeDeposited": str(self.total_volume_deposited),
            "totalVolumeWithdrawn": str(self.total_volume_withdrawn),
            "pendingDeposits": len(self.pending_deposits),
            "pendingWithdrawals": len(self.pending_withdrawals)
        }


class L1Bridge:
    """
    Layer 1 Bridge Contract Interface
    
    Handles:
    - Deposit locking
    - Withdrawal verification
    - Proof submission
    """
    
    def __init__(self, config: BridgeConfig, web3=None):
        self.config = config
        self.web3 = web3  # Web3.py instance
        
        # Event cache
        self.deposit_events: List[Dict] = []
        self.withdrawal_events: List[Dict] = []
    
    def deposit(self, user: Address, amount: Amount, l2_recipient: Address) -> Dict:
        """
        Initiate a deposit from L1 to L2
        
        Args:
            user: L1 address making the deposit
            amount: Amount to deposit
            l2_recipient: L2 address to receive the funds
            
        Returns:
            Transaction receipt
        """
        if self.config.paused:
            raise Exception("Bridge is paused")
        
        if amount < self.config.min_deposit:
            raise ValueError(f"Amount below minimum: {self.config.min_deposit}")
        
        if amount > self.config.max_deposit:
            raise ValueError(f"Amount above maximum: {self.config.max_deposit}")
        
        # In real implementation, this would call the L1 contract
        # For now, simulate the transaction
        logger.info(f"L1 deposit: {amount} from {user.hex()[:8]} to L2 {l2_recipient.hex()[:8]}")
        
        # Create deposit event
        deposit = Deposit(
            depositor=user,
            recipient=l2_recipient,
            amount=amount,
            l1_tx_hash=HashlibHasher.keccak256(b"deposit" + user + l2_recipient + amount.to_bytes(32, "big")),
            timestamp=int(time.time())
        )
        
        self.deposit_events.append(deposit.to_dict())
        
        return {
            "success": True,
            "deposit": deposit.to_dict(),
            "message": "Deposit initiated"
        }
    
    def verify_withdrawal_proof(self, proof: WithdrawalProof) -> bool:
        """
        Verify a withdrawal proof on L1
        
        Args:
            proof: WithdrawalProof from L2
            
        Returns:
            True if proof is valid
        """
        # In real implementation, this would verify the ZK proof on-chain
        # or use the verifier contract
        
        logger.info(f"Verifying withdrawal proof for {proof.user.hex()[:8]}")
        
        # Verify proof structure
        if not proof.merkle_proof or len(proof.merkle_proof) < 32:
            return False
        
        # In production: call Verifier contract to verify ZK proof
        return True
    
    def finalize_withdrawal(
        self, 
        user: Address, 
        amount: Amount, 
        proof: WithdrawalProof
    ) -> Dict:
        """
        Finalize a withdrawal on L1
        
        Args:
            user: User to receive funds
            amount: Amount to withdraw
            proof: WithdrawalProof from L2
            
        Returns:
            Transaction receipt
        """
        # Verify proof first
        if not self.verify_withdrawal_proof(proof):
            return {
                "success": False,
                "error": "Invalid proof"
            }
        
        # In real implementation, this would transfer ETH from bridge to user
        logger.info(f"Finalizing withdrawal: {amount} to {user.hex()[:8]}")
        
        return {
            "success": True,
            "message": "Withdrawal finalized"
        }
    
    def pause(self):
        """Pause the bridge"""
        self.config.paused = True
        logger.warning("Bridge paused")
    
    def unpause(self):
        """Unpause the bridge"""
        self.config.paused = False
        logger.info("Bridge unpaused")


class L2Bridge:
    """
    Layer 2 Bridge Contract Interface
    
    Handles:
    - Deposit finalization (minting on L2)
    - Withdrawal initiation (burning on L2)
    - Merkle proof generation
    """
    
    def __init__(self, config: BridgeConfig, state_manager=None):
        self.config = config
        self.state_manager = state_manager
        
        # Withdrawal tracking
        self.pending_withdrawals: Dict[Hash, Withdrawal] = {}
        self.nullifiers: set = set()
    
    def finalize_deposit(self, deposit: Deposit) -> Transaction:
        """
        Finalize a deposit on L2 (mint tokens)
        
        Args:
            deposit: Deposit from L1
            
        Returns:
            L2 transaction
        """
        if self.config.paused:
            raise Exception("Bridge is paused")
        
        logger.info(
            f"Finalizing L2 deposit: {deposit.amount} to {deposit.recipient.hex()[:8]}"
        )
        
        # Create L2 transaction to mint tokens
        tx = Transaction(
            transaction_type=TransactionType.BRIDGE_DEPOSIT,
            sender=self.config.l2_bridge_address,
            recipient=deposit.recipient,
            amount=deposit.amount,
            fee=0,
            nonce=0,
            data=b""
        )
        
        deposit.finalized = True
        return tx
    
    def initiate_withdrawal(self, user: Address, recipient: Address, amount: Amount) -> WithdrawalProof:
        """
        Initiate a withdrawal on L2 (burn tokens)
        
        Args:
            user: L2 address initiating withdrawal
            recipient: L1 address to receive funds
            amount: Amount to withdraw
            
        Returns:
            WithdrawalProof that can be used on L1
        """
        if self.config.paused:
            raise Exception("Bridge is paused")
        
        logger.info(
            f"Initiating L2 withdrawal: {amount} from {user.hex()[:8]} to L1"
        )
        
        # Create burn transaction
        tx = Transaction(
            transaction_type=TransactionType.BRIDGE_WITHDRAW,
            sender=user,
            recipient=self.config.l2_bridge_address,
            amount=amount,
            fee=0,
            nonce=0,
            data=recipient  # Include L1 recipient in data
        )
        
        # Generate nullifier to prevent double-spending
        nullifier = HashlibHasher.keccak256(
            tx.hash + int.to_bytes(int(time.time()), 32, "big")
        )
        
        # Record nullifier
        self.nullifiers.add(nullifier)
        
        # Generate Merkle proof of the burn
        # In real implementation, this would be generated from the state tree
        merkle_proof = self._generate_merkle_proof(user, amount)
        
        # Create withdrawal record
        withdrawal = Withdrawal(
            user=user,
            recipient=recipient,
            amount=amount,
            l2_tx_hash=tx.hash,
            timestamp=int(time.time())
        )
        
        self.pending_withdrawals[tx.hash] = withdrawal
        
        # Create withdrawal proof
        proof = WithdrawalProof(
            user=recipient,
            amount=amount,
            l2_tx_hash=tx.hash,
            nullifier=nullifier,
            merkle_proof=merkle_proof
        )
        
        return proof
    
    def _generate_merkle_proof(self, user: Address, amount: Amount) -> List[Hash]:
        """
        Generate Merkle proof for withdrawal
        
        In production, this would query the state tree
        """
        # Generate dummy proof for simulation
        return [HashlibHasher.keccak256(b"proof" + bytes([i])) for i in range(32)]
    
    def is_nullifier_used(self, nullifier: Hash) -> bool:
        """Check if a nullifier has been used"""
        return nullifier in self.nullifiers
    
    def verify_withdrawal(self, proof: WithdrawalProof) -> bool:
        """
        Verify a withdrawal is valid
        
        Args:
            proof: WithdrawalProof to verify
            
        Returns:
            True if valid
        """
        # Check nullifier hasn't been used
        if self.is_nullifier_used(proof.nullifier):
            return False
        
        # Verify Merkle proof
        # In production, this would verify against the state root
        
        return True


class BridgeManager:
    """
    High-level bridge manager
    
    Coordinates between L1 and L2 bridges
    """
    
    def __init__(
        self,
        l1_bridge: L1Bridge,
        l2_bridge: L2Bridge,
        config: Optional[BridgeConfig] = None
    ):
        self.l1_bridge = l1_bridge
        self.l2_bridge = l2_bridge
        self.config = config or BridgeConfig()
        
        self.state = BridgeState()
        
        # Event watchers
        self.l1_event_watcher: Optional[threading.Thread] = None
        self.running = False
        
        # Callbacks
        self.on_deposit_finalized: Optional[Callable] = None
        self.on_withdrawal_initiated: Optional[Callable] = None
        
        logger.info("Bridge manager initialized")
    
    def start_event_watchers(self):
        """Start watching for L1 events"""
        self.running = True
        self.l1_event_watcher = threading.Thread(
            target=self._watch_l1_events,
            daemon=True
        )
        self.l1_event_watcher.start()
        logger.info("L1 event watcher started")
    
    def stop_event_watchers(self):
        """Stop event watchers"""
        self.running = False
        if self.l1_event_watcher:
            self.l1_event_watcher.join(timeout=1.0)
    
    def _watch_l1_events(self):
        """Watch for L1 deposit events"""
        while self.running:
            try:
                # In production, this would poll or use websocket for events
                self._process_pending_deposits()
            except Exception as e:
                logger.error(f"Error watching L1 events: {e}")
            
            time.sleep(5)  # Poll every 5 seconds
    
    def _process_pending_deposits(self):
        """Process pending L1 deposits"""
        for event in self.l1_bridge.deposit_events:
            deposit = Deposit(
                depositor=bytes.fromhex(event["depositor"].replace("0x", "")),
                recipient=bytes.fromhex(event["recipient"].replace("0x", "")),
                amount=int(event["amount"]),
                l1_tx_hash=bytes.fromhex(event["l1TxHash"].replace("0x", "")),
                timestamp=event["timestamp"]
            )
            
            if not deposit.finalized:
                self._finalize_deposit(deposit)
    
    def _finalize_deposit(self, deposit: Deposit):
        """Finalize a deposit on L2"""
        try:
            # Create L2 transaction
            tx = self.l2_bridge.finalize_deposit(deposit)
            
            # Update state
            self.state.total_deposits += 1
            self.state.total_volume_deposited += deposit.amount
            self.state.finalized_deposits.append(deposit)
            
            # Remove from pending
            self.state.pending_deposits = [
                d for d in self.state.pending_deposits
                if d.l1_tx_hash != deposit.l1_tx_hash
            ]
            
            logger.info(
                f"Deposit finalized: {deposit.amount} to {deposit.recipient.hex()[:8]}"
            )
            
            # Trigger callback
            if self.on_deposit_finalized:
                self.on_deposit_finalized(deposit, tx)
                
        except Exception as e:
            logger.error(f"Error finalizing deposit: {e}")
    
    def deposit(self, user: Address, amount: Amount, l2_recipient: Address) -> Dict:
        """
        Complete deposit flow: L1 -> L2
        
        Args:
            user: L1 address making the deposit
            amount: Amount to deposit
            l2_recipient: L2 address to receive funds
            
        Returns:
            Deposit result
        """
        # Initiate on L1
        result = self.l1_bridge.deposit(user, amount, l2_recipient)
        
        # Create deposit record
        deposit = Deposit(
            depositor=user,
            recipient=l2_recipient,
            amount=amount,
            l1_tx_hash=bytes.fromhex(result["deposit"]["l1TxHash"].replace("0x", "")),
            timestamp=result["deposit"]["timestamp"]
        )
        
        self.state.pending_deposits.append(deposit)
        
        return result
    
    def withdraw(self, user: Address, l1_recipient: Address, amount: Amount) -> WithdrawalProof:
        """
        Complete withdrawal flow: L2 -> L1
        
        Args:
            user: L2 address initiating withdrawal
            l1_recipient: L1 address to receive funds
            amount: Amount to withdraw
            
        Returns:
            WithdrawalProof that can be used on L1
        """
        # Initiate on L2
        proof = self.l2_bridge.initiate_withdrawal(user, l1_recipient, amount)
        
        # Create withdrawal record
        withdrawal = Withdrawal(
            user=user,
            recipient=l1_recipient,
            amount=amount,
            l2_tx_hash=proof.l2_tx_hash,
            timestamp=int(time.time())
        )
        
        self.state.pending_withdrawals.append(withdrawal)
        
        # Trigger callback
        if self.on_withdrawal_initiated:
            self.on_withdrawal_initiated(withdrawal, proof)
        
        return proof
    
    def finalize_withdrawal(self, proof: WithdrawalProof) -> Dict:
        """
        Finalize a withdrawal on L1
        
        Args:
            proof: WithdrawalProof from L2
            
        Returns:
            Finalization result
        """
        # Verify and finalize on L1
        result = self.l1_bridge.finalize_withdrawal(
            proof.user,
            proof.amount,
            proof
        )
        
        if result["success"]:
            # Update state
            self.state.total_withdrawals += 1
            self.state.total_volume_withdrawn += proof.amount
            
            # Mark withdrawal as complete
            self.state.pending_withdrawals = [
                w for w in self.state.pending_withdrawals
                if w.l2_tx_hash != proof.l2_tx_hash
            ]
        
        return result
    
    def get_state(self) -> BridgeState:
        """Get current bridge state"""
        return self.state
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics"""
        return {
            **self.state.to_dict(),
            "paused": self.config.paused,
            "minDeposit": str(self.config.min_deposit),
            "maxDeposit": str(self.config.max_deposit),
            "withdrawalDelay": self.config.withdrawal_delay
        }


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for bridge testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NexusChain Bridge")
    parser.add_argument("--mode", choices=["deposit", "withdraw", "status"], 
                        default="status", help="Operation mode")
    parser.add_argument("--amount", type=int, default=1, help="Amount (in wei)")
    parser.add_argument("--l1-address", default="0x" + "00" * 20, help="L1 address")
    parser.add_argument("--l2-address", default="0x" + "00" * 20, help="L2 address")
    
    args = parser.parse_args()
    
    # Create bridges
    config = BridgeConfig()
    l1_bridge = L1Bridge(config)
    l2_bridge = L2Bridge(config)
    manager = BridgeManager(l1_bridge, l2_bridge, config)
    
    l1_address = bytes.fromhex(args.l1_address.replace("0x", ""))
    l2_address = bytes.fromhex(args.l2_address.replace("0x", ""))
    
    if args.mode == "deposit":
        result = manager.deposit(l1_address, args.amount, l2_address)
        print(f"Deposit initiated: {result}")
    
    elif args.mode == "withdraw":
        proof = manager.withdraw(l2_address, l1_address, args.amount)
        print(f"Withdrawal initiated: {proof.to_dict()}")
        
        # Finalize
        result = manager.finalize_withdrawal(proof)
        print(f"Withdrawal finalized: {result}")
    
    elif args.mode == "status":
        print(f"Bridge status:")
        print(json.dumps(manager.get_stats(), indent=2))


if __name__ == "__main__":
    main()
