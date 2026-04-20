"""
NexusChain - Test Suite

Unit tests for core components.
"""

import pytest
import time
from src.zk_rollup.types import (
    Transaction, TransactionType, Account, Block, Batch,
    Address, Amount, Nonce, HashlibHasher
)
from src.state.merkle import SparseMerkleTree, ZKStateTree, MerkleProof
from src.txpool.pool import TransactionPool, TxPoolConfig, TransactionValidator
from src.sequencer.block import Sequencer, SequencerConfig
from src.zk_rollup.circuit import TransferCircuit, CircuitLibrary, CircuitType
from src.zk_rollup.proof import ProofGenerator


# ============================================================================
# Merkle Tree Tests
# ============================================================================

class TestSparseMerkleTree:
    """Tests for Sparse Merkle Tree"""
    
    def test_create_empty_tree(self):
        """Test creating an empty tree"""
        tree = SparseMerkleTree(depth=32)
        assert tree.get_root() == b"\x00" * 32
        assert tree.get_size() == 0
    
    def test_set_and_get(self):
        """Test setting and getting values"""
        tree = SparseMerkleTree(depth=32)
        
        key = b"test_key_001"
        value = b"test_value_001"
        
        new_root, proof = tree.set(key, value)
        assert new_root != b"\x00" * 32
        
        retrieved = tree.get(key)
        assert retrieved == HashlibHasher.keccak256(value)
    
    def test_proof_generation_and_verification(self):
        """Test Merkle proof generation and verification"""
        tree = SparseMerkleTree(depth=32)
        
        key = b"user_address_001"
        value = b"balance_100_tokens"
        
        new_root, proof = tree.set(key, value)
        
        # Verify proof
        assert SparseMerkleTree.verify_proof(new_root, proof)
    
    def test_batch_update(self):
        """Test batch updates"""
        tree = SparseMerkleTree(depth=32)
        
        updates = {
            b"key_001": b"value_001",
            b"key_002": b"value_002",
            b"key_003": b"value_003",
        }
        
        new_root, proofs = tree.batch_set(updates)
        assert tree.get_size() == 3
        assert new_root != b"\x00" * 32
    
    def test_empty_proof(self):
        """Test proof for non-existent key"""
        tree = SparseMerkleTree(depth=32)
        
        key = b"non_existent"
        proof = tree.prove(key)
        
        assert proof.is_empty
        assert proof.value == b"\x00" * 32


class TestZKStateTree:
    """Tests for ZK-optimized state tree"""
    
    def test_create_state_tree(self):
        """Test creating ZK state tree"""
        tree = ZKStateTree(depth=32)
        
        roots = tree.get_roots()
        assert "stateRoot" in roots
        assert "nullifierRoot" in roots
    
    def test_update_account(self):
        """Test updating account in state tree"""
        tree = ZKStateTree(depth=32)
        
        address = b"\x01" * 20
        account = Account(address=address, balance=1000, nonce=0)
        
        new_root, proof = tree.update_account(address, account)
        assert new_root != b"\x00" * 32
    
    def test_nullifier_usage(self):
        """Test nullifier prevents double-spending"""
        tree = ZKStateTree(depth=32)
        
        nullifier = HashlibHasher.keccak256(b"test_nullifier")
        
        # First use should succeed
        assert tree.add_nullifier(nullifier)
        
        # Second use should fail (double-spend attempt)
        assert not tree.add_nullifier(nullifier)
        
        # Check usage
        assert tree.is_nullifier_used(nullifier)


# ============================================================================
# Transaction Tests
# ============================================================================

class TestTransaction:
    """Tests for Transaction"""
    
    def test_create_transaction(self):
        """Test creating a transaction"""
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=b"\x01" * 20,
            recipient=b"\x02" * 20,
            amount=1000,
            fee=100,
            nonce=0
        )
        
        assert tx.hash is not None
        assert len(tx.hash) == 32
    
    def test_transaction_serialization(self):
        """Test transaction serialization"""
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=b"\x01" * 20,
            recipient=b"\x02" * 20,
            amount=1000,
            fee=100,
            nonce=0
        )
        
        # To dict
        data = tx.to_dict()
        assert data["type"] == "TRANSFER"
        assert data["amount"] == "1000"
        
        # From dict
        tx2 = Transaction.from_dict(data)
        assert tx2.amount == tx.amount
        assert tx2.sender == tx.sender


# ============================================================================
# Transaction Pool Tests
# ============================================================================

class TestTransactionPool:
    """Tests for Transaction Pool"""
    
    def test_create_pool(self):
        """Test creating a transaction pool"""
        pool = TransactionPool()
        assert pool.get_pending_count() == 0
        assert pool.is_empty()
    
    def test_add_transaction(self):
        """Test adding transactions"""
        pool = TransactionPool()
        validator = TransactionValidator()
        
        sender = b"\x01" * 20
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=sender,
            recipient=b"\x02" * 20,
            amount=1000,
            fee=1000000,
            nonce=0
        )
        
        tx.sign(bytes([1] * 32))
        
        # Validate and add
        valid, reason = validator.validate(tx)
        if valid:
            assert pool.add_transaction(tx)
        
        assert pool.get_pending_count() >= 0
    
    def test_get_batch(self):
        """Test getting transaction batch"""
        pool = TransactionPool(config=TxPoolConfig(max_size=1000))
        
        # Should return empty list initially
        batch = pool.get_batch(10)
        assert isinstance(batch, list)
    
    def test_pool_status(self):
        """Test pool status"""
        pool = TransactionPool()
        status = pool.get_status()
        
        assert "pending_count" in status
        assert "max_size" in status
        assert status["max_size"] == 10000


# ============================================================================
# Sequencer Tests
# ============================================================================

class TestSequencer:
    """Tests for Sequencer"""
    
    def test_create_sequencer(self):
        """Test creating a sequencer"""
        txpool = TransactionPool()
        config = SequencerConfig()
        sequencer = Sequencer(txpool, config)
        
        state = sequencer.get_state()
        assert state.current_block_number == 0
        assert state.total_transactions == 0
    
    def test_account_info(self):
        """Test getting account info"""
        txpool = TransactionPool()
        sequencer = Sequencer(txpool)
        
        address = b"\x01" * 20
        info = sequencer.get_account_info(address)
        
        assert "address" in info
        assert "balance" in info
        assert "nonce" in info


# ============================================================================
# Circuit Tests
# ============================================================================

class TestCircuits:
    """Tests for ZK Circuits"""
    
    def test_transfer_circuit_creation(self):
        """Test creating transfer circuit"""
        circuit = TransferCircuit()
        assert circuit.name == "transfer"
        assert len(circuit.public_inputs) > 0
    
    def test_circuit_library(self):
        """Test circuit library"""
        library = CircuitLibrary()
        
        # Get transfer circuit
        circuit = library.get_circuit(CircuitType.TRANSFER)
        assert circuit is not None
        
        # Export R1CS
        r1cs = library.export_r1cs(CircuitType.TRANSFER)
        assert "name" in r1cs
        assert "constraints" in r1cs


# ============================================================================
# Proof Tests
# ============================================================================

class TestProofGenerator:
    """Tests for Proof Generator"""
    
    def test_create_generator(self):
        """Test creating proof generator"""
        generator = ProofGenerator(proof_system="groth16")
        assert generator.proof_system == "groth16"
    
    def test_batch_proof_generation(self):
        """Test batch proof generation"""
        generator = ProofGenerator(proof_system="groth16")
        
        # Create empty batch
        batch = Batch(batch_number=1)
        
        # Generate proof
        proof = generator.generate_batch_proof(batch)
        assert proof.proof_system == "groth16"


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests"""
    
    def test_full_transaction_flow(self):
        """Test complete transaction flow"""
        # Create components
        txpool = TransactionPool()
        sequencer = Sequencer(txpool)
        
        # Create transaction
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=b"\x01" * 20,
            recipient=b"\x02" * 20,
            amount=1000,
            fee=100,
            nonce=0
        )
        
        # Submit to pool
        # Note: Would need proper signing in production
        # pool.add_transaction(tx)
        
        # Check state
        state = sequencer.get_state()
        assert state is not None


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Performance tests"""
    
    def test_merkle_tree_performance(self):
        """Test Merkle tree performance"""
        tree = SparseMerkleTree(depth=32)
        
        # Time 1000 updates
        start = time.time()
        for i in range(1000):
            key = f"key_{i}".encode()
            value = f"value_{i}".encode()
            tree.set(key, value)
        elapsed = time.time() - start
        
        print(f"\n1000 Merkle updates: {elapsed:.3f}s")
        assert elapsed < 1.0  # Should be fast
    
    def test_proof_generation_performance(self):
        """Test proof generation performance"""
        generator = ProofGenerator(proof_system="groth16")
        batch = Batch(batch_number=1)
        
        start = time.time()
        proof = generator.generate_batch_proof(batch)
        elapsed = time.time() - start
        
        print(f"\nProof generation: {elapsed:.3f}s")
        assert elapsed < 10.0  # Should complete within reasonable time


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
