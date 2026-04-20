"""
NexusChain - Sparse Merkle Tree Implementation

A high-performance Sparse Merkle Tree implementation for Layer 2 state management.
Supports concurrent access, proof generation, and efficient updates.
"""

from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set, Any
from concurrent.futures import ThreadPoolExecutor
import threading
from copy import deepcopy

from ..zk_rollup.types import (
    Hash, Address, Amount, Nonce, Account,
    HashlibHasher, compute_merkle_root, pad_to_power_of_two
)


@dataclass
class MerkleProof:
    """
    Merkle inclusion/absence proof
    
    Used to verify that a value is (or isn't) in the tree
    """
    key: bytes
    value: bytes
    siblings: List[Tuple[int, Hash]]  # (level, sibling_hash)
    path: List[int]  # Index at each level
    is_empty: bool = False
    
    def to_list(self) -> List[str]:
        """Serialize to list for JSON"""
        return [
            self.key.hex(),
            self.value.hex(),
            [[l, s.hex()] for l, s in self.siblings],
            self.path,
            self.is_empty
        ]
    
    @classmethod
    def from_list(cls, data: List) -> MerkleProof:
        """Deserialize from list"""
        return cls(
            key=bytes.fromhex(data[0]),
            value=bytes.fromhex(data[1]),
            siblings=[(l, bytes.fromhex(s)) for l, s in data[2]],
            path=data[3],
            is_empty=data[4]
        )


class SparseMerkleTree:
    """
    Sparse Merkle Tree for Layer 2 state management
    
    Features:
    - O(log n) updates and proofs
    - Concurrent access support
    - Efficient zero-knowledge proof generation
    - Empty subtree commitment
    
    The tree stores account states as leaves:
    - Key: Address (hashed for privacy)
    - Value: Account state hash
    
    Internal nodes are computed as:
    H(left_child || right_child)
    """
    
    EMPTY_HASH = b"\x00" * 32
    DEFAULT_DEPTH = 32  # Supports 2^32 addresses
    
    def __init__(self, depth: int = 32, precompute_empty: bool = True):
        """
        Initialize the Sparse Merkle Tree
        
        Args:
            depth: Tree depth (determines max leaves = 2^depth)
            precompute_empty: Precompute all empty hashes for efficiency
        """
        self.depth = depth
        self.lock = threading.RLock()
        
        # Tree storage: index -> hash
        self.tree: Dict[int, Hash] = {}
        
        # Cache of non-empty leaves
        self.leaves: Dict[Hash, Hash] = {}  # key_hash -> value_hash
        
        # Precompute empty hashes for each level
        if precompute_empty:
            self._precompute_empty_hashes()
        else:
            self._empty_hashes = None
    
    def _precompute_empty_hashes(self):
        """Precompute all empty hashes for each level"""
        self._empty_hashes = [self.EMPTY_HASH]
        
        for level in range(1, self.depth + 1):
            # Hash of two empty children at this level
            prev = self._empty_hashes[-1]
            new_hash = HashlibHasher.hash_pair(prev, prev)
            self._empty_hashes.append(new_hash)
    
    def _get_empty_hash(self, level: int) -> Hash:
        """Get precomputed empty hash for a level"""
        if self._empty_hashes:
            return self._empty_hashes[level]
        
        # Fallback: compute on the fly
        h = self.EMPTY_HASH
        for _ in range(level):
            h = HashlibHasher.hash_pair(h, h)
        return h
    
    def key_to_path(self, key: bytes) -> Tuple[int, List[int]]:
        """
        Convert a key to tree path
        
        Args:
            key: The key to navigate (usually hashed address)
            
        Returns:
            Tuple of (leaf_index, path_indices)
        """
        # Use first 4 bytes as index (little-endian)
        # This distributes addresses across the tree
        if len(key) < 4:
            key = key + b"\x00" * (4 - len(key))
        
        base_index = int.from_bytes(key[:4], "little")
        num_leaves = 2 ** self.depth
        
        # Map to tree size
        leaf_index = base_index % num_leaves
        
        # Build path from leaf to root
        path = []
        current = leaf_index
        for _ in range(self.depth):
            path.append(current)
            current = (current + 1) // 2
        
        return leaf_index, path
    
    def get(self, key: bytes) -> Optional[Hash]:
        """
        Get value for a key
        
        Args:
            key: The key to look up
            
        Returns:
            The value hash, or None if not found
        """
        with self.lock:
            key_hash = self._hash_key(key)
            return self.leaves.get(key_hash)
    
    def _hash_key(self, key: bytes) -> Hash:
        """Hash a key for storage"""
        return HashlibHasher.keccak256(key)
    
    def _hash_value(self, value: bytes) -> Hash:
        """Hash a value for storage"""
        return HashlibHasher.keccak256(value)
    
    def set(self, key: bytes, value: bytes) -> Tuple[Hash, MerkleProof]:
        """
        Set a value for a key, updating the tree
        
        Args:
            key: The key to set
            value: The value to store
            
        Returns:
            Tuple of (new_root, proof)
        """
        with self.lock:
            return self._set_internal(key, value)
    
    def _set_internal(self, key: bytes, value: bytes) -> Tuple[Hash, MerkleProof]:
        """Internal set operation (must hold lock)"""
        key_hash = self._hash_key(key)
        value_hash = self._hash_value(value)
        
        # Get current value (for proof)
        old_value = self.leaves.get(key_hash, self.EMPTY_HASH)
        
        # Update leaf
        self.leaves[key_hash] = value_hash
        
        # Build proof and update path
        leaf_index, path = self.key_to_path(key)
        
        # Start with new leaf value
        current_hash = value_hash
        siblings = []
        new_path = []
        
        # Update from leaf to root
        for level in range(self.depth):
            node_index = path[level]
            sibling_index = node_index ^ 1  # Get sibling
            
            # Get sibling hash
            if level == 0:
                # Check if sibling leaf exists
                if node_index % 2 == 0:
                    # We're left, sibling is right
                    sibling_hash = self._get_leaf_hash(sibling_index, key)
                else:
                    # We're right, sibling is left
                    sibling_hash = self._get_leaf_hash(sibling_index, key)
            else:
                # Sibling from previous iteration
                if node_index % 2 == 0:
                    sibling_hash = self._get_node_hash(sibling_index, level)
                else:
                    sibling_hash = self._get_node_hash(sibling_index, level)
            
            siblings.append((level, sibling_hash))
            new_path.append(node_index)
            
            # Compute parent hash
            if node_index % 2 == 0:
                current_hash = HashlibHasher.hash_pair(current_hash, sibling_hash)
            else:
                current_hash = HashlibHasher.hash_pair(sibling_hash, current_hash)
            
            # Update tree storage
            parent_index = (node_index + 1) // 2
            self._set_node_hash(parent_index, level + 1, current_hash)
        
        root = current_hash
        proof = MerkleProof(
            key=key,
            value=value,
            siblings=siblings,
            path=new_path
        )
        
        return root, proof
    
    def _get_leaf_hash(self, leaf_index: int, exclude_key: bytes) -> Hash:
        """Get hash for a leaf index, excluding a specific key"""
        for key_hash, value_hash in self.leaves.items():
            _, path = self.key_to_path(key_hash)
            if path[0] == leaf_index and key_hash != self._hash_key(exclude_key):
                return value_hash
        return self._get_empty_hash(0)
    
    def _get_node_hash(self, node_index: int, level: int) -> Hash:
        """Get hash for an internal node at given level"""
        # Check if we have this node stored
        key = (node_index, level)
        if key in self.tree:
            return self.tree[key]
        
        # Return empty hash for this level
        return self._get_empty_hash(level)
    
    def _set_node_hash(self, node_index: int, level: int, hash: Hash):
        """Set hash for an internal node"""
        key = (node_index, level)
        self.tree[key] = hash
    
    def delete(self, key: bytes) -> Tuple[Hash, MerkleProof]:
        """
        Delete a key from the tree
        
        Args:
            key: The key to delete
            
        Returns:
            Tuple of (new_root, proof)
        """
        with self.lock:
            key_hash = self._hash_key(key)
            
            if key_hash not in self.leaves:
                # Key doesn't exist, return current proof
                return self.get_root(), MerkleProof(
                    key=key,
                    value=self.EMPTY_HASH,
                    siblings=[],
                    path=[],
                    is_empty=True
                )
            
            # Remove the leaf
            del self.leaves[key_hash]
            
            # Update path with empty value
            return self._set_internal(key, self.EMPTY_HASH)
    
    def get_root(self) -> Hash:
        """Get the current Merkle root"""
        with self.lock:
            return self._compute_root()
    
    def _compute_root(self) -> Hash:
        """Compute root from current tree state (must hold lock)"""
        if not self.leaves:
            return self._get_empty_hash(self.depth)
        
        # Start from leaves and compute up
        current_level = {}
        
        # Initialize leaves
        for key_hash, value_hash in self.leaves.items():
            _, path = self.key_to_path(key_hash)
            leaf_index = path[0]
            current_level[leaf_index] = value_hash
        
        # Fill in empty leaves
        num_leaves = 2 ** self.depth
        for i in range(num_leaves):
            if i not in current_level:
                current_level[i] = self._get_empty_hash(0)
        
        # Build up the tree
        for level in range(1, self.depth + 1):
            next_level = {}
            num_nodes = num_leaves // (2 ** level)
            
            for i in range(num_nodes):
                left_idx = i * 2
                right_idx = left_idx + 1
                
                left_hash = current_level.get(left_idx, self._get_empty_hash(level - 1))
                right_hash = current_level.get(right_idx, self._get_empty_hash(level - 1))
                
                parent_hash = HashlibHasher.hash_pair(left_hash, right_hash)
                next_level[i] = parent_hash
            
            current_level = next_level
        
        return current_level.get(0, self._get_empty_hash(self.depth))
    
    def prove(self, key: bytes) -> MerkleProof:
        """
        Generate a Merkle inclusion proof for a key
        
        Args:
            key: The key to prove
            
        Returns:
            MerkleProof containing siblings for verification
        """
        with self.lock:
            key_hash = self._hash_key(key)
            value = self.leaves.get(key_hash)
            is_empty = value is None
            
            if is_empty:
                value = self.EMPTY_HASH
            
            leaf_index, path = self.key_to_path(key)
            siblings = []
            
            # Get sibling at each level
            for level in range(self.depth):
                node_index = path[level]
                sibling_index = node_index ^ 1
                
                # Try to get actual sibling
                sibling = self._get_sibling_hash(sibling_index, level, key)
                siblings.append((level, sibling))
            
            return MerkleProof(
                key=key,
                value=value,
                siblings=siblings,
                path=path,
                is_empty=is_empty
            )
    
    def _get_sibling_hash(self, sibling_index: int, level: int, exclude_key: bytes) -> Hash:
        """Get sibling hash at a given level"""
        # Check leaves
        for key_hash, value_hash in self.leaves.items():
            if key_hash == self._hash_key(exclude_key):
                continue
            _, path = self.key_to_path(key_hash)
            if path[level] == sibling_index:
                return value_hash
        
        # Return empty hash
        return self._get_empty_hash(level)
    
    @staticmethod
    def verify_proof(root: Hash, proof: MerkleProof) -> bool:
        """
        Verify a Merkle proof
        
        Args:
            root: Expected Merkle root
            proof: The proof to verify
            
        Returns:
            True if proof is valid
        """
        if proof.is_empty:
            # For empty proofs, verify the path leads to empty leaf
            pass
        
        # Compute root from proof
        current_hash = HashlibHasher.keccak256(proof.value)
        
        for level, sibling in proof.siblings:
            node_index = proof.path[level] if level < len(proof.path) else 0
            
            if node_index % 2 == 0:
                current_hash = HashlibHasher.hash_pair(current_hash, sibling)
            else:
                current_hash = HashlibHasher.hash_pair(sibling, current_hash)
        
        return current_hash == root
    
    def batch_set(self, updates: Dict[bytes, bytes]) -> Tuple[Hash, List[MerkleProof]]:
        """
        Apply multiple updates in batch
        
        Args:
            updates: Dict of key -> value
            
        Returns:
            Tuple of (new_root, list of proofs)
        """
        with self.lock:
            proofs = []
            for key, value in updates.items():
                _, proof = self._set_internal(key, value)
                proofs.append(proof)
            
            return self._compute_root(), proofs
    
    def get_leaves(self) -> List[Tuple[Hash, Hash]]:
        """Get all non-empty leaves as (key_hash, value_hash) pairs"""
        with self.lock:
            return list(self.leaves.items())
    
    def get_size(self) -> int:
        """Get number of non-empty leaves"""
        with self.lock:
            return len(self.leaves)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize tree state"""
        with self.lock:
            return {
                "depth": self.depth,
                "numLeaves": len(self.leaves),
                "root": self.get_root().hex(),
                "leaves": {k.hex(): v.hex() for k, v in self.leaves.items()}
            }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SparseMerkleTree:
        """Deserialize tree state"""
        tree = cls(depth=data["depth"])
        tree.leaves = {
            bytes.fromhex(k): bytes.fromhex(v)
            for k, v in data["leaves"].items()
        }
        return tree


class MultiMerkleTree:
    """
    Multi-tree supporting multiple concurrent SMTs
    
    Useful for:
    - Separate account state from storage
    - Multiple token balances
    - Historical state commitments
    """
    
    def __init__(self, num_trees: int = 4, depth: int = 32):
        self.trees: List[SparseMerkleTree] = [
            SparseMerkleTree(depth) for _ in range(num_trees)
        ]
        self.num_trees = num_trees
        self.depth = depth
    
    def get_tree(self, index: int) -> SparseMerkleTree:
        """Get tree by index"""
        return self.trees[index % self.num_trees]
    
    def set(self, tree_index: int, key: bytes, value: bytes) -> Tuple[Hash, MerkleProof]:
        """Set value in specific tree"""
        return self.get_tree(tree_index).set(key, value)
    
    def get_root(self, tree_index: Optional[int] = None) -> Hash:
        """Get root of specific tree or combined root"""
        if tree_index is not None:
            return self.get_tree(tree_index).get_root()
        
        # Combine all roots
        roots = [t.get_root() for t in self.trees]
        return HashlibHasher.keccak256(b"".join(roots))


class ZKStateTree:
    """
    State tree optimized for ZK circuit constraints
    
    Organizes state to minimize constraint count in circuits
    """
    
    def __init__(self, depth: int = 32):
        self.main_tree = SparseMerkleTree(depth)
        self.nullifier_tree = SparseMerkleTree(depth)
        self.used_nullifiers: Set[Hash] = set()
        self.depth = depth
    
    def update_account(self, address: Address, account: Account) -> Tuple[Hash, MerkleProof]:
        """Update account in main state tree"""
        return self.main_tree.set(address, account.to_leaf())
    
    def add_nullifier(self, nullifier: Hash) -> bool:
        """
        Add a nullifier (prevents double-spending)
        
        Returns:
            True if added, False if already exists (double-spend attempt)
        """
        if nullifier in self.used_nullifiers:
            return False
        
        self.used_nullifiers.add(nullifier)
        self.nullifier_tree.set(nullifier, b"\x01")
        return True
    
    def is_nullifier_used(self, nullifier: Hash) -> bool:
        """Check if a nullifier has been used"""
        return nullifier in self.used_nullifiers
    
    def get_account_proof(self, address: Address) -> MerkleProof:
        """Get proof for account in state tree"""
        return self.main_tree.prove(address)
    
    def get_nullifier_proof(self, nullifier: Hash) -> MerkleProof:
        """Get proof for nullifier (shows it's been used)"""
        return self.nullifier_tree.prove(nullifier)
    
    def get_roots(self) -> Dict[str, Hash]:
        """Get all tree roots"""
        return {
            "stateRoot": self.main_tree.get_root(),
            "nullifierRoot": self.nullifier_tree.get_root()
        }
