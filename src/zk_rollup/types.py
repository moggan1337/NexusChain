"""
NexusChain - Layer 2 ZK-Rollup Types and Data Structures

This module defines the core types used throughout the NexusChain system.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
import rlp
from rlp.sedes import (
    big_endian_int,
    binary,
    List as RLPList,
    Binary
)

# ============================================================================
# Basic Types
# ============================================================================

Address = bytes  # 20 bytes
Hash = bytes  # 32 bytes
Signature = bytes  # 65 bytes (r, s, v)
PublicKey = bytes  # 64 bytes
PrivateKey = bytes  # 32 bytes
Amount = int
Nonce = int
Gas = int
GasPrice = int
Timestamp = int
BlockNumber = int


class HashlibHasher:
    """Hash function using keccak256 (Ethereum's hash function)"""
    
    @staticmethod
    def keccak256(data: bytes) -> bytes:
        """Ethereum's keccak256 hash function"""
        return hashlib.sha3_256(data).digest()
    
    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Hash two values together (for Merkle trees)"""
        return HashlibHasher.keccak256(left + right)


# ============================================================================
# Transaction Types
# ============================================================================

class TransactionType(Enum):
    """Layer 2 transaction types"""
    TRANSFER = 0x00
    DEPLOY_CONTRACT = 0x01
    CALL_CONTRACT = 0x02
    CREATE_ACCOUNT = 0x03
    MINT = 0x04
    BURN = 0x05
    BRIDGE_DEPOSIT = 0x10
    BRIDGE_WITHDRAW = 0x11
    DELEGATE = 0x20
    STAKE = 0x21
    UNSTAKE = 0x22


@dataclass
class Transaction:
    """
    Layer 2 transaction structure
    
    For ZK circuits, we need:
    - Public inputs: sender, recipient, amount, nonce, hash
    - Private inputs: signature, chain_id
    """
    transaction_type: TransactionType
    sender: Address
    recipient: Address
    amount: Amount
    fee: Amount
    nonce: Nonce
    data: bytes = b""
    chain_id: int = 1337
    signature: Optional[Signature] = None
    
    # Computed fields
    _hash: Optional[Hash] = field(default=None, repr=False)
    
    def __post_init__(self):
        if self._hash is None:
            self._hash = self.compute_hash()
    
    @property
    def hash(self) -> Hash:
        return self._hash
    
    def compute_hash(self) -> Hash:
        """Compute transaction hash (used as nullifier)"""
        tx_data = rlp.encode([
            self.transaction_type.value,
            self.sender,
            self.recipient,
            big_endian_int.serialize(self.amount),
            big_endian_int.serialize(self.fee),
            big_endian_int.serialize(self.nonce),
            self.data,
            big_endian_int.serialize(self.chain_id)
        ])
        return HashlibHasher.keccak256(tx_data)
    
    def sign(self, private_key: PrivateKey) -> Transaction:
        """Sign this transaction"""
        from eth_keys import keys
        from eth_utils import keccak
        
        # Sign the transaction hash
        msg_hash = self.compute_hash()
        pk = keys.PrivateKey(private_key)
        signature = pk.sign_msg_hash(msg_hash)
        
        return Transaction(
            transaction_type=self.transaction_type,
            sender=self.sender,
            recipient=self.recipient,
            amount=self.amount,
            fee=self.fee,
            nonce=self.nonce,
            data=self.data,
            chain_id=self.chain_id,
            signature=signature.to_bytes(),
            _hash=self._hash
        )
    
    def verify_signature(self) -> bool:
        """Verify transaction signature"""
        from eth_keys import keys
        from eth_utils import keccak
        
        if self.signature is None:
            return False
        
        msg_hash = self.compute_hash()
        pk = keys.PublicKey.from_signature_and_hash(self.signature, msg_hash)
        recovered_sender = pk.to_checksum_address()
        
        return recovered_sender == self.sender.hex()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "type": self.transaction_type.name,
            "sender": self.sender.hex(),
            "recipient": self.recipient.hex(),
            "amount": str(self.amount),
            "fee": str(self.fee),
            "nonce": self.nonce,
            "data": self.data.hex(),
            "chainId": self.chain_id,
            "hash": self.hash.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Transaction:
        """Create from dictionary"""
        return cls(
            transaction_type=TransactionType[data["type"]],
            sender=bytes.fromhex(data["sender"].replace("0x", "")),
            recipient=bytes.fromhex(data["recipient"].replace("0x", "")),
            amount=int(data["amount"]),
            fee=int(data["fee"]),
            nonce=int(data["nonce"]),
            data=bytes.fromhex(data["data"].replace("0x", "")),
            chain_id=int(data["chainId"]),
            _hash=bytes.fromhex(data["hash"].replace("0x", ""))
        )
    
    def get_public_inputs(self) -> List[bytes]:
        """Get public inputs for ZK circuit"""
        return [
            self.sender,
            self.recipient,
            big_endian_int.serialize(self.amount),
            big_endian_int.serialize(self.nonce),
            self.hash
        ]
    
    def get_private_inputs(self) -> Dict[str, bytes]:
        """Get private inputs for ZK circuit"""
        return {
            "signature": self.signature or b"",
            "chain_id": big_endian_int.serialize(self.chain_id)
        }


@dataclass
class Account:
    """
    Layer 2 account state
    
    Stored in the Merkle tree
    """
    address: Address
    balance: Amount = 0
    nonce: Nonce = 0
    code_hash: Hash = b"\x00" * 32
    storage_root: Hash = b"\x00" * 32
    
    def to_leaf(self) -> bytes:
        """Convert to Merkle tree leaf"""
        return HashlibHasher.keccak256(rlp.encode([
            self.address,
            big_endian_int.serialize(self.balance),
            big_endian_int.serialize(self.nonce),
            self.code_hash,
            self.storage_root
        ]))
    
    @classmethod
    def from_leaf(cls, address: Address, leaf: bytes) -> Account:
        """Create from Merkle tree leaf"""
        data = rlp.decode(leaf)
        return cls(
            address=address,
            balance=big_endian_int.deserialize(data[1]),
            nonce=big_endian_int.deserialize(data[2]),
            code_hash=data[3],
            storage_root=data[4]
        )


# ============================================================================
# Block Types
# ============================================================================

@dataclass
class BlockHeader:
    """Layer 2 block header"""
    parent_hash: Hash
    block_number: BlockNumber
    timestamp: Timestamp
    state_root: Hash
    tx_root: Hash
    receipt_root: Hash
    gas_used: Gas
    gas_limit: Gas
    proposer: Address
    batch_hash: Hash  # Hash of the ZK batch
    proof_hash: Hash  # Hash of the ZK proof
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "parentHash": self.parent_hash.hex(),
            "blockNumber": self.block_number,
            "timestamp": self.timestamp,
            "stateRoot": self.state_root.hex(),
            "txRoot": self.tx_root.hex(),
            "receiptRoot": self.receipt_root.hex(),
            "gasUsed": self.gas_used,
            "gasLimit": self.gas_limit,
            "proposer": self.proposer.hex(),
            "batchHash": self.batch_hash.hex(),
            "proofHash": self.proof_hash.hex()
        }


@dataclass
class TransactionReceipt:
    """Transaction execution receipt"""
    transaction_hash: Hash
    block_number: BlockNumber
    status: bool  # True if successful
    gas_used: Gas
    logs: List[Dict[str, Any]]
    bloom_filter: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "transactionHash": self.transaction_hash.hex(),
            "blockNumber": self.block_number,
            "status": 1 if self.status else 0,
            "gasUsed": self.gas_used,
            "logs": self.logs
        }


@dataclass 
class Block:
    """Layer 2 block containing transactions"""
    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)
    receipts: List[TransactionReceipt] = field(default_factory=list)
    
    def add_transaction(self, tx: Transaction, receipt: TransactionReceipt):
        self.transactions.append(tx)
        self.receipts.append(receipt)
    
    def compute_tx_root(self) -> Hash:
        """Compute Merkle root of transactions"""
        if not self.transactions:
            return b"\x00" * 32
        
        leaves = [tx.hash for tx in self.transactions]
        return compute_merkle_root(leaves)
    
    def compute_receipt_root(self) -> Hash:
        """Compute Merkle root of receipts"""
        if not self.receipts:
            return b"\x00" * 32
        
        leaves = [HashlibHasher.keccak256(rlp.encode(r.to_dict())) for r in self.receipts]
        return compute_merkle_root(leaves)


# ============================================================================
# Batch and Proof Types
# ============================================================================

@dataclass
class StateDiff:
    """
    State difference for a batch
    
    Records changes to account states
    """
    account: Address
    old_balance: Amount
    new_balance: Amount
    old_nonce: Nonce
    new_nonce: Nonce
    storage_changes: Dict[Hash, Hash]  # slot -> new value
    
    def get_public_inputs(self) -> List[bytes]:
        return [
            self.account,
            big_endian_int.serialize(self.old_balance),
            big_endian_int.serialize(self.new_balance),
            big_endian_int.serialize(self.old_nonce),
            big_endian_int.serialize(self.new_nonce)
        ]


@dataclass
class Batch:
    """
    ZK Rollup batch
    
    Contains blocks and state diffs for proof generation
    """
    batch_number: BlockNumber
    blocks: List[Block] = field(default_factory=list)
    state_diffs: List[StateDiff] = field(default_factory=list)
    old_state_root: Hash = b"\x00" * 32
    new_state_root: Hash = b"\x00" * 32
    signature: Optional[Signature] = None
    
    def add_block(self, block: Block):
        self.blocks.append(block)
    
    def add_state_diff(self, diff: StateDiff):
        self.state_diffs.append(diff)
    
    def finalize(self):
        """Finalize the batch and compute roots"""
        if self.blocks:
            self.new_state_root = self.blocks[-1].header.state_root
        else:
            self.new_state_root = self.old_state_root
    
    def get_public_inputs(self) -> List[bytes]:
        """Get public inputs for ZK proof"""
        return [
            self.old_state_root,
            self.new_state_root,
            big_endian_int.serialize(len(self.blocks)),
            big_endian_int.serialize(sum(len(b.transactions) for b in self.blocks)),
            self.get_commitment()
        ]
    
    def get_commitment(self) -> Hash:
        """Compute batch commitment"""
        data = b"".join([
            big_endian_int.serialize(self.batch_number),
            self.old_state_root,
            self.new_state_root,
            big_endian_int.serialize(len(self.blocks))
        ])
        return HashlibHasher.keccak256(data)


@dataclass
class ZKProof:
    """
    Zero-knowledge proof
    
    Can be Groth16 or PLONK format
    """
    proof_system: str  # "groth16" or "plonk"
    
    # Groth16 proof elements
    pi_a: Optional[Tuple[bytes, bytes]] = None  # (A.x, A.y)
    pi_b: Optional[Tuple[Tuple[bytes, bytes], Tuple[bytes, bytes]]] = None  # ((B.x, B.y), (B.z, B.w))
    pi_c: Optional[Tuple[bytes, bytes]] = None  # (C.x, C.y)
    
    # PLONK proof elements
    w_l: Optional[bytes] = None  # Left wire commitment
    w_r: Optional[bytes] = None  # Right wire commitment  
    w_o: Optional[bytes] = None  # Output wire commitment
    z: Optional[bytes] = None  # Permutation polynomial commitment
    t_1: Optional[bytes] = None  # Quotient polynomial part 1
    t_2: Optional[bytes] = None  # Quotient polynomial part 2
    t_3: Optional[bytes] = None  # Quotient polynomial part 3
    eval_a: Optional[bytes] = None  # Wire A evaluation
    eval_b: Optional[bytes] = None  # Wire B evaluation
    eval_c: Optional[bytes] = None  # Wire C evaluation
    eval_s1: Optional[bytes] = None  # Selector 1 evaluation
    eval_s2: Optional[bytes] = None  # Selector 2 evaluation
    eval_zw: Optional[bytes] = None  # Z * X evaluation
    
    # Verification data
    public_inputs: List[bytes] = field(default_factory=list)
    verification_time: float = 0.0
    
    def to_bytes(self) -> bytes:
        """Serialize proof to bytes"""
        if self.proof_system == "groth16":
            return self._serialize_groth16()
        else:
            return self._serialize_plonk()
    
    def _serialize_groth16(self) -> bytes:
        parts = [
            self.pi_a[0], self.pi_a[1],
            self.pi_b[0][0], self.pi_b[0][1], self.pi_b[1][0], self.pi_b[1][1],
            self.pi_c[0], self.pi_c[1]
        ]
        return b"".join(parts)
    
    def _serialize_plonk(self) -> bytes:
        parts = [
            self.w_l or b"", self.w_r or b"", self.w_o or b"",
            self.z or b"", self.t_1 or b"", self.t_2 or b"", self.t_3 or b"",
            self.eval_a or b"", self.eval_b or b"", self.eval_c or b"",
            self.eval_s1 or b"", self.eval_s2 or b"", self.eval_zw or b""
        ]
        return b"".join(parts)
    
    def to_json(self) -> Dict[str, Any]:
        """Serialize to JSON"""
        return {
            "proofSystem": self.proof_system,
            "publicInputs": [p.hex() for p in self.public_inputs],
            "verificationTime": self.verification_time,
            **self._json_data()
        }
    
    def _json_data(self) -> Dict[str, Any]:
        if self.proof_system == "groth16":
            return {
                "piA": [p.hex() for p in self.pi_a] if self.pi_a else None,
                "piB": [[p.hex() for p in pair] for pair in self.pi_b] if self.pi_b else None,
                "piC": [p.hex() for p in self.pi_c] if self.pi_c else None
            }
        else:
            return {
                "wL": self.w_l.hex() if self.w_l else None,
                "wR": self.w_r.hex() if self.w_r else None,
                "wO": self.w_o.hex() if self.w_o else None,
                "z": self.z.hex() if self.z else None,
                "t1": self.t_1.hex() if self.t_1 else None,
                "t2": self.t_2.hex() if self.t_2 else None,
                "t3": self.t_3.hex() if self.t_3 else None
            }


@dataclass
class WithdrawalProof:
    """
    Proof for L2 -> L1 withdrawal
    
    Allows users to withdraw funds from L2 to L1
    """
    user: Address
    amount: Amount
    l2_tx_hash: Hash
    nullifier: Hash
    merkle_proof: List[Hash]
    withdrawal_receipt: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "user": self.user.hex(),
            "amount": str(self.amount),
            "l2TxHash": self.l2_tx_hash.hex(),
            "nullifier": self.nullifier.hex(),
            "merkleProof": [p.hex() for p in self.merkle_proof]
        }


# ============================================================================
# Bridge Types
# ============================================================================

@dataclass
class Deposit:
    """L1 -> L2 deposit"""
    depositor: Address
    recipient: Address
    amount: Amount
    l1_tx_hash: Hash
    timestamp: Timestamp
    finalized: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "depositor": self.depositor.hex(),
            "recipient": self.recipient.hex(),
            "amount": str(self.amount),
            "l1TxHash": self.l1_tx_hash.hex(),
            "timestamp": self.timestamp,
            "finalized": self.finalized
        }


@dataclass
class Withdrawal:
    """L2 -> L1 withdrawal"""
    user: Address
    recipient: Address
    amount: Amount
    l2_tx_hash: Hash
    l1_tx_hash: Optional[Hash] = None
    proof_submitted: bool = False
    timestamp: Timestamp = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "user": self.user.hex(),
            "recipient": self.recipient.hex(),
            "amount": str(self.amount),
            "l2TxHash": self.l2_tx_hash.hex(),
            "l1TxHash": self.l1_tx_hash.hex() if self.l1_tx_hash else None,
            "proofSubmitted": self.proof_submitted,
            "timestamp": self.timestamp
        }


# ============================================================================
# Utility Functions
# ============================================================================

def compute_merkle_root(leaves: List[bytes]) -> Hash:
    """
    Compute Merkle root from leaves
    
    Args:
        leaves: List of leaf hashes
        
    Returns:
        Merkle root hash
    """
    if not leaves:
        return b"\x00" * 32
    
    # Pad to power of 2
    n = len(leaves)
    if n & (n - 1):
        # Not a power of 2, pad
        next_pow = 1 << (n - 1).bit_length()
        leaves = leaves + [b"\x00" * 32] * (next_pow - n)
    
    # Build tree from bottom up
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            next_level.append(HashlibHasher.hash_pair(left, right))
        current_level = next_level
    
    return current_level[0]


def pad_to_power_of_two(data: List[bytes]) -> List[bytes]:
    """Pad a list to the next power of 2"""
    n = len(data)
    if n == 0:
        return []
    
    next_pow = 1 << (n - 1).bit_length()
    return data + [b"\x00" * 32] * (next_pow - n)


def bytes_to_uint32(value: bytes) -> int:
    """Convert bytes to uint32"""
    return int.from_bytes(value[:4], "big")


def uint32_to_bytes(value: int) -> bytes:
    """Convert uint32 to bytes"""
    return value.to_bytes(4, "big")


def address_to_index(address: Address, depth: int = 32) -> int:
    """Convert address to Merkle tree index"""
    # Use the last 4 bytes of address as index
    index = int.from_bytes(address[-4:], "big")
    return index % (2 ** depth)
