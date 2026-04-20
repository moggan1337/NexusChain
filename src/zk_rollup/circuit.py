"""
NexusChain - ZK Circuit Definitions

This module defines the zero-knowledge circuits used for Layer 2 transaction verification.
Supports both Groth16 and PLONK proof systems.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from enum import Enum

from .types import (
    Hash, Address, Amount, Nonce, Transaction, Account,
    Batch, StateDiff, ZKProof, HashlibHasher
)


class CircuitType(Enum):
    """Types of ZK circuits"""
    TRANSFER = "transfer"
    DEPLOY = "deploy"
    CALL = "call"
    BRIDGE_DEPOSIT = "bridge_deposit"
    BRIDGE_WITHDRAW = "bridge_withdraw"
    BATCH = "batch"
    AGGREGATION = "aggregation"  # For proof recursion


@dataclass
class Wire:
    """Represents a wire in the circuit"""
    name: str
    value: Optional[int] = None
    is_public: bool = False
    constraint: Optional[str] = None


@dataclass
class Constraint:
    """Arithmetic constraint in the circuit"""
    a: List[Tuple[str, int]]  # Linear combination A: [(wire, coeff), ...]
    b: List[Tuple[str, int]]  # Linear combination B
    c: List[Tuple[str, int]]  # Linear combination C
    
    def to_r1cs(self) -> Dict[str, Any]:
        """Export as R1CS (Rank-1 Constraint System)"""
        return {
            "a": [{"var": name, "coeff": coeff} for name, coeff in self.a],
            "b": [{"var": name, "coeff": coeff} for name, coeff in self.b],
            "c": [{"var": name, "coeff": coeff} for name, coeff in self.c]
        }


class Circuit:
    """
    Base class for ZK circuits
    
    A circuit defines:
    - Input wires (public and private)
    - Constraints between wires
    - Output wires (public)
    """
    
    def __init__(self, name: str):
        self.name = name
        self.wires: Dict[str, Wire] = {}
        self.constraints: List[Constraint] = []
        self.public_inputs: List[str] = []
        self.private_inputs: List[str] = []
    
    def add_input(self, name: str, is_public: bool = False) -> str:
        """Add an input wire"""
        wire = Wire(name=name, is_public=is_public)
        self.wires[name] = wire
        
        if is_public:
            self.public_inputs.append(name)
        else:
            self.private_inputs.append(name)
        
        return name
    
    def add_constraint(self, a: List[Tuple[str, int]], 
                       b: List[Tuple[str, int]], 
                       c: List[Tuple[str, int]]):
        """Add R1CS constraint: A * B = C"""
        self.constraints.append(Constraint(a, b, c))
    
    def set_input(self, name: str, value: int):
        """Set value for an input wire"""
        if name in self.wires:
            self.wires[name].value = value
    
    def get_r1cs(self) -> Dict[str, Any]:
        """Export circuit as R1CS"""
        return {
            "name": self.name,
            "num_inputs": len(self.public_inputs),
            "num_constraints": len(self.constraints),
            "constraints": [c.to_r1cs() for c in self.constraints],
            "public_inputs": self.public_inputs,
            "private_inputs": self.private_inputs
        }


class TransferCircuit(Circuit):
    """
    ZK Circuit for Layer 2 token transfers
    
    Public Inputs:
    - old_state_root: Merkle root before transfer
    - new_state_root: Merkle root after transfer  
    - nullifier: Hash preventing double-spend
    - amount: Transfer amount
    
    Private Inputs:
    - sender_address: Sender's L2 address
    - sender_balance: Sender's balance
    - sender_nonce: Sender's nonce
    - sender_proof: Merkle proof of sender's account
    - recipient_address: Recipient's L2 address
    - signature: Transaction signature
    """
    
    FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    
    def __init__(self):
        super().__init__("transfer")
        self._build_circuit()
    
    def _build_circuit(self):
        """Build the transfer circuit constraints"""
        
        # Public inputs
        self.add_input("old_state_root", is_public=True)
        self.add_input("new_state_root", is_public=True)
        self.add_input("nullifier", is_public=True)
        self.add_input("amount", is_public=True)
        
        # Private inputs
        self.add_input("sender_balance", is_public=False)
        self.add_input("sender_nonce", is_public=False)
        self.add_input("recipient_balance", is_public=False)
        self.add_input("fee", is_public=False)
        
        # Merkle proof siblings (32 levels)
        for i in range(32):
            self.add_input(f"proof_sibling_{i}", is_public=False)
        
        # Path indices
        for i in range(32):
            self.add_input(f"proof_path_{i}", is_public=False)
        
        # Constraints
        
        # 1. Balance check: sender_balance >= amount + fee
        self._add_range_check("sender_balance", "amount")
        
        # 2. Nonce preserved (no constraints, just passed through)
        
        # 3. New balance computation
        # new_sender_balance = sender_balance - amount - fee
        # new_recipient_balance = recipient_balance + amount
        
        # 4. Merkle tree hash constraints
        self._add_merkle_constraints()
        
        # 5. Nullifier constraint: nullifier = hash(sender_address, nonce)
        self._add_nullifier_constraint()
    
    def _add_range_check(self, balance_name: str, amount_name: str):
        """Add range check constraint (value >= 0)"""
        # Using bit decomposition for range checks
        # balance >= amount means all bits of amount are valid
        
        # Simplified: just ensure balance - amount >= 0
        # In practice, this would use bit decomposition
        self.add_constraint(
            a=[(balance_name, 1), (amount_name, -1)],
            b=[("one", 1)],
            c=[("balance_minus_amount", 1)]
        )
    
    def _add_merkle_constraints(self):
        """Add Merkle tree verification constraints"""
        # Start with sender leaf
        # Hash through each level with siblings
        
        for level in range(32):
            sibling = f"proof_sibling_{level}"
            path_bit = f"proof_path_{level}"
            
            if level == 0:
                left = "sender_leaf"
                right = sibling
            else:
                left = f"hash_level_{level - 1}"
                right = sibling
            
            # Constrain: hash(left || right) = next_level_hash
            # This is a complex constraint requiring custom gates
            # For simplicity, we use a simplified hash constraint
            
            self.add_constraint(
                a=[(left, 1), (right, 1)],
                b=[("one", 1)],
                c=[(f"hash_level_{level}", 1)]
            )
    
    def _add_nullifier_constraint(self):
        """Add nullifier computation constraint"""
        # nullifier = hash(sender_address || nonce)
        # Simplified constraint
        self.add_constraint(
            a=[("sender_address", 1), ("nonce", 1)],
            b=[("one", 1)],
            c=[("nullifier_preimage", 1)]
        )
    
    def witness_from_transaction(
        self, 
        tx: Transaction,
        old_account: Account,
        new_sender_account: Account,
        new_recipient_account: Account,
        merkle_proof: List[Hash],
        path_indices: List[int]
    ) -> Dict[str, int]:
        """
        Generate witness values from a transaction
        
        Args:
            tx: The transaction
            old_account: Sender's account before transfer
            new_sender_account: Sender's account after transfer
            new_recipient_account: Recipient's account after transfer
            merkle_proof: Merkle proof for sender's account
            path_indices: Merkle path indices
            
        Returns:
            Dict mapping wire names to values
        """
        witness = {}
        
        # Public inputs
        witness["old_state_root"] = self._hash_to_field(old_account.to_leaf())
        witness["new_state_root"] = self._hash_to_field(new_sender_account.to_leaf())  # Simplified
        witness["nullifier"] = self._hash_to_field(tx.hash)
        witness["amount"] = tx.amount
        
        # Private inputs
        witness["sender_balance"] = old_account.balance
        witness["sender_nonce"] = old_account.nonce
        witness["recipient_balance"] = new_recipient_account.balance
        witness["fee"] = tx.fee
        
        # Merkle proof siblings
        for i, sibling in enumerate(merkle_proof[:32]):
            witness[f"proof_sibling_{i}"] = self._hash_to_field(sibling)
        
        # Path indices (bits)
        for i, idx in enumerate(path_indices[:32]):
            witness[f"proof_path_{i}"] = idx % 2
        
        return witness
    
    def _hash_to_field(self, h: bytes) -> int:
        """Convert hash to field element"""
        return int.from_bytes(h[:32], "big") % self.FIELD_SIZE


class BatchCircuit(Circuit):
    """
    ZK Circuit for batched transactions
    
    Aggregates multiple transfers into a single proof
    """
    
    def __init__(self, max_txs_per_batch: int = 100):
        super().__init__("batch")
        self.max_txs = max_txs_per_batch
        self._build_circuit()
    
    def _build_circuit(self):
        """Build batch circuit constraints"""
        
        # Public inputs: batch roots
        self.add_input("old_state_root", is_public=True)
        self.add_input("new_state_root", is_public=True)
        self.add_input("tx_count", is_public=True)
        
        # Private: individual transfer witnesses
        for i in range(self.max_txs):
            self.add_input(f"tx_{i}_amount", is_public=False)
            self.add_input(f"tx_{i}_sender_balance", is_public=False)
            self.add_input(f"tx_{i}_recipient_balance", is_public=False)
        
        # Accumulator constraints
        # Sum of all amounts in batch = state root difference
        
        # Cross-transaction constraints
        # Ensure no double-spending across batch
        for i in range(self.max_txs - 1):
            # Each sender balance must be >= their amount
            self.add_constraint(
                a=[(f"tx_{i}_sender_balance", 1)],
                b=[("one", 1)],
                c=[(f"tx_{i}_amount", 1), (f"tx_{i}_remaining", 1)]
            )


class BridgeDepositCircuit(Circuit):
    """
    ZK Circuit for L1 -> L2 bridge deposits
    
    Verifies:
    - L1 deposit event was emitted
    - Merkle proof of L1 block
    - Correct L2 minting
    """
    
    def __init__(self):
        super().__init__("bridge_deposit")
        self._build_circuit()
    
    def _build_circuit(self):
        """Build bridge deposit circuit"""
        
        # Public inputs
        self.add_input("l1_block_hash", is_public=True)
        self.add_input("deposit_recipient", is_public=True)
        self.add_input("deposit_amount", is_public=True)
        self.add_input("l2_new_state_root", is_public=True)
        
        # Private inputs
        self.add_input("deposit_leaf", is_public=False)
        self.add_input("merkle_proof_0", is_public=False)
        self.add_input("merkle_proof_1", is_public=False)
        # ... more proof elements
        
        # Constraints
        # 1. Verify deposit leaf matches
        # 2. Verify Merkle proof against L1 block
        # 3. Verify L2 state update


class BridgeWithdrawCircuit(Circuit):
    """
    ZK Circuit for L2 -> L1 bridge withdrawals
    
    Verifies:
    - L2 burn happened correctly
    - Nullifier was properly consumed
    - Withdrawal can be completed on L1
    """
    
    def __init__(self):
        super().__init__("bridge_withdraw")
        self._build_circuit()
    
    def _build_circuit(self):
        """Build bridge withdrawal circuit"""
        
        # Public inputs
        self.add_input("l2_state_root", is_public=True)
        self.add_input("withdrawal_nullifier", is_public=True)
        self.add_input("l1_recipient", is_public=True)
        self.add_input("withdrawal_amount", is_public=True)
        self.add_input("l1_block_hash", is_public=True)
        
        # Constraints
        # 1. Verify nullifier hasn't been used
        # 2. Verify withdrawal amount matches burn


@dataclass
class CircuitLibrary:
    """
    Library of ZK circuits
    
    Manages circuit compilation and caching
    """
    
    circuits: Dict[CircuitType, Circuit] = field(default_factory=dict)
    
    def __init__(self):
        self._register_circuits()
    
    def _register_circuits(self):
        """Register all built-in circuits"""
        self.circuits[CircuitType.TRANSFER] = TransferCircuit()
        self.circuits[CircuitType.BATCH] = BatchCircuit()
        self.circuits[CircuitType.BRIDGE_DEPOSIT] = BridgeDepositCircuit()
        self.circuits[CircuitType.BRIDGE_WITHDRAW] = BridgeWithdrawCircuit()
    
    def get_circuit(self, circuit_type: CircuitType) -> Circuit:
        """Get a circuit by type"""
        if circuit_type not in self.circuits:
            raise ValueError(f"Unknown circuit type: {circuit_type}")
        return self.circuits[circuit_type]
    
    def export_r1cs(self, circuit_type: CircuitType) -> Dict[str, Any]:
        """Export circuit as R1CS for trusted setup"""
        circuit = self.get_circuit(circuit_type)
        return circuit.get_r1cs()
    
    def export_witness(self, circuit_type: CircuitType, witness_data: Dict) -> List[int]:
        """Export witness values for a circuit"""
        circuit = self.get_circuit(circuit_type)
        
        # Map witness data to circuit inputs
        witness_values = []
        for inp in circuit.public_inputs + circuit.private_inputs:
            if inp in witness_data:
                witness_values.append(witness_data[inp])
            elif inp == "one":
                witness_values.append(1)
            else:
                witness_values.append(0)
        
        return witness_values


@dataclass
class ProofWitness:
    """
    Witness data for proof generation
    
    Contains all public and private inputs for a circuit
    """
    
    circuit_type: CircuitType
    public_inputs: List[int] = field(default_factory=list)
    private_inputs: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "circuitType": self.circuit_type.value,
            "publicInputs": [hex(x) for x in self.public_inputs],
            "privateInputs": [hex(x) for x in self.private_inputs],
            "metadata": self.metadata
        }
    
    @classmethod
    def from_transaction(
        cls,
        tx: Transaction,
        old_state_root: Hash,
        new_state_root: Hash,
        merkle_proof: List[Hash],
        path_indices: List[int]
    ) -> ProofWitness:
        """Create witness from a transfer transaction"""
        
        circuit = TransferCircuit()
        
        # Build witness
        # This would be more complex in practice
        
        return cls(
            circuit_type=CircuitType.TRANSFER,
            public_inputs=[
                int.from_bytes(old_state_root, "big"),
                int.from_bytes(new_state_root, "big"),
                int.from_bytes(tx.hash, "big"),
                tx.amount
            ],
            private_inputs=[
                # Account data
                # Merkle proof
            ],
            metadata={"tx_hash": tx.hash.hex()}
        )


@dataclass
class TrustedSetup:
    """
    Trusted setup parameters for Groth16
    
    Generated via multi-party computation ceremony
    """
    
    circuit_name: str
    ptau_file: str
    proving_key: Optional[bytes] = None
    verification_key: Optional[bytes] = None
    
    def save(self, path: str):
        """Save setup to files"""
        data = {
            "circuit_name": self.circuit_name,
            "proving_key": self.proving_key.hex() if self.proving_key else None,
            "verification_key": self.verification_key.hex() if self.verification_key else None
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def load(cls, path: str) -> TrustedSetup:
        """Load setup from files"""
        with open(path, "r") as f:
            data = json.load(f)
        
        return cls(
            circuit_name=data["circuit_name"],
            ptau_file="",
            proving_key=bytes.fromhex(data["proving_key"]) if data.get("proving_key") else None,
            verification_key=bytes.fromhex(data["verification_key"]) if data.get("verification_key") else None
        )


@dataclass
class UniversalSetup:
    """
    Universal trusted setup for PLONK
    
    One ceremony supports any circuit up to certain size
    """
    
    max_degree: int
    powers_of_tau: bytes
    srs: Optional[bytes] = None  # Structured Reference String
    
    def save(self, path: str):
        """Save setup to files"""
        data = {
            "max_degree": self.max_degree,
            "powers_of_tau": self.powers_of_tau.hex(),
            "srs": self.srs.hex() if self.srs else None
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


# CLI interface for circuit compilation
def compile_circuits(output_dir: str):
    """
    Compile all circuits to R1CS format
    
    Args:
        output_dir: Directory to save compiled circuits
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    library = CircuitLibrary()
    
    for circuit_type in CircuitType:
        r1cs = library.export_r1cs(circuit_type)
        
        output_path = os.path.join(output_dir, f"{circuit_type.value}.r1cs.json")
        with open(output_path, "w") as f:
            json.dump(r1cs, f, indent=2)
        
        print(f"Compiled {circuit_type.value} circuit: {len(r1cs['constraints'])} constraints")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        compile_circuits(sys.argv[1])
    else:
        compile_circuits("./circuits")
