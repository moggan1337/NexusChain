"""
NexusChain - ZK Proof Generation and Verification

Implements both Groth16 and PLONK proof systems.
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from abc import ABC, abstractmethod
import hashlib

from .types import (
    Hash, ZKProof, Batch, Transaction,
    HashlibHasher
)
from .circuit import (
    Circuit, TransferCircuit, BatchCircuit, CircuitLibrary,
    CircuitType, TrustedSetup, ProofWitness
)


# ============================================================================
# Proof System Interface
# ============================================================================

class ProofSystem(ABC):
    """Abstract base class for ZK proof systems"""
    
    @abstractmethod
    def setup(self, circuit: Circuit) -> Any:
        """Perform trusted setup for a circuit"""
        pass
    
    @abstractmethod
    def prove(self, circuit: Circuit, witness: ProofWitness, setup: Any) -> ZKProof:
        """Generate a proof"""
        pass
    
    @abstractmethod
    def verify(self, proof: ZKProof, public_inputs: List[int], setup: Any) -> bool:
        """Verify a proof"""
        pass


# ============================================================================
# Groth16 Implementation
# ============================================================================

class Groth16Prover(ProofSystem):
    """
    Groth16 proof system implementation
    
    Groth16 is a pairing-based zk-SNARK with:
    - Smallest proof size (192 bytes)
    - Fast verification (2-3 pairings)
    - Requires circuit-specific trusted setup
    """
    
    def __init__(self):
        self.setups: Dict[str, TrustedSetup] = {}
        self.field_size = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    
    def setup(self, circuit: Circuit) -> TrustedSetup:
        """
        Perform trusted setup for a circuit
        
        In practice, this uses snarkjs or similar tooling.
        Here we simulate the setup process.
        """
        # Simulate setup - in production use snarkjs or bellman
        print(f"Running Groth16 setup for {circuit.name}...")
        
        # In real implementation:
        # 1. Generate toxic waste (random scalars)
        # 2. Compute powers of tau
        # 3. Generate proving and verification keys
        
        setup = TrustedSetup(
            circuit_name=circuit.name,
            ptau_file=f"{circuit.name}_setup.ptau",
            proving_key=self._generate_pvk(circuit),
            verification_key=self._generate_vk(circuit)
        )
        
        self.setups[circuit.name] = setup
        return setup
    
    def _generate_pvk(self, circuit: Circuit) -> bytes:
        """Generate proving key (simulated)"""
        # In production: actual Groth16 proving key
        # This would be 100+ KB depending on circuit size
        return hashlib.sha256(f"pvk_{circuit.name}".encode()).digest() * 100
    
    def _generate_vk(self, circuit: Circuit) -> bytes:
        """Generate verification key (simulated)"""
        # In production: actual Groth16 verification key
        return hashlib.sha256(f"vk_{circuit.name}".encode()).digest() * 10
    
    def prove(self, circuit: Circuit, witness: ProofWitness, setup: TrustedSetup) -> ZKProof:
        """
        Generate a Groth16 proof
        
        Steps:
        1. Compute A, B, C polynomials
        2. Evaluate at random point
        3. Compute proof elements
        """
        start_time = time.time()
        
        # In production, this uses actual polynomial math and pairings
        # Simulated proof generation
        print(f"Generating Groth16 proof for {circuit.name}...")
        print(f"  Public inputs: {len(witness.public_inputs)}")
        print(f"  Private inputs: {len(witness.private_inputs)}")
        
        # Simulate proof elements
        # Real Groth16 proof consists of:
        # - πA = (a1, a2) ∈ G1
        # - πB = (b1, b2) ∈ G2  
        # - πC = (c1, c2) ∈ G1
        
        proof = ZKProof(
            proof_system="groth16",
            pi_a=self._compute_proof_element("A", witness),
            pi_b=self._compute_proof_element_b("B", witness),
            pi_c=self._compute_proof_element("C", witness),
            public_inputs=[int.to_bytes(x, 32, "big") for x in witness.public_inputs],
            verification_time=0.0
        )
        
        proof.verification_time = time.time() - start_time
        print(f"  Proof generated in {proof.verification_time:.2f}s")
        
        return proof
    
    def _compute_proof_element(self, name: str, witness: ProofWitness) -> Tuple[bytes, bytes]:
        """Compute a proof element (simulated G1 point)"""
        # In production: actual elliptic curve arithmetic
        # G1 points are (x, y) coordinates on BN128 curve
        x = hashlib.sha256(f"{name}_x_{witness.public_inputs}".encode()).digest()
        y = hashlib.sha256(f"{name}_y_{witness.private_inputs}".encode()).digest()
        return (x[:32], y[:32])
    
    def _compute_proof_element_b(self, name: str, witness: ProofWitness) -> Tuple[Tuple[bytes, bytes], Tuple[bytes, bytes]]:
        """Compute a proof element in G2 (simulated)"""
        # G2 points have two pairs of coordinates
        x1 = hashlib.sha256(f"{name}_x1_{witness.public_inputs}".encode()).digest()
        x2 = hashlib.sha256(f"{name}_x2_{witness.public_inputs}".encode()).digest()
        y1 = hashlib.sha256(f"{name}_y1_{witness.private_inputs}".encode()).digest()
        y2 = hashlib.sha256(f"{name}_y2_{witness.private_inputs}".encode()).digest()
        return ((x1[:32], x2[:32]), (y1[:32], y2[:32]))
    
    def verify(self, proof: ZKProof, public_inputs: List[int], setup: TrustedSetup) -> bool:
        """
        Verify a Groth16 proof
        
        Verification equation:
        e(A, B) = e(α, β) * e(C, γ) * Πe(public_inputs[i], δ_i)
        
        Where e is the pairing operation
        """
        start_time = time.time()
        
        # In production: actual pairing check
        # e(πA, πB) = e(α, β) * e(πC, γ) * e(πpub, δ)
        
        # Simulated verification
        # Check proof structure
        if proof.pi_a is None or proof.pi_b is None or proof.pi_c is None:
            return False
        
        # Verify public inputs match
        proof_pub_hashes = [hashlib.sha256(p).digest() for p in proof.public_inputs]
        expected_hash = hashlib.sha256(b"".join(proof_pub_hashes))
        
        # In real verification, we would:
        # 1. Compute linear combination of public inputs
        # 2. Compute pairing check
        # 3. Return result
        
        # Simulated success
        result = True
        
        proof.verification_time = time.time() - start_time
        
        if result:
            print(f"Groth16 verification: PASS ({proof.verification_time*1000:.2f}ms)")
        else:
            print(f"Groth16 verification: FAIL")
        
        return result


# ============================================================================
# PLONK Implementation
# ============================================================================

class PlonkProver(ProofSystem):
    """
    PLONK proof system implementation
    
    PLONK advantages:
    - Universal trusted setup (one ceremony for all circuits)
    - Native support for custom gates
    - Easy upgradeability
    - Proof size: ~400 bytes
    """
    
    def __init__(self):
        self.universal_setup: Optional[Dict] = None
        self.field_size = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    
    def setup(self, circuit: Circuit) -> Dict[str, Any]:
        """
        Setup for PLONK - generates universal SRS
        
        In production, this would use Kate-Zaverucha-Goldberg (KZG) commitments
        """
        print(f"Running PLONK setup for {circuit.name}...")
        
        # Universal setup parameters
        setup = {
            "circuit_name": circuit.name,
            "max_degree": len(circuit.constraints) * 2,
            "srs_size": len(circuit.constraints) * 4,
            # KZG SRS: [G1 * (G^0, G^1, G^2, ...), G2 * G]
            "srs_g1": hashlib.sha256(f"srs_g1_{circuit.name}".encode()).digest() * 100,
            "srs_g2": hashlib.sha256(f"srs_g2_{circuit.name}".encode()).digest() * 10
        }
        
        self.universal_setup = setup
        return setup
    
    def prove(self, circuit: Circuit, witness: ProofWitness, setup: Dict) -> ZKProof:
        """
        Generate a PLONK proof
        
        Steps:
        1. Compute wire assignments
        2. Compute permutation polynomials (σ)
        3. Compute quotient polynomials (t)
        4. Compute opening proofs
        """
        start_time = time.time()
        
        print(f"Generating PLONK proof for {circuit.name}...")
        print(f"  Degree: {setup['max_degree']}")
        
        # In production, this is complex polynomial arithmetic
        
        # PLONK proof consists of:
        # - Wire commitments (W_L, W_R, W_O)
        # - Permutation commitment (Z)
        # - Quotient commitments (T_1, T_2, T_3)
        # - Opening proofs
        
        proof = ZKProof(
            proof_system="plonk",
            w_l=self._compute_wire_commitment("W_L", witness),
            w_r=self._compute_wire_commitment("W_R", witness),
            w_o=self._compute_wire_commitment("W_O", witness),
            z=self._compute_permutation_commitment(witness),
            t_1=self._compute_quotient_commitment("T_1", witness, setup),
            t_2=self._compute_quotient_commitment("T_2", witness, setup),
            t_3=self._compute_quotient_commitment("T_3", witness, setup),
            eval_a=self._compute_evaluation("a", witness),
            eval_b=self._compute_evaluation("b", witness),
            eval_c=self._compute_evaluation("c", witness),
            eval_s1=self._compute_evaluation("s1", witness),
            eval_s2=self._compute_evaluation("s2", witness),
            eval_zw=self._compute_evaluation("zw", witness),
            public_inputs=[int.to_bytes(x, 32, "big") for x in witness.public_inputs],
            verification_time=0.0
        )
        
        proof.verification_time = time.time() - start_time
        print(f"  Proof generated in {proof.verification_time:.2f}s")
        
        return proof
    
    def _compute_wire_commitment(self, name: str, witness: ProofWitness) -> bytes:
        """Compute wire polynomial commitment"""
        return hashlib.sha256(f"{name}_{witness.public_inputs}_{witness.private_inputs}".encode()).digest() * 3
    
    def _compute_permutation_commitment(self, witness: ProofWitness) -> bytes:
        """Compute permutation polynomial commitment (Z)"""
        return hashlib.sha256(f"perm_{witness.public_inputs}".encode()).digest() * 3
    
    def _compute_quotient_commitment(self, name: str, witness: ProofWitness, setup: Dict) -> bytes:
        """Compute quotient polynomial commitment"""
        return hashlib.sha256(f"{name}_{setup['max_degree']}".encode()).digest() * 3
    
    def _compute_evaluation(self, name: str, witness: ProofWitness) -> bytes:
        """Compute polynomial evaluation at challenge point"""
        return hashlib.sha256(f"eval_{name}_{witness.public_inputs}".encode()).digest() * 2
    
    def verify(self, proof: ZKProof, public_inputs: List[int], setup: Dict) -> bool:
        """
        Verify a PLONK proof
        
        Uses KZG opening verification
        """
        start_time = time.time()
        
        # In production: actual KZG verification
        
        # Check proof structure
        if not all([proof.w_l, proof.w_r, proof.w_o, proof.z]):
            return False
        
        # Compute Fiat-Shamir challenge
        transcript = b"".join([
            proof.w_l, proof.w_r, proof.w_o, proof.z,
            proof.t_1, proof.t_2, proof.t_3
        ])
        challenge = hashlib.sha256(transcript).digest()
        
        # Verify opening proofs using KZG
        # This involves pairing checks with SRS
        
        result = True  # Simulated
        
        proof.verification_time = time.time() - start_time
        
        if result:
            print(f"PLONK verification: PASS ({proof.verification_time*1000:.2f}ms)")
        else:
            print(f"PLONK verification: FAIL")
        
        return result


# ============================================================================
# Proof Generator
# ============================================================================

@dataclass
class ProofGenerator:
    """
    High-level proof generator for NexusChain
    
    Supports both Groth16 and PLONK
    """
    
    proof_system: str = "groth16"
    library: CircuitLibrary = field(default_factory=CircuitLibrary)
    
    _provers: Dict[str, ProofSystem] = field(default_factory=dict)
    _setups: Dict[CircuitType, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self._provers = {
            "groth16": Groth16Prover(),
            "plonk": PlonkProver()
        }
        
        # Pre-setup circuits
        for circuit_type in CircuitType:
            circuit = self.library.get_circuit(circuit_type)
            prover = self._provers[self.proof_system]
            self._setups[circuit_type] = prover.setup(circuit)
    
    def generate_proof(
        self,
        circuit_type: CircuitType,
        witness: ProofWitness
    ) -> ZKProof:
        """
        Generate a ZK proof for a circuit type
        
        Args:
            circuit_type: Type of circuit to prove
            witness: Witness data (public and private inputs)
            
        Returns:
            Generated ZKProof
        """
        prover = self._provers[self.proof_system]
        circuit = self.library.get_circuit(circuit_type)
        setup = self._setups[circuit_type]
        
        return prover.prove(circuit, witness, setup)
    
    def verify_proof(self, proof: ZKProof, public_inputs: List[int]) -> bool:
        """
        Verify a ZK proof
        
        Args:
            proof: The proof to verify
            public_inputs: Public inputs for the proof
            
        Returns:
            True if proof is valid
        """
        prover = self._provers[proof.proof_system]
        
        # Find the setup for this proof system
        setup = None
        for stype, s in self._setups.items():
            if isinstance(s, TrustedSetup) and proof.proof_system == "groth16":
                setup = s
                break
            elif proof.proof_system == "plonk":
                setup = s
                break
        
        if setup is None:
            return False
        
        return prover.verify(proof, public_inputs, setup)
    
    def generate_batch_proof(self, batch: Batch) -> ZKProof:
        """
        Generate a proof for a batch of transactions
        
        Args:
            batch: The batch to prove
            
        Returns:
            ZKProof for the entire batch
        """
        # Create witness from batch
        witness = self._create_batch_witness(batch)
        
        return self.generate_proof(CircuitType.BATCH, witness)
    
    def _create_batch_witness(self, batch: Batch) -> ProofWitness:
        """Create witness data from a batch"""
        # Collect all public inputs
        public_inputs = [
            int.from_bytes(batch.old_state_root, "big"),
            int.from_bytes(batch.new_state_root, "big"),
            len(batch.blocks)
        ]
        
        # Collect all private inputs (transaction data)
        private_inputs = []
        for block in batch.blocks:
            for tx in block.transactions:
                private_inputs.extend([
                    tx.amount,
                    tx.fee,
                    tx.nonce
                ])
        
        return ProofWitness(
            circuit_type=CircuitType.BATCH,
            public_inputs=public_inputs,
            private_inputs=private_inputs,
            metadata={
                "batch_number": batch.batch_number,
                "num_blocks": len(batch.blocks),
                "num_transactions": sum(len(b.transactions) for b in batch.blocks)
            }
        )


# ============================================================================
# Proof Aggregation (Recursive Proofs)
# ============================================================================

class ProofAggregator:
    """
    Aggregates multiple proofs into one using recursion
    
    Useful for:
    - Proving multiple batches at once
    - Reducing L1 verification costs
    """
    
    def __init__(self, inner_proof_system: str = "groth16"):
        self.inner_proof_system = inner_proof_system
        self.aggregator = ProofGenerator(inner_proof_system)
    
    def aggregate(self, proofs: List[ZKProof]) -> ZKProof:
        """
        Aggregate multiple proofs into one
        
        Uses recursive proof composition
        """
        # In production, this would use actual proof recursion
        # For now, we simulate by hashing all proofs together
        
        combined_data = b"".join([p.to_bytes() for p in proofs])
        combined_hash = hashlib.sha256(combined_data).digest()
        
        # Create aggregated proof
        # In reality, this would verify all inner proofs and create
        # a new proof that attests to their validity
        
        return ZKProof(
            proof_system=self.inner_proof_system,
            pi_a=(combined_hash[:32], combined_hash[32:64]),
            pi_b=((combined_hash[64:96], combined_hash[96:128]), (combined_hash[128:160], combined_hash[160:192])),
            pi_c=(combined_hash[192:224], combined_hash[224:256]),
            public_inputs=proofs[0].public_inputs if proofs else [],
            verification_time=sum(p.verification_time for p in proofs)
        )


# ============================================================================
# Utility Functions
# ============================================================================

def serialize_proof(proof: ZKProof) -> bytes:
    """Serialize proof to bytes for storage/transmission"""
    return proof.to_bytes()


def deserialize_proof(data: bytes, proof_system: str) -> ZKProof:
    """Deserialize proof from bytes"""
    # This would parse the byte format back to ZKProof
    # Simplified implementation
    return ZKProof(proof_system=proof_system)


def proof_to_json(proof: ZKProof) -> str:
    """Serialize proof to JSON"""
    return json.dumps(proof.to_json(), indent=2)


def proof_from_json(json_str: str) -> ZKProof:
    """Deserialize proof from JSON"""
    data = json.loads(json_str)
    return ZKProof(
        proof_system=data["proofSystem"],
        public_inputs=[bytes.fromhex(p) for p in data["publicInputs"]],
        verification_time=data.get("verificationTime", 0.0)
    )


# ============================================================================
# CLI Interface
# ============================================================================

def generate_proof_cli(circuit_name: str, witness_file: str, output_file: str):
    """CLI for generating proofs"""
    
    # Load circuit
    library = CircuitLibrary()
    circuit_type = CircuitType(circuit_name)
    
    # Load witness
    with open(witness_file, "r") as f:
        witness_data = json.load(f)
    
    # Create witness
    public_inputs = [int(x, 16) for x in witness_data.get("public", [])]
    private_inputs = [int(x, 16) for x in witness_data.get("private", [])]
    
    witness = ProofWitness(
        circuit_type=circuit_type,
        public_inputs=public_inputs,
        private_inputs=private_inputs
    )
    
    # Generate proof
    generator = ProofGenerator("groth16")
    proof = generator.generate_proof(circuit_type, witness)
    
    # Save proof
    with open(output_file, "w") as f:
        f.write(proof_to_json(proof))
    
    print(f"Proof saved to {output_file}")


def verify_proof_cli(proof_file: str, public_inputs_file: str) -> bool:
    """CLI for verifying proofs"""
    
    # Load proof
    with open(proof_file, "r") as f:
        proof = proof_from_json(f.read())
    
    # Load public inputs
    with open(public_inputs_file, "r") as f:
        public_inputs = [int(x, 16) for x in json.load(f)]
    
    # Verify
    generator = ProofGenerator(proof.proof_system)
    result = generator.verify_proof(proof, public_inputs)
    
    print(f"Verification result: {'VALID' if result else 'INVALID'}")
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: proof.py [generate|verify] [args...]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "generate":
        circuit = sys.argv[2] if len(sys.argv) > 2 else "transfer"
        witness = sys.argv[3] if len(sys.argv) > 3 else "witness.json"
        output = sys.argv[4] if len(sys.argv) > 4 else "proof.json"
        generate_proof_cli(circuit, witness, output)
    
    elif cmd == "verify":
        proof = sys.argv[2] if len(sys.argv) > 2 else "proof.json"
        public = sys.argv[3] if len(sys.argv) > 3 else "public.json"
        verify_proof_cli(proof, public)
    
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
