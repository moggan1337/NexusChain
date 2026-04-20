"""
NexusChain - Prover Main Module

Handles proof generation for batches of transactions.
"""

from __future__ import annotations
import time
import json
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from queue import Queue, Empty
import logging

from ..zk_rollup.types import Batch, ZKProof
from ..zk_rollup.proof import ProofGenerator, ProofAggregator, ProofWitness
from ..zk_rollup.circuit import CircuitType, CircuitLibrary


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProverConfig:
    """Prover configuration"""
    proof_system: str = "groth16"  # "groth16" or "plonk"
    batch_size: int = 100  # Transactions per proof
    max_concurrent_proofs: int = 4
    proof_timeout: float = 300.0  # 5 minutes
    cache_dir: str = "./proof_cache"


@dataclass
class ProverState:
    """Current prover state"""
    total_proofs_generated: int = 0
    total_proofs_verified: int = 0
    total_proof_time: float = 0.0
    current_batch: Optional[Batch] = None
    proof_queue_size: int = 0
    
    # Metrics
    avg_proof_time: float = 0.0
    avg_verification_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "totalProofsGenerated": self.total_proofs_generated,
            "totalProofsVerified": self.total_proofs_verified,
            "totalProofTime": f"{self.total_proof_time:.2f}s",
            "avgProofTime": f"{self.avg_proof_time:.2f}s",
            "avgVerificationTime": f"{self.avg_verification_time:.2f}s",
            "currentBatch": self.current_batch.batch_number if self.current_batch else None,
            "proofQueueSize": self.proof_queue_size
        }


class Prover:
    """
    ZK Proof Prover for NexusChain
    
    Responsibilities:
    - Receive batches from sequencer
    - Generate ZK proofs
    - Verify proofs
    - Handle proof aggregation
    """
    
    def __init__(self, config: Optional[ProverConfig] = None):
        self.config = config or ProverConfig()
        
        # Proof generator
        self.generator = ProofGenerator(self.config.proof_system)
        self.aggregator = ProofAggregator(self.config.proof_system)
        
        # State
        self.state = ProverState()
        
        # Batch queue
        self.batch_queue: Queue[Batch] = Queue()
        
        # Pending proofs
        self.pending_proofs: Dict[str, ZKProof] = {}
        self.completed_proofs: List[Tuple[Batch, ZKProof]] = []
        
        # Workers
        self.workers: List[threading.Thread] = []
        self.running = False
        
        # Callbacks
        self.on_proof_ready: Optional[callable] = None
        self.on_proof_verified: Optional[callable] = None
        
        logger.info(f"Prover initialized: system={self.config.proof_system}")
    
    def start(self):
        """Start the prover workers"""
        self.running = True
        
        # Start worker threads
        for i in range(self.config.max_concurrent_proofs):
            worker = threading.Thread(
                target=self._proof_worker,
                name=f"prover-worker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        logger.info(f"Started {self.config.max_concurrent_proofs} prover workers")
    
    def stop(self):
        """Stop the prover workers"""
        self.running = False
        
        for worker in self.workers:
            worker.join(timeout=1.0)
        
        self.workers.clear()
        logger.info("Prover stopped")
    
    def submit_batch(self, batch: Batch):
        """
        Submit a batch for proof generation
        
        Args:
            batch: The batch to prove
        """
        self.batch_queue.put(batch)
        self.state.proof_queue_size = self.batch_queue.qsize()
        
        logger.info(f"Batch {batch.batch_number} submitted: {len(batch.blocks)} blocks")
    
    def _proof_worker(self):
        """Worker thread for proof generation"""
        while self.running:
            try:
                # Get batch from queue with timeout
                try:
                    batch = self.batch_queue.get(timeout=1.0)
                except Empty:
                    continue
                
                self.state.current_batch = batch
                
                # Generate proof
                logger.info(f"Generating proof for batch {batch.batch_number}...")
                start_time = time.time()
                
                proof = self._generate_batch_proof(batch)
                
                proof_time = time.time() - start_time
                self.state.total_proof_time += proof_time
                self.state.avg_proof_time = (
                    self.state.total_proof_time / self.state.total_proofs_generated
                )
                
                # Verify proof
                verified = self._verify_proof(proof, batch)
                
                if verified:
                    self.state.total_proofs_verified += 1
                
                # Store completed proof
                self.completed_proofs.append((batch, proof))
                
                # Update state
                self.state.total_proofs_generated += 1
                self.state.current_batch = None
                self.state.proof_queue_size = self.batch_queue.qsize()
                
                logger.info(
                    f"Proof for batch {batch.batch_number}: "
                    f"time={proof_time:.2f}s verified={verified}"
                )
                
                # Trigger callback
                if self.on_proof_ready and verified:
                    self.on_proof_ready(batch, proof)
                
                self.batch_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in proof worker: {e}")
    
    def _generate_batch_proof(self, batch: Batch) -> ZKProof:
        """
        Generate a ZK proof for a batch
        
        Args:
            batch: The batch to prove
            
        Returns:
            Generated ZKProof
        """
        # Create witness from batch
        witness = self._create_batch_witness(batch)
        
        # Generate proof
        proof = self.generator.generate_batch_proof(batch)
        
        return proof
    
    def _create_batch_witness(self, batch: Batch) -> ProofWitness:
        """Create witness data from a batch"""
        # Collect public inputs
        public_inputs = [
            int.from_bytes(batch.old_state_root, "big"),
            int.from_bytes(batch.new_state_root, "big"),
            len(batch.blocks),
            sum(len(b.transactions) for b in batch.blocks)
        ]
        
        # Collect private inputs (all transaction data)
        private_inputs = []
        for block in batch.blocks:
            for tx in block.transactions:
                private_inputs.extend([
                    tx.amount,
                    tx.fee,
                    tx.nonce,
                    int.from_bytes(tx.sender, "big"),
                    int.from_bytes(tx.recipient, "big")
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
    
    def _verify_proof(self, proof: ZKProof, batch: Batch) -> bool:
        """
        Verify a generated proof
        
        Args:
            proof: The proof to verify
            batch: The batch the proof corresponds to
            
        Returns:
            True if proof is valid
        """
        start_time = time.time()
        
        # Get public inputs
        public_inputs = [int.from_bytes(p, "big") for p in proof.public_inputs]
        
        # Verify
        result = self.generator.verify_proof(proof, public_inputs)
        
        verification_time = time.time() - start_time
        
        # Update metrics
        if self.state.total_proofs_verified > 0:
            current_avg = self.state.avg_verification_time
            n = self.state.total_proofs_verified
            self.state.avg_verification_time = (
                (current_avg * (n - 1) + verification_time) / n
            )
        
        return result
    
    def get_pending_proofs(self) -> List[Tuple[Batch, ZKProof]]:
        """Get list of completed but not yet submitted proofs"""
        return self.completed_proofs.copy()
    
    def get_state(self) -> ProverState:
        """Get current prover state"""
        return self.state
    
    def wait_for_proof(self, batch_number: int, timeout: float = 300.0) -> Optional[ZKProof]:
        """
        Wait for a proof to be generated for a specific batch
        
        Args:
            batch_number: The batch number to wait for
            timeout: Maximum time to wait
            
        Returns:
            The proof if generated, None if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            for batch, proof in self.completed_proofs:
                if batch.batch_number == batch_number:
                    return proof
            
            time.sleep(0.1)
        
        return None
    
    def get_proof_stats(self) -> Dict[str, Any]:
        """Get proof generation statistics"""
        return {
            "proof_system": self.config.proof_system,
            "total_proofs": self.state.total_proofs_generated,
            "verified_proofs": self.state.total_proofs_verified,
            "pending_batches": self.state.proof_queue_size,
            "avg_proof_time": f"{self.state.avg_proof_time:.2f}s",
            "avg_verification_time": f"{self.state.avg_verification_time:.2f}ms",
            "total_time": f"{self.state.total_proof_time:.2f}s"
        }


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for prover"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NexusChain Prover")
    parser.add_argument("--proof-system", choices=["groth16", "plonk"], 
                        default="groth16", help="Proof system to use")
    parser.add_argument("--batch-size", type=int, default=100, 
                        help="Transactions per proof")
    parser.add_argument("--workers", type=int, default=4, 
                        help="Number of concurrent workers")
    
    args = parser.parse_args()
    
    # Create prover
    config = ProverConfig(
        proof_system=args.proof_system,
        batch_size=args.batch_size,
        max_concurrent_proofs=args.workers
    )
    
    prover = Prover(config)
    
    print(f"Starting prover...")
    print(f"Proof system: {args.proof_system}")
    print(f"Workers: {args.workers}")
    print(f"Batch size: {args.batch_size}")
    
    prover.start()
    
    # Keep running
    try:
        while True:
            time.sleep(1)
            print(f"\rProofs: {prover.state.total_proofs_generated}, "
                  f"Verified: {prover.state.total_proofs_verified}, "
                  f"Queue: {prover.state.proof_queue_size}", end="")
    except KeyboardInterrupt:
        print("\nStopping prover...")
        prover.stop()


if __name__ == "__main__":
    main()
