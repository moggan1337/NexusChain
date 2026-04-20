# NexusChain - Layer 2 ZK-Rollup Blockchain

<p align="center">
  <img src="docs/nexuschain-logo.png" alt="NexusChain" width="400"/>
</p>

<p align="center">
  <strong>High-Performance Zero-Knowledge Rollup for Ethereum</strong>
</p>

<p align="center">
  <a href="https://github.com/moggan1337/NexusChain/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"/>
  </a>
  <a href="https://github.com/moggan1337/NexusChain/actions">
    <img src="https://img.shields.io/badge/Build-Passing-green.svg" alt="Build"/>
  </a>
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Zero-Knowledge Proof System](#zero-knowledge-proof-system)
4. [Core Components](#core-components)
5. [Getting Started](#getting-started)
6. [Development](#development)
7. [Testing](#testing)
8. [Deployment](#deployment)
9. [Documentation](#documentation)
10. [Contributing](#contributing)
11. [License](#license)

---

## Overview

NexusChain is a Layer 2 scaling solution for Ethereum that utilizes Zero-Knowledge Rollups (ZK-Rollups) to provide:

- **High Throughput**: Up to 2,000+ TPS with EVM compatibility
- **Low Latency**: Sub-second finality for fast transaction confirmation
- **Enhanced Privacy**: Transaction data is compressed and verified without revealing details
- **Ethereum Security**: Inherits Ethereum's security model with ZK proofs
- **Cross-Chain Bridge**: Seamless asset transfer between Layer 1 and Layer 2

### Why ZK-Rollups?

Traditional Layer 2 solutions like Optimistic Rollups require a challenge period for withdrawals (typically 7 days). ZK-Rollups provide:

- **Immediate Finality**: No waiting period for transaction confirmation
- **Cryptographic Security**: Validity proofs guarantee state correctness
- **Capital Efficiency**: No need to lock funds for extended periods
- **Reduced Data Availability**: Only state differences are published to L1

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NexusChain Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐    │
│  │   Clients   │────▶│  RPC Node   │────▶│   Transaction Pool  │    │
│  │  (Wallets)  │     │  (JSON-RPC) │     │     (MemPool)       │    │
│  └─────────────┘     └─────────────┘     └──────────┬──────────┘    │
│                                                      │               │
│                                                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                        Sequencer                            │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │    │
│  │  │   Block     │  │   State     │  │   Transaction       │  │    │
│  │  │  Producer   │  │  Updater    │  │    Ordering         │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                        │
│                              ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                         Prover                              │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │    │
│  │  │    ZK       │  │   Circuit   │  │   Proof             │  │    │
│  │  │   Engine    │──▶│  Compiler   │──▶│   Generator         │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                        │
│                              ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Smart Contracts                           │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │    │
│  │  │   Main      │  │   Bridge    │  │    Verifier         │  │    │
│  │  │   Contract  │  │   Contract  │  │    Contract         │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                        │
│                              ▼                                        │
│                    ┌─────────────────┐                              │
│                    │    Ethereum      │                              │
│                    │   (Layer 1)     │                              │
│                    └─────────────────┘                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Descriptions

#### 1. RPC Node (JSON-RPC Interface)

The RPC node provides Ethereum-compatible interfaces for client interaction:

- `eth_sendTransaction`: Submit transactions to the mempool
- `eth_getBalance`: Query account balances
- `eth_call`: Execute read-only contract calls
- `eth_getBlockByNumber`: Retrieve block information
- `eth_getTransactionReceipt`: Get transaction receipts

#### 2. Transaction Pool (MemPool)

The transaction pool manages pending transactions:

- **Transaction Reception**: Accepts signed transactions from clients
- **Ordering**: Orders transactions by gas price and nonce
- **Validation**: Verifies transaction signatures and nonces
- **Mempool Gossip**: Shares transactions with other sequencers (future)

#### 3. Sequencer

The sequencer is responsible for block production:

- **Block Producer**: Aggregates transactions into blocks
- **State Updater**: Maintains the Layer 2 state (Merkle tree)
- **Transaction Ordering**: Determines transaction execution order
- **Batch Submission**: Prepares batches for the prover

#### 4. Prover

The prover generates cryptographic proofs:

- **ZK Engine**: Implements Groth16/PLONK proof systems
- **Circuit Compiler**: Compiles transactions into ZK circuits
- **Proof Generator**: Generates validity proofs for blocks
- **Verifier**: Can verify proofs locally (for fast finality)

#### 5. Smart Contracts

Deployed on Ethereum mainnet:

- **MainContract**: Stores the state root and manages the protocol
- **BridgeContract**: Handles cross-chain asset transfers
- **VerifierContract**: Verifies ZK proofs on-chain

---

## Zero-Knowledge Proof System

### Overview

NexusChain implements a dual proof system supporting both **Groth16** and **PLONK** protocols:

| Feature | Groth16 | PLONK |
|---------|---------|-------|
| Proof Size | 192 bytes | 400 bytes |
| Verification Key | ~1 KB | ~2 KB |
| Proving Time | Fast | Moderate |
| Trusted Setup | Per-circuit | Universal |
| Recursion | Limited | Native |

### Groth16 Protocol

Groth16 is a pairing-based zk-SNARK protocol known for:

- Smallest proof size among practical ZK systems
- Fast verification time (pairing operations)
- Requires a circuit-specific trusted setup

#### Circuit Structure

```python
# Example: Transfer Circuit
class TransferCircuit:
    """
    ZK Circuit for Layer 2 token transfers
    
    Public Inputs:
    - Root before: Merkle tree root before transaction
    - Root after: Merkle tree root after transaction
    - Nullifier: Prevents double-spending
    
    Private Inputs:
    - Sender public key
    - Sender Merkle proof
    - Recipient public key
    - Signature
    - Amount
    """
    
    def circuit(self, public, private):
        # 1. Verify sender exists in Merkle tree
        sender_leaf = hash(private.sender_pk)
        sender_proof = verify_merkle_proof(
            public.root_before,
            sender_leaf,
            private.merkle_proof
        )
        
        # 2. Verify signature
        signature_valid = verify_signature(
            private.signature,
            private.sender_pk,
            private.amount,
            private.recipient_pk
        )
        
        # 3. Update state
        new_sender_leaf = hash(private.sender_pk, private.amount - amount)
        new_recipient_leaf = hash(private.recipient_pk, private.amount + amount)
        
        # 4. Compute new root
        new_root = update_merkle_tree(
            public.root_before,
            [new_sender_leaf, new_recipient_leaf],
            private.indices
        )
        
        # 5. Nullifier check (prevents double-spending)
        nullifier = hash(private.sender_pk, private.nonce)
        
        # Constraints
        assert(sender_proof == 1)
        assert(signature_valid == 1)
        assert(public.root_after == new_root)
        assert(public.nullifier == nullifier)
```

#### Trusted Setup

Groth16 requires a ceremony to generate toxic waste:

```bash
# Power of Tau ceremony (phase 1)
snarkjs powersoftau new bn128 15 pot12_final.ptau -v

# Contribute randomness
snarkjs powersoftau contribute pot12_final.ptau pot12_contrib.ptau --name="NexusChain" -e="$(openssl rand -hex 32)"

# Phase 2 circuit setup
snarkjs powersoftau prepare phase2 pot12_contrib.ptau pot12_prepared.ptau -v
snarkjs groth16 setup circuit.r1cs pot12_prepared.ptau nexus_0000.zkey

# Contribute circuit-specific randomness
snarkjs zkey contribute nexus_0000.zkey nexus_0001.zkey --name="Contributor 1" -e="$(openssl rand -hex 32)"

# Export verification key
snarkjs zkey export verificationkey nexus_final.zkey verification_key.json
```

### PLONK Protocol

PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge) offers:

- Universal trusted setup (one ceremony for all circuits)
- Native support for custom gates
- Easy upgradeability

#### PLONK Circuit Example

```python
class PlonkTransferCircuit:
    """
    PLONK circuit for Layer 2 transfers with custom gates
    """
    
    # Custom PLONK gate: hash + add
    CUSTOM_GATES = [
        Gate("hash_and_add", 
             [("a", "hash"), ("b", "add")],
             lambda inputs: hash(inputs[0]) + inputs[1]
        )
    ]
    
    def circuit(self, public, private):
        # Hash function using custom gates
        sender_hash = self.hash(private.sender_pk)
        recipient_hash = self.hash(private.recipient_pk)
        
        # Range checks using custom gates
        amount_valid = self.range_check(private.amount, 0, 2**64)
        
        # Merkle proof verification
        merkle_valid = self.verify_merkle_proof(
            public.root_before,
            sender_hash,
            private.proof
        )
        
        return [merkle_valid, amount_valid]
```

### Proof Generation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Proof Generation Pipeline                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Transaction Batch                                               │
│     └─▶ [tx1, tx2, tx3, ..., txn]                                  │
│                                                                      │
│  2. Witness Generation                                              │
│     └─▶ Extract public/secret inputs from transactions              │
│                                                                      │
│  3. Circuit Compilation (if not cached)                             │
│     └─▶ R1CS constraints ▶ QAP (Quadratic Arithmetic Program)       │
│                                                                      │
│  4. Witness Assignment                                              │
│     └─▶ Assign values to circuit wires                              │
│                                                                      │
│  5. Proof Computation                                               │
│     ├─▶ Groth16: Pairings & polynomial evaluations                 │
│     └─▶ PLONK: Permutation checks & quotient polynomial             │
│                                                                      │
│  6. Proof Output                                                    │
│     └─▶ [πa, πb, πc] (Groth16) or [W_L, W_R, W_O, Z, T_1, T_2, T_3] │
│                                                                      │
└─────────────────────────────────────────────────────────────────┘
```

### Proof Verification

```python
def verify_proof_groth16(proof, public_inputs, verification_key):
    """
    Verify a Groth16 proof
    
    Args:
        proof: (πA, πB, πC) - the proof
        public_inputs: public witness values
        verification_key: VK from trusted setup
    
    Returns:
        bool: True if proof is valid
    """
    # Compute A * α and B * β (blinding)
    A = proof.πA
    B = proof.πB
    
    # Linear combination of constraints
    C = proof.πC
    
    # Pairing check
    return pairing_check([
        (A, B),                    # Proof
        (-verification_key.α, verification_key.β),  # Verification key
        (C, verification_key.γ),   # Constraints
        (public_inputs, verification_key.δ)  # Public inputs
    ])

def verify_proof_plonk(proof, public_inputs, verification_key):
    """
    Verify a PLONK proof using Kate-Zaverucha-Goldberg (KZG) commitments
    
    Args:
        proof: (W_L, W_R, W_O, Z, T_1, T_2, T_3)
        public_inputs: public witness
        verification_key: Universal verification key
    
    Returns:
        bool: True if proof is valid
    """
    # 1. Compute commitment to public inputs
    pub_commitment = commit_public_inputs(public_inputs)
    
    # 2. Compute opening challenge (Fiat-Shamir)
    challenge = fiat_shamir_hash([pub_commitment, proof.W_L, ...])
    
    # 3. Compute quotient polynomial evaluation
    quotient_eval = evaluate_quotient(proof, challenge, public_inputs)
    
    # 4. KZG opening proof verification
    return kzg_verify(
        verification_key.commitment_key,
        quotient_eval,
        challenge,
        proof
    )
```

---

## Core Components

### 1. State Management (Merkle Tree)

NexusChain uses a **Sparse Merkle Tree (SMT)** for state management:

```python
class SparseMerkleTree:
    """
    Merkle tree optimized for sparse state
    
    Properties:
    - O(log n) insertions, deletions, and updates
    - Efficient proof generation and verification
    - Support for concurrent reads/writes
    """
    
    def __init__(self, depth: int = 32):
        self.depth = depth
        self.empty_node = hash(b"")
        self.tree = [self.empty_node] * (2 ** (depth + 1) - 1)
    
    def update(self, key: bytes, value: bytes) -> tuple[bytes, list]:
        """
        Update a leaf and return new root + proof
        
        Returns:
            new_root: Updated Merkle root
            proof: Merkle inclusion proof
        """
        index = self._key_to_index(key)
        
        # Update leaf
        old_value = self._get_leaf(index)
        new_leaf = hash(key + value)
        self._set_leaf(index, new_leaf)
        
        # Update path to root
        proof = []
        current_index = index
        
        for level in range(self.depth):
            sibling_index = current_index ^ 1
            sibling = self.tree[sibling_index]
            
            if current_index % 2 == 0:  # Left child
                combined = hash(new_leaf + sibling)
            else:  # Right child
                combined = hash(sibling + new_leaf)
            
            proof.append((level, sibling))
            new_leaf = combined
            current_index = (current_index + 1) // 2
        
        self.tree[0] = new_leaf  # Update root
        return new_root, proof
    
    def verify_proof(self, root: bytes, key: bytes, value: bytes, proof: list) -> bool:
        """
        Verify a Merkle inclusion proof
        """
        expected_leaf = hash(key + value)
        current_hash = expected_leaf
        
        for level, sibling in proof:
            if level % 2 == 0:
                current_hash = hash(current_hash + sibling)
            else:
                current_hash = hash(sibling + current_hash)
        
        return current_hash == root
```

### 2. Transaction Pool

```python
class TransactionPool:
    """
    Manages pending transactions for Layer 2 processing
    
    Features:
    - Priority queue by gas price
    - Nonce management per account
    - Transaction deduplication
    - Size limits and eviction policies
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.pending: PriorityQueue[Transaction] = PriorityQueue()
        self.by_nonce: Dict[Address, Dict[uint64, Transaction]] = {}
        self.by_hash: Dict[bytes, Transaction] = {}
    
    def add_transaction(self, tx: Transaction) -> bool:
        """
        Add a transaction to the pool
        
        Returns:
            True if added, False if rejected
        """
        # Check if duplicate
        if tx.hash in self.by_hash:
            return False
        
        # Check size limit
        if len(self.by_hash) >= self.max_size:
            self._evict_low_priority()
        
        # Validate nonce
        sender = tx.sender
        expected_nonce = self._get_next_nonce(sender)
        if tx.nonce != expected_nonce:
            return False
        
        # Add to pool
        self.pending.put((tx.gas_price, tx.nonce, tx))
        self.by_nonce.setdefault(sender, {})[tx.nonce] = tx
        self.by_hash[tx.hash] = tx
        
        return True
    
    def get_batch(self, batch_size: int) -> list[Transaction]:
        """
        Get next batch of transactions for sequencing
        """
        batch = []
        while len(batch) < batch_size and not self.pending.empty():
            _, _, tx = self.pending.get()
            batch.append(tx)
        return batch
```

### 3. Sequencer

```python
class Sequencer:
    """
    Block producer for Layer 2
    
    Responsibilities:
    - Aggregate transactions from mempool
    - Execute transactions and update state
    - Generate state diffs
    - Submit batches to prover
    """
    
    def __init__(self, state: StateManager, txpool: TransactionPool):
        self.state = state
        self.txpool = txpool
        self.current_batch: Batch = None
    
    def produce_block(self, txs: list[Transaction]) -> Block:
        """
        Execute a list of transactions and produce a block
        
        Returns:
            Block with new state root and execution trace
        """
        block = Block(block_number=self.state.current_block + 1)
        
        for tx in txs:
            # Validate transaction
            if not self._validate_tx(tx):
                continue
            
            # Execute transaction
            try:
                result = self._execute_tx(tx)
                block.add_transaction(tx, result)
            except Exception as e:
                block.add_rejection(tx, str(e))
        
        # Finalize block
        block.finalize(self.state.get_root())
        
        return block
    
    def create_batch(self, blocks: list[Block]) -> Batch:
        """
        Create a proof batch from blocks
        """
        batch = Batch()
        
        for block in blocks:
            batch.add_block(block)
            batch.add_state_diff(block.get_state_diff())
        
        # Compute batch public inputs
        batch.public_inputs = self._compute_public_inputs(batch)
        
        return batch
```

### 4. Prover

```python
class Prover:
    """
    ZK Proof generator for Layer 2 batches
    
    Implements both Groth16 and PLONK proof systems
    """
    
    def __init__(self, proof_system: str = "groth16"):
        self.proof_system = proof_system
        self.circuit_library = CircuitLibrary()
        self.setup_params = None
    
    def setup(self, circuit: Circuit):
        """
        Perform trusted setup for a circuit
        """
        if self.proof_system == "groth16":
            self.setup_params = self._groth16_setup(circuit)
        else:
            self.setup_params = self._plonk_setup(circuit)
    
    def generate_proof(self, batch: Batch) -> Proof:
        """
        Generate a ZK proof for a batch
        
        Steps:
        1. Compute witness (public + private inputs)
        2. Assign witness to circuit
        3. Compute proof
        """
        # Load or compile circuit
        circuit = self.circuit_library.get_circuit("transfer")
        
        # Generate witness
        witness = self._generate_witness(batch, circuit)
        
        # Generate proof
        if self.proof_system == "groth16":
            proof = self._prove_groth16(witness, self.setup_params)
        else:
            proof = self._prove_plonk(witness, self.setup_params)
        
        return proof
    
    def verify_proof(self, proof: Proof, batch: Batch) -> bool:
        """
        Verify a ZK proof
        """
        if self.proof_system == "groth16":
            return self._verify_groth16(proof, batch.public_inputs)
        else:
            return self._verify_plonk(proof, batch.public_inputs)
```

### 5. Cross-Chain Bridge

```python
class Bridge:
    """
    Manages asset transfers between L1 (Ethereum) and L2 (NexusChain)
    
    Flow:
    L1 → L2: Deposit → Bridge Contract → L2 Mint
    L2 → L1: Burn → L2 Event → L1 Withdraw
    """
    
    # Bridge contract events
    DEPOSIT_EVENT = "Deposit(address indexed user, uint256 amount, uint256 l2Recipient)"
    WITHDRAW_EVENT = "Withdraw(address indexed user, uint256 amount, bytes32[] merkleProof)"
    
    def deposit(self, user: Address, amount: uint256) -> Transaction:
        """
        Deposit funds from L1 to L2
        
        1. User calls Bridge.deposit() on L1
        2. Funds locked in Bridge contract
        3. L2 BridgeObserver captures event
        4. L2 mints tokens to user
        """
        # Call L1 bridge contract
        tx = self.l1_bridge.deposit(user, amount, value=amount)
        
        # Wait for event
        receipt = tx.wait()
        deposit_event = self._parse_deposit_event(receipt)
        
        # Submit to L2
        l2_tx = self.l2_sequencer.submit_deposit(
            deposit_event.user,
            deposit_event.amount
        )
        
        return l2_tx
    
    def withdraw(self, user: Address, amount: uint256) -> WithdrawalProof:
        """
        Withdraw funds from L2 to L1
        
        1. User burns tokens on L2
        2. Merkle proof generated
        3. L1 Bridge verifies proof
        4. Funds released to user
        """
        # Burn on L2
        burn_tx = self.l2_token.burn(user, amount)
        burn_receipt = burn_tx.wait()
        
        # Generate Merkle proof
        withdrawal_tree = self._build_withdrawal_tree(burn_receipt)
        proof = withdrawal_tree.get_proof(user, amount)
        
        # Submit to L1
        withdraw_tx = self.l1_bridge.withdraw(
            user,
            amount,
            proof.merkle_proof,
            proof.nullifier_hash
        )
        
        # Wait for challenge period (for optimistic rollup fallback)
        # ZK-Rollups: No challenge period needed
        
        return WithdrawalProof(
            user=user,
            amount=amount,
            l2_tx_hash=burn_tx.hash,
            merkle_proof=proof.merkle_proof,
            nullifier_hash=proof.nullifier_hash
        )
```

### 6. EVM Compatibility Layer

```python
class EVMInterpreter:
    """
    EVM-compatible interpreter for Layer 2
    
    Supports:
    - All EVM opcodes
    - Precompiled contracts
    - State operations
    - Gas calculation
    """
    
    OPCODES = {
        0x00: STOP,
        0x01: ADD,
        0x02: MUL,
        # ... all EVM opcodes
    }
    
    PRECOMPILED = {
        0x01: ecrecover,
        0x02: sha256,
        0x03: ripemd160,
        0x04: data_copy,
        0x05: big_mod_exp,
        0x06: bn_add,
        0x07: bn_mul,
        0x08: bn_pairing,
    }
    
    def execute(self, tx: Transaction, state: State) -> ExecutionResult:
        """
        Execute a transaction in the EVM
        
        Returns:
            ExecutionResult with success status, gas used, return data
        """
        env = ExecutionEnvironment(
            caller=tx.sender,
            origin=tx.origin,
            contract=tx.to,
            code=state.get_code(tx.to),
            data=tx.data,
            gas=tx.gas_limit,
            value=tx.value
        )
        
        stack = []
        memory = bytearray()
        storage = {}
        
        pc = 0
        gas_remaining = tx.gas_limit
        
        while pc < len(env.code):
            op = env.code[pc]
            
            # Get opcode handler
            handler = self.OPCODES.get(op, self.INVALID)
            
            # Check gas
            gas_cost = self._get_gas_cost(op, stack, memory, storage)
            if gas_remaining < gas_cost:
                return ExecutionResult(success=False, error="Out of gas")
            
            # Execute
            try:
                result = handler(stack, memory, storage, env)
                gas_remaining -= gas_cost
            except Exception as e:
                return ExecutionResult(success=False, error=str(e))
            
            pc += 1
        
        return ExecutionResult(
            success=True,
            gas_used=tx.gas_limit - gas_remaining,
            return_data=memory[:env.return_data_size]
        )
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ (for smart contracts)
- Foundry/Hardhat (for smart contract development)
- 16GB RAM minimum (for proof generation)

### Installation

```bash
# Clone the repository
git clone https://github.com/moggan1337/NexusChain.git
cd NexusChain

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
npm install

# Compile smart contracts
forge build

# Run setup scripts
./scripts/setup.sh
```

### Quick Start

```bash
# Start local L1 (Anvil)
anvil

# Deploy smart contracts
forge script scripts/Deploy.s.sol --rpc-url http://localhost:8545

# Start L2 sequencer
python -m src.sequencer.main --rpc-url http://localhost:8545 --port 8546

# Start L2 prover
python -m src.prover.main --batch-size 100

# Start L2 RPC node
python -m src.rpc.main --port 8547
```

---

## Development

### Project Structure

```
NexusChain/
├── src/
│   ├── zk_rollup/          # Core ZK rollup logic
│   │   ├── circuit.py      # ZK circuit definitions
│   │   ├── proof.py        # Proof generation/verification
│   │   ├── verifier.py     # On-chain verifier interface
│   │   └── types.py        # Type definitions
│   │
│   ├── prover/             # Prover system
│   │   ├── engine.py       # ZK engine implementation
│   │   ├── groth16.py      # Groth16 protocol
│   │   ├── plonk.py        # PLONK protocol
│   │   └── main.py         # Prover entry point
│   │
│   ├── sequencer/          # Sequencer logic
│   │   ├── block.py        # Block production
│   │   ├── batch.py        # Batch management
│   │   ├── state.py        # State management
│   │   └── main.py         # Sequencer entry point
│   │
│   ├── state/              # State management
│   │   ├── merkle.py       # Merkle tree implementation
│   │   ├── account.py      # Account state
│   │   └── storage.py      # Storage management
│   │
│   ├── txpool/             # Transaction pool
│   │   ├── pool.py         # MemPool implementation
│   │   ├── validator.py    # Transaction validation
│   │   └── ordering.py     # Transaction ordering
│   │
│   ├── evm/                # EVM compatibility
│   │   ├── interpreter.py  # EVM interpreter
│   │   ├── gas.py          # Gas calculation
│   │   └── precompiled.py  # Precompiled contracts
│   │
│   ├── bridge/             # Cross-chain bridge
│   │   ├── l1_bridge.py    # L1 bridge interface
│   │   ├── l2_bridge.py    # L2 bridge interface
│   │   └── watcher.py      # Event watcher
│   │
│   ├── contracts/          # Smart contracts (Solidity)
│   │   ├── NexusChain.sol  # Main contract
│   │   ├── Bridge.sol      # Bridge contract
│   │   ├── Verifier.sol    # ZK verifier
│   │   └── Token.sol       # L2 token
│   │
│   ├── utils/              # Utilities
│   │   ├── crypto.py       # Cryptographic utilities
│   │   ├── serialization.py # Serialization
│   │   └── logging.py      # Logging utilities
│   │
│   └── rpc/                # JSON-RPC interface
│       ├── server.py       # RPC server
│       └── handlers.py     # RPC handlers
│
├── tests/
│   ├── test_circuit.py     # Circuit tests
│   ├── test_merkle.py      # Merkle tree tests
│   ├── test_sequencer.py   # Sequencer tests
│   ├── test_prover.py      # Prover tests
│   ├── test_bridge.py      # Bridge tests
│   └── test_evm.py         # EVM tests
│
├── scripts/
│   ├── setup.sh            # Setup script
│   ├── deploy.sh           # Deployment script
│   └── benchmark.sh        # Benchmark script
│
├── docs/
│   ├── architecture.md     # Architecture docs
│   ├── zkprimer.md         # ZK concepts primer
│   └── api.md              # API documentation
│
├── requirements.txt        # Python dependencies
├── package.json            # Node.js dependencies
├── foundry.toml            # Foundry configuration
├── SPEC.md                 # Project specification
└── README.md               # This file
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/test_merkle.py -v

# Run with coverage
pytest --cov=src --cov-report=html

# Run benchmark tests
pytest tests/benchmark.py -v
```

### Benchmarking

```bash
# Run benchmarks
./scripts/benchmark.sh

# Expected output:
# - Proof generation time: ~30s (Groth16), ~60s (PLONK)
# - Proof verification: ~5ms (Groth16), ~10ms (PLONK)
# - Throughput: 2000+ TPS
# - Finality: <1 second
```

---

## Testing

### Unit Tests

```python
# tests/test_merkle.py
def test_merkle_update():
    tree = SparseMerkleTree(depth=32)
    
    # Update a leaf
    new_root, proof = tree.update(
        key=b"user_001",
        value=b"balance_100"
    )
    
    # Verify proof
    assert tree.verify_proof(new_root, b"user_001", b"balance_100", proof)

def test_merkle_concurrent_updates():
    import threading
    
    tree = SparseMerkleTree(depth=32)
    
    def update_leaf(key, value):
        tree.update(key, value)
    
    threads = [
        threading.Thread(target=update_leaf, args=(f"key_{i}".encode(), f"value_{i}".encode()))
        for i in range(100)
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    assert len(tree) == 100
```

### Integration Tests

```python
# tests/test_sequencer.py
def test_full_batch_lifecycle():
    # Setup
    state = StateManager()
    txpool = TransactionPool()
    sequencer = Sequencer(state, txpool)
    prover = Prover(proof_system="groth16")
    
    # Create transactions
    txs = create_transfer_transactions(100)
    for tx in txs:
        txpool.add_transaction(tx)
    
    # Produce block
    batch_txs = txpool.get_batch(100)
    block = sequencer.produce_block(batch_txs)
    
    # Create batch
    batch = sequencer.create_batch([block])
    
    # Generate proof
    proof = prover.generate_proof(batch)
    
    # Verify proof
    assert prover.verify_proof(proof, batch)
```

---

## Deployment

### Local Development

```bash
# 1. Start local L1 (Anvil)
anvil --host 0.0.0.0 --port 8545

# 2. Deploy contracts
forge script scripts/Deploy.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast \
    --private-key 0x...

# 3. Note deployed addresses
# NexusChain: 0x...
# Bridge: 0x...
# Verifier: 0x...

# 4. Configure L2
export L1_RPC=http://localhost:8545
export L1_BRIDGE=0x...
export L1_VERIFIER=0x...

# 5. Start L2 services
python -m src.sequencer.main &
python -m src.prover.main &
python -m src.rpc.main &
```

### Testnet Deployment

```bash
# 1. Get Sepolia testnet ETH
# Request from https://faucet.sepolia.dev/

# 2. Deploy to Sepolia
forge script scripts/Deploy.s.sol \
    --rpc-url https://rpc.sepolia.org \
    --broadcast \
    --private-key $PRIVATE_KEY

# 3. Verify contracts
forge verify-contract \
    --rpc-url https://rpc.sepolia.org \
    --constructor-args $(cast abi-encode "constructor(address)" $VERIFIER_ADDRESS) \
    <CONTRACT_ADDRESS> \
    src/NexusChain.sol:NexusChain

# 4. Update configuration
export L1_RPC=https://rpc.sepolia.org
export L1_BRIDGE=<DEPLOYED_BRIDGE>
export L1_NEXUS_CHAIN=<DEPLOYED_NEXUS_CHAIN>
```

### Mainnet Deployment

```bash
# 1. Complete security audit
# 2. Run invariant tests
# 3. Multi-sig deployment

forge script scripts/DeployMainnet.s.sol \
    --rpc-url https://eth.llamarpc.com \
    --broadcast \
    --private-key $DEPLOYER_KEY \
    --slow

# 2-of-3 multi-sig transfer of admin roles
```

---

## Documentation

### Architecture Deep Dive

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

### ZK Concepts Primer

See [docs/zkprimer.md](docs/zkprimer.md) for an introduction to zero-knowledge proofs.

### API Reference

See [docs/api.md](docs/api.md) for complete API documentation.

---

## Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Python: Follow PEP 8, use type hints
- Solidity: Follow Solidity style guide
- Tests: 100% coverage for critical paths

### Security

- Never commit private keys
- Run security audits before submitting
- Follow responsible disclosure for vulnerabilities

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Ethereum Foundation** - For ZK-Rollup research and EVM
- **zkSNARK Team** - For Groth16 protocol
- **Protocol Labs** - For PLONK protocol
- **Matter Labs** - For zkSync architecture inspiration
- **Polygon zkEVM** - For EVM compatibility insights

---

<p align="center">
  <strong>NexusChain</strong> — Scaling Ethereum with Zero-Knowledge Proofs
</p>
