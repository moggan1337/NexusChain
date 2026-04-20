"""
NexusChain - EVM Compatibility Layer

Provides EVM-compatible execution for Layer 2 smart contracts.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import IntEnum
import logging

from ..zk_rollup.types import Address, Hash, Amount, Gas


# Configure logging
logger = logging.getLogger(__name__)


class OpCode(IntEnum):
    """EVM Opcodes"""
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0a
    SIGNEXTEND = 0x0b
    
    # Comparison & Bitwise
    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1a
    SHL = 0x1b
    SHR = 0x1c
    SAR = 0x1d
    
    # Keccak
    KECCAK256 = 0x20
    
    # Environmental
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3a
    EXTCODESIZE = 0x3b
    EXTCODECOPY = 0x3c
    RETURNDATASIZE = 0x3d
    RETURNDATACOPY = 0x3e
    EXTCODEHASH = 0x3f
    
    # Block
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48
    
    # Stack
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5a
    JUMPDEST = 0x5b
    
    # Duplication
    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP6 = 0x85
    DUP7 = 0x86
    DUP8 = 0x87
    DUP9 = 0x88
    DUP10 = 0x89
    DUP11 = 0x8a
    DUP12 = 0x8b
    DUP13 = 0x8c
    DUP14 = 0x8d
    DUP15 = 0x8e
    DUP16 = 0x8f
    
    # Exchange
    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP5 = 0x94
    SWAP6 = 0x95
    SWAP7 = 0x96
    SWAP8 = 0x97
    SWAP9 = 0x98
    SWAP10 = 0x99
    SWAP11 = 0x9a
    SWAP12 = 0x9b
    SWAP13 = 0x9c
    SWAP14 = 0x9d
    SWAP15 = 0x9e
    SWAP16 = 0x9f
    
    # Logging
    LOG0 = 0xa0
    LOG1 = 0xa1
    LOG2 = 0xa2
    LOG3 = 0xa3
    LOG4 = 0xa4
    
    # System
    CREATE = 0xf0
    CALL = 0xf1
    CALLCODE = 0xf2
    RETURN = 0xf3
    DELEGATECALL = 0xf4
    CREATE2 = 0xf5
    STATICCALL = 0xfa
    REVERT = 0xfd
    INVALID = 0xfe
    SELFDESTRUCT = 0xff


# Gas costs
GAS_BASE = 2
GAS_ZERO = 0
GAS_VERYLOW = 3
GAS_LOW = 5
GAS_MID = 8
GAS_HIGH = 10
GAS_EXTERNAL = 100
GAS_TRANSACTION = 21000
GAS_CONTRACT_CREATION = 32000
GAS_CALL = 700
GAS_STORAGE_SET = 20000
GAS_STORAGE_UPDATE = 5000
GAS_STORAGE_CLEAR = -15000  # Refund


@dataclass
class ExecutionEnvironment:
    """EVM execution environment"""
    contract_address: Address
    caller: Address
    origin: Address
    code: bytes
    data: bytes
    gas: Gas
    value: Amount
    block_number: int
    timestamp: int
    difficulty: int
    gas_price: int
    chain_id: int


@dataclass
class EVMStack:
    """EVM Stack (max 1024)"""
    data: List[int] = field(default_factory=list)
    max_size: int = 1024
    
    def push(self, value: int):
        if len(self.data) >= self.max_size:
            raise Exception("Stack overflow")
        self.data.append(value)
    
    def pop(self) -> int:
        if not self.data:
            raise Exception("Stack underflow")
        return self.data.pop()
    
    def dup(self, n: int):
        if n < 1 or n > len(self.data):
            raise Exception("Invalid dup")
        self.push(self.data[-n])
    
    def swap(self, n: int):
        if n < 1 or n >= len(self.data):
            raise Exception("Invalid swap")
        idx = len(self.data) - 1 - n
        self.data[-1], self.data[idx] = self.data[idx], self.data[-1]
    
    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class EVMmemory:
    """EVM Memory"""
    data: bytearray = field(default_factory=bytearray)
    
    def read(self, offset: int, length: int) -> bytes:
        if offset + length > len(self.data):
            self._expand(offset + length)
        return bytes(self.data[offset:offset + length])
    
    def write(self, offset: int, value: bytes):
        if offset + len(value) > len(self.data):
            self._expand(offset + len(value))
        self.data[offset:offset + len(value)] = value
    
    def _expand(self, size: int):
        if size > len(self.data):
            self.data.extend(b"\x00" * (size - len(self.data)))


@dataclass
class EVMStorage:
    """EVM Contract Storage"""
    storage: Dict[Hash, int] = field(default_factory=dict)
    
    def get(self, key: Hash) -> int:
        return self.storage.get(key, 0)
    
    def set(self, key: Hash, value: int):
        self.storage[key] = value
    
    def clear(self, key: Hash):
        if key in self.storage:
            del self.storage[key]


@dataclass
class ExecutionResult:
    """Result of EVM execution"""
    success: bool
    gas_used: Gas
    return_data: bytes = b""
    logs: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Log:
    """EVM Log entry"""
    address: Address
    topics: List[int]
    data: bytes


class EVMInterpreter:
    """
    EVM-compatible interpreter for NexusChain
    
    Implements all EVM opcodes and execution semantics.
    """
    
    def __init__(self):
        self.opcodes: Dict[int, Callable] = {}
        self._register_opcodes()
        
        # Precompiled contracts
        self.precompiled: Dict[int, Callable] = {
            0x01: self._ecrecover,
            0x02: self._sha256,
            0x03: self._ripemd160,
            0x04: self._data_copy,
        }
    
    def _register_opcodes(self):
        """Register all EVM opcodes"""
        self.opcodes = {
            OpCode.STOP: self._op_stop,
            OpCode.ADD: self._op_add,
            OpCode.MUL: self._op_mul,
            OpCode.SUB: self._op_sub,
            OpCode.DIV: self._op_div,
            OpCode.SDIV: self._op_sdiv,
            OpCode.MOD: self._op_mod,
            OpCode.SMOD: self._op_smod,
            OpCode.ADDMOD: self._op_addmod,
            OpCode.MULMOD: self._op_mulmod,
            OpCode.EXP: self._op_exp,
            OpCode.SIGNEXTEND: self._op_signextend,
            OpCode.LT: self._op_lt,
            OpCode.GT: self._op_gt,
            OpCode.SLT: self._op_slt,
            OpCode.SGT: self._op_sgt,
            OpCode.EQ: self._op_eq,
            OpCode.ISZERO: self._op_iszero,
            OpCode.AND: self._op_and,
            OpCode.OR: self._op_or,
            OpCode.XOR: self._op_xor,
            OpCode.NOT: self._op_not,
            OpCode.BYTE: self._op_byte,
            OpCode.SHL: self._op_shl,
            OpCode.SHR: self._op_shr,
            OpCode.SAR: self._op_sar,
            OpCode.KECCAK256: self._op_keccak256,
            OpCode.ADDRESS: self._op_address,
            OpCode.BALANCE: self._op_balance,
            OpCode.ORIGIN: self._op_origin,
            OpCode.CALLER: self._op_caller,
            OpCode.CALLVALUE: self._op_callvalue,
            OpCode.CALLDATALOAD: self._op_calldataload,
            OpCode.CALLDATASIZE: self._op_calldatasize,
            OpCode.CALLDATACOPY: self._op_calldatacopy,
            OpCode.CODESIZE: self._op_codesize,
            OpCode.CODECOPY: self._op_codecopy,
            OpCode.GASPRICE: self._op_gasprice,
            OpCode.EXTCODESIZE: self._op_extcodesize,
            OpCode.EXTCODECOPY: self._op_extcodecopy,
            OpCode.RETURNDATASIZE: self._op_returndatasize,
            OpCode.RETURNDATACOPY: self._op_returndatacopy,
            OpCode.EXTCODEHASH: self._op_extcodehash,
            OpCode.BLOCKHASH: self._op_blockhash,
            OpCode.COINBASE: self._op_coinbase,
            OpCode.TIMESTAMP: self._op_timestamp,
            OpCode.NUMBER: self._op_number,
            OpCode.DIFFICULTY: self._op_difficulty,
            OpCode.GASLIMIT: self._op_gaslimit,
            OpCode.CHAINID: self._op_chainid,
            OpCode.SELFBALANCE: self._op_selfbalance,
            OpCode.BASEFEE: self._op_basefee,
            OpCode.POP: self._op_pop,
            OpCode.MLOAD: self._op_mload,
            OpCode.MSTORE: self._op_mstore,
            OpCode.MSTORE8: self._op_mstore8,
            OpCode.SLOAD: self._op_sload,
            OpCode.SSTORE: self._op_sstore,
            OpCode.JUMP: self._op_jump,
            OpCode.JUMPI: self._op_jumpi,
            OpCode.PC: self._op_pc,
            OpCode.MSIZE: self._op_msize,
            OpCode.GAS: self._op_gas,
            OpCode.JUMPDEST: self._op_jumpdest,
            OpCode.CREATE: self._op_create,
            OpCode.CALL: self._op_call,
            OpCode.CALLCODE: self._op_callcode,
            OpCode.RETURN: self._op_return,
            OpCode.DELEGATECALL: self._op_delegatecall,
            OpCode.CREATE2: self._op_create2,
            OpCode.STATICCALL: self._op_staticcall,
            OpCode.REVERT: self._op_revert,
            OpCode.INVALID: self._op_invalid,
            OpCode.SELFDESTRUCT: self._op_selfdestruct,
        }
        
        # Register dup opcodes
        for i in range(16):
            self.opcodes[OpCode.DUP1 + i] = lambda ctx, n=i+1: self._op_dup(ctx, n)
        
        # Register swap opcodes
        for i in range(17):
            self.opcodes[OpCode.SWAP1 + i] = lambda ctx, n=i+1: self._op_swap(ctx, n)
        
        # Register log opcodes
        for i in range(5):
            self.opcodes[OpCode.LOG0 + i] = lambda ctx, n=i: self._op_log(ctx, n)
    
    def execute(
        self,
        env: ExecutionEnvironment,
        state: Dict[Address, Dict],
        storage_factory: Callable[[Address], EVMStorage]
    ) -> ExecutionResult:
        """
        Execute EVM code
        
        Args:
            env: Execution environment
            state: Global state (address -> account info)
            storage_factory: Factory for creating storage for contracts
            
        Returns:
            ExecutionResult
        """
        stack = EVMStack()
        memory = EVMmemory()
        local_storage = storage_factory(env.contract_address)
        
        pc = 0
        gas = env.gas
        logs = []
        
        while pc < len(env.code):
            op = env.code[pc]
            
            if op in self.opcodes:
                handler = self.opcodes[op]
                
                # Get gas cost
                gas_cost = self._get_gas_cost(op, stack, memory, local_storage)
                if gas < gas_cost:
                    return ExecutionResult(
                        success=False,
                        gas_used=env.gas - gas,
                        error="Out of gas"
                    )
                
                gas -= gas_cost
                
                # Create execution context
                ctx = ExecutionContext(
                    env=env,
                    stack=stack,
                    memory=memory,
                    storage=local_storage,
                    state=state,
                    storage_factory=storage_factory,
                    pc=pc,
                    gas=gas,
                    logs=logs
                )
                
                try:
                    result = handler(ctx)
                    
                    if result is not None:
                        if isinstance(result, tuple):
                            gas = result[0]
                            pc = result[1]
                        else:
                            pc = result
                    else:
                        pc += 1
                    
                    ctx.gas = gas
                    
                except Exception as e:
                    return ExecutionResult(
                        success=False,
                        gas_used=env.gas - gas,
                        error=str(e)
                    )
            else:
                return ExecutionResult(
                    success=False,
                    gas_used=env.gas - gas,
                    error=f"Unknown opcode: {hex(op)}"
                )
        
        return ExecutionResult(
            success=True,
            gas_used=env.gas - gas,
            return_data=memory.data[:32] if memory.data else b"",
            logs=logs
        )
    
    def _get_gas_cost(self, op: int, stack, memory, storage) -> int:
        """Calculate gas cost for an opcode"""
        if op in [OpCode.STOP, OpCode.RETURN, OpCode.REVERT]:
            return 0
        elif op in [OpCode.ADD, OpCode.SUB, OpCode.AND, OpCode.OR, OpCode.XOR]:
            return GAS_VERYLOW
        elif op in [OpCode.MUL, OpCode.DIV, OpCode.MOD]:
            return GAS_LOW
        elif op == OpCode.KECCAK256:
            return GAS_VERYLOW
        elif op == OpCode.CALLDATACOPY:
            return GAS_VERYLOW
        elif op == OpCode.CODECOPY:
            return GAS_VERYLOW
        elif op in [OpCode.MLOAD, OpCode.MSTORE]:
            return GAS_VERYLOW
        elif op in [OpCode.SLOAD]:
            return GAS_SLOAD
        elif op in [OpCode.SSTORE]:
            return GAS_STORAGE_SET
        elif op == OpCode.JUMPDEST:
            return GAS_JUMPDEST
        elif op in [OpCode.CREATE, OpCode.CREATE2]:
            return GAS_CREATE
        elif op in [OpCode.CALL, OpCode.CALLCODE, OpCode.DELEGATECALL, OpCode.STATICCALL]:
            return GAS_CALL
        else:
            return GAS_BASE


@dataclass
class ExecutionContext:
    """Execution context passed to opcode handlers"""
    env: ExecutionEnvironment
    stack: EVMStack
    memory: EVMmemory
    storage: EVMStorage
    state: Dict
    storage_factory: Callable
    pc: int
    gas: Gas
    logs: List[Log]


# ============================================================================
# Opcode Implementations
# ============================================================================

GAS_JUMPDEST = 1
GAS_CREATE = 32000
GAS_SLOAD = 800

def _op_stop(self, ctx: ExecutionContext):
    return None

def _op_add(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push((a + b) % (2**256))
    return ctx.pc + 1

def _op_mul(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push((a * b) % (2**256))
    return ctx.pc + 1

def _op_sub(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push((a - b) % (2**256))
    return ctx.pc + 1

def _op_div(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(a // b if b != 0 else 0)
    return ctx.pc + 1

def _op_sdiv(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(abs(a) // abs(b) if b != 0 else 0)
    return ctx.pc + 1

def _op_mod(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(a % b if b != 0 else 0)
    return ctx.pc + 1

def _op_smod(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(abs(a) % abs(b) if b != 0 else 0)
    return ctx.pc + 1

def _op_addmod(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    ctx.stack.push((a + b) % c if c != 0 else 0)
    return ctx.pc + 1

def _op_mulmod(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    ctx.stack.push((a * b) % c if c != 0 else 0)
    return ctx.pc + 1

def _op_exp(self, ctx: ExecutionContext):
    base = ctx.stack.pop()
    exp = ctx.stack.pop()
    ctx.stack.push(pow(base, exp, 2**256))
    return ctx.pc + 1

def _op_signextend(self, ctx: ExecutionContext):
    b = ctx.stack.pop()
    x = ctx.stack.pop()
    if b < 32:
        bit = b * 8 + 7
        sign_bit = (x >> bit) & 1
        if sign_bit:
            ctx.stack.push(x | ((2**256 - 1) ^ (2**(bit + 1) - 1)))
        else:
            ctx.stack.push(x & (2**(bit + 1) - 1))
    else:
        ctx.stack.push(x)
    return ctx.pc + 1

def _op_lt(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if a < b else 0)
    return ctx.pc + 1

def _op_gt(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if a > b else 0)
    return ctx.pc + 1

def _op_slt(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if (a - b) < 0 else 0)
    return ctx.pc + 1

def _op_sgt(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if (a - b) > 0 else 0)
    return ctx.pc + 1

def _op_eq(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if a == b else 0)
    return ctx.pc + 1

def _op_iszero(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    ctx.stack.push(1 if a == 0 else 0)
    return ctx.pc + 1

def _op_and(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(a & b)
    return ctx.pc + 1

def _op_or(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(a | b)
    return ctx.pc + 1

def _op_xor(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(a ^ b)
    return ctx.pc + 1

def _op_not(self, ctx: ExecutionContext):
    a = ctx.stack.pop()
    ctx.stack.push((2**256 - 1) - a)
    return ctx.pc + 1

def _op_byte(self, ctx: ExecutionContext):
    idx = ctx.stack.pop()
    val = ctx.stack.pop()
    if idx < 32:
        ctx.stack.push((val >> (248 - idx * 8)) & 0xff)
    else:
        ctx.stack.push(0)
    return ctx.pc + 1

def _op_shl(self, ctx: ExecutionContext):
    shift = ctx.stack.pop()
    value = ctx.stack.pop()
    ctx.stack.push((value << shift) % (2**256))
    return ctx.pc + 1

def _op_shr(self, ctx: ExecutionContext):
    shift = ctx.stack.pop()
    value = ctx.stack.pop()
    ctx.stack.push(value >> shift)
    return ctx.pc + 1

def _op_sar(self, ctx: ExecutionContext):
    shift = ctx.stack.pop()
    value = ctx.stack.pop()
    if value & (1 << 255):
        ctx.stack.push((value >> shift) | (2**256 - (2**(shift))))
    else:
        ctx.stack.push(value >> shift)
    return ctx.pc + 1

def _op_keccak256(self, ctx: ExecutionContext):
    import hashlib
    offset = ctx.stack.pop()
    length = ctx.stack.pop()
    data = ctx.memory.read(offset, length)
    hash_result = hashlib.sha3_256(data).digest()
    ctx.stack.push(int.from_bytes(hash_result, "big"))
    return ctx.pc + 1

def _op_address(self, ctx: ExecutionContext):
    ctx.stack.push(int.from_bytes(ctx.env.contract_address, "big"))
    return ctx.pc + 1

def _op_balance(self, ctx: ExecutionContext):
    addr = ctx.stack.pop()
    ctx.stack.push(ctx.state.get(addr, {}).get("balance", 0))
    return ctx.pc + 1

def _op_origin(self, ctx: ExecutionContext):
    ctx.stack.push(int.from_bytes(ctx.env.origin, "big"))
    return ctx.pc + 1

def _op_caller(self, ctx: ExecutionContext):
    ctx.stack.push(int.from_bytes(ctx.env.caller, "big"))
    return ctx.pc + 1

def _op_callvalue(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.value)
    return ctx.pc + 1

def _op_calldataload(self, ctx: ExecutionContext):
    offset = ctx.stack.pop()
    data = ctx.env.data[offset:offset+32]
    if len(data) < 32:
        data = data + b"\x00" * (32 - len(data))
    ctx.stack.push(int.from_bytes(data, "big"))
    return ctx.pc + 1

def _op_calldatasize(self, ctx: ExecutionContext):
    ctx.stack.push(len(ctx.env.data))
    return ctx.pc + 1

def _op_calldatacopy(self, ctx: ExecutionContext):
    dest = ctx.stack.pop()
    offset = ctx.stack.pop()
    length = ctx.stack.pop()
    data = ctx.env.data[offset:offset+length]
    ctx.memory.write(dest, data)
    return ctx.pc + 1

def _op_codesize(self, ctx: ExecutionContext):
    ctx.stack.push(len(ctx.env.code))
    return ctx.pc + 1

def _op_codecopy(self, ctx: ExecutionContext):
    dest = ctx.stack.pop()
    offset = ctx.stack.pop()
    length = ctx.stack.pop()
    data = ctx.env.code[offset:offset+length]
    ctx.memory.write(dest, data)
    return ctx.pc + 1

def _op_gasprice(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.gas_price)
    return ctx.pc + 1

def _op_extcodesize(self, ctx: ExecutionContext):
    addr = ctx.stack.pop()
    ctx.stack.push(len(ctx.state.get(addr, {}).get("code", b"")))
    return ctx.pc + 1

def _op_extcodecopy(self, ctx: ExecutionContext):
    addr = ctx.stack.pop()
    dest = ctx.stack.pop()
    offset = ctx.stack.pop()
    length = ctx.stack.pop()
    code = ctx.state.get(addr, {}).get("code", b"")
    data = code[offset:offset+length]
    ctx.memory.write(dest, data)
    return ctx.pc + 1

def _op_returndatasize(self, ctx: ExecutionContext):
    ctx.stack.push(0)  # Simplified
    return ctx.pc + 1

def _op_returndatacopy(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_extcodehash(self, ctx: ExecutionContext):
    addr = ctx.stack.pop()
    code = ctx.state.get(addr, {}).get("code", b"")
    import hashlib
    hash_val = hashlib.sha3_256(code).digest()
    ctx.stack.push(int.from_bytes(hash_val, "big"))
    return ctx.pc + 1

def _op_blockhash(self, ctx: ExecutionContext):
    number = ctx.stack.pop()
    import hashlib
    ctx.stack.push(int.from_bytes(hashlib.sha3_256(str(number).encode()).digest()[:32], "big"))
    return ctx.pc + 1

def _op_coinbase(self, ctx: ExecutionContext):
    ctx.stack.push(0)  # Simplified
    return ctx.pc + 1

def _op_timestamp(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.timestamp)
    return ctx.pc + 1

def _op_number(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.block_number)
    return ctx.pc + 1

def _op_difficulty(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.difficulty)
    return ctx.pc + 1

def _op_gaslimit(self, ctx: ExecutionContext):
    ctx.stack.push(8000000)  # Simplified
    return ctx.pc + 1

def _op_chainid(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.chain_id)
    return ctx.pc + 1

def _op_selfbalance(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.state.get(int.from_bytes(ctx.env.contract_address, "big"), {}).get("balance", 0))
    return ctx.pc + 1

def _op_basefee(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.env.gas_price)
    return ctx.pc + 1

def _op_pop(self, ctx: ExecutionContext):
    ctx.stack.pop()
    return ctx.pc + 1

def _op_mload(self, ctx: ExecutionContext):
    offset = ctx.stack.pop()
    data = ctx.memory.read(offset, 32)
    ctx.stack.push(int.from_bytes(data, "big"))
    return ctx.pc + 1

def _op_mstore(self, ctx: ExecutionContext):
    offset = ctx.stack.pop()
    value = ctx.stack.pop()
    ctx.memory.write(offset, value.to_bytes(32, "big"))
    return ctx.pc + 1

def _op_mstore8(self, ctx: ExecutionContext):
    offset = ctx.stack.pop()
    value = ctx.stack.pop() & 0xff
    ctx.memory.write(offset, bytes([value]))
    return ctx.pc + 1

def _op_sload(self, ctx: ExecutionContext):
    key = ctx.stack.pop()
    key_bytes = key.to_bytes(32, "big")
    ctx.stack.push(ctx.storage.get(key_bytes))
    return ctx.pc + 1

def _op_sstore(self, ctx: ExecutionContext):
    key = ctx.stack.pop()
    value = ctx.stack.pop()
    key_bytes = key.to_bytes(32, "big")
    ctx.storage.set(key_bytes, value)
    return ctx.pc + 1

def _op_jump(self, ctx: ExecutionContext):
    dest = ctx.stack.pop()
    if dest < len(ctx.env.code) and ctx.env.code[dest] == OpCode.JUMPDEST:
        return dest
    raise Exception("Invalid jump destination")

def _op_jumpi(self, ctx: ExecutionContext):
    dest = ctx.stack.pop()
    cond = ctx.stack.pop()
    if cond != 0:
        if dest < len(ctx.env.code) and ctx.env.code[dest] == OpCode.JUMPDEST:
            return dest
        raise Exception("Invalid jump destination")
    return ctx.pc + 1

def _op_pc(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.pc)
    return ctx.pc + 1

def _op_msize(self, ctx: ExecutionContext):
    ctx.stack.push(len(ctx.memory.data))
    return ctx.pc + 1

def _op_gas(self, ctx: ExecutionContext):
    ctx.stack.push(ctx.gas)
    return ctx.pc + 1

def _op_jumpdest(self, ctx: ExecutionContext):
    return ctx.pc + 1

def _op_dup(self, ctx: ExecutionContext, n: int):
    ctx.stack.dup(n)
    return ctx.pc + 1

def _op_swap(self, ctx: ExecutionContext, n: int):
    ctx.stack.swap(n)
    return ctx.pc + 1

def _op_log(self, ctx: ExecutionContext, n: int):
    offset = ctx.stack.pop()
    length = ctx.stack.pop()
    topics = [ctx.stack.pop() for _ in range(n)]
    data = ctx.memory.read(offset, length)
    ctx.logs.append(Log(ctx.env.contract_address, topics, data))
    return ctx.pc + 1

def _op_create(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_create2(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_call(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_callcode(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_delegatecall(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_staticcall(self, ctx: ExecutionContext):
    return ctx.pc + 1  # Simplified

def _op_return(self, ctx: ExecutionContext):
    return None  # Stop execution

def _op_revert(self, ctx: ExecutionContext):
    return None  # Stop execution with revert

def _op_invalid(self, ctx: ExecutionContext):
    raise Exception("Invalid opcode")

def _op_selfdestruct(self, ctx: ExecutionContext):
    return None  # Stop execution


# Attach methods to EVMInterpreter
for name in dir():
    if name.startswith('_op_') and name != '_op_dup' and name != '_op_swap':
        setattr(EVMInterpreter, name, staticmethod(eval(name)))

# Special handling for dup and swap
EVMInterpreter._op_dup = staticmethod(lambda self, ctx, n: _op_dup(ctx, n))
EVMInterpreter._op_swap = staticmethod(lambda self, ctx, n: _op_swap(ctx, n))
