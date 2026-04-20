"""
NexusChain - Utility Functions
"""

import hashlib
import json
from typing import Any, Dict


def keccak256(data: bytes) -> bytes:
    """Ethereum's keccak256 hash function"""
    return hashlib.sha3_256(data)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string"""
    return "0x" + data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def encode_uint256(value: int) -> bytes:
    """Encode integer as uint256 (32 bytes big-endian)"""
    return value.to_bytes(32, "big")


def decode_uint256(data: bytes) -> int:
    """Decode uint256 to integer"""
    return int.from_bytes(data[:32], "big")


def encode_address(address: bytes) -> bytes:
    """Encode address (20 bytes, padded)"""
    return address[:20].rjust(20, b"\x00")


def decode_address(data: bytes) -> bytes:
    """Decode address from 32-byte field"""
    return data[12:32]


def format_gwei(wei: int) -> str:
    """Format wei as Gwei string"""
    return f"{wei / 1e9:.9f} Gwei"


def format_eth(wei: int) -> str:
    """Format wei as ETH string"""
    return f"{wei / 1e18:.18f} ETH"


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for NexusChain types"""
    
    def default(self, obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__bytes__"):
            return "0x" + bytes(obj).hex()
        if isinstance(obj, bytes):
            return "0x" + obj.hex()
        return super().default(obj)


def to_json(obj: Any) -> str:
    """Convert object to JSON string"""
    return json.dumps(obj, cls=JSONEncoder, indent=2)


def from_json(json_str: str) -> Any:
    """Parse JSON string"""
    return json.loads(json_str)
