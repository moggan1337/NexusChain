"""
NexusChain - JSON-RPC Server

Provides Ethereum-compatible JSON-RPC interface for Layer 2.
"""

from __future__ import annotations
import json
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time

from ..zk_rollup.types import (
    Transaction, TransactionType, Address, Amount, Hash,
    Block, BlockHeader, Account, HashlibHasher
)
from ..sequencer.block import Sequencer, SequencerConfig
from ..txpool.pool import TransactionPool
from ..state.merkle import ZKStateTree


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RPCRequest:
    """JSON-RPC request"""
    jsonrpc: str = "2.0"
    method: str = ""
    params: List = field(default_factory=list)
    id: int = 1


@dataclass
class RPCResponse:
    """JSON-RPC response"""
    jsonrpc: str = "2.0"
    result: Any = None
    error: Optional[Dict] = None
    id: int = 1
    
    def to_dict(self) -> Dict:
        if self.error:
            return {
                "jsonrpc": self.jsonrpc,
                "error": self.error,
                "id": self.id
            }
        return {
            "jsonrpc": self.jsonrpc,
            "result": self.result,
            "id": self.id
        }


class RPCHandler:
    """
    JSON-RPC request handler
    
    Implements Ethereum-compatible RPC methods.
    """
    
    def __init__(self, sequencer: Sequencer, txpool: TransactionPool):
        self.sequencer = sequencer
        self.txpool = txpool
        self.state_tree = sequencer.state_tree
        
        # Register handlers
        self.handlers: Dict[str, Callable] = {
            # Chain info
            "eth_chainId": self.eth_chain_id,
            "eth_blockNumber": self.eth_block_number,
            "eth_getBlockByNumber": self.eth_get_block_by_number,
            "eth_getBlockByHash": self.eth_get_block_by_hash,
            "eth_getTransactionByHash": self.eth_get_transaction_by_hash,
            "eth_getTransactionReceipt": self.eth_get_transaction_receipt,
            
            # State
            "eth_getBalance": self.eth_get_balance,
            "eth_getCode": self.eth_get_code,
            "eth_getStorageAt": self.eth_get_storage_at,
            "eth_call": self.eth_call,
            "eth_estimateGas": self.eth_estimate_gas,
            
            # Transactions
            "eth_sendTransaction": self.eth_send_transaction,
            "eth_sendRawTransaction": self.eth_send_raw_transaction,
            "eth_getTransactionCount": self.eth_get_transaction_count,
            
            # Gas
            "eth_gasPrice": self.eth_gas_price,
            "eth_maxPriorityFeePerGas": self.eth_max_priority_fee_per_gas,
            
            # Accounts
            "eth_accounts": self.eth_accounts,
            "personal_listAccounts": self.personal_list_accounts,
            
            # Filter
            "eth_newFilter": self.eth_new_filter,
            "eth_getFilterChanges": self.eth_get_filter_changes,
            "eth_uninstallFilter": self.eth_uninstall_filter,
            
            # Misc
            "net_version": self.net_version,
            "web3_clientVersion": self.web3_client_version,
        }
    
    def handle(self, request: Dict) -> RPCResponse:
        """Handle a JSON-RPC request"""
        try:
            method = request.get("method")
            params = request.get("params", [])
            request_id = request.get("id", 1)
            
            if method not in self.handlers:
                return RPCResponse(
                    error={"code": -32601, "message": f"Method not found: {method}"},
                    id=request_id
                )
            
            handler = self.handlers[method]
            result = handler(params)
            
            return RPCResponse(result=result, id=request_id)
            
        except Exception as e:
            logger.error(f"RPC error: {e}")
            return RPCResponse(
                error={"code": -32603, "message": str(e)},
                id=request.get("id", 1)
            )
    
    # ========================================================================
    # Chain Info Methods
    # ========================================================================
    
    def eth_chain_id(self, params: List) -> int:
        """Get chain ID"""
        return 1337  # NexusChain L2 chain ID
    
    def eth_block_number(self, params: List) -> str:
        """Get current block number"""
        block_num = self.sequencer.state.current_block_number
        return hex(block_num)
    
    def eth_get_block_by_number(self, params: List) -> Dict:
        """Get block by number"""
        block_num = params[0] if params else "latest"
        
        # Parse block number
        if block_num == "latest":
            block_num = self.sequencer.state.current_block_number
        elif block_num == "earliest":
            block_num = 1
        elif block_num == "pending":
            block_num = self.sequencer.state.current_block_number + 1
        else:
            block_num = int(block_num, 16)
        
        # Get block (simplified)
        return {
            "number": hex(block_num),
            "hash": "0x" + "00" * 32,
            "parentHash": "0x" + "00" * 32,
            "timestamp": hex(int(time.time())),
            "transactions": [],
            "gasLimit": hex(8000000),
            "gasUsed": hex(0),
            "difficulty": hex(0),
            "miner": "0x" + "00" * 20,
            "stateRoot": "0x" + self.sequencer.state.state_root.hex(),
            "receiptsRoot": "0x" + "00" * 32,
            "transactionsRoot": "0x" + "00" * 32,
        }
    
    def eth_get_block_by_hash(self, params: List) -> Optional[Dict]:
        """Get block by hash"""
        return self.eth_get_block_by_number(params)
    
    def eth_get_transaction_by_hash(self, params: List) -> Optional[Dict]:
        """Get transaction by hash"""
        tx_hash = params[0]
        tx = self.txpool.get_transaction(bytes.fromhex(tx_hash.replace("0x", "")))
        
        if not tx:
            return None
        
        return {
            "hash": "0x" + tx.hash.hex(),
            "blockNumber": None,  # Not yet mined
            "from": "0x" + tx.sender.hex(),
            "to": "0x" + tx.recipient.hex(),
            "value": hex(tx.amount),
            "gas": hex(21000),
            "gasPrice": hex(tx.fee // 21000 if tx.fee > 0 else 0),
            "input": "0x" + tx.data.hex(),
            "v": 27,
            "r": 0,
            "s": 0,
            "nonce": hex(tx.nonce),
            "transactionIndex": None,
        }
    
    def eth_get_transaction_receipt(self, params: List) -> Optional[Dict]:
        """Get transaction receipt"""
        tx_hash = params[0]
        # In production, query the sequencer's blocks
        return None
    
    # ========================================================================
    # State Methods
    # ========================================================================
    
    def eth_get_balance(self, params: List) -> str:
        """Get account balance"""
        address = Address(bytes.fromhex(params[0].replace("0x", "")))
        account = self.sequencer.evm_state.get_account(address)
        return hex(account.balance)
    
    def eth_get_code(self, params: List) -> str:
        """Get contract code"""
        address = Address(bytes.fromhex(params[0].replace("0x", "")))
        code = self.sequencer.evm_state.get_code(address)
        return "0x" + code.hex()
    
    def eth_get_storage_at(self, params: List) -> str:
        """Get storage value at key"""
        address = Address(bytes.fromhex(params[0].replace("0x", "")))
        position = params[1]
        value = self.sequencer.evm_state.get_storage(address, bytes.fromhex(position.replace("0x", "")))
        return "0x" + value.hex()
    
    def eth_call(self, params: List) -> str:
        """Execute call without state changes"""
        # In production, this would execute the EVM
        return "0x"
    
    def eth_estimate_gas(self, params: List) -> str:
        """Estimate gas for transaction"""
        return hex(21000)
    
    # ========================================================================
    # Transaction Methods
    # ========================================================================
    
    def eth_send_transaction(self, params: List) -> str:
        """Send transaction (requires unlocked account)"""
        tx_data = params[0]
        
        # Create transaction
        tx = Transaction(
            transaction_type=TransactionType.CALL_CONTRACT if tx_data.get("to") else TransactionType.DEPLOY_CONTRACT,
            sender=bytes.fromhex(tx_data.get("from", "").replace("0x", "")),
            recipient=bytes.fromhex(tx_data.get("to", "0" * 40).replace("0x", "")),
            amount=int(tx_data.get("value", "0x0"), 16),
            fee=int(tx_data.get("gasPrice", "0x0"), 16) * 21000,
            nonce=int(tx_data.get("nonce", "0x0"), 16),
            data=bytes.fromhex(tx_data.get("data", "0x").replace("0x", ""))
        )
        
        # Sign (simplified - in production, use private key)
        tx.sign(bytes([1] * 32))
        
        # Submit to sequencer
        self.sequencer.submit_transaction(tx)
        
        return "0x" + tx.hash.hex()
    
    def eth_send_raw_transaction(self, params: List) -> str:
        """Send raw signed transaction"""
        raw_tx = bytes.fromhex(params[0].replace("0x", ""))
        
        # Parse transaction (simplified)
        # In production, use proper RLP decoding
        
        # For now, create a placeholder transaction
        tx = Transaction(
            transaction_type=TransactionType.TRANSFER,
            sender=b"\x00" * 20,
            recipient=b"\x00" * 20,
            amount=0,
            fee=0,
            nonce=0
        )
        
        return "0x" + tx.hash.hex()
    
    def eth_get_transaction_count(self, params: List) -> str:
        """Get transaction count for address"""
        address = Address(bytes.fromhex(params[0].replace("0x", "")))
        nonce = self.txpool.get_next_nonce(address)
        return hex(nonce)
    
    # ========================================================================
    # Gas Methods
    # ========================================================================
    
    def eth_gas_price(self, params: List) -> str:
        """Get current gas price"""
        return hex(1000000000)  # 1 gwei
    
    def eth_max_priority_fee_per_gas(self, params: List) -> str:
        """Get max priority fee per gas"""
        return hex(100000000)  # 0.1 gwei
    
    # ========================================================================
    # Account Methods
    # ========================================================================
    
    def eth_accounts(self, params: List) -> List[str]:
        """Get available accounts"""
        return []
    
    def personal_list_accounts(self, params: List) -> List[str]:
        """List accounts (personal)"""
        return []
    
    # ========================================================================
    # Filter Methods
    # ========================================================================
    
    def eth_new_filter(self, params: List) -> str:
        """Create new filter"""
        return hex(0)
    
    def eth_get_filter_changes(self, params: List) -> List:
        """Get filter changes"""
        return []
    
    def eth_uninstall_filter(self, params: List) -> bool:
        """Uninstall filter"""
        return True
    
    # ========================================================================
    # Misc Methods
    # ========================================================================
    
    def net_version(self, params: List) -> str:
        """Get network version"""
        return "1337"
    
    def web3_client_version(self, params: List) -> str:
        """Get client version"""
        return "NexusChain/v0.1.0"


class RPCHandlerRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for JSON-RPC"""
    
    def __init__(self, *args, handler: RPCHandler = None, **kwargs):
        self.handler = handler
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            request = json.loads(body.decode())
            
            # Handle batch requests
            if isinstance(request, list):
                responses = [self.handler.handle(r) for r in request]
                body = json.dumps([r.to_dict() for r in responses])
            else:
                response = self.handler.handle(request)
                body = json.dumps(response.to_dict())
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
            
        except Exception as e:
            logger.error(f"HTTP error: {e}")
            self.send_response(500)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class RPCServer:
    """
    JSON-RPC Server
    
    Provides Ethereum-compatible RPC interface for NexusChain L2.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8547):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[Thread] = None
        
        # Components (set via set_sequencer)
        self.sequencer: Optional[Sequencer] = None
        self.txpool: Optional[TransactionPool] = None
        self.handler: Optional[RPCHandler] = None
    
    def set_sequencer(self, sequencer: Sequencer):
        """Set sequencer and create handler"""
        self.sequencer = sequencer
        self.txpool = sequencer.txpool
        self.handler = RPCHandler(sequencer, self.txpool)
    
    def start(self):
        """Start the RPC server"""
        if not self.handler:
            raise ValueError("Handler not set. Call set_sequencer first.")
        
        handler = lambda *args, **kwargs: RPCHandlerRequestHandler(
            *args, handler=self.handler, **kwargs
        )
        
        self.server = HTTPServer((self.host, self.port), handler)
        
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        
        logger.info(f"RPC server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the RPC server"""
        if self.server:
            self.server.shutdown()
            self.server = None
        logger.info("RPC server stopped")
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.server is not None and self.thread is not None and self.thread.is_alive()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for RPC server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NexusChain RPC Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8547, help="Port to bind to")
    parser.add_argument("--sequencer-url", default=None, help="Sequencer URL (for remote)")
    
    args = parser.parse_args()
    
    # Create components
    txpool = TransactionPool()
    config = SequencerConfig()
    sequencer = Sequencer(txpool, config)
    
    # Create and start RPC server
    rpc_server = RPCServer(args.host, args.port)
    rpc_server.set_sequencer(sequencer)
    rpc_server.start()
    
    print(f"NexusChain RPC server running on http://{args.host}:{args.port}")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping RPC server...")
        rpc_server.stop()


if __name__ == "__main__":
    main()
