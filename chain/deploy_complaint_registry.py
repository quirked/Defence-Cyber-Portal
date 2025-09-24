import os, json
from web3 import Web3
from eth_account import Account
from solcx import install_solc, set_solc_version, compile_standard
from requests.exceptions import ConnectionError as ReqConnError

RPC = os.environ.get("RPC_HTTP_URL", "http://127.0.0.1:8545")
CHAIN_ID = int(os.environ.get("CHAIN_ID", "20250923"))

# Use PRIVATE_KEY from env, else ./ .pk
PK = os.environ.get("PRIVATE_KEY")
if not PK:
    with open(".pk") as f:
        PK = f.read().strip()

# Compile
install_solc("0.8.20")
set_solc_version("0.8.20")
src = open("contracts/ComplaintRegistry.sol").read()
compiled = compile_standard(
    {
        "language": "Solidity",
        "sources": {"ComplaintRegistry.sol": {"content": src}},
        "settings": {"outputSelection": {"*": {"*": ["abi","evm.bytecode"]}}},
    },
    allow_paths="."
)
abi = compiled["contracts"]["ComplaintRegistry.sol"]["ComplaintRegistry"]["abi"]
bytecode = compiled["contracts"]["ComplaintRegistry.sol"]["ComplaintRegistry"]["evm"]["bytecode"]["object"]

w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))
try:
    _ = w3.client_version  # quick handshake
except Exception as e:
    print(f"RPC handshake failed at {RPC}: {e}")
    # try localhost fallback
    RPC = "http://localhost:8545"
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))
    print("Retrying with", RPC)
    _ = w3.client_version
acct = Account.from_key(PK)

# For now, use the same address for both roles
intake = acct.address
analysis = acct.address

Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(acct.address)
tx = Contract.constructor(intake, analysis).build_transaction({
    "from": acct.address,
    "nonce": nonce,
    "gas": 1_800_000,
    "gasPrice": 0,
    "chainId": CHAIN_ID
})
signed = acct.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
rcpt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

print(json.dumps({
    "contractAddress": rcpt.contractAddress,
    "txHash": tx_hash.hex(),
    "blockNumber": rcpt.blockNumber,
    "intake": intake,
    "analysis": analysis
}, indent=2))