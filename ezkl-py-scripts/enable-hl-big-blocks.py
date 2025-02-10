import argparse
from dotenv import load_dotenv
from web3 import Web3
import os
import requests

from hyperliquid.utils.signing import (
    get_timestamp_ms,
    sign_l1_action,
)

load_dotenv()

def main(using_big_blocks):
    private_key = os.getenv("PRIVKEY")
    
    wallet = Web3().eth.account.from_key(private_key)
    print(f"Using wallet: {wallet.address}")

    timestamp = get_timestamp_ms()
    print(f"Using timestamp: {timestamp}")

    action = {
        "type": "evmUserModify",
        "usingBigBlocks": using_big_blocks
    }
    print(f"Using useBigBlock: {action}")

    signature = sign_l1_action(
        wallet,
        action,
        None,
        timestamp,
        False,  # False=Testnet, True=Mainnet
    )

    payload = {
        "action": action,
        "nonce": timestamp,
        "signature": signature
    }
    print(f"Using payload: {payload}")

    # Send the POST request
    response = requests.post(
        "https://api.hyperliquid-testnet.xyz/exchange",
        headers={"Content-Type": "application/json"},
        json=payload
    )

    # Print the response
    print(response.status_code)
    print(response.json())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to modify usingBigBlocks value.")
    parser.add_argument("usingBigBlocks", type=str, choices=["true", "false"], help="Boolean value for usingBigBlocks")
    args = parser.parse_args()

    # Convert the string argument to a boolean
    using_big_blocks = args.usingBigBlocks.lower() == "true"

    main(using_big_blocks)