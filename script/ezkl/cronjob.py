import requests
from typing import List
import time
import logging
from datetime import datetime
import json
from web3 import Web3
import logging
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cronjob.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Delay between calls in seconds
DELAY = 24 * 60 * 60

# API key
API_KEY = ""

# UniTickAttestor contract address
CONTRACT_ADDRESS = ""

# Risk Engine
RISK_ENGINE = ""

# Pool Id
POOL_ID = ""

# Asset
ASSET = ""

# Chain
CHAIN = "arbitrum"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fetch_data.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
ARBITRUM_RPC_URL = "https://arb1.arbitrum.io/rpc"
CONTRACT_ADDRESS = ""  # Add your UniTickAttestor contract address
DAYS_AGO = 20

# ABI for the consult function
ABI = [
    {
        "inputs": [
            {
                "internalType": "uint32",
                "name": "daysAgo",
                "type": "uint32"
            }
        ],
        "name": "consult",
        "outputs": [
            {
                "internalType": "int256[]",
                "name": "raioCumulatives",
                "type": "int256[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

def fetch_ratio_data() -> List[int]:
    """
    Fetches ratio data from the UniTickAttestor contract for the last 20 days.
    
    Returns:
        List[int]: List of ratio values for the specified number of days
    """
    try:
        # Initialize Web3
        w3 = Web3(Web3.HTTPProvider(ARBITRUM_RPC_URL))
        
        if not w3.is_connected():
            raise Exception("Failed to connect to Arbitrum network")
            
        logger.info("Connected to Arbitrum network")
        
        # Initialize contract
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=ABI
        )
        
        # Call consult function
        ratio_data = contract.functions.consult(DAYS_AGO).call()
        
        logger.info(f"Successfully fetched ratio data for {DAYS_AGO} days")
        logger.info(f"Ratio data: {ratio_data}")
        
        return ratio_data
        
    except Exception as e:
        logger.error(f"Error fetching ratio data: {str(e)}", exc_info=True)
        raise

def get_input_data() -> List[int]:
    """
    Main function to get input data for the cronjob script.
    
    Returns:
        List[int]: List of ratio values to be used as input data
    """
    try:
        ratio_data = fetch_ratio_data()
        return ratio_data
        
    except Exception as e:
        logger.error("Failed to get input data", exc_info=True)
        # Return None or raise exception based on your error handling preference
        raise

if __name__ == "__main__":
    try:
        input_data = get_input_data()
        print(f"Input data for cronjob: {input_data}")
    except Exception as e:
        logger.error("Script execution failed", exc_info=True)

def main(
    api_key: str,
    contract_address: str,
    input_data: List[int],
    action: int,
    risk_engine: str,
    pool_id: int,
    asset: str,
    chain: str = "arbitrum",
) -> None:
    try:
        res = requests.post(
            url="https://archon-v0.ezkl.xyz/recipe",
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
            json={
                "commands": [
                    {
                        "artifact": "garch-deploy",
                        "binary": "ezkl",
                        "deployment": None,
                        "command": [
                            "gen-witness",
                            "--data input.json",
                            "--compiled-circuit model.compiled",
                            "--output witness.json"
                        ],
                    },
                    {
                        "artifact": "garch-deploy",
                        "deployment": None,
                        "binary": "ezkl",
                        "command": [
                            "prove",
                            "--witness witness.json",
                            "--compiled-circuit model.compiled",
                            "--pk-path pk.key",
                            "--proof-path proof.json",
                        ],
                        "output_path": ["proof.json"]
                    },
                ],
                "data": [{
                    "target_path": "input.json",
                    "data": {
                        "input_data": [input_data]
                    }
                }],
                "response_settings": {
                    "callback": {
                        "chain": chain,
                        "contract_address": contract_address,
                        "function_interface": "function ltvUpdate(uint256 _action, address _riskEngine, uint256 _poolId, address _asset, bytes calldata proof, uint256[] calldata instances)",
                        "function_args": f'[{action}, {risk_engine}, {pool_id}, {asset}, "proof", "instances"]',
                    },
                },
            }
        )

        if res.status_code >= 400:
            logger.error(f"HTTP {res.status_code} error occurred")
            error_message = res.json().get('message', 'No error message provided')
            logger.error(f"Error message: {error_message}")
        else:
            data = res.json()
            logger.info(f"Request successful. Response data: {data}")
            logger.info(f"Get results with `archon get -i {data['id']}`")

    except Exception as e:
        logger.error(f"Error in API request: {str(e)}", exc_info=True)


if __name__ == "__main__":
    logger.info("Starting application...")

    while True:
        try:
            with open('timelog.txt', "r") as f:
                time_last = int(f.read())
                time_now = time.time()

                if time_now - time_last > DELAY:
                    logger.info("Delay period elapsed, executing main function")
                    main(
                        api_key=API_KEY,
                        contract_address=CONTRACT_ADDRESS,
                        input_data=input_data, 
                        action=0,
                        risk_engine=RISK_ENGINE,
                        pool_id=POOL_ID,
                        asset=ASSET,
                        chain="arbitrum",
                    )

        except FileNotFoundError:
            logger.info("Timelog file not found, creating new file")
            with open("timelog.txt", "w") as f:
                time_now = str(int(time.time()))
                f.write(time_now)

            logger.info("Executing main function for first time")
            main(
                api_key=API_KEY,
                contract_address=CONTRACT_ADDRESS,
                input_data=input_data, 
                action=0,
                risk_engine=RISK_ENGINE,
                pool_id=POOL_ID,
                asset=ASSET,
                chain="arbitrum",
            )

        except ValueError:
            logger.warning("Invalid data in timelog file, resetting file")
            with open("timelog.txt", "w") as f:
                time_now = str(int(time.time()))
                f.write(time_now)

            logger.info("Executing main function after resetting timelog")
            main(
                api_key=API_KEY,
                contract_address=CONTRACT_ADDRESS,
                input_data=input_data,
                action=0,
                risk_engine=RISK_ENGINE,
                pool_id=POOL_ID,
                asset=ASSET,
                chain="arbitrum",
            )

        logger.info("Sleeping as callback has been run...")
        # sleep every 60 seconds
        time.sleep(60)
