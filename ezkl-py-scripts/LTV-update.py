import requests
from typing import List
import time
import logging
from datetime import datetime
from dotenv import load_dotenv
import json
from web3 import Web3
import logging
from typing import List
import os

# Load environment variables
load_dotenv()

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

SECONDS_IN_DAY = 86400

# Delay between LTV update calls in seconds, every 20 days
LTV_UPDATE_PERIOD = (SECONDS_IN_DAY)*20

# SentimentOracleCache contract address
ORACLE_CACHE_ADDRESS = "0x8f981a7d8Ed904964160BB90c94B87216874F591"

# Comptroller contract address
COMPTROLLER_ADDRESS = "0xdFfDF3DfDeD0532B5549e5330FD5576c33F468c0"

# Risk Engine
RISK_ENGINE = "0x3463E8dBC202074c0c0102fD367a914d2FF22e90"

# Pool Id
POOL_ID = "106862083712814642108280330106973632744360221096518562188891018686660283800368"

# Debt Token Address
DEBT = "0x765a02fF66731f7551c8212b0aB777B2392Ae903"

# Asset Token Address
ASSET = "0x3f7D64EB22BE53f618adCAe15aa10b61bdB14d89"

# Chain
CHAIN = "hyperliquidTestnet"

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
HL_TEST_RPC_URL = "https://api.hyperliquid-testnet.xyz/evm"
DAYS_AGO = 20

# ABI for the comptroller with just consult function
ABI_CACHE = [
    {
        "inputs": [
                {
                    "name": "daysAgo",
                    "type": "uint32",
                    "internalType": "uint32"
                },
                {
                    "name": "debtToken",
                    "type": "address",
                    "internalType": "address"
                },
                {
                    "name": "assetToken",
                    "type": "address",
                    "internalType": "address"
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
# ABI for the ERC20 token with just decimals function
ABI_ERC20 = [
    {
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "internalType": "uint8",
                "name": "",
                "type": "uint8"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

def fetch_ratio_data() -> List[int]:
    """
    Fetches ratio data from the SentimentOracleCache contract for the last 20 days.
    
    Returns:
        List[int]: List of prices for the specified number of days
    """
    try:
        # Initialize Web3
        w3 = Web3(Web3.HTTPProvider(HL_TEST_RPC_URL))
        
        if not w3.is_connected():
            raise Exception("Failed to connect to hyperliquid test network")
            
        logger.info("Connected to hyperliquid test network")
        
        # Initialize contracts
        contract = w3.eth.contract(
            address=ORACLE_CACHE_ADDRESS,
            abi=ABI_CACHE
        )
        debt_token = w3.eth.contract(
            address=DEBT,
            abi=ABI_ERC20
        )
        
        # Call consult function to fetch ratio data
        ratio_data = contract.functions.consult(DAYS_AGO, DEBT, ASSET).call()

        # Call the decimals function on the debt token (b/c the ratio is in the debt token's decimals)
        debt_decimals = debt_token.functions.decimals().call()

        # Convert the ratio data to the correct decimal value
        ratio_data = [ratio / 10 ** debt_decimals for ratio in ratio_data]
        
        logger.info(f"Successfully fetched ratio data for {DAYS_AGO} days for debt {DEBT} and asset {ASSET} pairs")
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
    chain: str,
) -> None:
    # Build function arguments as a Python list.
    function_args_list = [
        action,
        risk_engine,
        pool_id,
        asset,
        "proof",
        "instances"
    ]

    # Serialize the list to a JSON string.
    function_args_json = json.dumps(function_args_list)
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
                        "artifact": "garch",
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
                        "artifact": "garch",
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
                        "function_interface": "function ltvUpdate(uint8 _action, address _riskEngine, uint256 _poolId, address _asset, bytes calldata proof, uint256[] calldata instances)",
                        "function_args": function_args_json,
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
    try:
        input_data = get_input_data()
        print(f"Input data for cronjob: {input_data}")
    except Exception as e:
        logger.error("Script execution failed", exc_info=True)

    api_key = os.getenv("ARCHON_API_KEY")

    while True:
        try:
            with open('timelog.txt', "r") as f:
                time_last = int(f.read())
                time_now = time.time()

                if time_now - time_last > LTV_UPDATE_PERIOD:
                    logger.info("LTV update period elapsed, executing main function to perfrom LTV update")
                    main(
                        api_key=api_key,
                        contract_address=COMPTROLLER_ADDRESS,
                        input_data=input_data, 
                        action=0,
                        risk_engine=RISK_ENGINE,
                        pool_id=POOL_ID,
                        asset=ASSET,
                        chain=CHAIN,
                    )
                if time_now - time_last > (LTV_UPDATE_PERIOD + SECONDS_IN_DAY):
                    logger.info("LTV update delay period elapsed, executing main function")
                    main(
                        api_key=api_key,
                        contract_address=COMPTROLLER_ADDRESS,
                        input_data=input_data, 
                        action=1,
                        risk_engine=RISK_ENGINE,
                        pool_id=POOL_ID,
                        asset=ASSET,
                        chain=CHAIN,
                    )   
                    # if the delay period has elapsed, update the timelog file
                    with open("timelog.txt", "w") as f:
                        time_now = str(int(time.time()))
                        f.write(time_now)          

        except FileNotFoundError:
            logger.info("Timelog file not found, creating new file")
            with open("timelog.txt", "w") as f:
                time_now = str(int(time.time()))
                f.write(time_now)

            logger.info("Executing main function for first time")
            main(
                api_key=api_key,
                contract_address=COMPTROLLER_ADDRESS,
                input_data=input_data, 
                action=0,
                risk_engine=RISK_ENGINE,
                pool_id=POOL_ID,
                asset=ASSET,
                chain=CHAIN,
            )

        except ValueError:
            logger.warning("Invalid data in timelog file, resetting file")
            with open("timelog.txt", "w") as f:
                time_now = str(int(time.time()))
                f.write(time_now)

            logger.info("Executing main function after resetting timelog")
            main(
                api_key=api_key,
                contract_address=COMPTROLLER_ADDRESS,
                input_data=input_data,
                action=0,
                risk_engine=RISK_ENGINE,
                pool_id=POOL_ID,
                asset=ASSET,
                chain=CHAIN,
            )

        logger.info("Sleeping as callback has been run...")
        # sleep every 60 seconds
        time.sleep(60)
