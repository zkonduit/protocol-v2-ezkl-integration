import requests
from typing import List
import time
import logging
from datetime import datetime

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

# Contract address
CONTRACT_ADDRESS = ""

# Risk Engine
RISK_ENGINE = ""

# Pool Id
POOL_ID = ""

# Asset
ASSET = ""

# Chain
CHAIN = "arbitrum"

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
                        input_data=[1,2,3,4],  # TODO: Create a script to obtain this automatically
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
                input_data=[1,2,3,4],  # TODO: Create a script to obtain this automatically
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
                input_data=[1,2,3,4],  # TODO: Create a script to obtain this automatically
                action=0,
                risk_engine=RISK_ENGINE,
                pool_id=POOL_ID,
                asset=ASSET,
                chain="arbitrum",
            )

        logger.info("Sleeping as callback has been run...")
        # sleep every 60 seconds
        time.sleep(60)
