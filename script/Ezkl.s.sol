// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseScript} from "./BaseScript.s.sol";
import {Halo2Verifier} from "src/ezkl/Verifier.sol";
import {SentimentOracleCache} from "src/ezkl/SentimentOracleCache.sol";
import {Comptroller} from "src/ezkl/Comptroller.sol";

import {MockERC20} from "test/mocks/MockERC20.sol";
import {Pool} from "src/Pool.sol";
import {RiskEngine} from "src/RiskEngine.sol";

contract Ezkl is BaseScript {
    // Halo2 verifier
    Halo2Verifier public verifier;
    // Sentiment oracle cache
    SentimentOracleCache public sentimentOracleCache;
    // Comptroller
    Comptroller public comptroller;
    // Pool ID
    uint256 public poolId;

    struct EzklParams {
        uint lookbackDays; // Number of days the GARCH model looks backs to for computing volatility
        int256[] dailyPrices; // Initial daily prices to populate the SentimentOracleCache with (for testing purposes exclusively)
        address debtToken; // Debt token used for the initial price data (Debt/Asset)
        address assetToken; // Asset token used for the initial price data (Debt/Asset)
        uint8 scales; // Number of bits the fixed point numbers are scaled by for the EZKL GARCH model inputs.
        address owner; // Owner of the comptroller contract
        address riskEngine; // Sentiment Risk Engine Address
        address pool; // Sentiment Pool Address
        bytes32 modelKey; // Model key
    }

    EzklParams public params;

    function run() public {
        fetchParams();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        _run();
        vm.stopBroadcast();
    }

    function runWithParams(EzklParams memory _params) public {
        params = _params;
        _run();
    }

    function _run() internal {
        verifier = new Halo2Verifier();

        // Take last lookbackDays prices
        int256[] memory recentPrices = new int256[](params.lookbackDays);
        for (uint i = 0; i < params.lookbackDays; i++) {
            recentPrices[i] = params.dailyPrices[
                params.dailyPrices.length - params.lookbackDays + i
            ];
        }
        uint256[] memory scales = new uint256[](params.lookbackDays);
        for (uint i = 0; i < params.lookbackDays; i++) {
            scales[i] = params.scales;
        }
        sentimentOracleCache = new SentimentOracleCache(
            recentPrices,
            params.riskEngine,
            params.debtToken,
            params.assetToken
        );
        bytes memory callData = abi.encodeWithSelector(
            sentimentOracleCache.consult.selector,
            params.lookbackDays,
            params.debtToken,
            params.assetToken
        ); // The call data which fetches the data to be attested to.

        comptroller = new Comptroller(
            callData,
            MockERC20(params.debtToken).decimals(),
            scales,
            0, // instance offset is 0 since we are attesting to the model inputs
            params.owner,
            address(verifier),
            address(sentimentOracleCache),
            params.pool,
            params.debtToken
        );
        poolId = Pool(params.pool).initializePool(
            address(comptroller),
            params.debtToken,
            params.modelKey,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        if (block.chainid != 31_337) generateLogs();
    }

    function fetchParams() internal {
        string memory config = getConfig();

        params.lookbackDays = vm.parseJsonUint(config, "$.Ezkl.lookbackDays");
        string memory jsonData = vm.readFile("price_data.json");
        bytes memory parsedData = vm.parseJson(jsonData);
        params.dailyPrices = abi.decode(parsedData, (int256[]));
        params.debtToken = vm.parseJsonAddress(config, "$.Ezkl.debtToken");
        params.assetToken = vm.parseJsonAddress(config, "$.Ezkl.assetToken");
        params.scales = uint8(vm.parseJsonUint(config, "$.Ezkl.scales"));
        params.owner = vm.parseJsonAddress(config, "$.Ezkl.owner");
        params.riskEngine = vm.parseJsonAddress(config, "$.Ezkl.riskEngine");
        params.pool = vm.parseJsonAddress(config, "$.Ezkl.pool");
        params.modelKey = vm.parseJsonBytes32(config, "$.Ezkl.modelKey");
    }

    function generateLogs() internal {
        string memory obj = "Deploy";

        // deployed contracts
        vm.serializeAddress(obj, "verifier", address(verifier));
        vm.serializeAddress(
            obj,
            "sentimentOracleCache",
            address(sentimentOracleCache)
        );
        vm.serializeAddress(obj, "comptroller", address(comptroller));
        vm.serializeUint(obj, "poolId", poolId);

        // deployment details
        vm.serializeUint(obj, "chainId", block.chainid);
        string memory json = vm.serializeUint(
            obj,
            "timestamp",
            vm.getBlockTimestamp()
        );

        string memory path = string.concat(
            getLogPathBase(),
            "Deploy-",
            vm.toString(vm.getBlockTimestamp()),
            ".json"
        );
        vm.writeJson(json, path);
    }
}
