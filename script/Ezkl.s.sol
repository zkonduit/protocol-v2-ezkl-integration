// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseScript} from "./BaseScript.s.sol";
import {Halo2Verifier} from "src/ezkl/Verifier.sol";
import {SentimentOracleCache} from "src/ezkl/SentimentOracleCache.sol";
import {Comptroller} from "src/ezkl/Comptroller.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Pool} from "src/Pool.sol";
import {Position} from "src/Position.sol";
import {PositionManager} from "src/PositionManager.sol";
import {Registry} from "src/Registry.sol";
import {RiskEngine} from "src/RiskEngine.sol";
import {RiskModule} from "src/RiskModule.sol";
import {SuperPoolFactory} from "src/SuperPoolFactory.sol";
import {PortfolioLens} from "src/lens/PortfolioLens.sol";
import {SuperPoolLens} from "src/lens/SuperPoolLens.sol";

contract Ezkl is BaseScript {
    // Halo2 verifier
    Halo2Verifier public verifier;
    // Sentiment oracle cache
    SentimentOracleCache public sentimentOracleCache;
    // Comptroller
    Comptroller public comptroller;

    // TODO
}
