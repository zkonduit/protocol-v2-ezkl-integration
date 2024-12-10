// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {RiskEngine} from "../RiskEngine.sol";
import {DataAttestationSingle} from "./DA.sol";
import {UniTickAttestor} from "./UniTickAttestor.sol";
import {Halo2Verifier} from "./Verifier.sol";

/// @title Replaces governance control of `RiskEngine.sol` with a comptroller contact
/// @notice Handles data aggregation, data attestation and verification of an off-chain data science model SNARKED using EZKL library

interface MockERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface ProtocolPool {
    function initializePool(
        address owner,
        address asset,
        bytes32 rateModelKey,
        uint256 depositCap,
        uint256 borrowCap,
        uint256 initialDepositAmt
    ) external returns (uint256 poolId);
}

contract Comptroller is DataAttestationSingle {
    address public verifier;
    bytes32 FIXED_RATE_MODEL_KEY =
        0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b;
    bytes32 LINEAR_RATE_MODEL_KEY =
        0x7922391f605f567c8e61c33be42b581e2f71019b5dce3c47110ad332b7dbd68c;
    bytes32 FIXED_RATE_MODEL2_KEY =
        0x65347a20305cbd3ca20cb81ec8a2261639f4e635b4b5f3039a9aa5e7e03f41a7;
    bytes32 LINEAR_RATE_MODEL2_KEY =
        0xd61dc960093d99acc135f998430c41a550d91de727e66a94fd8e7a8a24d99ecf;

    enum LtvUpdate {
        Request,
        Accept,
        Reject
    }

    constructor(
        bytes memory _callData,
        uint256 _decimals,
        uint[20] memory _scales,
        uint8 _instanceOffset,
        address _admin,
        address _verifier,
        address _uniTickAttestor
    )
        DataAttestationSingle(
            _uniTickAttestor,
            _callData,
            _decimals,
            _scales,
            _instanceOffset,
            _admin
        )
    {
        verifier = _verifier;
    }

    // TODO make this an admin function.
    function approveRiskEngine(
        address asset1,
        address asset2,
        address pool
    )
        external
        returns (
            uint256 fixedRatePool,
            uint256 linearRatePool,
            uint256 fixedRatePool2,
            uint256 linearRatePool2,
            uint256 alternateAssetPool
        )
    {
        MockERC20(asset1).approve(address(pool), type(uint256).max);
        MockERC20(asset2).approve(address(pool), type(uint256).max);
        fixedRatePool = ProtocolPool(pool).initializePool(
            address(this),
            address(asset1),
            FIXED_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        linearRatePool = ProtocolPool(pool).initializePool(
            address(this),
            address(asset1),
            LINEAR_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        fixedRatePool2 = ProtocolPool(pool).initializePool(
            address(this),
            address(asset1),
            FIXED_RATE_MODEL2_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        linearRatePool2 = ProtocolPool(pool).initializePool(
            address(this),
            address(asset1),
            LINEAR_RATE_MODEL2_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        alternateAssetPool = ProtocolPool(pool).initializePool(
            address(this),
            address(asset2),
            FIXED_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
    }
    function ltvUpdate(
        LtvUpdate _action,
        address _riskEngine,
        uint256 _poolId,
        address _asset,
        bytes memory proof,
        uint[] memory instances
    ) external {
        if (_action == LtvUpdate.Request) {
            // fetch the instances value at index 20 (LTC, aka output), then scale it to e18
            uint256 volatility = instances[20];
            // perform 1 - volatility scales to get ltv
            uint256 ltv;
            unchecked {
                uint256 rescaledVolatility = (volatility * 1e18) >> 13;
                ltv = 1e18 - rescaledVolatility;
            }
            // verify the proof.
            bytes memory _encodedProofData = abi.encodeWithSelector(
                Halo2Verifier.verifyProof.selector,
                proof,
                instances
            );
            verifyWithDataAttestation(verifier, _encodedProofData);
            RiskEngine(_riskEngine).requestLtvUpdate(_poolId, _asset, 0.81e18);
        } else if (_action == LtvUpdate.Accept) {
            RiskEngine(_riskEngine).acceptLtvUpdate(_poolId, _asset);
        } else if (_action == LtvUpdate.Reject) {
            RiskEngine(_riskEngine).rejectLtvUpdate(_poolId, _asset);
        }
    }
}
