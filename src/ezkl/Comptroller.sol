// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {RiskEngine} from "../RiskEngine.sol";
import {DataAttestationSingle} from "./DA.sol";
import {UniTickAttestor} from "./UniTickAttestor.sol";

/// @title Replaces governance control of `RiskEngine.sol` with a comptroller contact
/// @notice Handles data aggregation, data attestation and verification of an off-chain data science model SNARKED using EZKL library

contract Comptroller is DataAttestationSingle, UniTickAttestor {
    RiskEngine public riskEngine;
    address public verifier;

    enum LtvUpdate {
        Request,
        Accept,
        Reject
    }

    constructor(
        int256[] memory recentTicks,
        address pool,
        bytes memory _callData,
        uint256 _decimals,
        uint[20] memory _scales,
        uint8 _instanceOffset,
        address _admin,
        address _verifier
    )
        UniTickAttestor(recentTicks, pool)
        DataAttestationSingle(
            address(this),
            _callData,
            _decimals,
            _scales,
            _instanceOffset,
            _admin
        )
    {
        verifier = _verifier;
    }
    function ltvUpdate(
        LtvUpdate _action,
        uint256 _poolId,
        address _asset,
        bytes calldata _encodedProofData
    ) external {
        if (_action == LtvUpdate.Request) {
            uint256[] memory instances = getInstancesCalldata(
                _encodedProofData
            );
            // fetch the instances value at index 20 (LTC, aka output), then scale it to e18
            uint256 volatility = instances[20];
            // perform 1 - volatility scales to get ltv
            uint256 ltv;
            unchecked {
                uint256 rescaledVolatility = (volatility * 1e18) >> 13;
                ltv = 1e18 - rescaledVolatility;
            }
            // verifier the proof.
            verifyWithDataAttestation(verifier, _encodedProofData);
            riskEngine.requestLtvUpdate(_poolId, _asset, ltv);
        } else if (_action == LtvUpdate.Accept) {
            riskEngine.acceptLtvUpdate(_poolId, _asset);
        } else if (_action == LtvUpdate.Reject) {
            riskEngine.rejectLtvUpdate(_poolId, _asset);
        }
    }
}
