// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

interface RiskEngine {
    function requestLtvUpdate(
        uint256 poolId,
        address asset,
        uint256 ltv
    ) external;

    function acceptLtvUpdate(uint256 poolId, address asset) external;

    function rejectLtvUpdate(uint256 poolId, address asset) external;
}

contract Comptroller is DataAttestationSingle {
    address public verifier;

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
        address _uniTickAttestor,
        address _protocolPool,
        address _asset
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
        MockERC20(_asset).approve(_protocolPool, type(uint256).max);
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
            RiskEngine(_riskEngine).requestLtvUpdate(_poolId, _asset, ltv);
        } else if (_action == LtvUpdate.Accept) {
            RiskEngine(_riskEngine).acceptLtvUpdate(_poolId, _asset);
        } else if (_action == LtvUpdate.Reject) {
            RiskEngine(_riskEngine).rejectLtvUpdate(_poolId, _asset);
        }
    }
}
