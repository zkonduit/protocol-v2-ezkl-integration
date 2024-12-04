// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LoadInstances {
    /**
     * @dev Parse the instances array from the Halo2Verifier encoded calldata.
     * @notice must pass encoded bytes from memory
     * @param encoded - verifier calldata
     */
    function getInstancesMemory(
        bytes memory encoded
    ) internal pure returns (uint256[] memory instances) {
        bytes4 funcSig;
        uint256 instances_offset;
        uint256 instances_length;
        assembly {
            // fetch function sig. Either `verifyProof(bytes,uint256[])` or `verifyProof(address,bytes,uint256[])`
            funcSig := mload(add(encoded, 0x20))

            // Fetch instances offset which is 4 + 32 + 32 bytes away from
            // start of encoded for `verifyProof(bytes,uint256[])`,
            // and 4 + 32 + 32 +32 away for `verifyProof(address,bytes,uint256[])`

            instances_offset := mload(
                add(encoded, add(0x44, mul(0x20, eq(funcSig, 0xaf83a18d))))
            )

            instances_length := mload(add(add(encoded, 0x24), instances_offset))
        }
        instances = new uint256[](instances_length); // Allocate memory for the instances array.
        assembly {
            // Now instances points to the start of the array data
            // (right after the length field).
            for {
                let i := 0x20
            } lt(i, add(mul(instances_length, 0x20), 0x20)) {
                i := add(i, 0x20)
            } {
                mstore(
                    add(instances, i),
                    mload(add(add(encoded, add(i, 0x24)), instances_offset))
                )
            }
        }
    }
    /**
     * @dev Parse the instances array from the Halo2Verifier encoded calldata.
     * @notice must pass encoded bytes from calldata
     * @param encoded - verifier calldata
     */
    function getInstancesCalldata(
        bytes calldata encoded
    ) internal pure returns (uint256[] memory instances) {
        bytes4 funcSig;
        uint256 instances_offset;
        uint256 instances_length;
        assembly {
            // fetch function sig. Either `verifyProof(bytes,uint256[])` or `verifyProof(address,bytes,uint256[])`
            funcSig := calldataload(encoded.offset)

            // Fetch instances offset which is 4 + 32 + 32 bytes away from
            // start of encoded for `verifyProof(bytes,uint256[])`,
            // and 4 + 32 + 32 +32 away for `verifyProof(address,bytes,uint256[])`

            instances_offset := calldataload(
                add(
                    encoded.offset,
                    add(0x24, mul(0x20, eq(funcSig, 0xaf83a18d)))
                )
            )

            instances_length := calldataload(
                add(add(encoded.offset, 0x04), instances_offset)
            )
        }
        instances = new uint256[](instances_length); // Allocate memory for the instances array.
        assembly {
            // Now instances points to the start of the array data
            // (right after the length field).

            for {
                let i := 0x20
            } lt(i, add(mul(instances_length, 0x20), 0x20)) {
                i := add(i, 0x20)
            } {
                mstore(
                    add(instances, i),
                    calldataload(
                        add(add(encoded.offset, add(i, 0x04)), instances_offset)
                    )
                )
            }
        }
    }
}

// The kzg commitments of a given model, all aggregated into a single bytes array.
// At solidity generation time, the commitments are hardcoded into the contract via the COMMITMENT_KZG constant.
// It will be used to check that the proof commitments match the expected commitments.
bytes constant COMMITMENT_KZG = hex"";

contract SwapProofCommitments {
    /**
     * @dev Swap the proof commitments
     * @notice must pass encoded bytes from memory
     * @param encoded - verifier calldata
     */
    function checkKzgCommits(
        bytes calldata encoded
    ) internal pure returns (bool equal) {
        bytes4 funcSig;
        uint256 proof_offset;
        uint256 proof_length;
        assembly {
            // fetch function sig. Either `verifyProof(bytes,uint256[])` or `verifyProof(address,bytes,uint256[])`
            funcSig := calldataload(encoded.offset)

            // Fetch proof offset which is 4 + 32 bytes away from
            // start of encoded for `verifyProof(bytes,uint256[])`,
            // and 4 + 32 + 32 away for `verifyProof(address,bytes,uint256[])`

            proof_offset := calldataload(
                add(
                    encoded.offset,
                    add(0x04, mul(0x20, eq(funcSig, 0xaf83a18d)))
                )
            )

            proof_length := calldataload(
                add(add(encoded.offset, 0x04), proof_offset)
            )
        }
        // Check the length of the commitment against the proof bytes
        if (proof_length < COMMITMENT_KZG.length) {
            return false;
        }

        // Load COMMITMENT_KZG into memory
        bytes memory commitment = COMMITMENT_KZG;

        // Compare the first N bytes of the proof with COMMITMENT_KZG
        uint words = (commitment.length + 31) / 32; // Calculate the number of 32-byte words

        assembly {
            // Now we compare the commitment with the proof,
            // ensuring that the commitments divided up into 32 byte words are all equal.
            for {
                let i := 0x20
            } lt(i, add(mul(words, 0x20), 0x20)) {
                i := add(i, 0x20)
            } {
                let wordProof := calldataload(
                    add(add(encoded.offset, add(i, 0x04)), proof_offset)
                )
                let wordCommitment := mload(add(commitment, i))
                equal := eq(wordProof, wordCommitment)
                if eq(equal, 0) {
                    return(0, 0)
                }
            }
        }

        return equal; // Return true if the commitment comparison passed
    } /// end checkKzgCommits
}

contract DataAttestationSingle is LoadInstances, SwapProofCommitments {
    /**
     * @notice Struct used to make view only call to account to fetch the data that EZKL reads from.
     * @param the address of the account to make calls to
     * @param the abi encoded function calls to make to the `contractAddress`
     */
    struct AccountCall {
        address contractAddress;
        bytes callData;
        uint256 decimals;
    }
    AccountCall public accountCall;

    uint[] public scales;

    address public admin;

    /**
     * @notice EZKL P value
     * @dev In order to prevent the verifier from accepting two version of the same pubInput, n and the quantity (n + P),  where n + P <= 2^256, we require that all instances are stricly less than P. a
     * @dev The reason for this is that the assmebly code of the verifier performs all arithmetic operations modulo P and as a consequence can't distinguish between n and n + P.
     */
    uint256 constant ORDER =
        uint256(
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        );

    uint256 constant INPUT_LEN = 20;

    uint256 constant OUTPUT_LEN = 0;

    uint8 public instanceOffset;

    /**
     * @dev Initialize the contract with account calls the EZKL model will read from.
     * @param _contractAddresses - The calls to all the contracts EZKL reads storage from.
     * @param _callData - The abi encoded function calls to make to the `contractAddress` that EZKL reads storage from.
     */
    constructor(
        address _contractAddresses,
        bytes memory _callData,
        uint256 _decimals,
        uint[20] memory _scales,
        uint8 _instanceOffset,
        address _admin
    ) {
        admin = _admin;
        for (uint i; i < _scales.length; i++) {
            scales.push(1 << _scales[i]);
        }
        populateAccountCalls(_contractAddresses, _callData, _decimals);
        instanceOffset = _instanceOffset;
    }

    function updateAdmin(address _admin) external {
        require(msg.sender == admin, "Only admin can update admin");
        if (_admin == address(0)) {
            revert();
        }
        admin = _admin;
    }

    function updateAccountCalls(
        address _contractAddresses,
        bytes memory _callData,
        uint256 _decimals
    ) external {
        require(msg.sender == admin, "Only admin can update account calls");
        populateAccountCalls(_contractAddresses, _callData, _decimals);
    }

    function populateAccountCalls(
        address _contractAddresses,
        bytes memory _callData,
        uint256 _decimals
    ) internal {
        AccountCall memory _accountCall = accountCall;
        _accountCall.contractAddress = _contractAddresses;
        _accountCall.callData = _callData;
        _accountCall.decimals = 10 ** _decimals;
        accountCall = _accountCall;
    }

    function mulDiv(
        uint256 x,
        uint256 y,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        unchecked {
            uint256 prod0;
            uint256 prod1;
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            if (prod1 == 0) {
                return prod0 / denominator;
            }

            require(denominator > prod1, "Math: mulDiv overflow");

            uint256 remainder;
            assembly {
                remainder := mulmod(x, y, denominator)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            uint256 twos = denominator & (~denominator + 1);
            assembly {
                denominator := div(denominator, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }

            prod0 |= prod1 * twos;

            uint256 inverse = (3 * denominator) ^ 2;

            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;
            inverse *= 2 - denominator * inverse;

            result = prod0 * inverse;
            return result;
        }
    }
    /**
     * @dev Quantize the data returned from the account calls to the scale used by the EZKL model.
     * @param x - One of the elements of the data returned from the account calls
     * @param _decimals - Number of base 10 decimals to scale the data by.
     * @param _scale - The base 2 scale used to convert the floating point value into a fixed point value.
     *
     */
    function quantizeData(
        int x,
        uint256 _decimals,
        uint256 _scale
    ) internal pure returns (int256 quantized_data) {
        bool neg = x < 0;
        if (neg) x = -x;
        uint output = mulDiv(uint256(x), _scale, _decimals);
        if (mulmod(uint256(x), _scale, _decimals) * 2 >= _decimals) {
            output += 1;
        }
        quantized_data = neg ? -int256(output) : int256(output);
    }
    /**
     * @dev Make a static call to the account to fetch the data that EZKL reads from.
     * @param target - The address of the account to make calls to.
     * @param data  - The abi encoded function calls to make to the `contractAddress` that EZKL reads storage from.
     * @return The data returned from the account calls. (Must come from either a view or pure function. Will throw an error otherwise)
     */
    function staticCall(
        address target,
        bytes memory data
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        if (success) {
            if (returndata.length == 0) {
                require(
                    target.code.length > 0,
                    "Address: call to non-contract"
                );
            }
            return returndata;
        } else {
            revert("Address: low-level call failed");
        }
    }
    /**
     * @dev Convert the fixed point quantized data into a field element.
     * @param x - The quantized data.
     * @return field_element - The field element.
     */
    function toFieldElement(
        int256 x
    ) internal pure returns (uint256 field_element) {
        // The casting down to uint256 is safe because the order is about 2^254, and the value
        // of x ranges of -2^127 to 2^127, so x + int(ORDER) is always positive.
        return uint256(x + int(ORDER)) % ORDER;
    }

    /**
     * @dev Make the account calls to fetch the data that EZKL reads from and attest to the data.
     * @param instances - The public instances to the proof (the data in the proof that publicly accessible to the verifier).
     */
    function attestData(uint256[] memory instances) internal view {
        require(
            instances.length >= INPUT_LEN + OUTPUT_LEN,
            "Invalid public inputs length"
        );
        AccountCall memory _accountCall = accountCall;
        uint[] memory _scales = scales;
        bytes memory returnData = staticCall(
            _accountCall.contractAddress,
            _accountCall.callData
        );
        int256[] memory x = abi.decode(returnData, (int256[]));
        uint _offset;
        int output = quantizeData(x[0], _accountCall.decimals, _scales[0]);
        uint field_element = toFieldElement(output);
        for (uint i = 0; i < x.length; i++) {
            if (field_element != instances[i + instanceOffset]) {
                _offset += 1;
            } else {
                break;
            }
        }
        uint length = x.length - _offset;
        for (uint i = 1; i < length; i++) {
            output = quantizeData(x[i], _accountCall.decimals, _scales[i]);
            field_element = toFieldElement(output);
            require(
                field_element == instances[i + instanceOffset + _offset],
                "Public input does not match"
            );
        }
    }

    /**
     * @dev Verify the proof with the data attestation.
     * @param verifier - The address of the verifier contract.
     * @param encoded - The verifier calldata.
     */
    function verifyWithDataAttestation(
        address verifier,
        bytes calldata encoded
    ) public view returns (bool) {
        require(verifier.code.length > 0, "Address: call to non-contract");
        attestData(getInstancesCalldata(encoded));
        // static call the verifier contract to verify the proof
        (bool success, bytes memory returndata) = verifier.staticcall(encoded);

        if (success) {
            return abi.decode(returndata, (bool));
        } else {
            revert("low-level call to verifier failed");
        }
    }
}
