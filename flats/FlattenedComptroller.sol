// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0 ^0.8.20;

// src/ezkl/DA.sol

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
        bytes memory encoded
    ) public view returns (bool) {
        require(verifier.code.length > 0, "Address: call to non-contract");
        attestData(getInstancesMemory(encoded));
        // static call the verifier contract to verify the proof
        (bool success, bytes memory returndata) = verifier.staticcall(encoded);

        if (success) {
            return abi.decode(returndata, (bool));
        } else {
            revert("low-level call to verifier failed");
        }
    }
}

// src/ezkl/UniTickAttestor.sol

/// @title Contains 512-bit math functions
/// @notice Facilitates multiplication and division that can have overflow of an intermediate value without any loss of precision
/// @dev Handles "phantom overflow" i.e., allows multiplication and division where an intermediate value overflows 256 bits
library FullMath {
    /// @notice Calculates floor(a×b÷denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
    /// @param a The multiplicand
    /// @param b The multiplier
    /// @param denominator The divisor
    /// @return result The 256-bit result
    /// @dev Credit to Remco Bloemen under MIT license https://xn--2-umb.com/21/muldiv
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        // Handle division by zero
        require(denominator != 0);

        // 512-bit multiply [prod1 prod0] = a * b
        // Compute the product mod 2**256 and mod 2**256 - 1
        // then use the Chinese Remainder Theorem to reconstruct
        // the 512 bit result. The result is stored in two 256
        // variables such that product = prod1 * 2**256 + prod0
        uint256 prod0; // Least significant 256 bits of the product
        uint256 prod1; // Most significant 256 bits of the product
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }

        // Short circuit 256 by 256 division
        // This saves gas when a * b is small, at the cost of making the
        // large case a bit more expensive. Depending on your use case you
        // may want to remove this short circuit and always go through the
        // 512 bit path.
        if (prod1 == 0) {
            assembly {
                result := div(prod0, denominator)
            }
            return result;
        }

        ///////////////////////////////////////////////
        // 512 by 256 division.
        ///////////////////////////////////////////////

        // Handle overflow, the result must be < 2**256
        require(prod1 < denominator);

        // Make division exact by subtracting the remainder from [prod1 prod0]
        // Compute remainder using mulmod
        // Note mulmod(_, _, 0) == 0
        uint256 remainder;
        assembly {
            remainder := mulmod(a, b, denominator)
        }
        // Subtract 256 bit number from 512 bit number
        assembly {
            prod1 := sub(prod1, gt(remainder, prod0))
            prod0 := sub(prod0, remainder)
        }

        // Factor powers of two out of denominator
        // Compute largest power of two divisor of denominator.
        // Always >= 1.
        unchecked {
            // https://ethereum.stackexchange.com/a/96646
            uint256 twos = (type(uint256).max - denominator + 1) & denominator;
            // Divide denominator by power of two
            assembly {
                denominator := div(denominator, twos)
            }

            // Divide [prod1 prod0] by the factors of two
            assembly {
                prod0 := div(prod0, twos)
            }
            // Shift in bits from prod1 into prod0. For this we need
            // to flip `twos` such that it is 2**256 / twos.
            // If twos is zero, then it becomes one
            assembly {
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;

            // Invert denominator mod 2**256
            // Now that denominator is an odd number, it has an inverse
            // modulo 2**256 such that denominator * inv = 1 mod 2**256.
            // Compute the inverse by starting with a seed that is correct
            // correct for four bits. That is, denominator * inv = 1 mod 2**4
            // If denominator is zero the inverse starts with 2
            uint256 inv = (3 * denominator) ^ 2;
            // Now use Newton-Raphson iteration to improve the precision.
            // Thanks to Hensel's lifting lemma, this also works in modular
            // arithmetic, doubling the correct bits in each step.
            inv *= 2 - denominator * inv; // inverse mod 2**8
            inv *= 2 - denominator * inv; // inverse mod 2**16
            inv *= 2 - denominator * inv; // inverse mod 2**32
            inv *= 2 - denominator * inv; // inverse mod 2**64
            inv *= 2 - denominator * inv; // inverse mod 2**128
            inv *= 2 - denominator * inv; // inverse mod 2**256
            // If denominator is zero, inv is now 128

            // Because the division is now exact we can divide by multiplying
            // with the modular inverse of denominator. This will give us the
            // correct result modulo 2**256. Since the precoditions guarantee
            // that the outcome is less than 2**256, this is the final result.
            // We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inv;
            return result;
        }
    }

    /// @notice Calculates ceil(a×b÷denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
    /// @param a The multiplicand
    /// @param b The multiplier
    /// @param denominator The divisor
    /// @return result The 256-bit result
    function mulDivRoundingUp(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        result = mulDiv(a, b, denominator);
        if (mulmod(a, b, denominator) > 0) {
            require(result < type(uint256).max);
            result++;
        }
    }
}

/// @title Math library for computing sqrt prices from ticks and vice versa
/// @notice Computes sqrt price for ticks of size 1.0001, i.e. sqrt(1.0001^tick) as fixed point Q64.96 numbers. Supports
/// prices between 2**-128 and 2**128
library TickMath {
    /// @dev The minimum tick that may be passed to #getSqrtRatioAtTick computed from log base 1.0001 of 2**-128
    int24 internal constant MIN_TICK = -887272;
    /// @dev The maximum tick that may be passed to #getSqrtRatioAtTick computed from log base 1.0001 of 2**128
    int24 internal constant MAX_TICK = -MIN_TICK;

    /// @dev The minimum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MIN_TICK)
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    /// @dev The maximum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MAX_TICK)
    uint160 internal constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    /// @notice Calculates sqrt(1.0001^tick) * 2^96
    /// @dev Throws if |tick| > max tick
    /// @param tick The input tick for the above formula
    /// @return sqrtPriceX96 A Fixed point Q64.96 number representing the sqrt of the ratio of the two assets (token1/token0)
    /// at the given tick
    function getSqrtRatioAtTick(
        int24 tick
    ) internal pure returns (uint160 sqrtPriceX96) {
        uint256 absTick = tick < 0
            ? uint256(-int256(tick))
            : uint256(int256(tick));
        require(absTick <= uint256(uint24(MAX_TICK)), "T");

        uint256 ratio = absTick & 0x1 != 0
            ? 0xfffcb933bd6fad37aa2d162d1a594001
            : 0x100000000000000000000000000000000;
        if (absTick & 0x2 != 0)
            ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128;
        if (absTick & 0x4 != 0)
            ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
        if (absTick & 0x8 != 0)
            ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
        if (absTick & 0x10 != 0)
            ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128;
        if (absTick & 0x20 != 0)
            ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
        if (absTick & 0x40 != 0)
            ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
        if (absTick & 0x80 != 0)
            ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;
        if (absTick & 0x100 != 0)
            ratio = (ratio * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128;
        if (absTick & 0x200 != 0)
            ratio = (ratio * 0xf987a7253ac413176f2b074cf7815e54) >> 128;
        if (absTick & 0x400 != 0)
            ratio = (ratio * 0xf3392b0822b70005940c7a398e4b70f3) >> 128;
        if (absTick & 0x800 != 0)
            ratio = (ratio * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128;
        if (absTick & 0x1000 != 0)
            ratio = (ratio * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
        if (absTick & 0x2000 != 0)
            ratio = (ratio * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128;
        if (absTick & 0x4000 != 0)
            ratio = (ratio * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128;
        if (absTick & 0x8000 != 0)
            ratio = (ratio * 0x31be135f97d08fd981231505542fcfa6) >> 128;
        if (absTick & 0x10000 != 0)
            ratio = (ratio * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128;
        if (absTick & 0x20000 != 0)
            ratio = (ratio * 0x5d6af8dedb81196699c329225ee604) >> 128;
        if (absTick & 0x40000 != 0)
            ratio = (ratio * 0x2216e584f5fa1ea926041bedfe98) >> 128;
        if (absTick & 0x80000 != 0)
            ratio = (ratio * 0x48a170391f7dc42444e8fa2) >> 128;

        if (tick > 0) ratio = type(uint256).max / ratio;

        // this divides by 1<<32 rounding up to go from a Q128.128 to a Q128.96.
        // we then downcast because we know the result always fits within 160 bits due to our tick input constraint
        // we round up in the division so getTickAtSqrtRatio of the output price is always consistent
        sqrtPriceX96 = uint160(
            (ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1)
        );
    }

    /// @notice Calculates the greatest tick value such that getRatioAtTick(tick) <= ratio
    /// @dev Throws in case sqrtPriceX96 < MIN_SQRT_RATIO, as MIN_SQRT_RATIO is the lowest value getRatioAtTick may
    /// ever return.
    /// @param sqrtPriceX96 The sqrt ratio for which to compute the tick as a Q64.96
    /// @return tick The greatest tick for which the ratio is less than or equal to the input ratio
    function getTickAtSqrtRatio(
        uint160 sqrtPriceX96
    ) internal pure returns (int24 tick) {
        // second inequality must be < because the price can never reach the price at the max tick
        require(
            sqrtPriceX96 >= MIN_SQRT_RATIO && sqrtPriceX96 < MAX_SQRT_RATIO,
            "R"
        );
        uint256 ratio = uint256(sqrtPriceX96) << 32;

        uint256 r = ratio;
        uint256 msb = 0;

        assembly {
            let f := shl(7, gt(r, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(6, gt(r, 0xFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(5, gt(r, 0xFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(4, gt(r, 0xFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(3, gt(r, 0xFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(2, gt(r, 0xF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(1, gt(r, 0x3))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := gt(r, 0x1)
            msb := or(msb, f)
        }

        if (msb >= 128) r = ratio >> (msb - 127);
        else r = ratio << (127 - msb);

        int256 log_2 = (int256(msb) - 128) << 64;

        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(63, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(62, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(61, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(60, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(59, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(58, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(57, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(56, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(55, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(54, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(53, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(52, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(51, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(50, f))
        }

        int256 log_sqrt10001 = log_2 * 255738958999603826347141; // 128.128 number

        int24 tickLow = int24(
            (log_sqrt10001 - 3402992956809132418596140100660247210) >> 128
        );
        int24 tickHi = int24(
            (log_sqrt10001 + 291339464771989622907027621153398088495) >> 128
        );

        tick = tickLow == tickHi
            ? tickLow
            : getSqrtRatioAtTick(tickHi) <= sqrtPriceX96
                ? tickHi
                : tickLow;
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IUniswapV3PoolDerivedState {
    function observe(
        uint32[] calldata secondsAgos
    )
        external
        view
        returns (
            int56[] memory tickCumulatives,
            uint160[] memory secondsPerLiquidityCumulativeX128s
        );
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract UniTickAttestor {
    struct CacheInfo {
        uint48 firstTimestamp; // Timestamp of first cache
        uint16 counter; // Number of cached entries
    }

    uint public constant X96 = 2 ** 96;
    uint public constant X172 = 2 ** 172;

    int256[] public dailyRatioCache;
    CacheInfo public cacheInfo;
    address immutable USDC_WETH_005;
    int24 immutable DECIMAL_RATIO_TICK_BASIS;

    /*
     * @param _dailyRatioCache: Array of cached daily AMT values
     * @param pool: Address of the Uniswap V3 pool
     * @param decimalRatioTickBasis: Decimal ratio of asset  of tick basis
     */
    constructor(int256[] memory _dailyRatioCache, address pool) {
        dailyRatioCache = _dailyRatioCache;
        cacheInfo.counter = 0; // Initialize counter
        cacheInfo.firstTimestamp = uint48(block.timestamp);
        USDC_WETH_005 = pool;
        // fetch the token0 and token1 of the pool
        uint8 decimals0 = IERC20(IUniswapV3PoolDerivedState(pool).token0())
            .decimals();
        uint8 decimals1 = IERC20(IUniswapV3PoolDerivedState(pool).token1())
            .decimals();
        // calculate the decimal ratio of the tick basis
        int8 decimalsDiff = int8(decimals0) - int8(decimals1);
        // revert if decimal difference is not divisible by 2
        require(decimalsDiff % 2 == 0, "BP");
        uint160 sqrtRatioDecimalsScaled;
        if (decimalsDiff < 0) {
            sqrtRatioDecimalsScaled = uint160(
                X96 / (10 ** (uint8(-decimalsDiff) / 2))
            );
        } else {
            sqrtRatioDecimalsScaled = uint160(
                10 ** (uint8(decimalsDiff) / 2) * X96
            );
        }
        DECIMAL_RATIO_TICK_BASIS = TickMath.getTickAtSqrtRatio(
            sqrtRatioDecimalsScaled
        );
    }

    function consult(
        uint32 daysAgo
    ) public view returns (int256[] memory raioCumulatives) {
        raioCumulatives = new int256[](daysAgo);
        int256[] memory _dailyRatioCache = dailyRatioCache;
        for (uint256 i = 0; i < daysAgo; i++) {
            raioCumulatives[daysAgo - i - 1] = _dailyRatioCache[
                _dailyRatioCache.length - i - 1
            ];
        }
    }

    function consultRatio(
        IUniswapV3PoolDerivedState pool,
        uint32 secondsAgo,
        uint32 buffer
    ) public view returns (int256 ratioX20) {
        require(secondsAgo != 0, "BP");

        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = buffer + secondsAgo;
        secondsAgos[1] = buffer;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 arithmeticMeanTick = int24(
            tickCumulativesDelta / int32(secondsAgo)
        );
        if (
            tickCumulativesDelta < 0 &&
            (tickCumulativesDelta % int32(secondsAgo) != 0)
        ) arithmeticMeanTick--;
        arithmeticMeanTick = arithmeticMeanTick + DECIMAL_RATIO_TICK_BASIS;

        uint160 sqrtRatioX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);

        ratioX20 = int256(FullMath.mulDiv(sqrtRatioX96, sqrtRatioX96, X172));
    }

    function cacheDailyTick() public {
        CacheInfo memory _cacheInfo = cacheInfo;

        uint256 expectedTimestamp = uint256(cacheInfo.firstTimestamp) +
            (uint256(cacheInfo.counter - 1) * 24 * 60 * 60);

        uint256 timeSinceExpected = block.timestamp - expectedTimestamp;

        // Check that at least 24 hours have passed since last expected update
        require(
            timeSinceExpected >= 24 * 60 * 60,
            "Too early to cache new tick"
        );

        // Check that we're not too late
        require(
            timeSinceExpected <= (24 * 60 * 60 + 50000),
            "Too late to cache tick"
        );

        // Calculate the buffer as the time since the expected timestamp
        uint32 buffer = uint32(timeSinceExpected - 24 * 60 * 60);

        int256 ratioX96 = consultRatio(
            IUniswapV3PoolDerivedState(USDC_WETH_005),
            3600,
            buffer
        );

        dailyRatioCache.push(ratioX96);
        cacheInfo.counter++; // Increment counter after successful cache
        cacheInfo = _cacheInfo;
    }
}

// src/ezkl/Verifier.sol

contract Halo2Verifier {
    uint256 internal constant DELTA =
        4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant PROOF_LEN_CPTR = 0x6014f51944;
    uint256 internal constant PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x0ea4;
    uint256 internal constant INSTANCE_CPTR = 0x0ec4;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x05e4;
    uint256 internal constant LAST_QUOTIENT_X_CPTR = 0x06a4;

    uint256 internal constant VK_MPTR = 0x05a0;
    uint256 internal constant VK_DIGEST_MPTR = 0x05a0;
    uint256 internal constant NUM_INSTANCES_MPTR = 0x05c0;
    uint256 internal constant K_MPTR = 0x05e0;
    uint256 internal constant N_INV_MPTR = 0x0600;
    uint256 internal constant OMEGA_MPTR = 0x0620;
    uint256 internal constant OMEGA_INV_MPTR = 0x0640;
    uint256 internal constant OMEGA_INV_TO_L_MPTR = 0x0660;
    uint256 internal constant HAS_ACCUMULATOR_MPTR = 0x0680;
    uint256 internal constant ACC_OFFSET_MPTR = 0x06a0;
    uint256 internal constant NUM_ACC_LIMBS_MPTR = 0x06c0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x06e0;
    uint256 internal constant G1_X_MPTR = 0x0700;
    uint256 internal constant G1_Y_MPTR = 0x0720;
    uint256 internal constant G2_X_1_MPTR = 0x0740;
    uint256 internal constant G2_X_2_MPTR = 0x0760;
    uint256 internal constant G2_Y_1_MPTR = 0x0780;
    uint256 internal constant G2_Y_2_MPTR = 0x07a0;
    uint256 internal constant NEG_S_G2_X_1_MPTR = 0x07c0;
    uint256 internal constant NEG_S_G2_X_2_MPTR = 0x07e0;
    uint256 internal constant NEG_S_G2_Y_1_MPTR = 0x0800;
    uint256 internal constant NEG_S_G2_Y_2_MPTR = 0x0820;

    uint256 internal constant CHALLENGE_MPTR = 0x0e40;

    uint256 internal constant THETA_MPTR = 0x0e40;
    uint256 internal constant BETA_MPTR = 0x0e60;
    uint256 internal constant GAMMA_MPTR = 0x0e80;
    uint256 internal constant Y_MPTR = 0x0ea0;
    uint256 internal constant X_MPTR = 0x0ec0;
    uint256 internal constant ZETA_MPTR = 0x0ee0;
    uint256 internal constant NU_MPTR = 0x0f00;
    uint256 internal constant MU_MPTR = 0x0f20;

    uint256 internal constant ACC_LHS_X_MPTR = 0x0f40;
    uint256 internal constant ACC_LHS_Y_MPTR = 0x0f60;
    uint256 internal constant ACC_RHS_X_MPTR = 0x0f80;
    uint256 internal constant ACC_RHS_Y_MPTR = 0x0fa0;
    uint256 internal constant X_N_MPTR = 0x0fc0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x0fe0;
    uint256 internal constant L_LAST_MPTR = 0x1000;
    uint256 internal constant L_BLIND_MPTR = 0x1020;
    uint256 internal constant L_0_MPTR = 0x1040;
    uint256 internal constant INSTANCE_EVAL_MPTR = 0x1060;
    uint256 internal constant QUOTIENT_EVAL_MPTR = 0x1080;
    uint256 internal constant QUOTIENT_X_MPTR = 0x10a0;
    uint256 internal constant QUOTIENT_Y_MPTR = 0x10c0;
    uint256 internal constant R_EVAL_MPTR = 0x10e0;
    uint256 internal constant PAIRING_LHS_X_MPTR = 0x1100;
    uint256 internal constant PAIRING_LHS_Y_MPTR = 0x1120;
    uint256 internal constant PAIRING_RHS_X_MPTR = 0x1140;
    uint256 internal constant PAIRING_RHS_Y_MPTR = 0x1160;

    function verifyProof(
        bytes calldata,
        uint256[] calldata
    ) public view returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q)
                -> ret0, ret1, ret2
            {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(
                    ret0,
                    eq(
                        mulmod(y, y, q),
                        addmod(mulmod(x, mulmod(x, x, q), q), 3, q)
                    )
                )
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r)
                -> ret0, ret1
            {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for {

                } lt(mptr, sub(mptr_end, 0x20)) {

                } {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(
                    success,
                    staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20)
                )
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for {

                } lt(second_mptr, mptr) {

                } {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(
                    success,
                    staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40)
                )
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(
                    success,
                    staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40)
                )
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(
                    success,
                    staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40)
                )
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(
                    success,
                    staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40)
                )
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(
                    success,
                    staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20)
                )
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let
                q
            := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let
                r
            := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(
                    0x05a0,
                    0x16f622b5cd5504937ce14f78c93b33e2903fc642cc2f601b3641f46c3d3b38df
                ) // vk_digest
                mstore(
                    0x05c0,
                    0x0000000000000000000000000000000000000000000000000000000000000015
                ) // num_instances

                // Check valid length of proof
                success := and(
                    success,
                    eq(0x0e40, calldataload(sub(PROOF_LEN_CPTR, 0x6014F51900)))
                )

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(
                    success,
                    eq(num_instances, calldataload(NUM_INSTANCE_CPTR))
                )

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for {
                    let instance_cptr_end := add(
                        instance_cptr,
                        mul(0x20, num_instances)
                    )
                } lt(instance_cptr, instance_cptr_end) {

                } {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0180)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Phase 2
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0180)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0280)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Phase 4
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0100)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    success, proof_cptr, hash_mptr := read_ec_point(
                        success,
                        proof_cptr,
                        hash_mptr,
                        q
                    )
                }

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                )

                // Read evaluations
                for {
                    let proof_cptr_end := add(proof_cptr, 0x0740)
                } lt(proof_cptr, proof_cptr_end) {

                } {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                ) // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r) // nu

                success, proof_cptr, hash_mptr := read_ec_point(
                    success,
                    proof_cptr,
                    hash_mptr,
                    q
                ) // W

                challenge_mptr, hash_mptr := squeeze_challenge(
                    challenge_mptr,
                    hash_mptr,
                    r
                ) // mu

                success, proof_cptr, hash_mptr := read_ec_point(
                    success,
                    proof_cptr,
                    hash_mptr,
                    q
                ) // W'

                // Load full vk into memory
                mstore(
                    0x05a0,
                    0x16f622b5cd5504937ce14f78c93b33e2903fc642cc2f601b3641f46c3d3b38df
                ) // vk_digest
                mstore(
                    0x05c0,
                    0x0000000000000000000000000000000000000000000000000000000000000015
                ) // num_instances
                mstore(
                    0x05e0,
                    0x0000000000000000000000000000000000000000000000000000000000000010
                ) // k
                mstore(
                    0x0600,
                    0x30641e0e92bebef818268d663bcad6dbcfd6c0149170f6d7d350b1b1fa6c1001
                ) // n_inv
                mstore(
                    0x0620,
                    0x09d2cc4b5782fbe923e49ace3f647643a5f5d8fb89091c3ababd582133584b29
                ) // omega
                mstore(
                    0x0640,
                    0x0cf312e84f2456134e812826473d3dfb577b2bfdba762aba88b47b740472c1f0
                ) // omega_inv
                mstore(
                    0x0660,
                    0x17cbd779ed6ea1b8e9dbcde0345b2cfdb96e80bea0dd1318bdd0e183a00e0492
                ) // omega_inv_to_l
                mstore(
                    0x0680,
                    0x0000000000000000000000000000000000000000000000000000000000000000
                ) // has_accumulator
                mstore(
                    0x06a0,
                    0x0000000000000000000000000000000000000000000000000000000000000000
                ) // acc_offset
                mstore(
                    0x06c0,
                    0x0000000000000000000000000000000000000000000000000000000000000000
                ) // num_acc_limbs
                mstore(
                    0x06e0,
                    0x0000000000000000000000000000000000000000000000000000000000000000
                ) // num_acc_limb_bits
                mstore(
                    0x0700,
                    0x0000000000000000000000000000000000000000000000000000000000000001
                ) // g1_x
                mstore(
                    0x0720,
                    0x0000000000000000000000000000000000000000000000000000000000000002
                ) // g1_y
                mstore(
                    0x0740,
                    0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
                ) // g2_x_1
                mstore(
                    0x0760,
                    0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
                ) // g2_x_2
                mstore(
                    0x0780,
                    0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
                ) // g2_y_1
                mstore(
                    0x07a0,
                    0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
                ) // g2_y_2
                mstore(
                    0x07c0,
                    0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac
                ) // neg_s_g2_x_1
                mstore(
                    0x07e0,
                    0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2
                ) // neg_s_g2_x_2
                mstore(
                    0x0800,
                    0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753
                ) // neg_s_g2_y_1
                mstore(
                    0x0820,
                    0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a
                ) // neg_s_g2_y_2
                mstore(
                    0x0840,
                    0x24068df9dcdb2ea8e09e9591fd3a0490b0ba580e498ba73e5f04883e9850a63a
                ) // fixed_comms[0].x
                mstore(
                    0x0860,
                    0x08af5e18ccebb39c7e6b2fd22bb2279f880978348c0a6c397890cba6c2c816bf
                ) // fixed_comms[0].y
                mstore(
                    0x0880,
                    0x0fcc326edb1806d38c242d0fd12396fe211f318a5203c5ac2312f1e3a0ee3560
                ) // fixed_comms[1].x
                mstore(
                    0x08a0,
                    0x009977c61ab1cff18f17cf2e1eea195e4b0c74acced81f99990208ff36bcdae9
                ) // fixed_comms[1].y
                mstore(
                    0x08c0,
                    0x094701ff3b13a0ff95153c1808d8202e6e37863fca5af314ca0ff6458b8a2a31
                ) // fixed_comms[2].x
                mstore(
                    0x08e0,
                    0x29e77ecf4822624a093f91da9d745949121756930af1a53fe3a410bc70cf4893
                ) // fixed_comms[2].y
                mstore(
                    0x0900,
                    0x251852113e132a58653fd9a64ec5a3899a8d1e35edbe03f85ccb2488b7d65803
                ) // fixed_comms[3].x
                mstore(
                    0x0920,
                    0x1a23e0d2a8f004d7dfa15e6f33c32d33b523f41e532fea0f678b1d98af6aada4
                ) // fixed_comms[3].y
                mstore(
                    0x0940,
                    0x0dbae6d5df1891a57d646ab2c79653c7b1c0274127be23afbf7f0b653b8495d8
                ) // fixed_comms[4].x
                mstore(
                    0x0960,
                    0x0647bb7689eac2e471002797bcd99b454f0699a77c51d60796e283af7e431310
                ) // fixed_comms[4].y
                mstore(
                    0x0980,
                    0x2258b404fd8e7d88dd10dec449c9f3e5710785b75f13a0069c509f64093a00fd
                ) // fixed_comms[5].x
                mstore(
                    0x09a0,
                    0x198cb85920df2beb8effd733d5b5d858759c0d385c9e9ddb83bddfd530738b6a
                ) // fixed_comms[5].y
                mstore(
                    0x09c0,
                    0x094df44f2a1bc4f4245ded8396ddbc054975d696b6edce2c9daf8ce2a039727a
                ) // fixed_comms[6].x
                mstore(
                    0x09e0,
                    0x1fd87f52a1d7f7ae98d8aea9094f5ec5304a6bdd0f835c9e6e5dd15ed92e22ed
                ) // fixed_comms[6].y
                mstore(
                    0x0a00,
                    0x0295629d87df0a8a456ebb70cf30815c264984552083f72186b330c870e858cf
                ) // fixed_comms[7].x
                mstore(
                    0x0a20,
                    0x3055241091a8359d9dbe7b25326cab4e74f741f49e2ab24b8d42535f6005482a
                ) // fixed_comms[7].y
                mstore(
                    0x0a40,
                    0x15ad273a4ac51cee1f7570f85b66faafde7cac7a9571e8ac301f596c30b8121d
                ) // fixed_comms[8].x
                mstore(
                    0x0a60,
                    0x2453e5ac9414d987b7fb21a9abcb7a479fdf84a629e27690a5afcb6ae8e7ff70
                ) // fixed_comms[8].y
                mstore(
                    0x0a80,
                    0x0d99116e33f0c56020f1b8e6fd831b77ff18ce4b233dbcb38c3c833164fed6ef
                ) // fixed_comms[9].x
                mstore(
                    0x0aa0,
                    0x1092bd0373d9e037f21990f551070afedac93a406a4a1a40fcf0b3dd8f4efe00
                ) // fixed_comms[9].y
                mstore(
                    0x0ac0,
                    0x0fa896888377236e9127ab77f3612915844ad6d029afd448997cbb4f4ea520b6
                ) // fixed_comms[10].x
                mstore(
                    0x0ae0,
                    0x141338c996b237aec6c1a56ea6344f581360e28947eb6fbba9f23734c66bd6c5
                ) // fixed_comms[10].y
                mstore(
                    0x0b00,
                    0x051235a6b43da95a31da9f4c8b0e5bc0a43b14942d559dd246994e3052c3d79a
                ) // fixed_comms[11].x
                mstore(
                    0x0b20,
                    0x1cbaf0299adb0da7c27b32a2bbaf28050b46c9092ce9a7115d424b26296c147c
                ) // fixed_comms[11].y
                mstore(
                    0x0b40,
                    0x29b4bbec71462bcabd4d104f88f6aa7d7c3bb7e1c949b7249dce7b93f869838d
                ) // fixed_comms[12].x
                mstore(
                    0x0b60,
                    0x22bc4838bc0da6b67446808b7d7c5cc2eca6a4d7a8effa97a9c463676650433b
                ) // fixed_comms[12].y
                mstore(
                    0x0b80,
                    0x17f367ce43e4490f7d29c7da996666510ecdbc2f408f944a35013d6ebdff514f
                ) // fixed_comms[13].x
                mstore(
                    0x0ba0,
                    0x23e64b6496b8f626fc602873d9544281a9f2170272d90faa53899151c9412bd5
                ) // fixed_comms[13].y
                mstore(
                    0x0bc0,
                    0x29760be97467838e78b0abe7bb8574e8d0ae4de3fe574adc635dfe17c6655e46
                ) // fixed_comms[14].x
                mstore(
                    0x0be0,
                    0x0327a56d395bdc5dcbba009e3960470ae6a96118f835758f384557841283d0a7
                ) // fixed_comms[14].y
                mstore(
                    0x0c00,
                    0x052685c4c1e7e0dbb78fa3d7e6c0e4d1d79e1b019634e34bc79eb60ac2d997e4
                ) // fixed_comms[15].x
                mstore(
                    0x0c20,
                    0x0dea6c3eeb06245cc934425cb6509d604de389ef9e3c48a7ee6bf629bd423238
                ) // fixed_comms[15].y
                mstore(
                    0x0c40,
                    0x1c078aac77c2a5f37cc428291e6db4562cdbb080afae5dc7aaec20ad06cae471
                ) // permutation_comms[0].x
                mstore(
                    0x0c60,
                    0x1daa81a972f9b684e0f66863c62e46a242292aed0a2e01882a69eb7b2c3d207a
                ) // permutation_comms[0].y
                mstore(
                    0x0c80,
                    0x2caf29f7c537ed7a2f0bffdd9cc21291d42e2f710942290ae0fbd7ba02d92679
                ) // permutation_comms[1].x
                mstore(
                    0x0ca0,
                    0x28bbd87aed56660fb7d273a1f036ca2a0d2aa6581bb712ae69cd7f7593e085c1
                ) // permutation_comms[1].y
                mstore(
                    0x0cc0,
                    0x06eaabf17a75447c12ed6fcdf9d16f49d8da7212bb72f1fa38ee439692d9d3d6
                ) // permutation_comms[2].x
                mstore(
                    0x0ce0,
                    0x1cf764294dbe1a6e91bfa7e4958081eca23b325e7b2dda63194a099018d1e613
                ) // permutation_comms[2].y
                mstore(
                    0x0d00,
                    0x233baf590529de1acb213594c07a5ef3ddcd0af972fb99d435af14eee310d69a
                ) // permutation_comms[3].x
                mstore(
                    0x0d20,
                    0x1e77c257124c809388c634fd33b702f8c793b988e3c79a462919c0f23ac1c7ab
                ) // permutation_comms[3].y
                mstore(
                    0x0d40,
                    0x0a8a86ebf3bf64f3bda101bcd9a12ef73ae121ebcabac16323cd95f714f10d37
                ) // permutation_comms[4].x
                mstore(
                    0x0d60,
                    0x03f36c2885145f9e79e23ef371377426a94fdba23f52acf32284b9e23258895d
                ) // permutation_comms[4].y
                mstore(
                    0x0d80,
                    0x23e9d80c5d59d0f5a0edf6af727ef7dce365a0ad7c2559c1735291bb02e631cd
                ) // permutation_comms[5].x
                mstore(
                    0x0da0,
                    0x26c047c185cc96f556fe7c5dddc010a328ebd8482eb74e1df0fd7ca46debfe7b
                ) // permutation_comms[5].y
                mstore(
                    0x0dc0,
                    0x0d57e938e717b9488608737286a2c7220b2cc6c8a8d719138afb7ba926e3d27a
                ) // permutation_comms[6].x
                mstore(
                    0x0de0,
                    0x260783a0b7ab22d3c750e9c25e4107b256849e848d3f539a6a7baafe5ca03ed3
                ) // permutation_comms[6].y
                mstore(
                    0x0e00,
                    0x0104a380d25cd6436bf21e725208818e3ee8978d997e4cc2604e07aaf0d501cf
                ) // permutation_comms[7].x
                mstore(
                    0x0e20,
                    0x2247e9ce0c742196b1fc1c46149d8f88da91870213fdda74026773e3f089a0d7
                ) // permutation_comms[7].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(
                        INSTANCE_CPTR,
                        mul(mload(ACC_OFFSET_MPTR), 0x20)
                    )
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for {
                        let cptr_end := add(cptr, mul(0x20, num_limbs))
                        let shift := num_limb_bits
                    } lt(cptr, cptr_end) {

                    } {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(
                            lhs_y,
                            shl(shift, calldataload(add(cptr, lhs_y_off)))
                        )
                        rhs_x := add(
                            rhs_x,
                            shl(shift, calldataload(add(cptr, rhs_x_off)))
                        )
                        rhs_y := add(
                            rhs_y,
                            shl(shift, calldataload(add(cptr, rhs_y_off)))
                        )
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(
                        success,
                        eq(
                            mulmod(lhs_y, lhs_y, q),
                            addmod(
                                mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q),
                                3,
                                q
                            )
                        )
                    )
                    success := and(
                        success,
                        eq(
                            mulmod(rhs_y, rhs_y, q),
                            addmod(
                                mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q),
                                3,
                                q
                            )
                        )
                    )

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for {
                    let idx := 0
                } lt(idx, k) {
                    idx := add(idx, 1)
                } {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(
                    mptr,
                    mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6))
                )
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for {
                    let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR)
                } lt(mptr, mptr_end) {
                    mptr := add(mptr, 0x20)
                } {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for {
                    let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR)
                } lt(mptr, mptr_end) {
                    mptr := add(mptr, 0x20)
                } {
                    mstore(
                        mptr,
                        mulmod(
                            l_i_common,
                            mulmod(mload(mptr), pow_of_omega, r),
                            r
                        )
                    )
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for {
                    let l_i_cptr_end := add(X_N_MPTR, 0xc0)
                } lt(l_i_cptr, l_i_cptr_end) {
                    l_i_cptr := add(l_i_cptr, 0x20)
                } {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for {
                    let instance_cptr := INSTANCE_CPTR
                    let instance_cptr_end := add(
                        instance_cptr,
                        mul(0x20, mload(NUM_INSTANCES_MPTR))
                    )
                } lt(instance_cptr, instance_cptr_end) {
                    instance_cptr := add(instance_cptr, 0x20)
                    l_i_cptr := add(l_i_cptr, 0x20)
                } {
                    instance_eval := addmod(
                        instance_eval,
                        mulmod(mload(l_i_cptr), calldataload(instance_cptr), r),
                        r
                    )
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_11 := calldataload(0x0924)
                    let var0 := 0x2
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let a_0 := calldataload(0x06e4)
                    let a_2 := calldataload(0x0724)
                    let var7 := addmod(a_0, a_2, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_4, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := var10
                }
                {
                    let f_12 := calldataload(0x0944)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_5 := calldataload(0x0784)
                    let a_1 := calldataload(0x0704)
                    let a_3 := calldataload(0x0744)
                    let var7 := addmod(a_1, a_3, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_5, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var10,
                        r
                    )
                }
                {
                    let f_11 := calldataload(0x0924)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let a_0 := calldataload(0x06e4)
                    let a_2 := calldataload(0x0724)
                    let var7 := mulmod(a_0, a_2, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_4, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var10,
                        r
                    )
                }
                {
                    let f_13 := calldataload(0x0964)
                    let var0 := 0x2
                    let var1 := sub(R, f_13)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_13, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_5 := calldataload(0x0784)
                    let a_1 := calldataload(0x0704)
                    let a_3 := calldataload(0x0744)
                    let var7 := mulmod(a_1, a_3, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_5, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var10,
                        r
                    )
                }
                {
                    let f_11 := calldataload(0x0924)
                    let var0 := 0x1
                    let var1 := sub(R, f_11)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_11, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let a_0 := calldataload(0x06e4)
                    let a_2 := calldataload(0x0724)
                    let var7 := sub(R, a_2)
                    let var8 := addmod(a_0, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_4, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var11,
                        r
                    )
                }
                {
                    let f_12 := calldataload(0x0944)
                    let var0 := 0x1
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_5 := calldataload(0x0784)
                    let a_1 := calldataload(0x0704)
                    let a_3 := calldataload(0x0744)
                    let var7 := sub(R, a_3)
                    let var8 := addmod(a_1, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_5, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var11,
                        r
                    )
                }
                {
                    let f_12 := calldataload(0x0944)
                    let var0 := 0x2
                    let var1 := sub(R, f_12)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_12, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let var7 := 0x1
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_4, var8, R)
                    let var10 := mulmod(a_4, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var11,
                        r
                    )
                }
                {
                    let f_13 := calldataload(0x0964)
                    let var0 := 0x1
                    let var1 := sub(R, f_13)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_13, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_5 := calldataload(0x0784)
                    let var7 := sub(R, var0)
                    let var8 := addmod(a_5, var7, R)
                    let var9 := mulmod(a_5, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var10,
                        r
                    )
                }
                {
                    let f_14 := calldataload(0x0984)
                    let var0 := 0x2
                    let var1 := sub(R, f_14)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_14, var2, R)
                    let a_4 := calldataload(0x0764)
                    let a_4_prev_1 := calldataload(0x07a4)
                    let var4 := 0x0
                    let a_0 := calldataload(0x06e4)
                    let a_2 := calldataload(0x0724)
                    let var5 := mulmod(a_0, a_2, R)
                    let var6 := addmod(var4, var5, R)
                    let a_1 := calldataload(0x0704)
                    let a_3 := calldataload(0x0744)
                    let var7 := mulmod(a_1, a_3, R)
                    let var8 := addmod(var6, var7, R)
                    let var9 := addmod(a_4_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_4, var10, R)
                    let var12 := mulmod(var3, var11, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var12,
                        r
                    )
                }
                {
                    let f_13 := calldataload(0x0964)
                    let var0 := 0x1
                    let var1 := sub(R, f_13)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_13, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let var7 := 0x0
                    let a_0 := calldataload(0x06e4)
                    let a_2 := calldataload(0x0724)
                    let var8 := mulmod(a_0, a_2, R)
                    let var9 := addmod(var7, var8, R)
                    let a_1 := calldataload(0x0704)
                    let a_3 := calldataload(0x0744)
                    let var10 := mulmod(a_1, a_3, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_4, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var14,
                        r
                    )
                }
                {
                    let f_15 := calldataload(0x09a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_15)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_15, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let var7 := 0x1
                    let a_2 := calldataload(0x0724)
                    let var8 := mulmod(var7, a_2, R)
                    let a_3 := calldataload(0x0744)
                    let var9 := mulmod(var8, a_3, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_4, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var12,
                        r
                    )
                }
                {
                    let f_14 := calldataload(0x0984)
                    let var0 := 0x1
                    let var1 := sub(R, f_14)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_14, var2, R)
                    let a_4 := calldataload(0x0764)
                    let a_4_prev_1 := calldataload(0x07a4)
                    let a_2 := calldataload(0x0724)
                    let var4 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0744)
                    let var5 := mulmod(var4, a_3, R)
                    let var6 := mulmod(a_4_prev_1, var5, R)
                    let var7 := sub(R, var6)
                    let var8 := addmod(a_4, var7, R)
                    let var9 := mulmod(var3, var8, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var9,
                        r
                    )
                }
                {
                    let f_15 := calldataload(0x09a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_15)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_15, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0724)
                    let var8 := addmod(var7, a_2, R)
                    let a_3 := calldataload(0x0744)
                    let var9 := addmod(var8, a_3, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_4, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var12,
                        r
                    )
                }
                {
                    let f_15 := calldataload(0x09a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_15)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_15, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0764)
                    let a_4_prev_1 := calldataload(0x07a4)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0724)
                    let var8 := addmod(var7, a_2, R)
                    let a_3 := calldataload(0x0744)
                    let var9 := addmod(var8, a_3, R)
                    let var10 := addmod(a_4_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_4, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        var13,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(
                        l_0,
                        sub(R, mulmod(l_0, calldataload(0x0ae4), R)),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let perm_z_last := calldataload(0x0ba4)
                    let eval := mulmod(
                        mload(L_LAST_MPTR),
                        addmod(
                            mulmod(perm_z_last, perm_z_last, R),
                            sub(R, perm_z_last),
                            R
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let eval := mulmod(
                        mload(L_0_MPTR),
                        addmod(
                            calldataload(0x0b44),
                            sub(R, calldataload(0x0b24)),
                            R
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let eval := mulmod(
                        mload(L_0_MPTR),
                        addmod(
                            calldataload(0x0ba4),
                            sub(R, calldataload(0x0b84)),
                            R
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0b04)
                    let rhs := calldataload(0x0ae4)
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x06e4),
                                mulmod(beta, calldataload(0x09e4), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x0704),
                                mulmod(beta, calldataload(0x0a04), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x0724),
                                mulmod(beta, calldataload(0x0a24), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x06e4), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x0704), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x0724), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(
                        left_sub_right,
                        sub(
                            R,
                            mulmod(
                                left_sub_right,
                                addmod(
                                    mload(L_LAST_MPTR),
                                    mload(L_BLIND_MPTR),
                                    R
                                ),
                                R
                            )
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0b64)
                    let rhs := calldataload(0x0b44)
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x0744),
                                mulmod(beta, calldataload(0x0a44), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x0764),
                                mulmod(beta, calldataload(0x0a64), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x0784),
                                mulmod(beta, calldataload(0x0a84), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x0744), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x0764), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x0784), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(
                        left_sub_right,
                        sub(
                            R,
                            mulmod(
                                left_sub_right,
                                addmod(
                                    mload(L_LAST_MPTR),
                                    mload(L_BLIND_MPTR),
                                    R
                                ),
                                R
                            )
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0bc4)
                    let rhs := calldataload(0x0ba4)
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                calldataload(0x07c4),
                                mulmod(beta, calldataload(0x0aa4), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    lhs := mulmod(
                        lhs,
                        addmod(
                            addmod(
                                mload(INSTANCE_EVAL_MPTR),
                                mulmod(beta, calldataload(0x0ac4), R),
                                R
                            ),
                            gamma,
                            R
                        ),
                        R
                    )
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(calldataload(0x07c4), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(
                        rhs,
                        addmod(
                            addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R),
                            gamma,
                            R
                        ),
                        R
                    )
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(
                        left_sub_right,
                        sub(
                            R,
                            mulmod(
                                left_sub_right,
                                addmod(
                                    mload(L_LAST_MPTR),
                                    mload(L_BLIND_MPTR),
                                    R
                                ),
                                R
                            )
                        ),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0be4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0be4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x07e4)
                        let f_2 := calldataload(0x0804)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_5 := calldataload(0x0864)
                        let var0 := 0x1
                        let var1 := mulmod(f_5, var0, R)
                        let a_0 := calldataload(0x06e4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_4 := calldataload(0x0764)
                        let var8 := mulmod(var1, a_4, R)
                        let
                            var9
                        := 0x30644e72e131a029b85045b68181585ca833e84879b9709143e1f593f0000002
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0c24), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0c04),
                                sub(R, calldataload(0x0be4)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0c44), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0c44), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x07e4)
                        let f_2 := calldataload(0x0804)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_6 := calldataload(0x0884)
                        let var0 := 0x1
                        let var1 := mulmod(f_6, var0, R)
                        let a_1 := calldataload(0x0704)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_5 := calldataload(0x0784)
                        let var8 := mulmod(var1, a_5, R)
                        let
                            var9
                        := 0x30644e72e131a029b85045b68181585ca833e84879b9709143e1f593f0000002
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0c84), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0c64),
                                sub(R, calldataload(0x0c44)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0ca4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0ca4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0824)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x08a4)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, R)
                        let a_0 := calldataload(0x06e4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0ce4), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0cc4),
                                sub(R, calldataload(0x0ca4)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0d04), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0d04), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0824)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x08c4)
                        let var0 := 0x1
                        let var1 := mulmod(f_8, var0, R)
                        let a_1 := calldataload(0x0704)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0d44), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0d24),
                                sub(R, calldataload(0x0d04)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0d64), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0d64), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0844)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x08e4)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_0 := calldataload(0x06e4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let
                            var5
                        := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0da4), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0d84),
                                sub(R, calldataload(0x0d64)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0dc4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0dc4), R)
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0844)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_10 := calldataload(0x0904)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_1 := calldataload(0x0704)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let
                            var5
                        := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(
                            rhs,
                            sub(R, mulmod(calldataload(0x0e04), tmp, R)),
                            R
                        )
                        lhs := mulmod(
                            mulmod(table, tmp, R),
                            addmod(
                                calldataload(0x0de4),
                                sub(R, calldataload(0x0dc4)),
                                R
                            ),
                            R
                        )
                    }
                    let eval := mulmod(
                        addmod(
                            1,
                            sub(
                                R,
                                addmod(
                                    mload(L_BLIND_MPTR),
                                    mload(L_LAST_MPTR),
                                    R
                                )
                            ),
                            R
                        ),
                        addmod(lhs, sub(R, rhs), R),
                        R
                    )
                    quotient_eval_numer := addmod(
                        mulmod(quotient_eval_numer, y, r),
                        eval,
                        r
                    )
                }

                pop(y)

                let quotient_eval := mulmod(
                    quotient_eval_numer,
                    mload(X_N_MINUS_1_INV_MPTR),
                    r
                )
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for {
                    let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                    let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                } lt(cptr_end, cptr) {

                } {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(
                        success,
                        calldataload(cptr),
                        calldataload(add(cptr, 0x20))
                    )
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for {
                        let mptr := 0x0380
                        let mptr_end := 0x0400
                        let point_mptr := 0x0300
                    } lt(mptr, mptr_end) {
                        mptr := add(mptr, 0x20)
                        point_mptr := add(point_mptr, 0x20)
                    } {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(
                        coeff,
                        addmod(point_0, sub(R, point_3), R),
                        R
                    )
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(
                        coeff,
                        addmod(point_2, sub(R, point_3), R),
                        R
                    )
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(
                        coeff,
                        addmod(point_3, sub(R, point_2), R),
                        R
                    )
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for {
                        let mptr := 0x0440
                        let mptr_end := 0x04a0
                    } lt(mptr, mptr_end) {
                        mptr := add(mptr, 0x20)
                    } {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x09c4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R),
                        R
                    )
                    for {
                        let mptr := 0x0ac4
                        let mptr_end := 0x09c4
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x20)
                    } {
                        r_eval := addmod(
                            mulmod(r_eval, zeta, R),
                            mulmod(coeff, calldataload(mptr), R),
                            R
                        )
                    }
                    for {
                        let mptr := 0x09a4
                        let mptr_end := 0x07a4
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x20)
                    } {
                        r_eval := addmod(
                            mulmod(r_eval, zeta, R),
                            mulmod(coeff, calldataload(mptr), R),
                            R
                        )
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0e04), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0da4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0d44), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0ce4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0c84), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0c24), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(coeff, calldataload(0x0784), R),
                        R
                    )
                    for {
                        let mptr := 0x0744
                        let mptr_end := 0x06c4
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x20)
                    } {
                        r_eval := addmod(
                            mulmod(r_eval, zeta, R),
                            mulmod(coeff, calldataload(mptr), R),
                            R
                        )
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x40), calldataload(0x07a4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x60), calldataload(0x0764), R),
                        R
                    )
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x80), calldataload(0x0b84), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xa0), calldataload(0x0b44), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xc0), calldataload(0x0b64), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x80), calldataload(0x0b24), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xa0), calldataload(0x0ae4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xc0), calldataload(0x0b04), R),
                        R
                    )
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0dc4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0de4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0d64), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0d84), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0d04), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0d24), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0ca4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0cc4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0c44), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0c64), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0be4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0c04), R),
                        R
                    )
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0xe0), calldataload(0x0ba4), R),
                        R
                    )
                    r_eval := addmod(
                        r_eval,
                        mulmod(mload(0x0100), calldataload(0x0bc4), R),
                        R
                    )
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for {
                        let mptr := 0x00
                        let mptr_end := 0x80
                        let sum_mptr := 0x0520
                    } lt(mptr, mptr_end) {
                        mptr := add(mptr, 0x20)
                        sum_mptr := add(sum_mptr, 0x20)
                    } {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for {
                        let sum_inv_mptr := 0x40
                        let sum_inv_mptr_end := 0x80
                        let r_eval_mptr := 0x04e0
                    } lt(sum_inv_mptr, sum_inv_mptr_end) {
                        sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                        r_eval_mptr := sub(r_eval_mptr, 0x20)
                    } {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(
                            r_eval,
                            mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R),
                            R
                        )
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x05a4))
                    mstore(0x20, calldataload(0x05c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(
                        success,
                        mload(QUOTIENT_X_MPTR),
                        mload(QUOTIENT_Y_MPTR)
                    )
                    for {
                        let mptr := 0x0e00
                        let mptr_end := 0x0800
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x40)
                    } {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(
                            success,
                            mload(mptr),
                            mload(add(mptr, 0x20))
                        )
                    }
                    for {
                        let mptr := 0x0324
                        let mptr_end := 0x0164
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x40)
                    } {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(
                            success,
                            calldataload(mptr),
                            calldataload(add(mptr, 0x20))
                        )
                    }
                    for {
                        let mptr := 0x0124
                        let mptr_end := 0x24
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x40)
                    } {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(
                            success,
                            calldataload(mptr),
                            calldataload(add(mptr, 0x20))
                        )
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x03a4))
                    mstore(0xa0, calldataload(0x03c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(
                        success,
                        calldataload(0x0364),
                        calldataload(0x0384)
                    )
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x0564))
                    mstore(0xa0, calldataload(0x0584))
                    for {
                        let mptr := 0x0524
                        let mptr_end := 0x03a4
                    } lt(mptr_end, mptr) {
                        mptr := sub(mptr, 0x40)
                    } {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(
                            success,
                            calldataload(mptr),
                            calldataload(add(mptr, 0x20))
                        )
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0e24))
                    mstore(0xa0, calldataload(0x0e44))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0e64))
                    mstore(0xa0, calldataload(0x0e84))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x0e64))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x0e84))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(
                    success,
                    mload(PAIRING_LHS_X_MPTR),
                    mload(PAIRING_LHS_Y_MPTR)
                )
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(
                    success,
                    mload(PAIRING_RHS_X_MPTR),
                    mload(PAIRING_RHS_Y_MPTR)
                )
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}

// src/ezkl/Comptroller.sol

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
