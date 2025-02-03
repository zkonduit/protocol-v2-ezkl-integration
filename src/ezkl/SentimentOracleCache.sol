// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

/// @title IOracle
/// @notice Common interface for all oracle implementations
interface IOracle {
    /// @notice Compute the equivalent ETH value for a given amount of a particular asset
    /// @param asset Address of the asset to be priced
    /// @param amt Amount of the given asset to be priced
    /// @return valueInEth Equivalent ETH value for the given asset and amount, scaled by 18 decimals
    function getValueInEth(
        address asset,
        uint256 amt
    ) external view returns (uint256 valueInEth);
}

interface IRiskEngine {
    function oracleFor(address to) external view returns (address oracle);
}

contract SentimentOracleCache {
    struct CacheInfo {
        uint48 firstTimestamp; // Timestamp of first cache
        uint16 counter; // Number of cached entries
    }
    /// @dev Mapping of debt oracle => asset oracle => daily ratio cache
    mapping(address => mapping(address => int256[])) public dailyRatioCache;

    CacheInfo public cacheInfo;
    IRiskEngine public immutable riskEngine;

    /*
     * @param _dailyRatioCache: Array of cached daily prices values to initially populate the cache
     * @param oracle: Address of the oracle contract
     * @param decimalRatioTickBasis: Decimal ratio of asset of tick basis
     */
    constructor(
        int256[] memory _dailyRatioCache,
        address _riskEngine,
        address debtToken,
        address assetToken
    ) {
        require(
            IRiskEngine(_riskEngine).oracleFor(debtToken) != address(0),
            "SentimentOracleCache: Invalid debt token"
        );
        require(
            IRiskEngine(_riskEngine).oracleFor(assetToken) != address(0),
            "SentimentOracleCache: Invalid asset token"
        );
        riskEngine = IRiskEngine(_riskEngine);
        // Initialize cache for a provided debt-asset pair
        dailyRatioCache[debtToken][assetToken] = _dailyRatioCache;
        cacheInfo.counter = 0; // Initialize counter
        cacheInfo.firstTimestamp = uint48(block.timestamp);
    }

    function consult(
        uint32 daysAgo,
        address debtToken,
        address assetToken
    ) public view returns (int256[] memory raioCumulatives) {
        raioCumulatives = new int256[](daysAgo);
        int256[] storage _dailyRatioCache = dailyRatioCache[debtToken][
            assetToken
        ];
        uint256 start = _dailyRatioCache.length - daysAgo;
        for (uint256 i = 0; i < daysAgo; i++) {
            raioCumulatives[i] = _dailyRatioCache[start + i];
        }
    }
    function cacheDailyPrice(
        address debtToken,
        address assetToken
    ) public returns (uint256 ratio) {
        CacheInfo memory _cacheInfo = cacheInfo;

        uint256 expectedTimestamp = uint256(cacheInfo.firstTimestamp) +
            (uint256(cacheInfo.counter - 1) * 24 * 60 * 60);

        uint256 timeSinceExpected = block.timestamp - expectedTimestamp;

        // Check that at least 24 hours have passed since last expected update
        require(
            timeSinceExpected >= 24 * 60 * 60,
            "Too early to cache new tick"
        );

        // Get price data once instead of multiple calls
        (uint256 debtInEth, uint256 assetInEthScaled) = _getOracleValues(
            debtToken,
            assetToken
        );
        // Calculate ratio of asset to debt (The value of asset in terms of debt, using the debt decimals)
        ratio = assetInEthScaled / debtInEth;

        dailyRatioCache[debtToken][assetToken].push(int256(ratio));
        cacheInfo.counter++; // Increment counter after successful cache
        cacheInfo = _cacheInfo;
    }

    function _getOracleValues(
        address debtToken,
        address assetToken
    ) private view returns (uint256 debtInEth, uint256 assetInEthScaled) {
        // get oracles
        address debtOracle = riskEngine.oracleFor(debtToken);
        address assetOracle = riskEngine.oracleFor(assetToken);
        // get decimals
        uint256 debtDecimals = 10 ** IERC20(debtToken).decimals();
        uint256 assetDecimals = 10 ** IERC20(assetToken).decimals();

        return (
            IOracle(debtOracle).getValueInEth(debtToken, debtDecimals),
            IOracle(assetOracle).getValueInEth(
                assetToken,
                assetDecimals * debtDecimals
            )
        );
    }
}
