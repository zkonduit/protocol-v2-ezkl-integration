// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// types
import {Pool} from "./Pool.sol";
import {AssetData, DebtData} from "./PositionManager.sol";
import {Registry} from "./Registry.sol";
import {RiskModule} from "./RiskModule.sol";
import {IOracle} from "./interfaces/IOracle.sol";

// contracts
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title RiskEngine
contract RiskEngine is Ownable {
    /// @notice Timelock delay to update asset LTVs
    uint256 public constant TIMELOCK_DURATION = 24 * 60 * 60; // 24 hours
    /// @notice Timelock deadline to enforce timely updates
    uint256 public constant TIMELOCK_DEADLINE = 3 * 24 * 60 * 60; // 72 hours
    /// @notice Sentiment Pool registry key hash
    /// @dev keccak(SENTIMENT_POOL_KEY)
    bytes32 public constant SENTIMENT_POOL_KEY =
        0x1a99cbf6006db18a0e08427ff11db78f3ea1054bc5b9d48122aae8d206c09728;
    /// @notice Sentiment Risk Module registry key hash
    /// @dev keccak(SENTIMENT_RISK_MODULE_KEY)
    bytes32 public constant SENTIMENT_RISK_MODULE_KEY =
        0x881469d14b8443f6c918bdd0a641e9d7cae2592dc28a4f922a2c4d7ca3d19c77;

    /// @title LtvUpdate
    /// @notice Utility struct to store pending Pool LTV updates
    struct LtvUpdate {
        uint256 ltv;
        uint256 validAfter;
    }

    // Protocol LTV configs:
    // - pool owners are free to configure a different LTV for every asset on their pool
    // - however these custom LTVs must fall within the global protocol limits
    // - the global LTV limits can only be modified by the protocol owner
    // - ltv updates will revert if they fall outside of the protocol bounds

    /// @notice Minimum LTV bound
    uint256 public minLtv;
    /// @notice Maximum LTV bound
    uint256 public maxLtv;

    /// @notice Sentiment Registry
    Registry public registry;
    /// @notice Sentiment Singleton Pool
    Pool public pool;
    /// @notice Sentiment Risk Module
    RiskModule public riskModule;

    /// @dev Asset to Oracle mapping
    mapping(address asset => address oracle) public oracleFor;
    /// @notice Fetch the ltv for a given asset in a pool
    mapping(uint256 poolId => mapping(address asset => uint256 ltv))
        public ltvFor;
    /// @notice Fetch pending LTV update details for a given pool and asset pair, if any
    mapping(uint256 poolId => mapping(address asset => LtvUpdate ltvUpdate))
        public ltvUpdateFor;
    /// @notice Check if poolA lends to positions that also borrow from poolB
    mapping(uint256 poolA => mapping(uint256 poolB => bool isAllowed))
        public isAllowedPair;

    /// @notice Pool address was updated
    event PoolSet(address pool);
    /// @notice Registry address was updated
    event RegistrySet(address registry);
    /// @notice Risk Module address was updated
    event RiskModuleSet(address riskModule);
    /// @notice Protocol LTV bounds were updated
    event LtvBoundsSet(uint256 minLtv, uint256 maxLtv);
    /// @notice Oracle associated with an asset was updated
    event OracleSet(address indexed asset, address oracle);
    /// @notice Pending LTV update was rejected
    event LtvUpdateRejected(uint256 indexed poolId, address indexed asset);
    /// @notice Pending LTV update was accepted
    event LtvUpdateAccepted(
        uint256 indexed poolId,
        address indexed asset,
        uint256 ltv
    );
    /// @notice LTV update was requested
    event LtvUpdateRequested(
        uint256 indexed poolId,
        address indexed asset,
        LtvUpdate ltvUpdate
    );
    /// @notice Allowed base pool pair toggled
    event PoolPairToggled(
        uint256 indexed poolA,
        uint256 indexed poolB,
        bool isAllowed
    );

    /// @notice There is no oracle associated with the given asset
    error RiskEngine_NoOracleFound(address asset);
    /// @notice Proposed LTV is outside of protocol LTV bounds
    error RiskEngine_LtvLimitBreached(uint256 ltv);
    /// @notice There is no pending LTV update for the given Pool-Asset pair
    error RiskEngine_NoLtvUpdate(uint256 poolId, address asset);
    /// @notice Function access is restricted to the owner of the pool
    error RiskEngine_OnlyPoolOwner(uint256 poolId, address sender);
    /// @notice Timelock delay for the pending LTV update has not been completed
    error RiskEngine_LtvUpdateTimelocked(uint256 poolId, address asset);
    /// @notice Timelock deadline for LTV update has passed
    error RiskEngine_LtvUpdateExpired(uint256 poolId, address asset);
    /// @notice Global min ltv cannot be zero
    error RiskEngine_MinLtvTooLow();
    /// @notice Global max ltv must be less than 100%
    error RiskEngine_MaxLtvTooHigh();
    /// @notice Pool LTV for the asset being lent out must be zero
    error RiskEngine_CannotBorrowPoolAsset(uint256 poolId);
    /// @notice Min Ltv is not less than Max Ltv
    error RiskEngine_InvalidLtvLimits(uint256 minLtv, uint256 maxLtv);
    /// @notice Base pool has not been initialized
    error RiskEngine_InvalidBasePool(uint256 poolId);

    /// @param registry_ Sentiment Registry
    /// @param minLtv_ Minimum LTV bound
    /// @param maxLtv_ Maximum LTV bound
    constructor(address registry_, uint256 minLtv_, uint256 maxLtv_) Ownable() {
        if (minLtv_ == 0) revert RiskEngine_MinLtvTooLow();
        if (maxLtv_ >= 1e18) revert RiskEngine_MaxLtvTooHigh();
        if (minLtv_ >= maxLtv_)
            revert RiskEngine_InvalidLtvLimits(minLtv_, maxLtv_);

        registry = Registry(registry_);
        minLtv = minLtv_;
        maxLtv = maxLtv_;

        emit LtvBoundsSet(minLtv_, maxLtv_);
    }

    /// @notice Fetch and update module addreses from the registry
    function updateFromRegistry() external {
        pool = Pool(registry.addressFor(SENTIMENT_POOL_KEY));
        riskModule = RiskModule(registry.addressFor(SENTIMENT_RISK_MODULE_KEY));
        emit PoolSet(address(pool));
        emit RiskModuleSet(address(riskModule));
    }

    /// @notice Fetch value of given asset amount in ETH
    function getValueInEth(
        address asset,
        uint256 amt
    ) public view returns (uint256) {
        if (amt == 0) return 0;
        address oracle = oracleFor[asset];
        if (oracle == address(0)) revert RiskEngine_NoOracleFound(asset);
        return IOracle(oracle).getValueInEth(asset, amt);
    }

    /// @notice Fetch position health factor
    function getPositionHealthFactor(
        address position
    ) external view returns (uint256) {
        return riskModule.getPositionHealthFactor(position);
    }

    /// @notice Validate liquidator data and value of assets seized
    function validateLiquidation(
        address position,
        DebtData[] calldata debtData,
        AssetData[] calldata assetData
    )
        external
        view
        returns (uint256, uint256, DebtData[] memory, AssetData[] memory)
    {
        return riskModule.validateLiquidation(position, debtData, assetData);
    }

    /// @notice Validate liquidator data for assets to be repaid
    function validateBadDebtLiquidation(
        address position,
        DebtData[] calldata debtData
    ) external view returns (DebtData[] memory, AssetData[] memory) {
        return riskModule.validateBadDebtLiquidation(position, debtData);
    }

    /// @notice Fetch risk-associated data for a given position
    /// @param position The address of the position to get the risk data for
    /// @return totalAssetValue The total asset value of the position
    /// @return totalDebtValue The total debt value of the position
    /// @return minReqAssetValue The minimum required asset value for the position to be healthy
    function getRiskData(
        address position
    ) external view returns (uint256, uint256, uint256) {
        return riskModule.getRiskData(position);
    }

    /// @notice Allow poolA to lend against positions that also borrow from poolB
    /// @dev When toggled or untoggled, only applies to future borrows
    function toggleAllowedPoolPair(uint256 poolA, uint256 poolB) external {
        if (pool.ownerOf(poolA) != msg.sender)
            revert RiskEngine_OnlyPoolOwner(poolA, msg.sender);
        if (pool.ownerOf(poolB) == address(0))
            revert RiskEngine_InvalidBasePool(poolB);
        isAllowedPair[poolA][poolB] = !isAllowedPair[poolA][poolB];
        emit PoolPairToggled(poolA, poolB, isAllowedPair[poolA][poolB]);
    }

    /// @notice Propose an LTV update for a given Pool-Asset pair
    /// @dev overwrites any pending or expired updates
    function requestLtvUpdate(
        uint256 poolId,
        address asset,
        uint256 ltv
    ) external {
        if (msg.sender != pool.ownerOf(poolId))
            revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        // set oracle before ltv so risk modules don't have to explicitly check if an oracle exists
        if (oracleFor[asset] == address(0))
            revert RiskEngine_NoOracleFound(asset);

        // ensure new ltv is within global limits. also enforces that an existing ltv cannot be updated to zero
        if (ltv < minLtv || ltv > maxLtv)
            revert RiskEngine_LtvLimitBreached(ltv);

        // Positions cannot borrow against the same asset that is being lent out
        if (pool.getPoolAssetFor(poolId) == asset)
            revert RiskEngine_CannotBorrowPoolAsset(poolId);

        LtvUpdate memory ltvUpdate;
        // only modification of previously set ltvs require a timelock
        if (ltvFor[poolId][asset] == 0)
            ltvUpdate = LtvUpdate({ltv: ltv, validAfter: block.timestamp});
        else
            ltvUpdate = LtvUpdate({
                ltv: ltv,
                validAfter: block.timestamp + TIMELOCK_DURATION
            });

        ltvUpdateFor[poolId][asset] = ltvUpdate;

        emit LtvUpdateRequested(poolId, asset, ltvUpdate);
    }

    /// @notice Apply a pending LTV update
    function acceptLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId))
            revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);
        if (oracleFor[asset] == address(0))
            revert RiskEngine_NoOracleFound(asset);

        LtvUpdate memory ltvUpdate = ltvUpdateFor[poolId][asset];

        // revert if there is no pending update
        if (ltvUpdate.validAfter == 0)
            revert RiskEngine_NoLtvUpdate(poolId, asset);

        // revert if called before timelock delay has passed
        if (ltvUpdate.validAfter > block.timestamp)
            revert RiskEngine_LtvUpdateTimelocked(poolId, asset);

        // revert if timelock deadline has passed
        if (block.timestamp > ltvUpdate.validAfter + TIMELOCK_DEADLINE) {
            revert RiskEngine_LtvUpdateExpired(poolId, asset);
        }

        // apply changes
        ltvFor[poolId][asset] = ltvUpdate.ltv;
        delete ltvUpdateFor[poolId][asset];
        emit LtvUpdateAccepted(poolId, asset, ltvUpdate.ltv);
    }

    /// @notice Reject a pending LTV update
    function rejectLtvUpdate(uint256 poolId, address asset) external {
        if (msg.sender != pool.ownerOf(poolId))
            revert RiskEngine_OnlyPoolOwner(poolId, msg.sender);

        delete ltvUpdateFor[poolId][asset];

        emit LtvUpdateRejected(poolId, asset);
    }

    /// @notice Set Protocol LTV bounds
    function setLtvBounds(uint256 _minLtv, uint256 _maxLtv) external onlyOwner {
        if (_minLtv == 0) revert RiskEngine_MinLtvTooLow();
        if (_maxLtv >= 1e18) revert RiskEngine_MaxLtvTooHigh();
        if (_minLtv >= _maxLtv)
            revert RiskEngine_InvalidLtvLimits(_minLtv, _maxLtv);

        minLtv = _minLtv;
        maxLtv = _maxLtv;

        emit LtvBoundsSet(_minLtv, _maxLtv);
    }

    /// @notice Set the oracle address used to price a given asset
    /// @dev Does not support ERC777s, rebasing and fee-on-transfer tokens
    function setOracle(address asset, address oracle) external onlyOwner {
        oracleFor[asset] = oracle;

        emit OracleSet(asset, oracle);
    }

    /// @notice Update the registry associated with this Risk Engine
    function setRegistry(address newRegistry) external onlyOwner {
        registry = Registry(newRegistry);
        emit RegistrySet(newRegistry);
    }
}
