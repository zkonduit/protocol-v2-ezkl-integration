// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Deploy} from "../script/Deploy.s.sol";
import {FixedRateModel} from "../src/irm/FixedRateModel.sol";
import {LinearRateModel} from "../src/irm/LinearRateModel.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockSwap} from "./mocks/MockSwap.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Pool} from "src/Pool.sol";
import {Position} from "src/Position.sol";
import {PositionManager} from "src/PositionManager.sol";
import {Action, Operation, PositionManager} from "src/PositionManager.sol";
import {Registry} from "src/Registry.sol";
import {RiskEngine} from "src/RiskEngine.sol";
import {RiskModule} from "src/RiskModule.sol";
import {SuperPool} from "src/SuperPool.sol";
import {SuperPoolFactory} from "src/SuperPoolFactory.sol";
import {PortfolioLens} from "src/lens/PortfolioLens.sol";
import {SuperPoolLens} from "src/lens/SuperPoolLens.sol";
import {FixedPriceOracle} from "src/oracle/FixedPriceOracle.sol";
import {Comptroller} from "src/ezkl/Comptroller.sol";
import {Halo2Verifier} from "src/ezkl/Verifier.sol";
import {UniTickAttestor} from "src/ezkl/UniTickAttestor.sol";

// Add Uniswap V3 imports
import {IUniswapV3Factory} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol";
import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

contract BaseTest is Test {
    address public user = makeAddr("user");
    address public user2 = makeAddr("user2");
    address public lender = makeAddr("lender");
    address public poolOwner;
    address public proxyAdmin = makeAddr("proxyAdmin");
    address public protocolOwner = makeAddr("protocolOwner");

    MockERC20 public asset1;
    MockERC20 public asset2;
    MockERC20 public asset3;

    MockSwap public mockswap;
    bytes4 public constant SWAP_FUNC_SELECTOR =
        bytes4(
            bytes32(
                0xdf791e5000000000000000000000000000000000000000000000000000000000
            )
        );

    uint256 public fixedRatePool;
    uint256 public linearRatePool;
    uint256 public fixedRatePool2;
    uint256 public linearRatePool2;
    uint256 public alternateAssetPool;

    Deploy public protocol;
    uint public constant LOOKBACK_DAYS = 20;
    Comptroller public comptroller;
    int256[] public dailyPrices;
    IUniswapV3Factory public uniswapFactory;
    IUniswapV3Pool public uniswapPool;
    uint24 public constant POOL_FEE = 3000; // 0.3% fee tier

    // Split pool creation into separate function

    function setUp() public virtual {
        Deploy.DeployParams memory params = Deploy.DeployParams({
            owner: protocolOwner,
            proxyAdmin: proxyAdmin,
            feeRecipient: address(this),
            minLtv: 1e17, // 0.1
            maxLtv: 9e17, // 0.9
            minDebt: 0,
            minBorrow: 0,
            liquidationFee: 0,
            liquidationDiscount: 200_000_000_000_000_000,
            badDebtLiquidationDiscount: 1e16,
            defaultOriginationFee: 0,
            defaultInterestFee: 0
        });

        protocol = new Deploy();
        protocol.runWithParams(params);

        asset1 = new MockERC20("Asset1", "ASSET1", 18);
        asset2 = new MockERC20("Asset2", "ASSET2", 18);
        asset3 = new MockERC20("Asset3", "ASSET3", 18);

        mockswap = new MockSwap();

        vm.startPrank(protocolOwner);
        protocol.positionManager().toggleKnownAsset(address(asset1));
        protocol.positionManager().toggleKnownAsset(address(asset2));
        protocol.positionManager().toggleKnownAsset(address(asset3));
        protocol.positionManager().toggleKnownSpender(address(mockswap));
        protocol.positionManager().toggleKnownFunc(
            address(mockswap),
            SWAP_FUNC_SELECTOR
        );
        vm.stopPrank();

        FixedPriceOracle testOracle = new FixedPriceOracle(1e18);
        vm.startPrank(protocolOwner);
        protocol.riskEngine().setOracle(address(asset1), address(testOracle));
        protocol.riskEngine().setOracle(address(asset2), address(testOracle));
        vm.stopPrank();

        address fixedRateModel = address(new FixedRateModel(1e18));
        address linearRateModel = address(new LinearRateModel(1e18, 2e18));
        address fixedRateModel2 = address(new FixedRateModel(2e18));
        address linearRateModel2 = address(new LinearRateModel(2e18, 3e18));

        bytes32 FIXED_RATE_MODEL_KEY = 0xeba2c14de8b8ca05a15d7673453a0a3b315f122f56770b8bb643dc4bfbcf326b;
        bytes32 LINEAR_RATE_MODEL_KEY = 0x7922391f605f567c8e61c33be42b581e2f71019b5dce3c47110ad332b7dbd68c;
        bytes32 FIXED_RATE_MODEL2_KEY = 0x65347a20305cbd3ca20cb81ec8a2261639f4e635b4b5f3039a9aa5e7e03f41a7;
        bytes32 LINEAR_RATE_MODEL2_KEY = 0xd61dc960093d99acc135f998430c41a550d91de727e66a94fd8e7a8a24d99ecf;

        vm.startPrank(protocolOwner);
        Registry(protocol.registry()).setRateModel(
            FIXED_RATE_MODEL_KEY,
            fixedRateModel
        );
        Registry(protocol.registry()).setRateModel(
            LINEAR_RATE_MODEL_KEY,
            linearRateModel
        );
        Registry(protocol.registry()).setRateModel(
            FIXED_RATE_MODEL2_KEY,
            fixedRateModel2
        );
        Registry(protocol.registry()).setRateModel(
            LINEAR_RATE_MODEL2_KEY,
            linearRateModel2
        );
        vm.stopPrank();

        // Load historical price data from a JSON file
        string memory jsonData = vm.readFile("price_data.json");
        bytes memory parsedData = vm.parseJson(jsonData);
        dailyPrices = abi.decode(parsedData, (int256[]));

        // Ensure we have enough data
        require(
            dailyPrices.length >= LOOKBACK_DAYS,
            "Not enough historical data"
        );

        // Take last LOOKBACK_DAYS prices
        int256[] memory recentPrices = new int256[](LOOKBACK_DAYS);
        for (uint i = 0; i < LOOKBACK_DAYS; i++) {
            recentPrices[i] = dailyPrices[
                dailyPrices.length - LOOKBACK_DAYS + i
            ];
        }
        // Deploy the verifier contract
        Halo2Verifier verifier = new Halo2Verifier();

        uint256[20] memory scales = [
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13),
            uint256(13)
        ];

        // Deploy UniTickAttestor
        UniTickAttestor uniTickAttestor = new UniTickAttestor(
            recentPrices,
            address(testOracle)
        );

        bytes memory call_data = abi.encodeWithSelector(
            UniTickAttestor.consult.selector,
            LOOKBACK_DAYS
        ); // The call data which fetches the data to be attested to.

        // Update the comptroller deployment to use the actual Uniswap pool
        comptroller = new Comptroller(
            call_data,
            6, // The number of decimals in USDC
            scales,
            0,
            address(this),
            address(verifier),
            address(uniTickAttestor),
            address(protocol.pool()),
            address(asset1)
        );

        poolOwner = address(comptroller);

        asset1.mint(poolOwner, 4e7);
        asset2.mint(poolOwner, 1e7);

        vm.startPrank(poolOwner);
        asset1.approve(address(protocol.pool()), type(uint256).max);
        asset2.approve(address(protocol.pool()), type(uint256).max);
        fixedRatePool = protocol.pool().initializePool(
            poolOwner,
            address(asset1),
            FIXED_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        linearRatePool = protocol.pool().initializePool(
            poolOwner,
            address(asset1),
            LINEAR_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        fixedRatePool2 = protocol.pool().initializePool(
            poolOwner,
            address(asset1),
            FIXED_RATE_MODEL2_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        linearRatePool2 = protocol.pool().initializePool(
            poolOwner,
            address(asset1),
            LINEAR_RATE_MODEL2_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        alternateAssetPool = protocol.pool().initializePool(
            poolOwner,
            address(asset2),
            FIXED_RATE_MODEL_KEY,
            type(uint256).max,
            type(uint256).max,
            1e7
        );
        vm.stopPrank();
    }

    function newPosition(
        address owner,
        bytes32 salt
    ) internal view returns (address payable, Action memory) {
        bytes memory data = abi.encodePacked(owner, salt);
        (address position, ) = protocol.portfolioLens().predictAddress(
            owner,
            salt
        );
        Action memory action = Action({op: Operation.NewPosition, data: data});
        return (payable(position), action);
    }

    function deposit(
        address asset,
        uint256 amt
    ) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(asset, amt);
        Action memory action = Action({op: Operation.Deposit, data: data});
        return action;
    }

    function addToken(address asset) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(asset);
        Action memory action = Action({op: Operation.AddToken, data: data});
        return action;
    }

    function removeToken(address asset) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(asset);
        Action memory action = Action({op: Operation.RemoveToken, data: data});
        return action;
    }

    function borrow(
        uint256 poolId,
        uint256 amt
    ) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(poolId, amt);
        Action memory action = Action({op: Operation.Borrow, data: data});
        return action;
    }

    function approve(
        address spender,
        address asset,
        uint256 amt
    ) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(spender, asset, amt);
        Action memory action = Action({op: Operation.Approve, data: data});
        return action;
    }

    function transfer(
        address recipient,
        address asset,
        uint256 amt
    ) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(recipient, asset, amt);
        Action memory action = Action({op: Operation.Transfer, data: data});
        return action;
    }

    function exec(
        address target,
        uint256 value,
        bytes memory execData
    ) internal pure returns (Action memory) {
        bytes memory data = abi.encodePacked(target, value, execData);
        Action memory action = Action({op: Operation.Exec, data: data});
        return action;
    }
}
