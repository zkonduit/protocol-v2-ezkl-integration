// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FixedRateModel} from "../../src/irm/FixedRateModel.sol";
import {LinearRateModel} from "../../src/irm/LinearRateModel.sol";
import "../BaseTest.t.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {Action, Operation} from "src/PositionManager.sol";
import {RiskEngine} from "src/RiskEngine.sol";
import {FixedPriceOracle} from "src/oracle/FixedPriceOracle.sol";
import {Halo2Verifier} from "src/ezkl/Verifier.sol";
import {console2} from "forge-std/console2.sol";
import {console} from "forge-std/console.sol";

contract RiskEngineUnitTests is BaseTest {
    Pool pool;
    address position;
    Registry registry;
    RiskEngine riskEngine;
    address positionOwner = makeAddr("positionOwner");
    FixedPriceOracle asset1Oracle = new FixedPriceOracle(10e18);
    FixedPriceOracle asset2Oracle = new FixedPriceOracle(0.5e18);
    uint256[] public instances = [
        uint256(
            0x00000000000000000000000000000000000000000000000000000000000307f2
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002f24c
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002e41f
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002b66b
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000000000000289e5
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000000000028e79
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002e2d2
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000000000030a4f
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002c52f
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002d9d7
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002e790
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002c4c2
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002e4fb
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002c24c
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002f7d0
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000003760a
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000000000035d0c
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002f4e5
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000002c56a
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000003068e
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000000000000334
        )
    ];
    function setUp() public override {
        super.setUp();

        pool = protocol.pool();
        registry = protocol.registry();
        riskEngine = protocol.riskEngine();

        vm.startPrank(protocolOwner);
        riskEngine.setOracle(address(asset1), address(asset1Oracle));
        riskEngine.setOracle(address(asset2), address(asset2Oracle));
        vm.stopPrank();

        asset1.mint(address(this), 10_000 ether);
        asset1.approve(address(pool), 10_000 ether);

        pool.deposit(linearRatePool, 10_000 ether, address(0x9));
    }

    function testRiskEngineInit() public {
        RiskEngine testRiskEngine = new RiskEngine(
            address(registry),
            0.1e18,
            0.9e18
        );
        assertEq(address(testRiskEngine.registry()), address(registry));
        assertEq(testRiskEngine.minLtv(), 0.1e18);
        assertEq(testRiskEngine.maxLtv(), 0.9e18);
    }

    function testNoOracleFound(address asset) public view {
        vm.assume(asset != address(asset1) && asset != address(asset2));
        assertEq(riskEngine.oracleFor(asset), address(0));
    }

    function testComptrollerCanUpdateLTV() public {
        uint256 startLtv = riskEngine.ltvFor(linearRatePool, address(asset2));
        assertEq(startLtv, 0);

        // Get proof data and log its size
        string[] memory inputs = new string[](1);
        inputs[0] = "./hex_proof_script.sh";
        bytes memory proof = vm.ffi(inputs);

        comptroller.ltvUpdate(
            Comptroller.LtvUpdate.Request,
            address(riskEngine),
            linearRatePool,
            address(asset2),
            proof,
            instances
        );

        uint[] memory dummyInstances = new uint[](0);

        comptroller.ltvUpdate(
            Comptroller.LtvUpdate.Accept,
            address(riskEngine),
            linearRatePool,
            address(asset2),
            "",
            dummyInstances
        );

        assertEq(
            riskEngine.ltvFor(linearRatePool, address(asset2)),
            899902343750000000
        );
    }

    function testOnlyOwnerCanUpdateLTV(address sender) public {
        vm.assume(sender != poolOwner);

        vm.startPrank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(
                RiskEngine.RiskEngine_OnlyPoolOwner.selector,
                linearRatePool,
                sender
            )
        );
        riskEngine.requestLtvUpdate(linearRatePool, address(asset1), 0.75e18);
    }

    function testCannotUpdateLTVForUnknownAsset(
        address asset,
        uint256 ltv
    ) public {
        vm.assume(asset != address(asset1) && asset != address(asset2));

        vm.prank(poolOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                RiskEngine.RiskEngine_NoOracleFound.selector,
                asset
            )
        );
        riskEngine.requestLtvUpdate(linearRatePool, asset, ltv);
    }

    function testOwnerCanRejectLTVUpdated() public {
        // Set a starting non-zero ltv
        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));

        assertEq(riskEngine.ltvFor(linearRatePool, address(asset2)), 0.75e18);

        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.5e18);
        riskEngine.rejectLtvUpdate(linearRatePool, address(asset2));

        assertEq(riskEngine.ltvFor(linearRatePool, address(asset2)), 0.75e18);
    }

    function testNoLTVUpdate() public {
        vm.prank(poolOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                RiskEngine.RiskEngine_NoLtvUpdate.selector,
                linearRatePool,
                address(asset1)
            )
        );
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset1));
    }

    function testNonOwnerCannotUpdateLTV() public {
        vm.prank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);

        vm.startPrank(makeAddr("notOwner"));
        vm.expectRevert();
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));

        vm.expectRevert();
        riskEngine.rejectLtvUpdate(linearRatePool, address(asset2));

        assertEq(riskEngine.ltvFor(linearRatePool, address(asset2)), 0);
    }

    function testCannotSetLTVOutsideGlobalLimits() public {
        vm.prank(riskEngine.owner());
        riskEngine.setLtvBounds(0.25e18, 0.75e18);

        vm.startPrank(poolOwner);
        vm.expectRevert();
        riskEngine.requestLtvUpdate(linearRatePool, address(asset1), 0.24e18);

        vm.expectRevert();
        riskEngine.requestLtvUpdate(linearRatePool, address(asset1), 0.76e18);

        assertEq(riskEngine.ltvFor(linearRatePool, address(asset1)), 0);
    }

    function testCannotUpdateLTVBeforeTimelock() public {
        vm.startPrank(poolOwner);
        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.75e18);
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));

        riskEngine.requestLtvUpdate(linearRatePool, address(asset2), 0.5e18);

        vm.expectRevert();
        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));

        assertEq(riskEngine.ltvFor(linearRatePool, address(asset2)), 0.75e18);

        vm.warp(block.timestamp + 2 days);

        riskEngine.acceptLtvUpdate(linearRatePool, address(asset2));
    }
}
