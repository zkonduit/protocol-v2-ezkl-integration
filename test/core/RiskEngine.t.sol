// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FixedRateModel} from "../../src/irm/FixedRateModel.sol";
import {LinearRateModel} from "../../src/irm/LinearRateModel.sol";
import "../BaseTest.t.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {Action, Operation} from "src/PositionManager.sol";
import {RiskEngine} from "src/RiskEngine.sol";
import {FixedPriceOracle} from "src/oracle/FixedPriceOracle.sol";
import {UniTickAttestor} from "src/ezkl/UniTickAttestor.sol";
import {Halo2Verifier} from "src/ezkl/Verifier.sol";
import {console2} from "forge-std/console2.sol";

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
            0x000000000000000000000000000000000000000000000000000012fccba90000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000011fdbf298000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000012796ca06000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000011d897bc0000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000012d1ba826000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000012ead8404000
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000128b6deea000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000012398af00000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000011ff20eb4000
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000001245b0352000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000011b845ae8000
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000129307f04000
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000001302a1b7e000
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000001321e0604000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000013acf2ae4000
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000001335ff7b6000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000013b17ba86000
        ),
        uint256(
            0x00000000000000000000000000000000000000000000000000001347bbd98000
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000142096a58000
        ),
        uint256(
            0x0000000000000000000000000000000000000000000000000000137bd4546000
        ),
        uint256(
            0x000000000000000000000000000000000000000000000000000000000000033e
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
        uint256 startLtv = riskEngine.ltvFor(linearRatePool, address(asset1));
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

        // assertEq(riskEngine.ltvFor(linearRatePool, address(asset2)), 0.75e18);
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
