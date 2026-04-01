// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TOPRFRegistry.sol";

contract TOPRFRegistryTest is Test {
    TOPRFRegistry registry;
    address owner = address(this);

    function setUp() public {
        registry = new TOPRFRegistry();
    }

    function testRecordNode() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aabb",
            attestationReport: hex"ccdd",
            certChain: hex"eeff",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);
        assertEq(registry.nodeCount(), 1);
    }

    function testRecordMultipleNodes() public {
        for (uint8 i = 1; i <= 3; i++) {
            TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
                nodeId: i,
                dkgCommitment: abi.encodePacked(i),
                attestationReport: abi.encodePacked(i),
                certChain: abi.encodePacked(i),
                verificationShare: bytes32(uint256(i))
            });
            registry.recordNode(i, record);
        }
        assertEq(registry.nodeCount(), 3);
    }

    function testFinalize() public {
        // Record 2 nodes
        for (uint8 i = 1; i <= 2; i++) {
            TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
                nodeId: i,
                dkgCommitment: abi.encodePacked(i),
                attestationReport: abi.encodePacked(i),
                certChain: abi.encodePacked(i),
                verificationShare: bytes32(uint256(i))
            });
            registry.recordNode(i, record);
        }
        registry.finalize(bytes32(uint256(42)), "https://github.com/ruonlabs/threshold-oprf", 2);
        assertTrue(registry.finalized());
        assertEq(registry.groupPublicKey(), bytes32(uint256(42)));
        assertEq(registry.threshold(), 2);
        assertEq(keccak256(bytes(registry.sourceRepo())), keccak256(bytes("https://github.com/ruonlabs/threshold-oprf")));
    }

    function testCannotRecordAfterFinalize() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);
        registry.finalize(bytes32(uint256(42)), "repo", 1);

        TOPRFRegistry.NodeRecord memory record2 = TOPRFRegistry.NodeRecord({
            nodeId: 2,
            dkgCommitment: hex"dd",
            attestationReport: hex"ee",
            certChain: hex"ff",
            verificationShare: bytes32(uint256(2))
        });
        vm.expectRevert("Already finalized");
        registry.recordNode(2, record2);
    }

    function testCannotFinalizeWithoutEnoughNodes() public {
        vm.expectRevert("Not enough nodes");
        registry.finalize(bytes32(uint256(42)), "repo", 2);
    }

    function testCannotFinalizeTwice() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);
        registry.finalize(bytes32(uint256(42)), "repo", 1);

        vm.expectRevert("Already finalized");
        registry.finalize(bytes32(uint256(99)), "repo2", 1);
    }

    function testCannotRecordDuplicateNode() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);

        vm.expectRevert("Node already recorded");
        registry.recordNode(1, record);
    }

    function testNonOwnerCannotRecord() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        vm.prank(address(0xdead));
        vm.expectRevert();
        registry.recordNode(1, record);
    }

    function testNonOwnerCannotFinalize() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);

        vm.prank(address(0xdead));
        vm.expectRevert();
        registry.finalize(bytes32(uint256(42)), "repo", 1);
    }
}
