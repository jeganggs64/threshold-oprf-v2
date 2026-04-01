// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TOPRFRegistry.sol";

contract TOPRFRegistryTest is Test {

    function _makeNodes(uint8 count) internal pure returns (TOPRFRegistry.NodeRecord[] memory) {
        TOPRFRegistry.NodeRecord[] memory nodes = new TOPRFRegistry.NodeRecord[](count);
        for (uint8 i = 0; i < count; i++) {
            nodes[i] = TOPRFRegistry.NodeRecord({
                nodeId: i + 1,
                dkgCommitment: abi.encodePacked(i + 1),
                attestationReport: abi.encodePacked(i + 1),
                certChain: abi.encodePacked(i + 1),
                verificationShare: bytes32(uint256(i + 1))
            });
        }
        return nodes;
    }

    function testDeployWithThreeNodes() public {
        TOPRFRegistry.NodeRecord[] memory nodes = _makeNodes(3);
        TOPRFRegistry registry = new TOPRFRegistry(
            bytes32(uint256(42)),
            "https://github.com/ruonlabs/threshold-oprf",
            2,
            nodes
        );

        assertEq(registry.groupPublicKey(), bytes32(uint256(42)));
        assertEq(registry.threshold(), 2);
        assertEq(registry.nodeCount(), 3);
        assertEq(registry.dkgTimestamp(), block.timestamp);

        (uint8 nodeId,,,,) = registry.nodes(1);
        assertEq(nodeId, 1);

        (uint8 nodeId2,,,,) = registry.nodes(2);
        assertEq(nodeId2, 2);
    }

    function testSourceRepo() public {
        TOPRFRegistry.NodeRecord[] memory nodes = _makeNodes(2);
        TOPRFRegistry registry = new TOPRFRegistry(
            bytes32(uint256(1)),
            "https://github.com/ruonlabs/threshold-oprf",
            2,
            nodes
        );
        assertEq(
            keccak256(bytes(registry.sourceRepo())),
            keccak256(bytes("https://github.com/ruonlabs/threshold-oprf"))
        );
    }

    function testImmutableAfterDeploy() public {
        TOPRFRegistry.NodeRecord[] memory nodes = _makeNodes(2);
        TOPRFRegistry registry = new TOPRFRegistry(
            bytes32(uint256(42)),
            "repo",
            2,
            nodes
        );
        assertEq(registry.groupPublicKey(), bytes32(uint256(42)));
        assertEq(registry.nodeCount(), 2);
    }

    function testRejectsNotEnoughNodes() public {
        TOPRFRegistry.NodeRecord[] memory nodes = _makeNodes(1);
        vm.expectRevert("Not enough nodes");
        new TOPRFRegistry(bytes32(uint256(42)), "repo", 2, nodes);
    }

    function testRejectsDuplicateNodeId() public {
        TOPRFRegistry.NodeRecord[] memory nodes = new TOPRFRegistry.NodeRecord[](2);
        nodes[0] = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        nodes[1] = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"dd",
            attestationReport: hex"ee",
            certChain: hex"ff",
            verificationShare: bytes32(uint256(2))
        });
        vm.expectRevert("Duplicate nodeId");
        new TOPRFRegistry(bytes32(uint256(42)), "repo", 1, nodes);
    }

    function testRejectsNodeIdZero() public {
        TOPRFRegistry.NodeRecord[] memory nodes = new TOPRFRegistry.NodeRecord[](1);
        nodes[0] = TOPRFRegistry.NodeRecord({
            nodeId: 0,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        vm.expectRevert("nodeId must be nonzero");
        new TOPRFRegistry(bytes32(uint256(42)), "repo", 1, nodes);
    }

    function testSingleNodeWithThresholdOne() public {
        TOPRFRegistry.NodeRecord[] memory nodes = _makeNodes(1);
        TOPRFRegistry registry = new TOPRFRegistry(
            bytes32(uint256(99)),
            "repo",
            1,
            nodes
        );
        assertEq(registry.nodeCount(), 1);
        assertEq(registry.threshold(), 1);
    }
}
