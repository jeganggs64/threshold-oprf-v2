// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TOPRFRegistry
/// @notice Immutable on-chain record of a FROST DKG ceremony.
///         All data is set in the constructor. No functions, no owner, no mutations.
///         Exists solely as public proof that DKG happened and no one held the master key.
contract TOPRFRegistry {
    struct NodeRecord {
        uint8   nodeId;
        bytes   dkgCommitment;
        bytes   attestationReport;
        bytes   certChain;
        bytes32 verificationShare;
    }

    bytes32 public immutable groupPublicKey;
    string  public sourceRepo;
    uint8   public immutable threshold;
    uint8   public immutable nodeCount;
    uint256 public immutable dkgTimestamp;

    mapping(uint8 => NodeRecord) public nodes;

    constructor(
        bytes32 _groupPublicKey,
        string memory _sourceRepo,
        uint8 _threshold,
        NodeRecord[] memory _nodes
    ) {
        require(_nodes.length >= _threshold, "Not enough nodes");

        groupPublicKey = _groupPublicKey;
        sourceRepo = _sourceRepo;
        threshold = _threshold;
        nodeCount = uint8(_nodes.length);
        dkgTimestamp = block.timestamp;

        for (uint8 i = 0; i < _nodes.length; i++) {
            require(_nodes[i].nodeId > 0, "nodeId must be nonzero");
            require(nodes[_nodes[i].nodeId].nodeId == 0, "Duplicate nodeId");
            nodes[_nodes[i].nodeId] = _nodes[i];
        }
    }
}
