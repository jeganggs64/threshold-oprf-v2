// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TOPRFRegistry is Ownable {
    struct NodeRecord {
        uint8   nodeId;
        bytes   dkgCommitment;
        bytes   attestationReport;
        bytes   certChain;
        bytes32 verificationShare;
    }

    bytes32 public groupPublicKey;
    string  public sourceRepo;
    uint8   public threshold;
    uint256 public dkgTimestamp;
    bool    public finalized;

    mapping(uint8 => NodeRecord) public nodes;
    uint8 public nodeCount;

    event NodeRecorded(uint8 indexed nodeId);
    event Finalized(bytes32 groupPublicKey, uint8 threshold);

    constructor() Ownable(msg.sender) {}

    function recordNode(uint8 nodeId, NodeRecord calldata record) external onlyOwner {
        require(!finalized, "Already finalized");
        require(nodes[nodeId].nodeId == 0, "Node already recorded");
        nodes[nodeId] = record;
        nodeCount++;
        emit NodeRecorded(nodeId);
    }

    function finalize(
        bytes32 _groupPublicKey,
        string calldata _sourceRepo,
        uint8 _threshold
    ) external onlyOwner {
        require(!finalized, "Already finalized");
        require(nodeCount >= _threshold, "Not enough nodes");
        groupPublicKey = _groupPublicKey;
        sourceRepo = _sourceRepo;
        threshold = _threshold;
        dkgTimestamp = block.timestamp;
        finalized = true;
        emit Finalized(_groupPublicKey, _threshold);
    }
}
