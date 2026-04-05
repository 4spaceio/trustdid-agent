// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

interface ITrustDIDRegistry {
    function createDID(
        string calldata didStr,
        bytes32 documentHash,
        bytes32 preRotationCommitment
    ) external;

    function updateDID(
        string calldata didStr,
        bytes32 newDocumentHash
    ) external;

    function deactivateDID(string calldata didStr) external;

    function decommissionDID(string calldata didStr) external;

    function rotateKey(
        string calldata didStr,
        bytes32 newDocumentHash,
        bytes32 preRotationProof,
        bytes32 newCommitment
    ) external;

    function registerDelegation(
        string calldata parentDIDStr,
        string calldata childDIDStr,
        uint8 depth
    ) external;

    function resolve(string calldata didStr) external view returns (
        address owner,
        uint8 status,
        uint32 nonce,
        uint8 delegationDepth,
        bytes32 documentHash,
        bytes32 preRotationCommitment
    );

    function isActive(string calldata didStr) external view returns (bool);

    function childCount(string calldata didStr) external view returns (uint256);
}
