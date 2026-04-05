// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

/// @title DelegationChain
/// @notice On-chain delegation graph for AI agent capability chains.
/// @dev Tracks parent-child relationships with depth enforcement and cascading revocation.
contract DelegationChain {
    // ──────────────────────────────── Storage ────────────────────────────────

    struct Delegation {
        bytes32 parentHash;
        bytes32 childHash;
        address registeredBy;
        uint8 depth;
        uint8 maxDepth;
        bytes32 capabilityHash;   // keccak256 of capability list
        uint64 createdAt;
        bool revoked;
    }

    /// @dev Delegation ID => Delegation record
    mapping(bytes32 => Delegation) private _delegations;

    /// @dev Parent hash => list of delegation IDs
    mapping(bytes32 => bytes32[]) private _parentDelegations;

    /// @dev Child hash => delegation ID (each child has exactly one parent delegation)
    mapping(bytes32 => bytes32) private _childDelegation;

    uint8 public constant MAX_DELEGATION_DEPTH = 10;

    // ──────────────────────────────── Events ─────────────────────────────────

    event DelegationCreated(
        bytes32 indexed delegationId,
        bytes32 indexed parentHash,
        bytes32 indexed childHash,
        uint8 depth,
        uint8 maxDepth,
        uint256 timestamp
    );

    event DelegationRevoked(bytes32 indexed delegationId, bool cascade, uint256 timestamp);

    // ──────────────────────────────── Errors ─────────────────────────────────

    error DepthExceeded();
    error DelegationNotFound();
    error DelegationAlreadyRevoked();
    error NotDelegationOwner();
    error ChildAlreadyDelegated();

    // ──────────────────────────────── Core Operations ────────────────────────

    /// @notice Register a new delegation from parent to child.
    function createDelegation(
        string calldata parentDID,
        string calldata childDID,
        uint8 depth,
        uint8 maxDepth,
        bytes32 capabilityHash
    ) external returns (bytes32) {
        if (depth > MAX_DELEGATION_DEPTH || depth > maxDepth) revert DepthExceeded();

        bytes32 parentHash = keccak256(bytes(parentDID));
        bytes32 childHash = keccak256(bytes(childDID));

        if (_childDelegation[childHash] != bytes32(0)) revert ChildAlreadyDelegated();

        bytes32 delegationId = keccak256(abi.encodePacked(parentHash, childHash, block.timestamp));

        _delegations[delegationId] = Delegation({
            parentHash: parentHash,
            childHash: childHash,
            registeredBy: msg.sender,
            depth: depth,
            maxDepth: maxDepth,
            capabilityHash: capabilityHash,
            createdAt: uint64(block.timestamp),
            revoked: false
        });

        _parentDelegations[parentHash].push(delegationId);
        _childDelegation[childHash] = delegationId;

        emit DelegationCreated(delegationId, parentHash, childHash, depth, maxDepth, block.timestamp);
        return delegationId;
    }

    /// @notice Revoke a delegation. Optionally cascade to all children.
    function revokeDelegation(bytes32 delegationId, bool cascade) external {
        Delegation storage d = _delegations[delegationId];
        if (d.registeredBy == address(0)) revert DelegationNotFound();
        if (d.registeredBy != msg.sender) revert NotDelegationOwner();
        if (d.revoked) revert DelegationAlreadyRevoked();

        d.revoked = true;
        emit DelegationRevoked(delegationId, cascade, block.timestamp);

        if (cascade) {
            _cascadeRevoke(d.childHash);
        }
    }

    function _cascadeRevoke(bytes32 parentHash) internal {
        bytes32[] storage childDelegations = _parentDelegations[parentHash];
        for (uint256 i = 0; i < childDelegations.length; i++) {
            Delegation storage child = _delegations[childDelegations[i]];
            if (!child.revoked) {
                child.revoked = true;
                emit DelegationRevoked(childDelegations[i], true, block.timestamp);
                _cascadeRevoke(child.childHash);
            }
        }
    }

    // ──────────────────────────────── View Functions ─────────────────────────

    function getDelegation(bytes32 delegationId) external view returns (
        bytes32 parentHash,
        bytes32 childHash,
        address registeredBy,
        uint8 depth,
        uint8 maxDepth,
        bytes32 capabilityHash,
        uint64 createdAt,
        bool revoked
    ) {
        Delegation storage d = _delegations[delegationId];
        if (d.registeredBy == address(0)) revert DelegationNotFound();
        return (d.parentHash, d.childHash, d.registeredBy, d.depth, d.maxDepth, d.capabilityHash, d.createdAt, d.revoked);
    }

    function getChildDelegation(string calldata childDID) external view returns (bytes32) {
        bytes32 childHash = keccak256(bytes(childDID));
        return _childDelegation[childHash];
    }

    function getChildCount(string calldata parentDID) external view returns (uint256) {
        bytes32 parentHash = keccak256(bytes(parentDID));
        return _parentDelegations[parentHash].length;
    }

    function isRevoked(bytes32 delegationId) external view returns (bool) {
        return _delegations[delegationId].revoked;
    }

    /// @notice Verify the full delegation chain from child to root is valid (not revoked).
    function verifyChain(string calldata childDID) external view returns (bool valid, uint8 depth) {
        bytes32 currentHash = keccak256(bytes(childDID));
        depth = 0;

        while (true) {
            bytes32 delegationId = _childDelegation[currentHash];
            if (delegationId == bytes32(0)) {
                // Reached root (no parent delegation)
                return (true, depth);
            }

            Delegation storage d = _delegations[delegationId];
            if (d.revoked) {
                return (false, depth);
            }

            currentHash = d.parentHash;
            depth++;

            if (depth > MAX_DELEGATION_DEPTH) {
                return (false, depth);
            }
        }

        return (true, depth);
    }
}
