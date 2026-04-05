// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

/// @title AgentCapabilityRegistry
/// @notice On-chain registry of agent capabilities as verifiable credential hashes.
/// @dev Stores capability credential hashes linked to agent DIDs for fast on-chain lookup.
contract AgentCapabilityRegistry {
    // ──────────────────────────────── Storage ────────────────────────────────

    struct CapabilityRecord {
        bytes32 credentialHash;   // keccak256 of the VC
        address grantedBy;
        uint64 grantedAt;
        uint64 expiresAt;         // 0 = no expiry
        bool revoked;
    }

    /// @dev Agent DID hash => list of capability record IDs
    mapping(bytes32 => bytes32[]) private _agentCapabilities;

    /// @dev Capability record ID => CapabilityRecord
    mapping(bytes32 => CapabilityRecord) private _records;

    // ──────────────────────────────── Events ─────────────────────────────────

    event CapabilityGranted(
        bytes32 indexed agentHash,
        bytes32 indexed recordId,
        bytes32 credentialHash,
        uint64 expiresAt,
        uint256 timestamp
    );

    event CapabilityRevoked(bytes32 indexed recordId, uint256 timestamp);

    // ──────────────────────────────── Errors ─────────────────────────────────

    error RecordNotFound();
    error NotGranter();
    error AlreadyRevoked();

    // ──────────────────────────────── Core Operations ────────────────────────

    /// @notice Grant a capability to an agent by registering a credential hash.
    function grantCapability(
        string calldata agentDID,
        bytes32 credentialHash,
        uint64 expiresAt
    ) external returns (bytes32) {
        bytes32 agentHash = keccak256(bytes(agentDID));
        bytes32 recordId = keccak256(abi.encodePacked(agentHash, credentialHash, block.timestamp));

        _records[recordId] = CapabilityRecord({
            credentialHash: credentialHash,
            grantedBy: msg.sender,
            grantedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revoked: false
        });

        _agentCapabilities[agentHash].push(recordId);

        emit CapabilityGranted(agentHash, recordId, credentialHash, expiresAt, block.timestamp);
        return recordId;
    }

    /// @notice Revoke a capability grant.
    function revokeCapability(bytes32 recordId) external {
        CapabilityRecord storage record = _records[recordId];
        if (record.grantedBy == address(0)) revert RecordNotFound();
        if (record.grantedBy != msg.sender) revert NotGranter();
        if (record.revoked) revert AlreadyRevoked();

        record.revoked = true;
        emit CapabilityRevoked(recordId, block.timestamp);
    }

    /// @notice Revoke all capabilities for an agent (used during decommission).
    function revokeAll(string calldata agentDID) external {
        bytes32 agentHash = keccak256(bytes(agentDID));
        bytes32[] storage records = _agentCapabilities[agentHash];

        for (uint256 i = 0; i < records.length; i++) {
            CapabilityRecord storage record = _records[records[i]];
            if (!record.revoked && record.grantedBy == msg.sender) {
                record.revoked = true;
                emit CapabilityRevoked(records[i], block.timestamp);
            }
        }
    }

    // ──────────────────────────────── View Functions ─────────────────────────

    function getCapability(bytes32 recordId) external view returns (
        bytes32 credentialHash,
        address grantedBy,
        uint64 grantedAt,
        uint64 expiresAt,
        bool revoked
    ) {
        CapabilityRecord storage record = _records[recordId];
        if (record.grantedBy == address(0)) revert RecordNotFound();
        return (record.credentialHash, record.grantedBy, record.grantedAt, record.expiresAt, record.revoked);
    }

    function getCapabilityCount(string calldata agentDID) external view returns (uint256) {
        bytes32 agentHash = keccak256(bytes(agentDID));
        return _agentCapabilities[agentHash].length;
    }

    function isActive(bytes32 recordId) external view returns (bool) {
        CapabilityRecord storage record = _records[recordId];
        if (record.grantedBy == address(0)) return false;
        if (record.revoked) return false;
        if (record.expiresAt != 0 && block.timestamp > record.expiresAt) return false;
        return true;
    }

    function getAgentCapabilities(string calldata agentDID) external view returns (bytes32[] memory) {
        bytes32 agentHash = keccak256(bytes(agentDID));
        return _agentCapabilities[agentHash];
    }
}
