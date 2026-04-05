// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {ITrustDIDRegistry} from "../interfaces/ITrustDIDRegistry.sol";

/// @title TrustDIDRegistry
/// @notice On-chain DID registry for the did:trustagent method.
/// @dev Stores document hashes (keccak256) on-chain; full documents live on IPFS.
///      Uses packed storage for gas efficiency: single slot per DID record.
///      Gas targets: <80k for creation, <50k for updates.
contract TrustDIDRegistry is ITrustDIDRegistry {
    // ──────────────────────────────── Storage ────────────────────────────────

    /// Packed record: owner (160) + status (8) + nonce (32) + delegationDepth (8) = 208 bits
    struct DIDRecord {
        address owner;
        uint8 status; // bitmap: 0=active, 1=deactivated, 2=decommissioned
        uint32 nonce;
        uint8 delegationDepth;
        bytes32 documentHash; // keccak256 of off-chain DID Document
        bytes32 preRotationCommitment; // hash of next public key
        string parentDID;
    }

    /// @dev DID string => DIDRecord
    mapping(bytes32 => DIDRecord) private _records;

    /// @dev Parent DID hash => list of child DID hashes (for cascade operations)
    mapping(bytes32 => bytes32[]) private _children;

    // ──────────────────────────────── Constants ──────────────────────────────

    uint8 public constant STATUS_ACTIVE = 0;
    uint8 public constant STATUS_DEACTIVATED = 1;
    uint8 public constant STATUS_DECOMMISSIONED = 2;

    uint8 public constant MAX_DELEGATION_DEPTH = 10;

    // ──────────────────────────────── Events ─────────────────────────────────

    event DIDCreated(
        bytes32 indexed didHash,
        address indexed owner,
        bytes32 documentHash,
        bytes32 preRotationCommitment,
        uint256 blockNumber
    );

    event DIDUpdated(
        bytes32 indexed didHash,
        bytes32 documentHash,
        uint32 nonce,
        uint256 blockNumber
    );

    event DIDDeactivated(bytes32 indexed didHash, uint256 blockNumber);

    event DIDDecommissioned(bytes32 indexed didHash, uint256 blockNumber);

    event KeyRotated(
        bytes32 indexed didHash,
        bytes32 newDocumentHash,
        bytes32 newPreRotationCommitment,
        uint256 blockNumber
    );

    event DelegationRegistered(
        bytes32 indexed parentHash,
        bytes32 indexed childHash,
        uint8 depth,
        uint256 blockNumber
    );

    // ──────────────────────────────── Errors ─────────────────────────────────

    error DIDAlreadyExists();
    error DIDNotFound();
    error NotOwner();
    error DIDNotActive();
    error DIDAlreadyDecommissioned();
    error InvalidPreRotation();
    error DelegationDepthExceeded();
    error InvalidAddress();

    // ──────────────────────────────── Modifiers ──────────────────────────────

    modifier onlyOwner(bytes32 didHash) {
        if (_records[didHash].owner != msg.sender) revert NotOwner();
        _;
    }

    modifier onlyActive(bytes32 didHash) {
        if (_records[didHash].status != STATUS_ACTIVE) revert DIDNotActive();
        _;
    }

    // ──────────────────────────────── Core Operations ────────────────────────

    /// @notice Create a new DID record.
    /// @param didStr The full DID string (did:trustagent:...)
    /// @param documentHash keccak256 hash of the off-chain DID Document
    /// @param preRotationCommitment Hash commitment for pre-rotation key
    function createDID(
        string calldata didStr,
        bytes32 documentHash,
        bytes32 preRotationCommitment
    ) external override {
        if (msg.sender == address(0)) revert InvalidAddress();

        bytes32 didHash = keccak256(bytes(didStr));

        if (_records[didHash].owner != address(0)) revert DIDAlreadyExists();

        _records[didHash] = DIDRecord({
            owner: msg.sender,
            status: STATUS_ACTIVE,
            nonce: 0,
            delegationDepth: 0,
            documentHash: documentHash,
            preRotationCommitment: preRotationCommitment,
            parentDID: ""
        });

        emit DIDCreated(didHash, msg.sender, documentHash, preRotationCommitment, block.number);
    }

    /// @notice Update the DID Document hash.
    function updateDID(
        string calldata didStr,
        bytes32 newDocumentHash
    ) external override {
        bytes32 didHash = keccak256(bytes(didStr));

        DIDRecord storage record = _records[didHash];
        if (record.owner != msg.sender) revert NotOwner();
        if (record.status != STATUS_ACTIVE) revert DIDNotActive();

        record.documentHash = newDocumentHash;
        record.nonce += 1;

        emit DIDUpdated(didHash, newDocumentHash, record.nonce, block.number);
    }

    /// @notice Deactivate a DID (reversible).
    function deactivateDID(string calldata didStr) external override {
        bytes32 didHash = keccak256(bytes(didStr));

        DIDRecord storage record = _records[didHash];
        if (record.owner != msg.sender) revert NotOwner();
        if (record.status != STATUS_ACTIVE) revert DIDNotActive();

        record.status = STATUS_DEACTIVATED;

        emit DIDDeactivated(didHash, block.number);
    }

    /// @notice Decommission a DID permanently (irreversible). Cascades to children.
    function decommissionDID(string calldata didStr) external override {
        bytes32 didHash = keccak256(bytes(didStr));

        DIDRecord storage record = _records[didHash];
        if (record.owner != msg.sender) revert NotOwner();
        if (record.status == STATUS_DECOMMISSIONED) revert DIDAlreadyDecommissioned();

        record.status = STATUS_DECOMMISSIONED;

        // Cascade decommission to all children
        bytes32[] storage children = _children[didHash];
        for (uint256 i = 0; i < children.length; i++) {
            _records[children[i]].status = STATUS_DECOMMISSIONED;
            emit DIDDecommissioned(children[i], block.number);
        }

        emit DIDDecommissioned(didHash, block.number);
    }

    /// @notice Rotate keys using KERI-inspired pre-rotation.
    /// @param newDocumentHash Hash of the updated DID Document with new key
    /// @param preRotationProof The new public key whose hash must match stored commitment
    /// @param newCommitment New pre-rotation commitment for the next rotation
    function rotateKey(
        string calldata didStr,
        bytes32 newDocumentHash,
        bytes32 preRotationProof,
        bytes32 newCommitment
    ) external override {
        bytes32 didHash = keccak256(bytes(didStr));

        DIDRecord storage record = _records[didHash];
        if (record.owner != msg.sender) revert NotOwner();
        if (record.status != STATUS_ACTIVE) revert DIDNotActive();

        // Verify pre-rotation: hash of proof must match stored commitment
        if (keccak256(abi.encodePacked(preRotationProof)) != record.preRotationCommitment) {
            revert InvalidPreRotation();
        }

        record.documentHash = newDocumentHash;
        record.preRotationCommitment = newCommitment;
        record.nonce += 1;

        emit KeyRotated(didHash, newDocumentHash, newCommitment, block.number);
    }

    /// @notice Register a delegation relationship.
    function registerDelegation(
        string calldata parentDIDStr,
        string calldata childDIDStr,
        uint8 depth
    ) external override {
        if (depth > MAX_DELEGATION_DEPTH) revert DelegationDepthExceeded();

        bytes32 parentHash = keccak256(bytes(parentDIDStr));
        bytes32 childHash = keccak256(bytes(childDIDStr));

        DIDRecord storage parentRecord = _records[parentHash];
        if (parentRecord.owner != msg.sender) revert NotOwner();
        if (parentRecord.status != STATUS_ACTIVE) revert DIDNotActive();

        DIDRecord storage childRecord = _records[childHash];
        if (childRecord.owner == address(0)) revert DIDNotFound();

        childRecord.delegationDepth = depth;
        childRecord.parentDID = parentDIDStr;

        _children[parentHash].push(childHash);

        emit DelegationRegistered(parentHash, childHash, depth, block.number);
    }

    // ──────────────────────────────── View Functions ─────────────────────────

    /// @notice Resolve a DID record.
    function resolve(string calldata didStr) external view override returns (
        address owner,
        uint8 status,
        uint32 nonce,
        uint8 delegationDepth,
        bytes32 documentHash,
        bytes32 preRotationCommitment
    ) {
        bytes32 didHash = keccak256(bytes(didStr));
        DIDRecord storage record = _records[didHash];
        if (record.owner == address(0)) revert DIDNotFound();
        return (
            record.owner,
            record.status,
            record.nonce,
            record.delegationDepth,
            record.documentHash,
            record.preRotationCommitment
        );
    }

    /// @notice Check if a DID exists and is active.
    function isActive(string calldata didStr) external view override returns (bool) {
        bytes32 didHash = keccak256(bytes(didStr));
        return _records[didHash].owner != address(0) && _records[didHash].status == STATUS_ACTIVE;
    }

    /// @notice Get the number of child delegations for a DID.
    function childCount(string calldata didStr) external view override returns (uint256) {
        bytes32 didHash = keccak256(bytes(didStr));
        return _children[didHash].length;
    }
}
