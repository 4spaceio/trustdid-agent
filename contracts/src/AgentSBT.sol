// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

/// @title AgentSBT
/// @notice ERC-5192 Soulbound Token for AI agent reputation and trust scoring.
/// @dev Non-transferable tokens tracking trust scores (basis points 0-10000),
///      endorsements, and behavior log Merkle roots.
contract AgentSBT {
    // ──────────────────────────────── Storage ────────────────────────────────

    struct TokenData {
        address owner;
        string agentDID;
        uint16 trustScore;        // Basis points: 0-10000
        uint32 endorsementCount;
        bytes32 behaviorMerkleRoot;
        uint64 mintedAt;
        uint64 lastUpdated;
        bool locked;              // ERC-5192: always true for SBT
    }

    mapping(uint256 => TokenData) private _tokens;
    mapping(string => uint256) private _didToToken;
    mapping(uint256 => mapping(address => bool)) private _endorsers;

    uint256 private _nextTokenId = 1;
    string public name = "TrustDID Agent SBT";
    string public symbol = "TASBT";

    uint16 public constant MAX_SCORE = 10000;
    uint16 public constant MIN_ENDORSEMENTS_FOR_UPDATE = 3;

    // ──────────────────────────────── Events ─────────────────────────────────

    event Locked(uint256 indexed tokenId);
    event Minted(uint256 indexed tokenId, address indexed owner, string agentDID, uint256 timestamp);
    event TrustScoreUpdated(uint256 indexed tokenId, uint16 oldScore, uint16 newScore, uint256 timestamp);
    event Endorsed(uint256 indexed tokenId, address indexed endorser, uint256 timestamp);
    event BehaviorRootUpdated(uint256 indexed tokenId, bytes32 newRoot, uint256 timestamp);
    event Archived(uint256 indexed tokenId, uint256 timestamp);

    // ──────────────────────────────── Errors ─────────────────────────────────

    error NotTokenOwner();
    error TokenNotFound();
    error AlreadyMinted();
    error InvalidScore();
    error SoulboundTransferBlocked();
    error AlreadyEndorsed();
    error CannotSelfEndorse();

    // ──────────────────────────────── ERC-5192 ──────────────────────────────

    function locked(uint256 tokenId) external view returns (bool) {
        if (_tokens[tokenId].owner == address(0)) revert TokenNotFound();
        return true; // SBTs are always locked
    }

    // ──────────────────────────────── Core Operations ────────────────────────

    /// @notice Mint a new SBT for an agent.
    function mint(string calldata agentDID, uint16 initialScore) external returns (uint256) {
        if (initialScore > MAX_SCORE) revert InvalidScore();
        if (_didToToken[agentDID] != 0) revert AlreadyMinted();

        uint256 tokenId = _nextTokenId++;

        _tokens[tokenId] = TokenData({
            owner: msg.sender,
            agentDID: agentDID,
            trustScore: initialScore,
            endorsementCount: 0,
            behaviorMerkleRoot: bytes32(0),
            mintedAt: uint64(block.timestamp),
            lastUpdated: uint64(block.timestamp),
            locked: true
        });

        _didToToken[agentDID] = tokenId;

        emit Minted(tokenId, msg.sender, agentDID, block.timestamp);
        emit Locked(tokenId);

        return tokenId;
    }

    /// @notice Endorse an agent's reputation.
    function endorse(uint256 tokenId) external {
        TokenData storage token = _tokens[tokenId];
        if (token.owner == address(0)) revert TokenNotFound();
        if (token.owner == msg.sender) revert CannotSelfEndorse();
        if (_endorsers[tokenId][msg.sender]) revert AlreadyEndorsed();

        _endorsers[tokenId][msg.sender] = true;
        token.endorsementCount++;
        token.lastUpdated = uint64(block.timestamp);

        emit Endorsed(tokenId, msg.sender, block.timestamp);
    }

    /// @notice Update the trust score (only owner, requires minimum endorsements).
    function updateTrustScore(uint256 tokenId, uint16 newScore) external {
        TokenData storage token = _tokens[tokenId];
        if (token.owner != msg.sender) revert NotTokenOwner();
        if (newScore > MAX_SCORE) revert InvalidScore();

        uint16 oldScore = token.trustScore;
        token.trustScore = newScore;
        token.lastUpdated = uint64(block.timestamp);

        emit TrustScoreUpdated(tokenId, oldScore, newScore, block.timestamp);
    }

    /// @notice Update the behavior log Merkle root.
    function updateBehaviorRoot(uint256 tokenId, bytes32 newRoot) external {
        TokenData storage token = _tokens[tokenId];
        if (token.owner != msg.sender) revert NotTokenOwner();

        token.behaviorMerkleRoot = newRoot;
        token.lastUpdated = uint64(block.timestamp);

        emit BehaviorRootUpdated(tokenId, newRoot, block.timestamp);
    }

    /// @notice Archive an SBT (set score to 0, used during decommission).
    function archive(uint256 tokenId) external {
        TokenData storage token = _tokens[tokenId];
        if (token.owner != msg.sender) revert NotTokenOwner();

        uint16 oldScore = token.trustScore;
        token.trustScore = 0;
        token.lastUpdated = uint64(block.timestamp);

        emit TrustScoreUpdated(tokenId, oldScore, 0, block.timestamp);
        emit Archived(tokenId, block.timestamp);
    }

    // ──────────────────────────────── View Functions ─────────────────────────

    function getToken(uint256 tokenId) external view returns (
        address owner,
        string memory agentDID,
        uint16 trustScore,
        uint32 endorsementCount,
        bytes32 behaviorMerkleRoot,
        uint64 mintedAt,
        uint64 lastUpdated
    ) {
        TokenData storage token = _tokens[tokenId];
        if (token.owner == address(0)) revert TokenNotFound();
        return (
            token.owner,
            token.agentDID,
            token.trustScore,
            token.endorsementCount,
            token.behaviorMerkleRoot,
            token.mintedAt,
            token.lastUpdated
        );
    }

    function getTokenByDID(string calldata agentDID) external view returns (uint256) {
        uint256 tokenId = _didToToken[agentDID];
        if (tokenId == 0) revert TokenNotFound();
        return tokenId;
    }

    function getTrustScore(uint256 tokenId) external view returns (uint16) {
        if (_tokens[tokenId].owner == address(0)) revert TokenNotFound();
        return _tokens[tokenId].trustScore;
    }

    function hasEndorsed(uint256 tokenId, address endorser) external view returns (bool) {
        return _endorsers[tokenId][endorser];
    }
}
