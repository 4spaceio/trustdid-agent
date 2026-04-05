// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AgentSBT} from "../src/AgentSBT.sol";

contract AgentSBTTest is Test {
    AgentSBT public sbt;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);

    string constant DID_1 = "did:trustagent:evm:137:autonomous:z6MkTest1";
    string constant DID_2 = "did:trustagent:evm:137:delegated:z6MkTest2";

    bytes32 constant BEHAVIOR_ROOT = keccak256("behavior-log-root");
    bytes32 constant BEHAVIOR_ROOT_2 = keccak256("behavior-log-root-2");

    function setUp() public {
        sbt = new AgentSBT();
    }

    // ──────── Mint Tests ────────

    function test_mint() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        assertEq(tokenId, 1);

        (
            address owner,
            string memory agentDID,
            uint16 trustScore,
            uint32 endorsementCount,
            bytes32 behaviorMerkleRoot,
            uint64 mintedAt,
            uint64 lastUpdated
        ) = sbt.getToken(tokenId);

        assertEq(owner, alice);
        assertEq(agentDID, DID_1);
        assertEq(trustScore, 5000);
        assertEq(endorsementCount, 0);
        assertEq(behaviorMerkleRoot, bytes32(0));
        assertEq(mintedAt, block.timestamp);
        assertEq(lastUpdated, block.timestamp);
    }

    function test_mint_incrementsTokenId() public {
        vm.prank(alice);
        uint256 id1 = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        uint256 id2 = sbt.mint(DID_2, 7000);

        assertEq(id1, 1);
        assertEq(id2, 2);
    }

    function test_mint_emitsEvents() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit AgentSBT.Minted(1, alice, DID_1, block.timestamp);
        sbt.mint(DID_1, 5000);
    }

    function test_mint_lockedAlwaysTrue() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        assertTrue(sbt.locked(tokenId));
    }

    function test_mint_zeroScore() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 0);

        assertEq(sbt.getTrustScore(tokenId), 0);
    }

    function test_mint_maxScore() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 10000);

        assertEq(sbt.getTrustScore(tokenId), 10000);
    }

    function test_mint_duplicateDID_reverts() public {
        vm.prank(alice);
        sbt.mint(DID_1, 5000);

        vm.prank(bob);
        vm.expectRevert(AgentSBT.AlreadyMinted.selector);
        sbt.mint(DID_1, 3000);
    }

    function test_mint_invalidScore_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgentSBT.InvalidScore.selector);
        sbt.mint(DID_1, 10001);
    }

    // ──────── Endorse Tests ────────

    function test_endorse() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        sbt.endorse(tokenId);

        (, , , uint32 endorsementCount, , , ) = sbt.getToken(tokenId);
        assertEq(endorsementCount, 1);
        assertTrue(sbt.hasEndorsed(tokenId, bob));
    }

    function test_endorse_multipleEndorsers() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        sbt.endorse(tokenId);

        vm.prank(carol);
        sbt.endorse(tokenId);

        (, , , uint32 endorsementCount, , , ) = sbt.getToken(tokenId);
        assertEq(endorsementCount, 2);
        assertTrue(sbt.hasEndorsed(tokenId, bob));
        assertTrue(sbt.hasEndorsed(tokenId, carol));
    }

    function test_endorse_updatesTimestamp() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.warp(block.timestamp + 100);

        vm.prank(bob);
        sbt.endorse(tokenId);

        (, , , , , , uint64 lastUpdated) = sbt.getToken(tokenId);
        assertEq(lastUpdated, block.timestamp);
    }

    function test_endorse_emitsEvent() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit AgentSBT.Endorsed(tokenId, bob, block.timestamp);
        sbt.endorse(tokenId);
    }

    function test_endorse_selfEndorse_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        vm.expectRevert(AgentSBT.CannotSelfEndorse.selector);
        sbt.endorse(tokenId);
    }

    function test_endorse_doubleEndorse_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        sbt.endorse(tokenId);

        vm.prank(bob);
        vm.expectRevert(AgentSBT.AlreadyEndorsed.selector);
        sbt.endorse(tokenId);
    }

    function test_endorse_tokenNotFound_reverts() public {
        vm.prank(bob);
        vm.expectRevert(AgentSBT.TokenNotFound.selector);
        sbt.endorse(999);
    }

    // ──────── UpdateTrustScore Tests ────────

    function test_updateTrustScore() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        sbt.updateTrustScore(tokenId, 8000);

        assertEq(sbt.getTrustScore(tokenId), 8000);
    }

    function test_updateTrustScore_emitsEvent() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit AgentSBT.TrustScoreUpdated(tokenId, 5000, 8000, block.timestamp);
        sbt.updateTrustScore(tokenId, 8000);
    }

    function test_updateTrustScore_updatesTimestamp() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.warp(block.timestamp + 200);

        vm.prank(alice);
        sbt.updateTrustScore(tokenId, 8000);

        (, , , , , , uint64 lastUpdated) = sbt.getToken(tokenId);
        assertEq(lastUpdated, block.timestamp);
    }

    function test_updateTrustScore_notOwner_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        vm.expectRevert(AgentSBT.NotTokenOwner.selector);
        sbt.updateTrustScore(tokenId, 8000);
    }

    function test_updateTrustScore_invalidScore_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        vm.expectRevert(AgentSBT.InvalidScore.selector);
        sbt.updateTrustScore(tokenId, 10001);
    }

    // ──────── UpdateBehaviorRoot Tests ────────

    function test_updateBehaviorRoot() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        sbt.updateBehaviorRoot(tokenId, BEHAVIOR_ROOT);

        (, , , , bytes32 root, , ) = sbt.getToken(tokenId);
        assertEq(root, BEHAVIOR_ROOT);
    }

    function test_updateBehaviorRoot_emitsEvent() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit AgentSBT.BehaviorRootUpdated(tokenId, BEHAVIOR_ROOT, block.timestamp);
        sbt.updateBehaviorRoot(tokenId, BEHAVIOR_ROOT);
    }

    function test_updateBehaviorRoot_overwrite() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        sbt.updateBehaviorRoot(tokenId, BEHAVIOR_ROOT);

        vm.prank(alice);
        sbt.updateBehaviorRoot(tokenId, BEHAVIOR_ROOT_2);

        (, , , , bytes32 root, , ) = sbt.getToken(tokenId);
        assertEq(root, BEHAVIOR_ROOT_2);
    }

    function test_updateBehaviorRoot_notOwner_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        vm.expectRevert(AgentSBT.NotTokenOwner.selector);
        sbt.updateBehaviorRoot(tokenId, BEHAVIOR_ROOT);
    }

    // ──────── Archive Tests ────────

    function test_archive() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        sbt.archive(tokenId);

        assertEq(sbt.getTrustScore(tokenId), 0);
    }

    function test_archive_emitsEvents() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit AgentSBT.Archived(tokenId, block.timestamp);
        sbt.archive(tokenId);
    }

    function test_archive_notOwner_reverts() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        vm.prank(bob);
        vm.expectRevert(AgentSBT.NotTokenOwner.selector);
        sbt.archive(tokenId);
    }

    // ──────── View Function Tests ────────

    function test_getToken_notFound_reverts() public {
        vm.expectRevert(AgentSBT.TokenNotFound.selector);
        sbt.getToken(999);
    }

    function test_getTokenByDID() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        assertEq(sbt.getTokenByDID(DID_1), tokenId);
    }

    function test_getTokenByDID_notFound_reverts() public {
        vm.expectRevert(AgentSBT.TokenNotFound.selector);
        sbt.getTokenByDID("did:nonexistent");
    }

    function test_getTrustScore() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 7500);

        assertEq(sbt.getTrustScore(tokenId), 7500);
    }

    function test_getTrustScore_notFound_reverts() public {
        vm.expectRevert(AgentSBT.TokenNotFound.selector);
        sbt.getTrustScore(999);
    }

    function test_hasEndorsed_false() public {
        vm.prank(alice);
        uint256 tokenId = sbt.mint(DID_1, 5000);

        assertFalse(sbt.hasEndorsed(tokenId, bob));
    }

    function test_locked_notFound_reverts() public {
        vm.expectRevert(AgentSBT.TokenNotFound.selector);
        sbt.locked(999);
    }

    function test_nameAndSymbol() public view {
        assertEq(sbt.name(), "TrustDID Agent SBT");
        assertEq(sbt.symbol(), "TASBT");
    }
}
