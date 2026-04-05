// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AgentCapabilityRegistry} from "../src/AgentCapabilityRegistry.sol";

contract AgentCapabilityRegistryTest is Test {
    AgentCapabilityRegistry public registry;

    address alice = address(0x1);
    address bob = address(0x2);

    string constant AGENT_DID = "did:trustagent:evm:137:autonomous:z6MkAgent1";
    string constant AGENT_DID_2 = "did:trustagent:evm:137:delegated:z6MkAgent2";

    bytes32 constant CRED_HASH = keccak256("credential-hash-1");
    bytes32 constant CRED_HASH_2 = keccak256("credential-hash-2");
    bytes32 constant CRED_HASH_3 = keccak256("credential-hash-3");

    function setUp() public {
        registry = new AgentCapabilityRegistry();
    }

    // ──────── Helper ────────

    function _agentHash() internal pure returns (bytes32) {
        return keccak256(bytes(AGENT_DID));
    }

    // ──────── GrantCapability Tests ────────

    function test_grantCapability() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        assertTrue(recordId != bytes32(0));

        (
            bytes32 credentialHash,
            address grantedBy,
            uint64 grantedAt,
            uint64 expiresAt,
            bool revoked
        ) = registry.getCapability(recordId);

        assertEq(credentialHash, CRED_HASH);
        assertEq(grantedBy, alice);
        assertEq(grantedAt, block.timestamp);
        assertEq(expiresAt, 0);
        assertFalse(revoked);
    }

    function test_grantCapability_withExpiry() public {
        uint64 expiry = uint64(block.timestamp + 1 days);

        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, expiry);

        (, , , uint64 expiresAt, ) = registry.getCapability(recordId);
        assertEq(expiresAt, expiry);
    }

    function test_grantCapability_emitsEvent() public {
        bytes32 expectedRecordId = keccak256(abi.encodePacked(_agentHash(), CRED_HASH, block.timestamp));

        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit AgentCapabilityRegistry.CapabilityGranted(_agentHash(), expectedRecordId, CRED_HASH, 0, block.timestamp);
        registry.grantCapability(AGENT_DID, CRED_HASH, 0);
    }

    function test_grantCapability_incrementsCount() public {
        vm.prank(alice);
        registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        assertEq(registry.getCapabilityCount(AGENT_DID), 1);

        vm.warp(block.timestamp + 1); // advance to avoid same recordId
        vm.prank(alice);
        registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        assertEq(registry.getCapabilityCount(AGENT_DID), 2);
    }

    function test_grantCapability_multipleGranters() public {
        vm.prank(alice);
        bytes32 r1 = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(bob);
        bytes32 r2 = registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        (, address grantedBy1, , , ) = registry.getCapability(r1);
        (, address grantedBy2, , , ) = registry.getCapability(r2);

        assertEq(grantedBy1, alice);
        assertEq(grantedBy2, bob);
    }

    function test_getAgentCapabilities() public {
        vm.prank(alice);
        bytes32 r1 = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        bytes32 r2 = registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        bytes32[] memory caps = registry.getAgentCapabilities(AGENT_DID);
        assertEq(caps.length, 2);
        assertEq(caps[0], r1);
        assertEq(caps[1], r2);
    }

    // ──────── RevokeCapability Tests ────────

    function test_revokeCapability() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.prank(alice);
        registry.revokeCapability(recordId);

        (, , , , bool revoked) = registry.getCapability(recordId);
        assertTrue(revoked);
    }

    function test_revokeCapability_emitsEvent() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit AgentCapabilityRegistry.CapabilityRevoked(recordId, block.timestamp);
        registry.revokeCapability(recordId);
    }

    function test_revokeCapability_notGranter_reverts() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.prank(bob);
        vm.expectRevert(AgentCapabilityRegistry.NotGranter.selector);
        registry.revokeCapability(recordId);
    }

    function test_revokeCapability_notFound_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgentCapabilityRegistry.RecordNotFound.selector);
        registry.revokeCapability(bytes32(uint256(999)));
    }

    function test_revokeCapability_alreadyRevoked_reverts() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.prank(alice);
        registry.revokeCapability(recordId);

        vm.prank(alice);
        vm.expectRevert(AgentCapabilityRegistry.AlreadyRevoked.selector);
        registry.revokeCapability(recordId);
    }

    // ──────── RevokeAll Tests ────────

    function test_revokeAll() public {
        vm.prank(alice);
        bytes32 r1 = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        bytes32 r2 = registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        vm.prank(alice);
        registry.revokeAll(AGENT_DID);

        (, , , , bool revoked1) = registry.getCapability(r1);
        (, , , , bool revoked2) = registry.getCapability(r2);
        assertTrue(revoked1);
        assertTrue(revoked2);
    }

    function test_revokeAll_onlyRevokesSenderGrants() public {
        vm.prank(alice);
        bytes32 r1 = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(bob);
        bytes32 r2 = registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        // Alice revokes all - should only revoke r1
        vm.prank(alice);
        registry.revokeAll(AGENT_DID);

        (, , , , bool revoked1) = registry.getCapability(r1);
        (, , , , bool revoked2) = registry.getCapability(r2);
        assertTrue(revoked1);
        assertFalse(revoked2);
    }

    function test_revokeAll_skipsAlreadyRevoked() public {
        vm.prank(alice);
        bytes32 r1 = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        bytes32 r2 = registry.grantCapability(AGENT_DID, CRED_HASH_2, 0);

        // Revoke r1 individually first
        vm.prank(alice);
        registry.revokeCapability(r1);

        // RevokeAll should skip r1 (already revoked) and revoke r2
        vm.prank(alice);
        registry.revokeAll(AGENT_DID);

        (, , , , bool revoked1) = registry.getCapability(r1);
        (, , , , bool revoked2) = registry.getCapability(r2);
        assertTrue(revoked1);
        assertTrue(revoked2);
    }

    function test_revokeAll_noCapabilities() public {
        // Should not revert when there are no capabilities
        vm.prank(alice);
        registry.revokeAll(AGENT_DID);
    }

    // ──────── IsActive Tests ────────

    function test_isActive_true() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        assertTrue(registry.isActive(recordId));
    }

    function test_isActive_false_revoked() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        vm.prank(alice);
        registry.revokeCapability(recordId);

        assertFalse(registry.isActive(recordId));
    }

    function test_isActive_false_expired() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);

        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, expiry);

        // Still active before expiry
        assertTrue(registry.isActive(recordId));

        // Warp past expiry
        vm.warp(block.timestamp + 2 hours);
        assertFalse(registry.isActive(recordId));
    }

    function test_isActive_false_nonexistent() public view {
        assertFalse(registry.isActive(bytes32(uint256(999))));
    }

    function test_isActive_noExpiry_neverExpires() public {
        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, 0);

        // Warp far into the future
        vm.warp(block.timestamp + 365 days);
        assertTrue(registry.isActive(recordId));
    }

    function test_isActive_exactExpiry_stillActive() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);

        vm.prank(alice);
        bytes32 recordId = registry.grantCapability(AGENT_DID, CRED_HASH, expiry);

        // Warp to exact expiry time - should still be active (uses > not >=)
        vm.warp(expiry);
        assertTrue(registry.isActive(recordId));
    }

    // ──────── GetCapability Not Found ────────

    function test_getCapability_notFound_reverts() public {
        vm.expectRevert(AgentCapabilityRegistry.RecordNotFound.selector);
        registry.getCapability(bytes32(uint256(999)));
    }

    // ──────── GetCapabilityCount ────────

    function test_getCapabilityCount_zero() public view {
        assertEq(registry.getCapabilityCount(AGENT_DID), 0);
    }
}
