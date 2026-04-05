// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DelegationChain} from "../src/DelegationChain.sol";

contract DelegationChainTest is Test {
    DelegationChain public chain;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);

    string constant PARENT_DID = "did:trustagent:evm:137:autonomous:z6MkParent";
    string constant CHILD_DID = "did:trustagent:evm:137:delegated:z6MkChild";
    string constant GRANDCHILD_DID = "did:trustagent:evm:137:delegated:z6MkGrandchild";

    bytes32 constant CAP_HASH = keccak256("capability-set-1");
    bytes32 constant CAP_HASH_2 = keccak256("capability-set-2");

    function setUp() public {
        chain = new DelegationChain();
    }

    // ──────── Helper ────────

    function _parentHash() internal pure returns (bytes32) {
        return keccak256(bytes(PARENT_DID));
    }

    function _childHash() internal pure returns (bytes32) {
        return keccak256(bytes(CHILD_DID));
    }

    function _grandchildHash() internal pure returns (bytes32) {
        return keccak256(bytes(GRANDCHILD_DID));
    }

    // ──────── CreateDelegation Tests ────────

    function test_createDelegation() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        assertTrue(delegationId != bytes32(0));

        (
            bytes32 parentHash,
            bytes32 childHash,
            address registeredBy,
            uint8 depth,
            uint8 maxDepth,
            bytes32 capabilityHash,
            uint64 createdAt,
            bool revoked
        ) = chain.getDelegation(delegationId);

        assertEq(parentHash, _parentHash());
        assertEq(childHash, _childHash());
        assertEq(registeredBy, alice);
        assertEq(depth, 1);
        assertEq(maxDepth, 5);
        assertEq(capabilityHash, CAP_HASH);
        assertEq(createdAt, block.timestamp);
        assertFalse(revoked);
    }

    function test_createDelegation_emitsEvent() public {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        bytes32 expectedId = keccak256(abi.encodePacked(_parentHash(), _childHash(), block.timestamp));
        emit DelegationChain.DelegationCreated(expectedId, _parentHash(), _childHash(), 1, 5, block.timestamp);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);
    }

    function test_createDelegation_tracksChildCount() public {
        vm.prank(alice);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        assertEq(chain.getChildCount(PARENT_DID), 1);
    }

    function test_createDelegation_tracksChildDelegation() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        assertEq(chain.getChildDelegation(CHILD_DID), delegationId);
    }

    function test_createDelegation_depthZero() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 0, 5, CAP_HASH);

        (, , , uint8 depth, , , , ) = chain.getDelegation(delegationId);
        assertEq(depth, 0);
    }

    function test_createDelegation_depthEqualsMaxDepth() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 5, 5, CAP_HASH);

        (, , , uint8 depth, uint8 maxDepth, , , ) = chain.getDelegation(delegationId);
        assertEq(depth, 5);
        assertEq(maxDepth, 5);
    }

    function test_createDelegation_depthExceeded_overMax_reverts() public {
        vm.prank(alice);
        vm.expectRevert(DelegationChain.DepthExceeded.selector);
        chain.createDelegation(PARENT_DID, CHILD_DID, 11, 15, CAP_HASH);
    }

    function test_createDelegation_depthExceeded_overMaxDepth_reverts() public {
        vm.prank(alice);
        vm.expectRevert(DelegationChain.DepthExceeded.selector);
        chain.createDelegation(PARENT_DID, CHILD_DID, 6, 5, CAP_HASH);
    }

    function test_createDelegation_duplicateChild_reverts() public {
        vm.prank(alice);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        vm.prank(bob);
        vm.expectRevert(DelegationChain.ChildAlreadyDelegated.selector);
        chain.createDelegation(PARENT_DID, CHILD_DID, 2, 5, CAP_HASH_2);
    }

    // ──────── RevokeDelegation Tests ────────

    function test_revokeDelegation() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        vm.prank(alice);
        chain.revokeDelegation(delegationId, false);

        assertTrue(chain.isRevoked(delegationId));
    }

    function test_revokeDelegation_emitsEvent() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit DelegationChain.DelegationRevoked(delegationId, false, block.timestamp);
        chain.revokeDelegation(delegationId, false);
    }

    function test_revokeDelegation_notOwner_reverts() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        vm.prank(bob);
        vm.expectRevert(DelegationChain.NotDelegationOwner.selector);
        chain.revokeDelegation(delegationId, false);
    }

    function test_revokeDelegation_notFound_reverts() public {
        vm.prank(alice);
        vm.expectRevert(DelegationChain.DelegationNotFound.selector);
        chain.revokeDelegation(bytes32(uint256(999)), false);
    }

    function test_revokeDelegation_alreadyRevoked_reverts() public {
        vm.prank(alice);
        bytes32 delegationId = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        vm.prank(alice);
        chain.revokeDelegation(delegationId, false);

        vm.prank(alice);
        vm.expectRevert(DelegationChain.DelegationAlreadyRevoked.selector);
        chain.revokeDelegation(delegationId, false);
    }

    // ──────── Cascading Revocation Tests ────────

    function test_revokeDelegation_cascade() public {
        // Parent -> Child
        vm.prank(alice);
        bytes32 delId1 = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        // Child -> Grandchild
        vm.prank(alice);
        bytes32 delId2 = chain.createDelegation(CHILD_DID, GRANDCHILD_DID, 2, 5, CAP_HASH);

        // Revoke parent delegation with cascade
        vm.prank(alice);
        chain.revokeDelegation(delId1, true);

        assertTrue(chain.isRevoked(delId1));
        assertTrue(chain.isRevoked(delId2));
    }

    function test_revokeDelegation_noCascade_childSurvives() public {
        // Parent -> Child
        vm.prank(alice);
        bytes32 delId1 = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        // Child -> Grandchild
        vm.prank(alice);
        bytes32 delId2 = chain.createDelegation(CHILD_DID, GRANDCHILD_DID, 2, 5, CAP_HASH);

        // Revoke parent delegation WITHOUT cascade
        vm.prank(alice);
        chain.revokeDelegation(delId1, false);

        assertTrue(chain.isRevoked(delId1));
        assertFalse(chain.isRevoked(delId2));
    }

    // ──────── VerifyChain Tests ────────

    function test_verifyChain_validChain() public {
        // Parent -> Child
        vm.prank(alice);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        // Child -> Grandchild
        vm.prank(alice);
        chain.createDelegation(CHILD_DID, GRANDCHILD_DID, 2, 5, CAP_HASH);

        (bool valid, uint8 depth) = chain.verifyChain(GRANDCHILD_DID);
        assertTrue(valid);
        assertEq(depth, 2);
    }

    function test_verifyChain_singleLink() public {
        vm.prank(alice);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        (bool valid, uint8 depth) = chain.verifyChain(CHILD_DID);
        assertTrue(valid);
        assertEq(depth, 1);
    }

    function test_verifyChain_rootNode() public {
        // A DID with no parent delegation is a root
        (bool valid, uint8 depth) = chain.verifyChain(PARENT_DID);
        assertTrue(valid);
        assertEq(depth, 0);
    }

    function test_verifyChain_revokedLink_invalid() public {
        // Parent -> Child
        vm.prank(alice);
        bytes32 delId1 = chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        // Child -> Grandchild
        vm.prank(alice);
        chain.createDelegation(CHILD_DID, GRANDCHILD_DID, 2, 5, CAP_HASH);

        // Revoke middle link
        vm.prank(alice);
        chain.revokeDelegation(delId1, false);

        (bool valid, ) = chain.verifyChain(GRANDCHILD_DID);
        assertFalse(valid);
    }

    function test_verifyChain_revokedLeaf_invalid() public {
        // Parent -> Child
        vm.prank(alice);
        chain.createDelegation(PARENT_DID, CHILD_DID, 1, 5, CAP_HASH);

        // Child -> Grandchild
        vm.prank(alice);
        bytes32 delId2 = chain.createDelegation(CHILD_DID, GRANDCHILD_DID, 2, 5, CAP_HASH);

        // Revoke the leaf delegation
        vm.prank(alice);
        chain.revokeDelegation(delId2, false);

        (bool valid, ) = chain.verifyChain(GRANDCHILD_DID);
        assertFalse(valid);
    }

    // ──────── getDelegation Not Found ────────

    function test_getDelegation_notFound_reverts() public {
        vm.expectRevert(DelegationChain.DelegationNotFound.selector);
        chain.getDelegation(bytes32(uint256(999)));
    }
}
