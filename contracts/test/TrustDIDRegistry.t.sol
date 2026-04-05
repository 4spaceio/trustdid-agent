// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {TrustDIDRegistry} from "../src/TrustDIDRegistry.sol";

contract TrustDIDRegistryTest is Test {
    TrustDIDRegistry public registry;

    address alice = address(0x1);
    address bob = address(0x2);

    string constant DID_1 = "did:trustagent:evm:137:autonomous:z6MkTest1";
    string constant DID_2 = "did:trustagent:evm:137:delegated:z6MkTest2";

    bytes32 constant DOC_HASH = keccak256("document-1");
    bytes32 constant DOC_HASH_2 = keccak256("document-2");
    bytes32 constant PRE_ROTATION = keccak256("next-public-key");
    bytes32 constant PRE_ROTATION_PROOF = keccak256("current-key");

    function setUp() public {
        registry = new TrustDIDRegistry();
    }

    // ──────── Creation Tests ────────

    function test_createDID() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        (address owner, uint8 status, uint32 nonce, , bytes32 docHash, bytes32 preRotation) =
            registry.resolve(DID_1);

        assertEq(owner, alice);
        assertEq(status, registry.STATUS_ACTIVE());
        assertEq(nonce, 0);
        assertEq(docHash, DOC_HASH);
        assertEq(preRotation, PRE_ROTATION);
    }

    function test_createDID_duplicate_reverts() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(alice);
        vm.expectRevert(TrustDIDRegistry.DIDAlreadyExists.selector);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);
    }

    function test_isActive() public {
        assertFalse(registry.isActive(DID_1));

        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        assertTrue(registry.isActive(DID_1));
    }

    // ──────── Update Tests ────���───

    function test_updateDID() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(alice);
        registry.updateDID(DID_1, DOC_HASH_2);

        (, , uint32 nonce, , bytes32 docHash, ) = registry.resolve(DID_1);
        assertEq(docHash, DOC_HASH_2);
        assertEq(nonce, 1);
    }

    function test_updateDID_notOwner_reverts() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(bob);
        vm.expectRevert(TrustDIDRegistry.NotOwner.selector);
        registry.updateDID(DID_1, DOC_HASH_2);
    }

    // ──────── Deactivation Tests ────────

    function test_deactivateDID() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(alice);
        registry.deactivateDID(DID_1);

        (, uint8 status, , , , ) = registry.resolve(DID_1);
        assertEq(status, registry.STATUS_DEACTIVATED());
        assertFalse(registry.isActive(DID_1));
    }

    // ──────── Decommission Tests ────────

    function test_decommissionDID() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(alice);
        registry.decommissionDID(DID_1);

        (, uint8 status, , , , ) = registry.resolve(DID_1);
        assertEq(status, registry.STATUS_DECOMMISSIONED());
    }

    function test_decommissionDID_cascades() public {
        // Create parent
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        // Create child
        vm.prank(bob);
        registry.createDID(DID_2, DOC_HASH_2, PRE_ROTATION);

        // Register delegation
        vm.prank(alice);
        registry.registerDelegation(DID_1, DID_2, 1);

        // Decommission parent - should cascade to child
        vm.prank(alice);
        registry.decommissionDID(DID_1);

        (, uint8 parentStatus, , , , ) = registry.resolve(DID_1);
        (, uint8 childStatus, , , , ) = registry.resolve(DID_2);

        assertEq(parentStatus, registry.STATUS_DECOMMISSIONED());
        assertEq(childStatus, registry.STATUS_DECOMMISSIONED());
    }

    // ──────── Key Rotation Tests ──���─────

    function test_rotateKey() public {
        // Pre-rotation commitment is keccak256(preRotationProof)
        bytes32 proof = bytes32(uint256(42));
        bytes32 commitment = keccak256(abi.encodePacked(proof));
        bytes32 newCommitment = keccak256("new-commitment");

        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, commitment);

        vm.prank(alice);
        registry.rotateKey(DID_1, DOC_HASH_2, proof, newCommitment);

        (, , uint32 nonce, , bytes32 docHash, bytes32 preRot) = registry.resolve(DID_1);
        assertEq(docHash, DOC_HASH_2);
        assertEq(preRot, newCommitment);
        assertEq(nonce, 1);
    }

    function test_rotateKey_invalidProof_reverts() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(alice);
        vm.expectRevert(TrustDIDRegistry.InvalidPreRotation.selector);
        registry.rotateKey(DID_1, DOC_HASH_2, bytes32(uint256(999)), keccak256("new"));
    }

    // ──────── Delegation Tests ────────

    function test_registerDelegation() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(bob);
        registry.createDID(DID_2, DOC_HASH_2, PRE_ROTATION);

        vm.prank(alice);
        registry.registerDelegation(DID_1, DID_2, 1);

        (, , , uint8 depth, , ) = registry.resolve(DID_2);
        assertEq(depth, 1);
        assertEq(registry.childCount(DID_1), 1);
    }

    function test_registerDelegation_depthExceeded_reverts() public {
        vm.prank(alice);
        registry.createDID(DID_1, DOC_HASH, PRE_ROTATION);

        vm.prank(bob);
        registry.createDID(DID_2, DOC_HASH_2, PRE_ROTATION);

        vm.prank(alice);
        vm.expectRevert(TrustDIDRegistry.DelegationDepthExceeded.selector);
        registry.registerDelegation(DID_1, DID_2, 11); // Max is 10
    }

    // ──────── Resolve Tests ────────

    function test_resolve_notFound_reverts() public {
        vm.expectRevert(TrustDIDRegistry.DIDNotFound.selector);
        registry.resolve("did:trustagent:evm:137:autonomous:nonexistent");
    }
}
