# TrustDID Agent Delegation Protocol

**Version:** 0.1.0 | **Status:** Draft

---

## 1. Overview

This protocol defines how delegation of capabilities flows from human controllers through organizations to AI agents within the TrustDID ecosystem, using DIDComm v2.1 messaging and W3C Verifiable Credentials v2.0.

## 2. Delegation Chain

```
Human (depth 0) -> Organization (depth 1) -> Agent (depth 2) -> Sub-Agent (depth 3)
```

- Maximum depth: 10 (configurable per ecosystem)
- Capabilities MUST attenuate (narrow) at each delegation step
- Each link is recorded as an `AgentDelegationCredential` (W3C VC v2.0)
- On-chain registration via `DelegationChain.sol` for chain-of-custody verification

## 3. Protocol Flow

### 3.1 Delegation Request (DIDComm)
```
Parent -> Child: DIDComm message type "https://trustdid.org/delegation/1.0/offer"
  body: { capabilities, maxDepth, expiresAt }
Child -> Parent: DIDComm message type "https://trustdid.org/delegation/1.0/accept"
Parent -> Registrar: POST /1.0/delegate
Registrar -> Chain: Register delegation on-chain
Registrar -> Parent: Return AgentDelegationCredential
Parent -> Child: Forward credential via DIDComm
```

### 3.2 Capability Attenuation Rules
- Child capabilities MUST be a subset of parent capabilities
- Numeric constraints MUST be equal or stricter (e.g., limit=1000 -> limit=500)
- New capabilities CANNOT be introduced at delegation

### 3.3 Cascading Revocation
- Revoking a parent delegation MUST cascade to all children
- On-chain cascade via `DelegationChain.sol::revokeDelegation(id, cascade=true)`
- Off-chain VC revocation via Bitstring Status List

## 4. Agent-to-Agent Authentication

### 4.1 Auth Flow (DIDComm)
```
AgentA -> AgentB: auth_request { required_capabilities }
AgentB -> Resolver: Resolve AgentA DID
AgentB -> Chain: Verify AgentA delegation chain
AgentB -> TrustRegistry: Check AgentA trust score >= threshold
AgentB -> AgentA: auth_response { delegation_chain_proof, trust_score }
Both: Mutual authentication established
```

## 5. Decommission Protocol
1. Dual-signature authorization (parent + agent, or parent alone)
2. Cascade-revoke all sub-delegations (on-chain + off-chain)
3. Revoke all issued credentials
4. Archive SBT reputation record (score -> 0)
5. Set lifecycle to `decommissioned` (irreversible)
