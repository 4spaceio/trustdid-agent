# TrustDID Agent Method Specification

**DID Method Name:** `trustagent`

**Version:** 0.1.0

**Status:** Draft

**Latest Version:** https://trustdid.org/spec/did-method/v0.1

**Editors:** TrustDID Foundation

**Conformance Target:** W3C DID Core v1.1 (Candidate Recommendation, March 2026)

---

## 1. Introduction

The `did:trustagent` method is a decentralized identifier method designed specifically for autonomous AI agents. It extends W3C DID Core v1.1 with agent-specific lifecycle management, delegation chains, capability-based authorization, and KERI-inspired pre-rotation key management.

### 1.1 Design Goals

- **Agent-Native**: First-class support for AI agent identity lifecycle (creation, delegation, rotation, decommission)
- **Ledger-Agnostic**: Single DID method supporting EVM chains, KERI infrastructure, and web-based resolution
- **Delegation-Aware**: Built-in support for human-to-agent and agent-to-agent delegation chains
- **Pre-Rotation**: KERI-inspired key management enabling autonomous key rotation without human intervention
- **Standards-Aligned**: Full compliance with W3C DID Core v1.1, W3C VC v2.0, DIDComm v2.1

### 1.2 Conformance

This specification conforms to W3C Decentralized Identifiers (DIDs) v1.1 [DID-CORE]. The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in [RFC2119].

---

## 2. DID Syntax

### 2.1 Method-Specific Identifier

```
did:trustagent:<network>:<agent-class>:<identifier>
```

Where:

```
trustagent-did      = "did:trustagent:" network ":" agent-class ":" identifier
network             = evm-network / keri-network / web-network
evm-network         = "evm:" chain-id
keri-network        = "keri"
web-network         = "web:" domain
chain-id            = 1*DIGIT
domain              = 1*(ALPHA / DIGIT / "." / "-")
agent-class         = "autonomous" / "delegated" / "ephemeral" / "org" / "human"
identifier          = multibase-btc-encoded-public-key
```

### 2.2 Agent Classes

| Class | Description | Typical Use |
|-------|-------------|-------------|
| `autonomous` | Self-governing AI agent with independent decision authority | Standalone agents, personal assistants |
| `delegated` | Agent operating under delegation from a parent entity | Task-specific agents, sub-agents |
| `ephemeral` | Short-lived agent instance with temporary identity | Session agents, one-time task runners |
| `org` | Organizational identity that may delegate to agents | Companies, departments, teams |
| `human` | Human controller identity (delegation chain root) | Agent owners, administrators |

### 2.3 Network Types

| Network | Format | Ledger Backend |
|---------|--------|----------------|
| EVM | `evm:<chain-id>` | Ethereum, Polygon, Arbitrum, etc. |
| KERI | `keri` | Key Event Receipt Infrastructure (ledger-less) |
| Web | `web:<domain>` | HTTPS-based DID resolution |

### 2.4 Examples

```
did:trustagent:evm:1:human:z6MkpTHR8VNs5xhqzV43EYm1VNkKCX2i3s9WnHJA11Yi5GQa
did:trustagent:evm:137:delegated:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
did:trustagent:keri:autonomous:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
did:trustagent:web:example.com:org:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J
did:trustagent:evm:42161:ephemeral:z6MktempSession123abc
```

---

## 3. DID Document

### 3.1 Context

Every `did:trustagent` DID Document MUST include the following `@context` values:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://trustdid.org/ns/agent/v1"
  ]
}
```

### 3.2 TrustAgent Extension

DID Documents MAY include a `trustagent` property containing agent-specific metadata:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `agentClass` | string | REQUIRED | One of: autonomous, delegated, ephemeral, org, human |
| `parentDID` | string | OPTIONAL | DID of the parent entity (for delegated/ephemeral agents) |
| `delegationChainRoot` | string | OPTIONAL | DID of the root human/org in the delegation chain |
| `delegationDepth` | integer | OPTIONAL | Depth in delegation chain (0 = root) |
| `preRotationCommitment` | string | OPTIONAL | Multibase-encoded hash of next public key |
| `lifecycle` | string | REQUIRED | Current lifecycle state |
| `capabilities` | array | OPTIONAL | List of granted capabilities |

### 3.3 Lifecycle States

```
created ──> active ──> suspended ──> active (resume)
                  ──> rotating ──> active (rotated)
                  ──> deactivated ──> decommissioned
            suspended ──> deactivated ──> decommissioned
```

| State | Description |
|-------|-------------|
| `created` | Identity created but not yet activated |
| `active` | Fully operational identity |
| `suspended` | Temporarily paused (reversible) |
| `rotating` | Key rotation in progress |
| `deactivated` | Permanently deactivated (reversible to decommissioned only) |
| `decommissioned` | Permanently destroyed, all delegations revoked |

### 3.4 Example DID Document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://trustdid.org/ns/agent/v1"
  ],
  "id": "did:trustagent:evm:137:delegated:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
  "controller": "did:trustagent:evm:137:org:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J",
  "verificationMethod": [
    {
      "id": "did:trustagent:evm:137:delegated:z6Mkf5r...#auth-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:trustagent:evm:137:delegated:z6Mkf5r...",
      "publicKeyMultibase": "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
    }
  ],
  "authentication": ["did:trustagent:evm:137:delegated:z6Mkf5r...#auth-1"],
  "assertionMethod": ["did:trustagent:evm:137:delegated:z6Mkf5r...#auth-1"],
  "service": [
    {
      "id": "#didcomm",
      "type": "DIDCommMessaging",
      "serviceEndpoint": "https://agent.example.com/didcomm"
    }
  ],
  "trustagent": {
    "agentClass": "delegated",
    "parentDID": "did:trustagent:evm:137:org:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2xJfmm7M8Go8J",
    "delegationChainRoot": "did:trustagent:evm:137:human:z6MkpTHR8VNs5xhqzV43EYm1VNkKCX2i3s9WnHJA11Yi5GQa",
    "delegationDepth": 2,
    "preRotationCommitment": "z6Mke4D1K2R...",
    "lifecycle": "active",
    "capabilities": [
      "credential:issue",
      "payment:authorize:limit=1000"
    ]
  }
}
```

---

## 4. Operations

### 4.1 Create

To create a new `did:trustagent` DID:

1. Generate a primary authentication keypair (Ed25519 RECOMMENDED)
2. Generate a pre-rotation keypair and compute commitment: `hash(nextPublicKey)`
3. Construct the DID identifier from the multibase-encoded public key
4. Build the DID Document with the `trustagent` extension
5. Anchor the DID Document on the appropriate ledger:
   - **EVM**: Call `TrustDIDRegistry.createDID()` with document hash
   - **KERI**: Create an inception event in the KEL
   - **Web**: Publish the DID Document at `https://<domain>/.well-known/did.json`
6. Return the DID Document and key material

### 4.2 Read (Resolve)

To resolve a `did:trustagent` DID:

1. Parse the DID to extract network, agent class, and identifier
2. Route to the appropriate ledger driver based on network segment
3. Retrieve the DID Document from the ledger
4. Return a `ResolutionResult` containing:
   - The DID Document
   - Resolution metadata (content type, duration)
   - Document metadata (created, updated, version, deactivated status)

### 4.3 Update

To update a `did:trustagent` DID Document:

1. Resolve the current DID Document
2. Verify the requester is the controller or owner
3. Apply update operations (add/remove verification methods, services, capabilities)
4. Verify lifecycle state transitions are valid
5. Re-anchor the updated document on the ledger

### 4.4 Deactivate

To deactivate a `did:trustagent` DID:

1. Verify the requester is the controller or owner
2. Set lifecycle state to `deactivated` on the ledger
3. The DID Document remains resolvable but marked as deactivated

### 4.5 Key Rotation (KERI-Inspired Pre-Rotation)

To rotate keys for a `did:trustagent` DID:

1. Generate a new keypair
2. Verify: `hash(newPublicKey) == storedPreRotationCommitment`
3. Generate the next pre-rotation commitment
4. Atomically update the DID Document with the new key and new commitment
5. The old key is immediately invalidated

### 4.6 Decommission (Agent-Specific)

To permanently decommission an agent:

1. Verify dual authorization (parent + agent, or parent alone)
2. Cascade-revoke all sub-delegations
3. Revoke all issued credentials
4. Archive the SBT reputation record
5. Set lifecycle to `decommissioned` (irreversible)
6. Zero all key material

---

## 5. Delegation Protocol

### 5.1 Delegation Chain

Delegation flows from human controllers through organizations to agents:

```
Human (depth 0) -> Organization (depth 1) -> Agent (depth 2) -> Sub-Agent (depth 3)
```

Maximum delegation depth: 10 (configurable per ecosystem).

### 5.2 Capability Delegation

Capabilities are expressed as structured tokens: `resource:action[:constraint=value]`

Examples:
- `credential:issue` - Can issue verifiable credentials
- `payment:authorize:limit=1000` - Can authorize payments up to 1000
- `data:read:scope=public` - Can read public data only

A child agent's capabilities MUST be a subset of its parent's capabilities. Delegation MUST NOT escalate privileges.

### 5.3 Delegation Credential

Each delegation is recorded as a W3C Verifiable Credential:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://trustdid.org/ns/agent/v1"],
  "type": ["VerifiableCredential", "AgentDelegationCredential"],
  "issuer": "did:trustagent:evm:137:org:z6MkParent...",
  "credentialSubject": {
    "id": "did:trustagent:evm:137:delegated:z6MkChild...",
    "capabilities": ["credential:issue", "payment:authorize:limit=1000"],
    "delegationDepth": 2,
    "maxDepth": 5
  }
}
```

---

## 6. Security Considerations

### 6.1 Key Management

- Pre-rotation commitments MUST be computed using SHA-256
- Key material MUST be stored in hardware security modules (HSMs) in production
- Ephemeral agents SHOULD use short-lived keys with automatic expiration
- Key rotation SHOULD be performed at regular intervals

### 6.2 Delegation Security

- Delegation depth MUST be enforced on-chain
- Cascading revocation MUST propagate to all descendants
- Capability attenuation MUST be verified at each delegation step
- Cross-network delegation SHOULD include additional verification

### 6.3 Privacy

- DID Documents SHOULD minimize personally identifiable information
- Selective disclosure (SD-JWT) SHOULD be used for agent attributes
- Service endpoints SHOULD use encrypted DIDComm messaging

---

## 7. Standards Alignment

| Standard | Status | Integration |
|----------|--------|-------------|
| W3C DID Core v1.1 | Candidate Recommendation | Full compliance |
| W3C VC v2.0 | Recommendation | Delegation credentials, capability tokens |
| DIDComm v2.1 | DIF Approved | Agent-to-agent communication |
| SD-JWT (RFC 9901) | Internet Standard | Selective disclosure of agent attributes |
| OID4VC | Finalized | Credential issuance and presentation |
| KERI | DIF Specification | Pre-rotation key management |
| ToIP Framework | Active | Trust registry governance |
| NIST AI Agent Standards | Active Initiative | Federal alignment |
| AIS-1 | v0.1 Draft | Agent identity standard alignment |
| DIF MCP-I | Active WG | Agent delegation protocol |
| CSA Agentic AI IAM | Published | Zero-trust agent identity |

---

## 8. References

- [DID-CORE] W3C Decentralized Identifiers (DIDs) v1.1, https://www.w3.org/TR/did-1.1/
- [VC-DATA-MODEL] W3C Verifiable Credentials Data Model v2.0, https://www.w3.org/TR/vc-data-model-2.0/
- [DIDCOMM] DIDComm Messaging v2.1, https://identity.foundation/didcomm-messaging/spec/v2.1/
- [SD-JWT] RFC 9901: Selective Disclosure JWT, https://www.rfc-editor.org/rfc/rfc9901.html
- [OID4VCI] OpenID for Verifiable Credential Issuance 1.0
- [KERI] Key Event Receipt Infrastructure, https://keri.one/
- [TOIP] Trust over IP Technology Architecture, https://trustoverip.org/
