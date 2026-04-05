# Agent Capability Credential Schema

**Version:** 0.1.0

**Status:** Draft

---

## 1. Overview

This specification defines the credential schemas used by the `did:trustagent` method for expressing agent capabilities, delegation relationships, and trust scores as W3C Verifiable Credentials v2.0.

---

## 2. Credential Types

### 2.1 AgentDelegationCredential

Issued by a parent entity to delegate capabilities to a child agent.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustdid.org/ns/agent/v1"
  ],
  "type": ["VerifiableCredential", "AgentDelegationCredential"],
  "issuer": "did:trustagent:evm:137:org:z6MkParent...",
  "validFrom": "2026-04-01T00:00:00Z",
  "validUntil": "2027-04-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:trustagent:evm:137:delegated:z6MkChild...",
    "capabilities": ["credential:issue", "payment:authorize:limit=1000"],
    "delegationDepth": 2,
    "maxDepth": 5,
    "delegationType": "capability"
  },
  "credentialSchema": {
    "id": "https://trustdid.org/schemas/delegation/v1",
    "type": "JsonSchema"
  }
}
```

**Required Claims:**
| Claim | Type | Description |
|-------|------|-------------|
| `capabilities` | string[] | Capabilities granted in compact format |
| `delegationDepth` | integer | Current depth in delegation chain (0 = root) |
| `maxDepth` | integer | Maximum allowed delegation depth (1-10) |

**Optional Claims:**
| Claim | Type | Description |
|-------|------|-------------|
| `delegationType` | string | Type of delegation: "capability", "identity", "full" |

### 2.2 AgentCapabilityCredential

Issued to an agent to grant specific operational capabilities.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustdid.org/ns/agent/v1"
  ],
  "type": ["VerifiableCredential", "AgentCapabilityCredential"],
  "issuer": "did:trustagent:evm:137:org:z6MkOrg...",
  "credentialSubject": {
    "id": "did:trustagent:evm:137:autonomous:z6MkAgent...",
    "capabilities": ["data:read:scope=public", "api:call:rate=100"],
    "grantedAt": "2026-04-01T00:00:00Z"
  }
}
```

### 2.3 AgentTrustScoreCredential

Issued by a trust registry to attest an agent's trust score.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustdid.org/ns/agent/v1"
  ],
  "type": ["VerifiableCredential", "AgentTrustScoreCredential"],
  "issuer": "did:trustagent:evm:137:org:z6MkTrustRegistry...",
  "credentialSubject": {
    "id": "did:trustagent:evm:137:autonomous:z6MkAgent...",
    "trustScore": 8500,
    "endorsements": 42,
    "behaviorHash": "z6Mk...",
    "evaluatedAt": "2026-04-01T00:00:00Z"
  }
}
```

### 2.4 AgentIdentityCredential

Issued to attest an agent's identity attributes.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://trustdid.org/ns/agent/v1"
  ],
  "type": ["VerifiableCredential", "AgentIdentityCredential"],
  "issuer": "did:trustagent:evm:137:org:z6MkOrg...",
  "credentialSubject": {
    "id": "did:trustagent:evm:137:autonomous:z6MkAgent...",
    "agentClass": "autonomous",
    "lifecycle": "active",
    "model": "claude-4",
    "version": "1.0.0"
  }
}
```

---

## 3. Capability Syntax

Capabilities use compact notation: `resource:action[:constraint=value[,constraint=value]]`

### 3.1 Standard Capabilities

| Capability | Description |
|-----------|-------------|
| `credential:issue` | Issue verifiable credentials |
| `credential:verify` | Verify credentials |
| `credential:revoke` | Revoke credentials |
| `payment:authorize` | Authorize payments |
| `payment:authorize:limit=N` | Authorize payments up to N |
| `data:read` | Read data |
| `data:read:scope=public` | Read only public data |
| `data:write` | Write data |
| `api:call` | Make API calls |
| `api:call:rate=N` | Make up to N API calls per minute |
| `agent:delegate` | Delegate to sub-agents |
| `agent:delegate:maxDepth=N` | Delegate up to depth N |

### 3.2 Capability Attenuation

A child agent's capabilities MUST be a subset of its parent's capabilities. Constraints on child capabilities MUST be equal to or stricter than the parent's constraints.

Example: If parent has `payment:authorize:limit=10000`, child can have `payment:authorize:limit=5000` but NOT `payment:authorize:limit=20000`.

---

## 4. Selective Disclosure

All credential types support SD-JWT (RFC 9901) for selective disclosure. Agents can present credentials while revealing only the claims needed for a specific interaction.

Example: An agent presenting capabilities to a verifier can disclose only the relevant capability without revealing its full delegation chain or trust score.
