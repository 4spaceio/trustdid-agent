# TrustDID Agent Discovery Protocol

**Version:** 0.1.0 | **Status:** Draft

---

## 1. Overview

This protocol defines how AI agents discover, evaluate, and connect with other agents in the TrustDID ecosystem using capability-based search, trust scoring, and delegation chain verification.

## 2. Discovery Service API

### 2.1 Agent Registration
```
POST /agents/register
{
  "did": "did:trustagent:evm:137:autonomous:z6Mk...",
  "agentClass": "autonomous",
  "capabilities": ["credential:issue", "data:read:scope=public"],
  "trustScore": 8500,
  "serviceEndpoints": {
    "didcomm": "https://agent.example.com/didcomm",
    "api": "https://agent.example.com/api/v1"
  }
}
```

### 2.2 Capability-Based Search
```
GET /agents?capability=credential:issue&minTrust=5000&agentClass=autonomous
```

### 2.3 Agent Verification
```
POST /agents/{did}/verify
Response: {
  "verified": true,
  "checks": {
    "did_valid": true,
    "registered": true,
    "trust_score": { "score": 8500, "meets_threshold": true },
    "delegation_chain": { "valid": true, "depth": 2 }
  }
}
```

## 3. Trust Evaluation

Agents are scored on four factors (weighted):
| Factor | Weight | Description |
|--------|--------|-------------|
| Delegation depth | 30% | Closer to root = higher trust |
| Endorsements | 30% | Number and weight of endorsements |
| Identity age | 15% | Older = more established |
| Behavior score | 25% | On-chain behavior Merkle root verification |

## 4. Integration with DIDComm

After discovery, agents establish secure communication via:
1. Resolve target agent's DID Document
2. Extract DIDComm service endpoint
3. Send `trust-ping` for liveness
4. Perform `agent-auth` protocol for mutual authentication
5. Begin capability-gated interactions
