# AgentFacts Registry

## What it does
A verifiable agent identity and discovery service — a working slice of the NANDA
"Internet of Agents" index. Register a cryptographically signed **AgentFacts**
document, let other agents discover you by capability, resolve your record, and
verify your signature. Unlike DNS, a compromised key can be **rotated or revoked
with immediate effect**: the moment you rotate, the previously-valid signature is
rejected on the very next resolve.

## Base URL
`https://agentfacts-registry.onrender.com`

Interactive OpenAPI docs live at `https://agentfacts-registry.onrender.com/docs`. This SKILL.md is served at `https://agentfacts-registry.onrender.com/skill`.

## Concepts (read once)
- Your identity is a **did:key** derived from a stable **controller** keypair. The
  controller key never changes and authorizes rotate/revoke.
- Your AgentFacts are signed by a separate **assertion** keypair, which you can rotate.
- All keys and signatures are **multibase base58btc**: a literal `z` followed by the
  base58 encoding of the raw bytes.
- **To sign any document:** remove its `signature` field, serialize the rest as
  **canonical JSON** (UTF-8, keys sorted lexicographically, no spaces:
  `separators=(",", ":")`), and Ed25519-sign those exact bytes.
- **Control statements** (register/rotate/revoke) are canonical JSON of
  `{"op": ..., "id": ..., "epoch": ...[, "new_assertion_key": ...]}`, signed by the
  **controller** key.
- The **`did:key` id is the trust anchor** — verify it, not the `handle`. Handles are
  advisory display names and are not unique across agents.

## Quickstart
1. `POST /keys` → returns a `did:key` `id` plus controller and assertion key pairs.
   (Or bring your own Ed25519 keys.)
2. Build your AgentFacts JSON (schema below) and sign it with your **assertion** private key.
3. `POST /agents` with `{"facts": <signed facts>, "controller_sig": <sig>}`, where
   `controller_sig` signs `{"op":"register","id":<id>,"epoch":1,"new_assertion_key":<assertion_pub>}`.
4. Discover: `GET /agents?capability=weather.forecast`
5. Resolve + verify: `GET /agents/{id}` → `{record, facts, verified, reason}`

## Endpoints
- `POST /keys` → `{id, controller_private, controller_public, assertion_private, assertion_public}`. Convenience only; keys are generated in memory and never stored.
- `POST /agents` — register. Body `{facts, controller_sig}`. → resolve result. `409` if the id already exists.
- `GET /agents?capability=&handle=&q=&include_revoked=` — discover. → list of public records (active only by default).
- `GET /agents/{id}` — resolve + verify. → `{record, facts, verified, reason}`.
- `GET /agents/{id}/facts.jsonld` — the raw signed AgentFacts document.
- `POST /agents/{id}/rotate` — body `{new_assertion_key, controller_sig, facts}`. `controller_sig` signs `{"op":"rotate","id":<id>,"epoch":<N+1>,"new_assertion_key":<new>}`; `facts` is a fresh document signed by the new assertion key with `epoch` = N+1.
- `POST /agents/{id}/revoke` — body `{controller_sig}` signing `{"op":"revoke","id":<id>,"epoch":<N>}`.
- `POST /verify` — body is a facts document; returns `{verified, reason}` by checking it against the key it names (no registry lookup).
- `GET /healthz` → `{"status":"ok"}`. `GET /docs` → OpenAPI UI.

## AgentFacts schema
```json
{
  "@context": "https://spec.projectnanda.org/agentfacts/v1.2.jsonld",
  "id": "did:key:z...",
  "handle": "@you/yourservice",
  "owner": "you",
  "endpoints": ["https://your.service/agent"],
  "capabilities": ["weather.forecast"],
  "assertion_key": "z...",
  "epoch": 1,
  "issued_at": "2026-06-24T00:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z",
  "meta": {},
  "signature": {"alg": "ed25519", "key": "z...", "value": "z..."}
}
```
Required fields: `@context`, `id`, `handle`, `assertion_key`, `epoch`, `expires_at`, `signature`.

## Signing recipe (Python)
```python
import json, base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sign(priv_mb, data):
    sk = Ed25519PrivateKey.from_private_bytes(base58.b58decode(priv_mb[1:]))
    return "z" + base58.b58encode(sk.sign(data)).decode()

# sign facts with the assertion key
facts.pop("signature", None)
facts["signature"] = {"alg": "ed25519", "key": assertion_pub, "value": sign(assertion_priv, canon(facts))}

# controller signature to register
stmt = {"op": "register", "id": facts["id"], "epoch": 1, "new_assertion_key": assertion_pub}
controller_sig = sign(controller_priv, canon(stmt))
```

## Signing recipe (JavaScript / Node)
```javascript
import nacl from "tweetnacl";
import bs58 from "bs58";

// recursively sort object keys so JSON.stringify is canonical (matches the server)
const sortDeep = (o) =>
  Array.isArray(o)
    ? o.map(sortDeep)
    : o && typeof o === "object"
      ? Object.keys(o).sort().reduce((acc, k) => ((acc[k] = sortDeep(o[k])), acc), {})
      : o;

const canon = (o) => Buffer.from(JSON.stringify(sortDeep(o)));      // sorted keys, no spaces

// privMb is the multibase 32-byte Ed25519 seed ("z" + base58)
const sign = (privMb, data) => {
  const kp = nacl.sign.keyPair.fromSeed(bs58.decode(privMb.slice(1)));
  return "z" + bs58.encode(nacl.sign.detached(data, kp.secretKey));
};
```
(The Python recipe above is the reference; both produce identical signatures for ASCII facts.)

## End-to-end with curl
```bash
BASE=https://agentfacts-registry.onrender.com
# 1. get keys
curl -s -X POST $BASE/keys > keys.json
# 2. build + sign facts (use the Python recipe), then:
curl -s -X POST $BASE/agents -H 'content-type: application/json' \
  -d '{"facts": <signed_facts>, "controller_sig": "<sig>"}'
# 3. discover, resolve
curl -s "$BASE/agents?capability=weather.forecast"
curl -s "$BASE/agents/<id>"
```

## Error reasons
`signature_invalid`, `signature_key_mismatch`, `controller_sig_invalid`,
`already_exists`, `not_found`, `revoked`, `expired`, `epoch_stale`,
`epoch_must_be_1`, `assertion_key_mismatch`, `missing_fields:<list>`, `bad_id`.
Every error is JSON `{"error": <reason>, "reason": <reason>}` with a matching HTTP status.
