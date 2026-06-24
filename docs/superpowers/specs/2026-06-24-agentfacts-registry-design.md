# Design: AgentFacts Registry — a verifiable NANDA-style agent identity & discovery service

- **Date:** 2026-06-24
- **Status:** Draft for review
- **Event:** NandaHack (MIT Media Lab × HCLTech), Step 2 service (80% of score). Finale 2026-07-11.
- **Working name:** AgentFacts Registry (renameable)

---

## 1. Context

NandaHack Step 2 asks for an **online-hosted service** plus a **SKILL.md** that teaches an AI agent how to call it, judged on usefulness, creativity, ease of setup, and whether an agent can use it from the SKILL.md alone.

We are building a faithful, single-node implementation of the **NANDA Index + Verified AgentFacts** concept ([arXiv:2507.14263](https://arxiv.org/abs/2507.14263), MIT Media Lab "Beyond DNS"). NANDA separates a **lean index** (agent id → endpoint → pointer to facts) from the rich, cryptographically signed **AgentFacts** document (capabilities, endpoints, owner, keys, TTL), resolved and verified by **resolvers** that support fast revocation and key rotation. Our service implements register → discover → resolve → verify, and makes **sub-second key rotation and revocation** the standout — the thing DNS cannot do.

The AgentFacts `@context` is `https://spec.projectnanda.org/agentfacts/v1.2.jsonld`; commonly cited required fields are `@context`, `id`, `handle`, `endpoint`, `meta`, plus `capabilities` and `owner`. (See §11 open item: confirm exact v1.2 field names against the live spec, which was unreachable at design time.)

## 2. Goal

Ship a hosted HTTP service where an agent can register a signed AgentFacts document, be discovered by capability, resolved, and cryptographically verified — and where the key behind those facts can be **rotated or revoked with immediate effect** on every subsequent resolve/verify. Provide a SKILL.md complete enough that an agent uses the whole loop from the doc alone.

### In scope
- Ed25519-signed AgentFacts with deterministic canonicalization.
- A two-key identity model (stable controller key → `did:key` id; rotatable assertion key signs facts) enabling clean rotation.
- REST API: register, resolve+verify, search/discover, raw facts JSON-LD, rotate, revoke, stateless verify, keypair convenience, health.
- SQLite persistence; FastAPI auto-OpenAPI.
- Dockerfile + Render/Railway deploy config.
- A SKILL.md and a `pytest` suite (happy + adversarial).

### Non-goals (named, not built)
- CRDT-based distributed replication and resolver federation (the paper's multi-node vision).
- Zero-knowledge / least-disclosure private discovery.
- Real DID method registration beyond `did:key`; no on-chain anchoring.
- Auth/rate-limiting beyond what the signing model itself provides (note as future hardening).

## 3. Architecture

A single FastAPI service with four internal units, each independently testable:

- `crypto` — Ed25519 keygen, `did:key` encode/decode, canonical JSON, sign, verify. No web or storage deps.
- `models` — Pydantic schemas for AgentFacts, index records, and request/response bodies.
- `store` — SQLite persistence (agents, current keys, epoch, status, facts blob, signatures). No web deps.
- `service` — the domain logic (register/resolve/search/rotate/revoke/verify) composed over `crypto` + `store`.
- `app` — thin FastAPI routing layer that validates input and delegates to `service`.

Data flow for the core loop: an agent canonicalizes its facts, signs with its **assertion** private key, and `POST /agents`. The service verifies the signature against the assertion key named in the facts, checks the `id` is the `did:key` of the declared **controller** key, and stores the lean record + facts + signature. Discovery is a query over capabilities/handle. Resolve returns the lean record, the facts, the signature, and a freshly recomputed `verified` boolean. Rotation/revocation are controller-signed state changes that bump an epoch and immediately change verification outcomes.

## 4. Identity & signing model

Two Ed25519 keys per agent, mirroring how real DID documents separate a controller from assertion (verification) keys:

- **Controller key** — stable, defines identity. The agent `id` is the `did:key` of this key (multibase base58btc, multicodec `0xed01` Ed25519 prefix, e.g. `did:key:z6Mk…`). The controller key signs **rotate** and **revoke** requests. It is the root of authority and is expected to stay offline/rarely used.
- **Assertion key** — signs the AgentFacts document. Rotatable. The current assertion public key lives in the facts and in the lean record.

**Canonicalization:** the document is serialized to deterministic JSON — UTF-8, keys sorted lexicographically, no insignificant whitespace, with the `signature` field omitted — and that byte string is what gets signed/verified. (RFC 8785 JCS is the principled alternative; we specify the simpler sorted-key form for SKILL.md reproducibility and will note JCS as an upgrade.)

**Signature encoding:** base64url, carried in a detached `signature` object `{ "alg": "ed25519", "key": "<assertion-pubkey-multibase>", "value": "<b64url>" }`.

**Verification (recomputed on every resolve):** strip `signature`, canonicalize, Ed25519-verify `value` against the record's **current** assertion key; check status is `active` and `expires_at` is in the future; confirm `signature.key` matches the current registered assertion key (so post-rotation, an old-key signature fails even though it was once valid).

## 5. Data model

**Lean index record** (the DNS-successor entry):
`{ id, handle, endpoint, facts_uri, controller_key, assertion_key, epoch, status: active|revoked, updated_at }`

**AgentFacts document** (signed JSON-LD, NANDA-aligned):
`{ "@context": "https://spec.projectnanda.org/agentfacts/v1.2.jsonld", "id": "did:key:…", "handle": "@owner/name", "owner": "<string>", "endpoints": ["https://…"], "capabilities": ["weather.forecast", "nl.summarize"], "assertion_key": "<multibase>", "epoch": 1, "issued_at": "<iso8601>", "expires_at": "<iso8601>", "meta": { … }, "signature": { "alg": "ed25519", "key": "…", "value": "…" } }`

`facts_uri` points back to our own `GET /agents/{id}/facts.jsonld` (we host the facts in this single-node implementation).

SQLite tables: `agents(id PK, handle, endpoint, controller_key, assertion_key, epoch, status, facts_json, issued_at, expires_at, updated_at)` and an index on `handle`; capabilities stored in `agent_capabilities(agent_id, capability)` for search.

## 6. API

FastAPI (auto OpenAPI at `/docs`). All bodies JSON.

- `POST /keys` — convenience: generate a **controller + assertion** Ed25519 keypair set (private/public in multibase) and the resulting `did:key` id, so an agent without a crypto lib can start. Keys are generated in-memory and never stored. Documented as a convenience; production agents bring their own keys.
- `POST /agents` — register. Body: the signed AgentFacts doc. Verifies signature + that `id == did:key(controller_key)`; stores; returns the lean record. `409` if id exists.
- `GET /agents/{id}` — resolve + verify. Returns `{ record, facts, verified, reason }`.
- `GET /agents?capability=&handle=&q=` — discover. Returns active, matching lean records (optionally with `verified`). Revoked/expired excluded by default (`?include_revoked=true` to override).
- `GET /agents/{id}/facts.jsonld` — raw signed JSON-LD (what `facts_uri` resolves to).
- `POST /agents/{id}/rotate` — rotate the assertion key **atomically**. Body: `{ new_assertion_key, controller_sig, facts }` where `controller_sig` is the controller key's signature over the canonical `rotate` statement `{op:"rotate", id, new_assertion_key, epoch:N+1}`, and `facts` is the new AgentFacts document signed by `new_assertion_key`. The service verifies `controller_sig` against the controller key, verifies `facts` against `new_assertion_key`, then in one transaction swaps the assertion key, stores the new facts, and bumps epoch to N+1. Old-key signatures now fail verify.
- `POST /agents/{id}/revoke` — revoke. Body: `{ controller_sig }` over `{op:"revoke", id, epoch}`. Sets status `revoked`; resolve/verify now fail and the agent leaves discovery.
- `POST /verify` — stateless: body `{ facts }`; recompute verification using the key named in the facts (does not consult the registry) — lets agents self-check before/after registering.
- `GET /healthz` — liveness. `GET /` — service info + link to SKILL.md and `/docs`.

Errors are JSON `{ error, reason }` with precise messages (e.g. `signature_invalid`, `id_key_mismatch`, `revoked`, `expired`, `epoch_stale`, `not_found`).

## 7. The standout: rotation, revocation, TTL

Rotation and revocation are **authenticated by the controller key**, so only the identity holder can perform them, and they take effect immediately because there is a single authoritative store:

- **Rotate:** controller signs `{op:"rotate", id, new_assertion_key, epoch:N+1}` and supplies new facts signed by the new key in the same call (see §6). Service verifies both, then atomically swaps the assertion key, stores the new facts, and bumps epoch to N+1. Any facts still signed by the old assertion key now fail (the verifier checks `signature.key == current assertion_key`). Demo line: "I rotated the key — the previously-valid signature is now rejected, sub-second."
- **Revoke:** controller signs `{op:"revoke", id, epoch}`. Status → `revoked`; resolve returns `verified:false, reason:"revoked"` and search omits it.
- **TTL:** `expires_at` in the facts; verification fails with `reason:"expired"` once passed, forcing a refresh — NANDA's TTL-based resolution.

`epoch` in the signed statements prevents replay of an old rotate/revoke request.

## 8. Agent-usability & SKILL.md

The judged friction is client-side signing, so SKILL.md is explicit and copy-pasteable: it states the canonicalization rules exactly, gives the Ed25519 signing recipe in curl + a ~10-line Python snippet + a JS snippet, and walks the full loop (generate keys via `POST /keys` → build facts → sign → `POST /agents` → `GET /agents?capability=` → `GET /agents/{id}` → `POST /agents/{id}/rotate`). It documents every endpoint with example request/response and every error `reason`. The `/verify` endpoint lets an agent confirm its signing before registering. Success criterion: a capable agent completes register→discover→resolve→verify using only SKILL.md.

SKILL.md required sections (per the hackathon): service name, what it does, base URL, endpoints, and step-by-step usage — all included.

## 9. Tech stack, hosting, testing

**Stack:** Python 3.12, FastAPI, uvicorn, `cryptography` (Ed25519), SQLite (stdlib `sqlite3`), Pydantic v2. Reuses our `cryptography` familiarity from Step 1; FastAPI gives OpenAPI for free.

**Hosting:** a `Dockerfile` (universal) plus a `render.yaml` as the primary one-click deploy (Render free web service); Railway/Fly noted as alternatives. Runs locally with `uvicorn agentfacts.app:app`. Ease-of-setup is a judged criterion, so a single deploy file + a 3-line README quickstart matter.

**Testing (`pytest`):** unit tests for `crypto` (sign/verify round-trip, `did:key` encode/decode, canonicalization determinism, tamper → fail) and `store`; API tests via FastAPI `TestClient` for the happy path and the adversarial cases that demonstrate rigor — wrong signature rejected, `id`/controller-key mismatch rejected, **old-key signature after rotation rejected**, revoked agent fails verify and disappears from search, expired TTL fails, replayed rotate (stale epoch) rejected, tampered facts fail.

## 10. Finale demo (≈2 minutes)

Register a "weather" agent with signed facts → `GET /agents?capability=weather.forecast` finds it → `GET /agents/{id}` shows `verified: true` → live `POST /agents/{id}/rotate`, then re-run resolve with the old signature to show `signature_invalid` and with the new to show green → `POST /agents/{id}/revoke` and show it vanish from search and fail verify. That arc is the NANDA-vs-DNS pitch made tangible.

## 11. Open items to confirm during implementation
1. **Exact AgentFacts v1.2 field names/shape** from `https://spec.projectnanda.org/agentfacts/v1.2.jsonld` (host was unreachable at design time). We follow the cited subset and will reconcile field names (e.g. `endpoint` vs `endpoints`, `meta` contents) against the live context, keeping the `@context` reference accurate.
2. **Canonicalization choice** — confirm sorted-key form is reproducible across the Python/JS snippets we ship; upgrade to RFC 8785 JCS only if needed.
3. **`did:key` multicodec details** for Ed25519 (`0xed01` + base58btc) — verify against the did:key spec during the crypto unit tests.

## 12. File structure
```
agentfacts-registry/
├── pyproject.toml
├── README.md
├── SKILL.md                 # the agent-facing Step 2 deliverable
├── Dockerfile
├── render.yaml
├── docs/superpowers/specs/2026-06-24-agentfacts-registry-design.md
├── src/agentfacts/
│   ├── __init__.py
│   ├── crypto.py            # Ed25519, did:key, canonical JSON, sign/verify
│   ├── models.py            # Pydantic schemas
│   ├── store.py             # SQLite persistence
│   ├── service.py           # register/resolve/search/rotate/revoke/verify
│   └── app.py               # FastAPI routes
└── tests/
    ├── test_crypto.py
    ├── test_service.py
    └── test_api.py
```

## 13. Future work
CRDT replication + federated resolvers; ZK least-disclosure discovery; real DID methods and on-chain anchoring; rate-limiting/abuse controls; signed audit log of rotations/revocations.
