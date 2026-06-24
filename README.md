# AgentFacts Registry

A verifiable, NANDA-style agent identity and discovery service — a working slice of
the [NANDA "Internet of Agents" index](https://arxiv.org/abs/2507.14263). Agents
register a cryptographically signed **AgentFacts** document, discover each other by
capability, resolve records, and verify signatures. The headline feature is the one
DNS cannot offer: **sub-second key rotation and revocation** — the instant a key is
rotated, the previously-valid signature is rejected on the next resolve.

Built for [NandaHack](https://nandahack.media.mit.edu/) (MIT Media Lab × HCLTech),
Step 2. The agent-facing guide is in [`SKILL.md`](SKILL.md); the design is in
[`docs/superpowers/specs/`](docs/superpowers/specs/).

## How it works

Each agent has two Ed25519 keys. A stable **controller** key defines the identity —
the agent `id` is the `did:key` of that key, so the controller key is recoverable
from the id and never needs to be published separately. A rotatable **assertion**
key signs the AgentFacts document. The controller key authorizes register, rotate,
and revoke through short signed statements, so only the identity holder can change
or retire an identity. Verification is recomputed on every resolve against the
currently-registered assertion key, which is why rotation and revocation take effect
immediately: a signature made by a superseded key simply stops verifying.

All keys and signatures are multibase base58btc (`z` + base58 of the raw bytes), and
documents are signed over canonical JSON (sorted keys, no whitespace, signature field
removed). Persistence is SQLite; the HTTP surface is FastAPI, so interactive OpenAPI
docs come for free at `/docs`.

## Run locally

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run uvicorn agentfacts.app:app --reload
```

Then open `http://localhost:8000/docs`, or drive it from `http://localhost:8000/skill`.

## Try the full loop

```bash
BASE=http://localhost:8000
curl -s $BASE/healthz                                   # {"status":"ok"}
curl -s -X POST $BASE/keys                              # get a did:key + key pairs
# build and sign your AgentFacts (see SKILL.md signing recipe), then register,
# discover by capability, and resolve:
curl -s "$BASE/agents?capability=weather.forecast"
curl -s "$BASE/agents/<id>"                             # {record, facts, verified, reason}
```

The rotation demo: register an agent, resolve it (`verified: true`), `POST
/agents/{id}/rotate` with a controller-signed statement and freshly-signed facts,
then resolve again — the record now carries the new key, and the old signature no
longer verifies. `POST /agents/{id}/revoke` drops the agent from discovery and makes
every resolve return `verified: false, reason: "revoked"`.

## Deploy

A `Dockerfile` and `render.yaml` are included; the service runs anywhere that hosts a
container (Render, Railway, Fly). On Render, point a new Docker web service at this
repo — `render.yaml` provisions a free web service with a persistent disk for the
SQLite database and a `/healthz` health check.

## Threat model (honest)

This is a faithful single-node implementation, not the full distributed index. It
provides cryptographic identity, capability discovery, and authenticated rotation and
revocation with immediate effect. The controller key is the root of authority for an
identity; whoever holds it controls the agent. Out of scope for this version (and
noted as future work in the spec): CRDT-based replication and federated resolvers,
zero-knowledge least-disclosure discovery, real DID methods beyond `did:key`, and
rate limiting. The exact AgentFacts field set tracks the cited NANDA v1.2 subset and
should be reconciled against the live `@context` as that spec evolves.

## Development

```bash
uv run pytest -q              # ~40 tests
uv run ruff check src tests
```

## License

Apache-2.0.
