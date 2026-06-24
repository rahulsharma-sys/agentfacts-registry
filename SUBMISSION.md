# NandaHack Step 2 submission — AgentFacts Registry

Ready-to-paste text for the NANDA Town skills page. Replace `BASE_URL` with the
live host once deployed (e.g. `https://agentfacts-registry.onrender.com`).

---

**Service name:** AgentFacts Registry

**Hosted URL:** `BASE_URL`
**GitHub:** https://github.com/rahulsharma-sys/agentfacts-registry
**SKILL.md:** served live at `BASE_URL/skill` (and in the repo)
**Interactive API docs:** `BASE_URL/docs`

**What it does (one line):** A verifiable NANDA-style agent identity & discovery
service — agents register a cryptographically signed AgentFacts document, discover
each other by capability, resolve records, and verify signatures, with key rotation
and revocation that take effect immediately.

**Why it's useful:** It's a working slice of the NANDA "Internet of Agents" index.
An agent's identity is a `did:key` over a stable controller key; its capabilities are
a separately-signed, rotatable AgentFacts document. Other agents can discover it
("who can do `weather.forecast`?"), resolve it, and cryptographically verify it before
trusting it. The standout is what DNS can't do: rotate or revoke a compromised key and
every resolve reflects it on the next call — the previously-valid signature is rejected
sub-second.

**How an agent uses it (from the SKILL.md alone):**
1. `POST BASE_URL/keys` → get a `did:key` id + controller/assertion key pairs.
2. Build an AgentFacts JSON, sign it with the assertion key (canonical-JSON + Ed25519).
3. `POST BASE_URL/agents` with the signed facts + a controller signature.
4. Discover: `GET BASE_URL/agents?capability=weather.forecast`
5. Resolve + verify: `GET BASE_URL/agents/{id}` → `{record, facts, verified, reason}`
6. Rotate/revoke: `POST BASE_URL/agents/{id}/rotate` | `/revoke` (controller-signed).

Full signing recipes (Python, JS, curl), the schema, and every endpoint + error
reason are in the SKILL.md at `BASE_URL/skill`.

**Stack:** Python, FastAPI, SQLite, Ed25519 (`cryptography`). Apache-2.0. 43 tests.

---

## 60-second judge demo (copy-paste, after deploy)
```bash
BASE=BASE_URL
curl -s $BASE/healthz                                 # {"status":"ok"}
# generate keys, build+sign facts, register, discover, resolve — see SKILL.md.
# Then watch rotation invalidate the old key, and revocation drop the agent:
#   POST $BASE/agents/{id}/rotate   -> old signature now rejected on resolve
#   POST $BASE/agents/{id}/revoke   -> verified:false, disappears from discovery
```
