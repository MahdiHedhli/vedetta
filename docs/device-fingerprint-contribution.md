# Device-Fingerprint Contribution (design)

How a Vedetta instance can help grow the community device-recognition corpus
([spec 008](../specs/008-device-fingerprint-corpus/) / #52) **without** any contribution
being linkable to a specific install, user/device ID, or IP. This document is a **design and
review artifact**; it does not authorize real-data contribution. Real contribution stays
disabled until the acceptance gates below — including an independent privacy review of the
exact deployed design — are met.

Owner direction (#52): anonymized device fingerprinting for the recognition database is
allowed, adapting #57's contract, but **never linked to a specific install, UID, or IP**.

## Stage 1 — local shadow mode (built)

`backend/internal/corpuscontrib` reduces a device's observed signals to the anonymized
`CanonicalShapeV1` that would be contributed (`Reduce`), gates on a contribution-worthiness bar
(`Contributable`), and enforces the #52 invariant (`AssertAnonymized`: 24-bit OUI prefixes
only, no MAC/IP/UUID in any field; hostnames excluded). **Off by default, no network, no
reporter identity.** This freezes the vector and lets the value be studied on synthetic or
explicitly consented data before anything leaves a household.

## Stage 2 — unlinkable transport (design; gated, not implemented)

A contribution is a single `CanonicalShapeV1` submitted so that **no server surface can link
it to a contributor or a household**:

- **Unlinkable authorization** — Privacy Pass–style tokens ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html))
  provide contribution bounds (one report per task/epoch) without a stable reporter identity.
  They do **not** prove one token = one independent household (advisory-only Sybil posture).
- **Addressing/content separation** — Oblivious HTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html))
  through an independent relay so the aggregator never sees the source address and the relay
  never sees the payload, under the stated non-collusion assumptions. Fixed-size padded
  envelopes, fresh contexts, delayed/batched delivery, and replay controls remain required.
- **No linkable metadata** — the existing signed telemetry path is explicitly **not** reused
  for contributions, because it carries a stable pseudonymous `reporter_id`. A fingerprint
  submission carries no install UUID, reporter pseudonym, timestamp, or source hash.
- **Staging, not the corpus** — accepted submissions land in a **staging store separate from
  the curated corpus**; only a curator promotes a shape into a published profile. A community
  submission is advisory and can never auto-create, suppress, resolve, or reprioritize a
  finding.

## Acceptance gates (before any real-data contribution)

Mirroring #57's discipline, adapted for the (potentially product-bearing) fingerprint shape:

- Approved data dictionary + canonical examples; the shape's no-carriable-field property is
  fuzzed at the producer, relay/gateway, and staging boundaries.
- No server surface can reconstruct contributor→shape or shape→household under the documented
  non-collusion assumptions.
- Enforced one-report/task/epoch bounds, replay/double-spend rejection, fixed manifests +
  padding, delayed batching, collection limits, and exercised kill switches.
- Poisoning / Sybil / malformed-submission red team; a curation model that resists seeded
  false shapes.
- Explicit opt-in consent that accurately describes residual metadata and the advisory-only
  trust limit.
- **Independent cryptographic/privacy review of the exact deployed design.**

Until then: shadow mode only, off by default, synthetic transport pilots only.
