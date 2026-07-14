# Spec: Curated Device Fingerprint Corpus

> Feature directory: `specs/008-device-fingerprint-corpus/`
> Status: Implemented and adversarially reviewed on the standalone operations branch;
> deployment pending
> Created: 2026-07-13

## Objective

Build a centrally curated, privacy-reduced device fingerprint corpus in the
threat-network service. Operators can create, revise, publish, withdraw, and audit
device profiles from the existing tailnet-only operations dashboard. Community
reporting is intentionally absent until a later privacy/trust gate.

The corpus turns class-level network signals such as DHCP option ordering, an OUI
prefix, mDNS service types, SSDP device types, and service ports into versioned public
product knowledge. Its only writer is a trusted curator; automatic and community
observations cannot reach these tables. The contract forbids storing an observed
household device, reporter, site, sensor, address, hostname, serial number, or event.

## User-visible outcome

The Threat Network dashboard gains a Device Corpus workspace where an authorized
operator can:

- search device profiles and inspect their published and draft state;
- create a manufacturer/model profile and one or more firmware/hardware variants;
- preview the exact privacy-reduced representation before publishing;
- revise a corpus claim without overwriting the published history;
- link actual firmware evolution independently from curator corrections;
- publish or withdraw a profile and review the append-only audit trail;
- inspect immutable corpus releases and the current public snapshot revision.

## Functional requirements

### Curated corpus only

- Manual management is the only write path in this feature.
- `/api/v1/ingest`, telemetry capabilities, reporter registration, consensus, and
  promotion remain unchanged and cannot submit device fingerprints.
- Drafts never appear in the public corpus snapshot.
- Community contribution requires a later explicit-opt-in contract and #57 privacy
  review; this feature creates no dormant or hidden contribution path.

### Version model

- A stable profile identity represents one manufacturer/model product class.
- Profile labels are immutable revisions with at most one draft and one published
  revision at a time.
- A stable variant series represents one external firmware/hardware fingerprint
  lineage. `predecessor_variant_id` represents real product evolution.
- Curator corrections create immutable variant revisions linked by
  `supersedes_revision_id`; they do not create a fake firmware successor.
- Several firmware variants for the same product may remain published and matchable.
- Publishing promotes drafts atomically and creates a complete immutable corpus
  release. Withdrawal creates another release; prior releases remain intact.
- Published content is never edited or deleted in place.

### Privacy-safe shape

The version-1 canonical shape is a fixed structure containing only:

- ordered DHCP option-55 codes;
- vetted DHCP vendor-class product tokens;
- 24-bit globally administered unicast OUI prefixes;
- curator-authored constrained hostname templates (at least one alphanumeric
  product literal plus `{hex}`, `{digits}`, or `{random}`; never a wildcard-only
  template, arbitrary regex, or observed hostname);
- mDNS service types, public product model tokens, and public vendor tokens;
- SSDP device-type URNs and public product/server tokens;
- TCP and UDP service-port sets.

The structure has no arbitrary fields or metadata. Curators must never enter raw
hostnames/friendly names, room/person names, or any other household-specific label.
Typed and lexical validators reject recognizable full MACs, IPs/CIDRs, DHCP client
IDs, SSDP UUID/USN/UDN/LOCATION, mDNS instances/TXT identifiers,
serial/account/token or certificate identities, local device/sensor/reporter/install
IDs, household timestamps/counts, URLs as fingerprint values, and arbitrary
observation blobs. Since an ordinary name cannot be distinguished reliably from a
legitimate public product label, the trusted curator and exact release preview remain
required privacy controls rather than claims of automated name detection.

Set-valued fields are normalized, sorted, and deduplicated. DHCP option-55 order is
preserved. A canonical shape must contain at least one signal family; publishing
requires either two independent families or one exact product signature backed by a
public authoritative citation.

The shape hash is:

`SHA256("vedetta-device-shape\0v1\0" || canonical_json)`

It is a content/deduplication key, not anonymization. Privacy is provided by structural
minimization, a trusted-curator boundary, leak-oriented validation, and an exact
pre-publication preview. Because bounded product labels and tokens are necessarily
human-authored strings, validation is defense in depth against accidental disclosure;
it is not a proof against a malicious curator deliberately encoding data. Identical
shapes may map to several profiles because shared chipsets legitimately create ambiguity.

### Management boundary

- Public threat-network traffic remains on the existing listener and never mounts
  admin routes.
- Management runs on a separate listener, disabled unless explicitly configured and
  bound to loopback by default.
- Management requires a dedicated 256-bit bearer secret read from a protected file;
  reporter/Core credentials are never accepted.
- The tailnet dashboard proxy reads that file and injects the bearer server-side. The
  token never enters HTML, JavaScript, browser storage, URLs, logs, or responses.
- The proxy uses exact path/method allowlists, body limits, same-origin CSRF checks,
  no CORS, and never proxies reporter registration or ingest.
- Every mutation is transactional, optimistic-concurrency protected, and paired with
  an append-only audit row.
- Publishing, profile retirement, and full variant withdrawal require both the reviewed
  profile ETag and the reviewed current corpus revision, so an intervening release for a
  different profile invalidates the action without mutating lifecycle or audit state.
  Discarding only a draft remains a profile-local edit and does not advance the corpus.

### Public corpus

- The public listener serves a manifest and an immutable current snapshot, separate
  from `/api/v1/feed/community` and with its own schema version.
- A snapshot contains only published profile/variant revisions, canonical shapes,
  version facts, confidence, product-evolution links, and privacy-reduced evidence
  provenance (public citations or kind-only manual/lab provenance).
- It excludes drafts, curator/audit data, management metadata, and withdrawn content.
- The response has a monotonic corpus revision, deterministic bytes, SHA-256/ETag,
  bounded size, and 304 support.
- Core does not consume the corpus for scoring in this feature. Signed-release
  verification and the local matcher are separate follow-up work.

## Non-goals

- Community/device reporting, consensus, Sybil handling, or reporter linkage.
- Exporting observed devices or building a household inventory centrally.
- Automatic import from Fingerbank or any corpus with unresolved redistribution terms.
  Every manually entered `import` source requires an explicit redistributable
  `license_code`; a license string records the curator's review and is not itself a
  legal determination.
- Raw hostname patterns, arbitrary regex, banners, TXT values, or packet captures.
- Opaque ML, automatic scoring changes, or Core-side device matching.
- Merging the operations dashboard into `main`; this implementation remains on a
  standalone operations branch and is deployed independently.

## Constitution check

- **Local value first:** this prepares reference data; no local feature depends on
  telemetry or community contribution.
- **Passive-first / native sensor:** no sensor behavior changes and no active probes are
  introduced.
- **V1 scope / Pi 4:** the off-node service uses indexed SQLite and bounded JSON; Core
  consumption is deferred.
- **Migration:** a new embedded threat-network migration is additive; migrations 001-003
  and existing feed tables remain untouched.
- **Privacy:** only reviewed product-class data is permitted by the typed contract;
  the authenticated curator and exact release preview are part of the trust boundary.
  Hashing and leak linting are not represented as anonymity proofs.
- **Environment data:** fixtures use synthetic/public product-like examples only. No
  live lab artifact is committed.
- **FOSS:** standard Go/SQLite/Python/browser APIs only; imported evidence is rejected
  unless the curator records an explicit redistributable license code.
