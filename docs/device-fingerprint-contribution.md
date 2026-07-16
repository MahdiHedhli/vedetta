# Device-Fingerprint Contribution (research gate; no transport)

This document records what must be solved before a Vedetta instance can help grow the
community device-recognition corpus ([spec 008](../specs/008-device-fingerprint-corpus/) /
issue `#52`). It does **not** authorize real-data contribution, and no contribution transport or
shadow persistence exists in this change.

Owner direction requires a contribution to be unlinkable to an install, user/device ID,
source IP, or household. That is a stronger property than removing obvious identifiers from
JSON. A rare, high-dimensional fingerprint can itself be identifying when combined with
outside knowledge. Privacy Pass and Oblivious HTTP do not solve that content-uniqueness risk.

## Stage 1 — local structural candidate (built, inert)

`backend/internal/corpuscontrib` can reduce an in-memory observation to a deliberately narrow
candidate for synthetic study. It is not wired into Core and does not store or transmit data.

The v1 candidate permits only:

- one globally administered, unicast 24-bit OUI prefix (never a full or randomized MAC);
- a bounded ordered DHCP option-55 sequence; and
- a bounded sorted set of observed TCP ports.

It rejects every device-controlled string field, including hostname templates, DHCP vendor
classes, mDNS services/models/vendors, and SSDP device types/server tokens. Those values are
useful for recognition but can carry a person, room, serial, address, or custom identifier;
no local regex can prove that arbitrary device text is a public product token. A future
revision may admit values only through a separately reviewed fixed public allowlist.

The structural validator also rejects locally administered/multicast OUIs, conflicting DHCP
sequences, duplicate/out-of-range option codes, UDP claims the current observation model
cannot distinguish, unsorted/duplicate ports, excessive list sizes, and all unsupported
fields. This is a **direct-carrier reduction**, not an anonymity proof: option sequences and
port combinations may still be rare or deliberately encode data.

## Stage 2 — unlinkable release (unresolved; not implemented)

Two different use cases need different privacy mechanisms:

1. **Corroborating a known public corpus variant.** A client could report a predeclared,
   coarse variant bucket through a Prio/DAP-style aggregate. Only cohort totals would be
   released; no collector would receive an individual plaintext report. This cannot discover
   a brand-new fingerprint shape.
2. **Discovering a new shape.** An open-ended fingerprint cannot use the same fixed-bucket
   aggregation. It would require a reviewed non-colluding shuffle/threshold-decryption design
   that batches fixed-size ciphertexts, exposes no per-report metadata, releases a shape only
   after a minimum cohort, and expires unreleased singleton/small-cohort ciphertexts. OHTTP
   may separate source addressing from ciphertext delivery, but is only one component.

The earlier idea of sending each plaintext shape to a staging database is rejected: even
without reporter IDs, that server would observe singleton fingerprints and could not meet the
hard shape-to-household unlinkability requirement.

## Acceptance gates before any real-data contribution

- A precise threat model covering relay/aggregator non-collusion, traffic analysis, rare-shape
  auxiliary knowledge, malicious devices, poisoning, Sybil attacks, replay, and operator
  compromise.
- An approved field dictionary and structural proof at producer, envelope, aggregation, and
  release boundaries; no free-text or extensible metadata maps.
- Fixed-size padding, delayed batches, minimum-cohort release, bounded retention, deletion of
  unreleased cohorts, rate/replay controls, and exercised client/server kill switches.
- Explicit opt-in consent that states residual fingerprint uniqueness honestly.
- Community output remains advisory and can never override `user_corrected`, create/suppress/
  resolve a finding, or silently change detection priority.
- Independent cryptographic and privacy review of the exact deployed protocol and operations.

Until all gates pass, the only permitted work is local synthetic evaluation. Real collection,
storage, transport, and dashboard submission remain disabled.
