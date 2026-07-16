# Local Device-Corpus Matching

Vedetta can recognize a device's **class** (manufacturer / model / device type) by matching
its already-observed signals against a curated community device-fingerprint corpus
([spec 008](../specs/008-device-fingerprint-corpus/), #52). This is **local and read-only**:
Core loads a signed corpus snapshot and matches locally. It never uploads a device's
signals — contributing to the corpus is a separate, opt-in path.

## What it does

For each observed device, Core projects its currently captured signals (OUI, mDNS service
types / TXT model / TXT vendor, SSDP device type / server token, DHCP option-55 sequence /
vendor class, and TCP ports) into the corpus shape vocabulary and matches them against
curated device-class shapes. The corpus schema also reserves hostname templates and UDP
ports, but Core does not claim those families until its observation model supplies them.

A device **matches** a corpus variant when either:

- **two independent signal families** agree (from DHCP / OUI / hostname / mDNS / SSDP /
  ports), or
- one **product-specific** signal agrees — a DHCP vendor class, hostname template, mDNS TXT
  model, or SSDP server token (an "exact product signature").

This is the client side of the corpus's own publish bar. Product-specific evidence outranks
generic multi-family evidence; an equally ranked conflict between different device classes
is left unresolved instead of choosing one by database order. Matching is bounded by an
inverted index, so a device is compared only against variants that share a signal with it
(Pi-4 friendly).

## How the match is used (fusion)

A match becomes a **descriptive** signal — `vendor` / `model` / `device_type` / `os_family`
— at source `corpus`, confidence capped at **0.85 and at the curated variant's own
confidence**. In the confidence-weighted resolver that means:

- it sits **below a device's own mDNS TXT** advertisement (0.9) — a device that announces
  its own model wins;
- it is **far below `user_corrected`** (1.0) — an operator's correction always locks the
  field;
- it is written as a device *signal*, never as identity evidence, so a class-level match can
  never merge two distinct devices.

A corpus match is advisory context; it cannot create, suppress, resolve, or reprioritize a
finding on its own.

## Delivery

The corpus snapshot ships as `corpus.json` inside the **signed device-DB bundle**
(see [Signed Device-DB Releases](device-db-releases.md)) — the same ed25519-verified,
generation-pointer mechanism as `oui.csv`. It is **optional**: a bundle without `corpus.json`
is valid (no corpus loaded, no matching), and a present-but-unparseable snapshot is rejected
so the updater rolls the generation back.

To include it when cutting a release, pass the corpus snapshot URL to the **release-db**
workflow's `corpus_snapshot_url` input; the workflow fetches it (HTTPS with connection,
duration, and size bounds), applies the Threat Network's canonical privacy/publication gate
and Core's exact runtime parser, signs it alongside `oui.csv`, and publishes it in the draft.

Matching only runs when the opt-in device-DB updater is enabled and a corpus has been
installed; otherwise device typing falls back to the existing OUI + passive signals.
