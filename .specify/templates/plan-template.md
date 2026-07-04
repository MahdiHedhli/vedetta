# Plan: [FEATURE NAME]

> Spec: `specs/NNN-feature-name/spec.md`
> Status: Draft | Approved
> Created: YYYY-MM-DD

## Architecture Overview

Where this sits in the Core + Sensor + Collector model. Diagram or component list.

## Data Flow

Source → normalization → ingest → storage → enrichment → UI, end to end.
Name the exact endpoints, tables, and services touched.

## Schema Changes

New sequential migration(s) in `siem/migrations/` — never edit committed migrations.
List columns/tables/indexes with types and defaults.

## API & Wire Contracts

New/changed endpoints and payload fields. Backward-compatibility notes for
independently-upgrading sensors. Contracts go in `contracts/` when crossing a
service boundary.

## Detection & Enrichment

Scoring, tagging, suppression interactions. Which existing detectors are affected.

## SNR Tuning Plan

Concrete suppression/whitelist/scoring work shipped WITH the feature, plus the
validation loop (simulated + live traffic) before the source is called supported.

## Failure Modes & Limits

What happens when the source is unreachable, malformed, or floods. Rate/volume
expectations on Pi 4.

## Constitution Check

Confirm the spec's constitution table still holds for this technical approach; call
out any new tension.

## Test Strategy

Unit, integration, and manual verification. Fresh-install migration test required for
any schema change.
