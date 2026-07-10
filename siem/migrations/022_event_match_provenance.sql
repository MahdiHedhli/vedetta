-- Match provenance for known_bad events (GHSA-hx86).
--
-- Core tags an event known_bad on two distinct paths — a threat-intel DOMAIN-list
-- hit and a threat-intel RESOLVED-IP hit — but previously stored nothing to tell
-- them apart, and the resolved-IP path leaked the observed QNAME downstream.
--
-- These two additive columns record WHICH indicator matched and via which path:
--   match_type        : '' (no match), 'domain', or 'resolved_ip'
--   matched_indicator : the matched list entry (the FQDN for a domain match,
--                       the matched IP for a resolved-IP match)
--
-- Additive style matching migrations 016/017; the runner is per-statement
-- idempotent (duplicate-column errors are tolerated on re-apply).

ALTER TABLE events ADD COLUMN matched_indicator TEXT DEFAULT '';
ALTER TABLE events ADD COLUMN match_type TEXT DEFAULT '';
