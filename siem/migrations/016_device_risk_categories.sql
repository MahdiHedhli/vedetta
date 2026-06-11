-- Generalize device risk categories beyond the original narrow IC3 EOL flag.
-- Supports three main categories as requested:
--   - "known_exploited": Specific devices/chipsets actively used in campaigns (e.g. IC3 AVrecon, Mirai targets with public exploits)
--   - "eol_eos": End of Life / End of Support (no patches available)
--   - "high_risk_iot": Commonly vulnerable IoT/routers/cameras due to weak defaults, poor security posture, etc.
--
-- A device can have a primary risk_category and multiple reasons in risk_reasons (JSON array).
-- The original eol_risk / eol_model columns are retained for transition/backward compatibility.

ALTER TABLE devices ADD COLUMN risk_category TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN risk_model TEXT DEFAULT '';
ALTER TABLE devices ADD COLUMN risk_reasons TEXT DEFAULT ''; -- JSON array of strings, e.g. ["ic3_avrecon", "public_rce", "mirai_prone"]

-- Optional future: risk_level or confidence if needed for differentiated scoring.