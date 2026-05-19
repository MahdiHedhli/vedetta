-- EOL Router / High-Risk Device Risk Flagging (IC3 FLASH 2026-03-12)
-- Adds explicit columns for devices matching known EOL/vulnerable router and camera models
-- targeted by AVrecon malware (SocksEscort residential proxy campaign).
-- These devices receive elevated anomaly scoring in the Enricher when exhibiting suspicious behavior.

ALTER TABLE devices ADD COLUMN eol_risk INTEGER DEFAULT 0;
ALTER TABLE devices ADD COLUMN eol_model TEXT DEFAULT '';