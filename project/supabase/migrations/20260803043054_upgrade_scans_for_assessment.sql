/*
# Upgrade scans table for full assessment platform

## Overview
Upgrades the existing scans table to store the full BugHunter Pro assessment
data: scope, workflow state, reconnaissance results, CVSS scores, evidence
packages, compliance reports, and DNS info. The existing `result` jsonb column
already holds the full JSON payload so no new columns are strictly required,
but we add summary columns for the new dimensions to support filtering and
dashboard queries without parsing JSON.

## Changes to existing table: `scans`
- `technologies_count` (integer) — number of technologies detected during recon
- `endpoints_count` (integer) — number of endpoints mapped
- `has_compliance_failures` (boolean) — whether any compliance framework check failed
- `cvss_max_score` (numeric) — highest CVSS score across all findings

## Security
- RLS already enabled. No policy changes needed — existing anon/authenticated
  CRUD policies remain valid since this is still a single-tenant no-auth app.

## Notes
1. All new columns are nullable with defaults so existing rows are not affected.
2. The `result` jsonb column continues to hold the full assessment payload.
*/

ALTER TABLE scans ADD COLUMN IF NOT EXISTS technologies_count integer DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS endpoints_count integer DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS has_compliance_failures boolean DEFAULT false;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS cvss_max_score numeric(4,1) DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_scans_score ON scans (score DESC);
