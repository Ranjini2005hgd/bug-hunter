/*
# Create scans table (single-tenant, no auth)

## Overview
Stores the history of website bug scans performed by the application. Each scan
record holds the full JSON result (findings, scores, stats) so users can re-open
past scans without re-running them, and so the downloadable reports can be
regenerated on demand.

## New Tables
- `scans`
  - `id` (uuid, primary key) — unique scan identifier
  - `url` (text, not null) — the target URL the user scanned
  - `final_url` (text) — the resolved URL after any redirects
  - `score` (integer) — overall health score 0-100
  - `grade` (text) — letter grade A-F derived from the score
  - `total_issues` (integer) — total number of findings
  - `critical_count` (integer) — number of critical severity findings
  - `high_count` (integer) — number of high severity findings
  - `medium_count` (integer) — number of medium severity findings
  - `low_count` (integer) — number of low severity findings
  - `info_count` (integer) — number of informational findings
  - `result` (jsonb, not null) — the complete ScanResult JSON payload
  - `created_at` (timestamptz) — when the scan was performed

## Security
- Enable RLS on `scans`.
- This is a single-tenant tool with no sign-in screen; the data is intentionally
  public/shared across all visitors. All CRUD operations are allowed for both
  `anon` and `authenticated` roles so the anon-key frontend can read and write
  its own scan records.

## Indexes
- Index on `created_at` descending so recent scans load fast.
- Index on `url` for lookups of scans by target site.

## Notes
1. No user_id column and no auth dependency — the app has no sign-in flow.
2. The full result JSON is stored in `result` so reports can be regenerated
   without re-scanning the target website.
*/

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  url text NOT NULL,
  final_url text,
  score integer NOT NULL DEFAULT 0,
  grade text NOT NULL DEFAULT 'F',
  total_issues integer NOT NULL DEFAULT 0,
  critical_count integer NOT NULL DEFAULT 0,
  high_count integer NOT NULL DEFAULT 0,
  medium_count integer NOT NULL DEFAULT 0,
  low_count integer NOT NULL DEFAULT 0,
  info_count integer NOT NULL DEFAULT 0,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_scans" ON scans;
CREATE POLICY "anon_select_scans"
  ON scans FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "anon_insert_scans" ON scans;
CREATE POLICY "anon_insert_scans"
  ON scans FOR INSERT
  TO anon, authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_scans" ON scans;
CREATE POLICY "anon_update_scans"
  ON scans FOR UPDATE
  TO anon, authenticated
  USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_scans" ON scans;
CREATE POLICY "anon_delete_scans"
  ON scans FOR DELETE
  TO anon, authenticated
  USING (true);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (url);
