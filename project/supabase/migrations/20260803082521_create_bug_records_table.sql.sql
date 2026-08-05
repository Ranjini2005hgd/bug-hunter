/*
# Create bug_records table (single-tenant, no auth)

1. New Tables
- `bug_records`
  - `id` (uuid, primary key) — unique bug ID
  - `bug_id` (text, unique) — human-readable ID like BUG-20260803-001
  - `title` (text, not null) — bug title entered by researcher
  - `severity` (text, not null) — critical | high | medium | low | info
  - `status` (text, not null, default 'open') — open | triaged | fixed | duplicate
  - `target_url` (text, not null) — the URL where the bug was found
  - `notes` (text) — researcher notes
  - `vulnerability_class` (text) — vulnerability category
  - `steps` (jsonb) — array of recorded step objects {timestamp, action, url, screenshot}
  - `http_entries` (jsonb) — array of HTTP request/response entries
  - `recording_duration` (integer) — video duration in seconds
  - `screenshot_count` (integer) — number of screenshots captured
  - `report_markdown` (text) — generated Markdown report content
  - `created_at` (timestamptz, default now()) — creation timestamp
  - `updated_at` (timestamptz, default now()) — last update timestamp

2. Security
- Enable RLS on `bug_records`.
- Allow anon + authenticated CRUD because this is a single-tenant tool with no sign-in.
- All data is intentionally accessible to the researcher using the tool.

3. Notes
- No user_id / auth.users FK — this is a single-tenant bug documentation assistant.
- JSONB columns store steps and HTTP entries as flexible structured data.
- The `bug_id` text column provides human-readable unique identifiers for organization.
*/