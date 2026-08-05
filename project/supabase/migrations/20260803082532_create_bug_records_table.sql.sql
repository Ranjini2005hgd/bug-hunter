CREATE TABLE IF NOT EXISTS bug_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bug_id text UNIQUE NOT NULL,
  title text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  status text NOT NULL DEFAULT 'open',
  target_url text NOT NULL,
  notes text,
  vulnerability_class text,
  steps jsonb DEFAULT '[]'::jsonb,
  http_entries jsonb DEFAULT '[]'::jsonb,
  recording_duration integer DEFAULT 0,
  screenshot_count integer DEFAULT 0,
  report_markdown text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE bug_records ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_bug_records" ON bug_records;
CREATE POLICY "anon_select_bug_records" ON bug_records FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_bug_records" ON bug_records;
CREATE POLICY "anon_insert_bug_records" ON bug_records FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_bug_records" ON bug_records;
CREATE POLICY "anon_update_bug_records" ON bug_records FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_bug_records" ON bug_records;
CREATE POLICY "anon_delete_bug_records" ON bug_records FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_bug_records_created_at ON bug_records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_records_severity ON bug_records(severity);
CREATE INDEX IF NOT EXISTS idx_bug_records_status ON bug_records(status);