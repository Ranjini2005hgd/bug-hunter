import { supabase } from './supabase';
import type { BugRecord, Severity, BugStatus, RecordingStep, HttpEntry } from './types';

interface BugRecordRow {
  id: string;
  bug_id: string;
  title: string;
  severity: string;
  status: string;
  target_url: string;
  notes: string;
  vulnerability_class: string | null;
  steps: RecordingStep[];
  http_entries: HttpEntry[];
  recording_duration: number;
  screenshot_count: number;
  report_markdown: string;
  created_at: string;
  updated_at: string;
}

function rowToRecord(row: BugRecordRow): BugRecord {
  return {
    id: row.id,
    bugId: row.bug_id,
    title: row.title,
    severity: row.severity as Severity,
    status: row.status as BugStatus,
    targetUrl: row.target_url,
    notes: row.notes || '',
    vulnerabilityClass: row.vulnerability_class || undefined,
    steps: row.steps || [],
    httpEntries: row.http_entries || [],
    recordingDuration: row.recording_duration || 0,
    screenshotCount: row.screenshot_count || 0,
    screenshots: [],
    reportMarkdown: row.report_markdown || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function saveBugRecord(record: Omit<BugRecord, 'id' | 'createdAt' | 'updatedAt'>): Promise<BugRecord | null> {
  const { data, error } = await supabase
    .from('bug_records')
    .insert({
      bug_id: record.bugId,
      title: record.title,
      severity: record.severity,
      status: record.status,
      target_url: record.targetUrl,
      notes: record.notes,
      vulnerability_class: record.vulnerabilityClass || null,
      steps: record.steps as unknown as Record<string, unknown>[],
      http_entries: record.httpEntries as unknown as Record<string, unknown>[],
      recording_duration: record.recordingDuration,
      screenshot_count: record.screenshotCount,
      report_markdown: record.reportMarkdown,
    })
    .select()
    .maybeSingle();

  if (error) {
    console.error('Failed to save bug record:', error);
    return null;
  }
  return data ? rowToRecord(data as BugRecordRow) : null;
}

export async function loadBugRecords(limit = 50): Promise<BugRecord[]> {
  const { data, error } = await supabase
    .from('bug_records')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    console.error('Failed to load bug records:', error);
    return [];
  }
  return (data as BugRecordRow[]).map(rowToRecord);
}

export async function deleteBugRecord(id: string): Promise<boolean> {
  const { error } = await supabase.from('bug_records').delete().eq('id', id);
  if (error) {
    console.error('Failed to delete bug record:', error);
    return false;
  }
  return true;
}

export async function updateBugRecordStatus(id: string, status: BugStatus): Promise<boolean> {
  const { error } = await supabase
    .from('bug_records')
    .update({ status, updated_at: new Date().toISOString() })
    .eq('id', id);
  if (error) {
    console.error('Failed to update bug record:', error);
    return false;
  }
  return true;
}

export function generateBugId(): string {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `BUG-${y}${m}${d}-${rand}`;
}
