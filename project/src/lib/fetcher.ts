import type { FetchResult, ScanContext, ScanResult, ComplianceItem } from './types';
import { supabase } from './supabase';
import { runScan } from './scanner';

const FETCH_TIMEOUT_MS = 30_000;

export function normalizeUrl(input: string): string {
  let trimmed = input.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }
  return trimmed;
}

export function isValidUrl(input: string): boolean {
  try {
    const u = new URL(normalizeUrl(input));
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

export async function fetchSite(rawUrl: string): Promise<FetchResult> {
  const url = normalizeUrl(rawUrl);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const apiUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/fetch-site`;
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`,
        apikey: import.meta.env.VITE_SUPABASE_ANON_KEY,
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      let message = `The scan service returned an error (HTTP ${response.status}).`;
      try {
        const body = await response.json();
        if (body && typeof body.error === 'string') message = body.error;
      } catch {
        // non-JSON error body
      }
      throw new Error(message);
    }

    const data = (await response.json()) as FetchResult;
    if (!data || typeof data.html !== 'string') {
      throw new Error('The scan service returned an unexpected response.');
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error('The scan timed out. The target site took too long to respond.');
    }
    throw err;
  }
}

export function buildScanContext(fetch: FetchResult): ScanContext {
  const parser = new DOMParser();
  const document = parser.parseFromString(fetch.html, 'text/html');

  const baseEl = document.createElement('base');
  baseEl.href = fetch.finalUrl || fetch.url;
  document.head.prepend(baseEl);

  return {
    document,
    html: fetch.html,
    headers: fetch.headers || {},
    url: fetch.url,
    finalUrl: fetch.finalUrl || fetch.url,
    robots: fetch.robots,
    sitemap: fetch.sitemap,
    isHttps: (fetch.finalUrl || fetch.url).startsWith('https://'),
  };
}

export async function saveScan(result: ScanResult): Promise<void> {
  const cvssMax = Math.max(0, ...result.findings.map((f) => f.cvss?.score || 0));
  const hasComplianceFail = Object.values(result.compliance).some((items: ComplianceItem[]) =>
    items.some((item) => item.status === 'fail'),
  );
  await supabase.from('scans').insert({
    id: result.id,
    url: result.url,
    final_url: result.finalUrl,
    score: result.score,
    grade: result.grade,
    total_issues: result.totalIssues,
    critical_count: result.severityCounts.critical,
    high_count: result.severityCounts.high,
    medium_count: result.severityCounts.medium,
    low_count: result.severityCounts.low,
    info_count: result.severityCounts.info,
    technologies_count: result.recon.technologies.length,
    endpoints_count: result.recon.endpoints.length,
    has_compliance_failures: hasComplianceFail,
    cvss_max_score: cvssMax,
    result: result as unknown as Record<string, unknown>,
  });
}

export async function loadScan(id: string): Promise<ScanResult | null> {
  const { data, error } = await supabase
    .from('scans')
    .select('result')
    .eq('id', id)
    .maybeSingle();
  if (error || !data) return null;
  return data.result as unknown as ScanResult;
}

export async function loadRecentScans(limit = 10): Promise<ScanResult[]> {
  const { data, error } = await supabase
    .from('scans')
    .select('result')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error || !data) return [];
  return data.map((row) => row.result as unknown as ScanResult);
}

export async function runScanFlow(fetch: FetchResult): Promise<ScanResult> {
  return runScan(fetch);
}
