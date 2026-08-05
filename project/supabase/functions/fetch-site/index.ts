import { createClient } from 'npm:@supabase/supabase-js@2.57.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

interface FetchBody {
  url: string;
}

interface ProbeResult {
  status: number;
  content: string;
  headers: Record<string, string>;
}

async function probe(url: string, accept: string = 'text/plain,*/*'): Promise<ProbeResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': 'BugHunter/1.0 (+https://bughunter.app/bot)',
        Accept: accept,
      },
    });
    clearTimeout(timeout);
    const content = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    return { status: res.status, content: content.slice(0, 200000), headers };
  } catch (_e) {
    return { status: 0, content: '', headers: {} };
  }
}

// Resolve DNS via DNS-over-HTTPS (Cloudflare)
async function resolveDns(hostname: string): Promise<{ ips: string[]; txtRecords: string[] }> {
  try {
    const aRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
      headers: { Accept: 'application/dns-json' },
    });
    const aData = await aRes.json();
    const ips = (aData.Answer || []).filter((a: Record<string, unknown>) => a.type === 1).map((a: Record<string, unknown>) => a.data as string);

    const txtRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=TXT`, {
      headers: { Accept: 'application/dns-json' },
    });
    const txtData = await txtRes.json();
    const txtRecords = (txtData.Answer || []).filter((a: Record<string, unknown>) => a.type === 16).map((a: Record<string, unknown>) => a.data as string);

    return { ips, txtRecords };
  } catch {
    return { ips: [], txtRecords: [] };
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { url } = (await req.json()) as FetchBody;

    if (!url || typeof url !== 'string') {
      return new Response(
        JSON.stringify({ error: 'A URL is required.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    let target = url.trim();
    if (!/^https?:\/\//i.test(target)) {
      target = `https://${target}`;
    }

    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch {
      return new Response(
        JSON.stringify({ error: 'The provided URL is not valid.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return new Response(
        JSON.stringify({ error: 'Only http and https URLs are supported.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const redirectChain: string[] = [];
    let currentUrl = target;
    let response: Response;

    try {
      response = await fetch(currentUrl, {
        redirect: 'follow',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; BugHunter/1.0; +https://bughunter.app/bot)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });
    } catch (e) {
      return new Response(
        JSON.stringify({ error: `Could not reach the site. ${e instanceof Error ? e.message : 'Network error.'}` }),
        { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const finalUrl = response.url || currentUrl;
    if (finalUrl !== currentUrl) {
      redirectChain.push(currentUrl, finalUrl);
    }

    const html = await response.text();
    const timingStart = Date.now();

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    // Probe robots.txt, sitemap.xml, and security.txt in parallel
    const robotsUrl = `${parsed.protocol}//${parsed.host}/robots.txt`;
    const sitemapUrl = `${parsed.protocol}//${parsed.host}/sitemap.xml`;
    const securityTxtUrl = `${parsed.protocol}//${parsed.host}/.well-known/security.txt`;
    const [robots, sitemap, securityTxt] = await Promise.all([
      probe(robotsUrl),
      probe(sitemapUrl),
      probe(securityTxtUrl),
    ]);

    // DNS resolution via DNS-over-HTTPS
    const dns = await resolveDns(parsed.hostname);

    const elapsed = Date.now() - timingStart;

    const result = {
      url: target,
      finalUrl,
      status: response.status,
      statusText: response.statusText,
      headers,
      html: html.slice(0, 500000),
      timingMs: elapsed,
      redirectChain,
      robots: robots.status > 0 ? { status: robots.status, content: robots.content } : null,
      sitemap: sitemap.status > 0 ? { status: sitemap.status, content: sitemap.content } : null,
      securityTxt: securityTxt.status > 0 ? { status: securityTxt.status, content: securityTxt.content } : null,
      dns: { hostname: parsed.hostname, ips: dns.ips, txtRecords: dns.txtRecords },
      fetchedAt: new Date().toISOString(),
    };

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: `An unexpected error occurred while fetching the site. ${err instanceof Error ? err.message : ''}` }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
