import type { ScanContext, DiscoveredAsset, EndpointInfo, TechnologyFingerprint, ReconResult, DnsInfo, FetchResult } from './types';

function uuid(): string {
  return crypto.randomUUID();
}

// Technology fingerprinting — detect frameworks, libraries, servers, CMS
function detectTechnologies(ctx: ScanContext): TechnologyFingerprint[] {
  const techs: TechnologyFingerprint[] = [];
  const { document: doc, headers, html } = ctx;

  const add = (name: string, category: string, evidence: string, confidence: 'certain' | 'high' | 'medium' = 'high', version?: string) => {
    techs.push({ name, category, version, confidence, evidence });
  };

  // Server
  const server = headers['server'];
  if (server) {
    const match = server.match(/(\w+)\/?([\d.]+)?/);
    if (match) add(match[1], 'Web Server', `Server header: ${server}`, 'certain', match[2]);
  }

  // X-Powered-By
  const xpb = headers['x-powered-by'];
  if (xpb) add(xpb.split(/[\/\s]/)[0], 'Framework', `X-Powered-By: ${xpb}`, 'certain', xpb.match(/[\d.]+/)?.[0]);

  // WordPress
  if (doc.querySelector('meta[name="generator"][content*="WordPress"]')) {
    const gen = doc.querySelector('meta[name="generator"]')?.getAttribute('content') || '';
    add('WordPress', 'CMS', gen, 'certain', gen.match(/[\d.]+/)?.[0]);
  }
  if (html.includes('wp-content/') || html.includes('wp-includes/')) add('WordPress', 'CMS', 'wp-content/ paths in HTML', 'high');

  // Drupal
  if (html.includes('Drupal.') || doc.querySelector('meta[name="generator"][content*="Drupal"]')) add('Drupal', 'CMS', 'Drupal generator meta', 'high');

  // Joomla
  if (doc.querySelector('meta[name="generator"][content*="Joomla"]')) add('Joomla', 'CMS', 'Joomla generator meta', 'high');

  // React
  if (html.includes('data-reactroot') || html.includes('__REACT_DEVTOOLS_GLOBAL_HOOK__') || html.includes('react-dom')) {
    add('React', 'JS Framework', 'React root attributes or react-dom reference', 'high');
  }

  // Next.js
  if (html.includes('__NEXT_DATA__') || html.includes('_next/static')) add('Next.js', 'JS Framework', '__NEXT_DATA__ or _next/ paths', 'certain');
  if (html.includes('id="__next"')) add('Next.js', 'JS Framework', 'id="__next" container', 'certain');

  // Vue
  if (html.includes('__VUE') || html.includes('data-v-') || html.includes('vue-app')) add('Vue.js', 'JS Framework', 'Vue data attributes', 'high');

  // Nuxt
  if (html.includes('__NUXT__') || html.includes('_nuxt/')) add('Nuxt', 'JS Framework', '__NUXT__ or _nuxt/ paths', 'certain');

  // Angular
  if (html.includes('ng-app') || html.includes('ng-version') || html.includes('angular')) add('Angular', 'JS Framework', 'Angular attributes', 'high');

  // SvelteKit
  if (html.includes('sveltekit') || html.includes('__sveltekit')) add('SvelteKit', 'JS Framework', 'sveltekit reference', 'high');

  // jQuery
  if (html.includes('jquery') || html.includes('jQuery(')) {
    const jqv = html.match(/jquery[.-](\d+\.\d+\.\d+)/i);
    add('jQuery', 'JS Library', 'jQuery script reference', 'high', jqv?.[1]);
  }

  // Bootstrap
  if (html.includes('bootstrap') || doc.querySelector('link[href*="bootstrap"]')) add('Bootstrap', 'CSS Framework', 'Bootstrap CSS link', 'high');

  // Tailwind CSS
  if (html.includes('tailwind') || doc.querySelector('link[href*="tailwind"]')) add('Tailwind CSS', 'CSS Framework', 'Tailwind reference', 'high');

  // Google Fonts
  if (doc.querySelector('link[href*="fonts.googleapis"]')) add('Google Fonts', 'Font Service', 'fonts.googleapis.com link', 'certain');

  // Google Analytics
  if (html.includes('google-analytics.com') || html.includes('gtag') || html.includes('UA-')) add('Google Analytics', 'Analytics', 'GA script reference', 'certain');

  // Google Tag Manager
  if (html.includes('googletagmanager.com') || html.includes('GTM-')) add('Google Tag Manager', 'Tag Manager', 'GTM script reference', 'certain');

  // Cloudflare
  if (headers['cf-ray'] || headers['server']?.includes('cloudflare')) add('Cloudflare', 'CDN', 'CF-Ray or Cloudflare server header', 'certain');

  // Vercel
  if (headers['x-vercel-id'] || headers['server']?.includes('vercel')) add('Vercel', 'Hosting', 'X-Vercel-ID header', 'certain');

  // Netlify
  if (headers['x-netlify'] || headers['server']?.includes('netlify')) add('Netlify', 'Hosting', 'X-Netlify header', 'certain');

  // GitHub Pages
  if (headers['server']?.includes('GitHub Pages')) add('GitHub Pages', 'Hosting', 'Server: GitHub Pages', 'certain');

  // nginx
  if (headers['server']?.toLowerCase().includes('nginx')) add('Nginx', 'Web Server', `Server: ${headers['server']}`, 'certain', headers['server'].match(/[\d.]+/)?.[0]);

  // Apache
  if (headers['server']?.toLowerCase().includes('apache')) add('Apache', 'Web Server', `Server: ${headers['server']}`, 'certain', headers['server'].match(/[\d.]+/)?.[0]);

  // Express
  if (headers['x-powered-by']?.includes('Express')) add('Express', 'Backend', 'X-Powered-By: Express', 'certain');

  // PHP
  if (headers['x-powered-by']?.includes('PHP')) add('PHP', 'Backend', `X-Powered-By: ${headers['x-powered-by']}`, 'certain', headers['x-powered-by'].match(/[\d.]+/)?.[0]);

  // Stripe
  if (html.includes('js.stripe.com') || html.includes('pk_live_') || html.includes('pk_test_')) add('Stripe', 'Payment', 'Stripe.js reference', 'certain');

  // Cloudflare Insights
  if (html.includes('cloudflareinsights.com')) add('Cloudflare Insights', 'Analytics', 'Cloudflare Insights beacon', 'certain');

  // Sentry
  if (html.includes('sentry.io') || html.includes('@sentry/browser')) add('Sentry', 'Error Tracking', 'Sentry SDK reference', 'high');

  // reCAPTCHA
  if (html.includes('recaptcha') || html.includes('grecaptcha')) add('reCAPTCHA', 'Security', 'reCAPTCHA script reference', 'certain');

  // Font Awesome
  if (doc.querySelector('link[href*="font-awesome"]') || html.includes('fontawesome')) add('Font Awesome', 'Icon Library', 'Font Awesome reference', 'high');

  // Shopify
  if (html.includes('cdn.shopify.com') || headers['x-shopify-stage']) add('Shopify', 'E-commerce', 'Shopify CDN reference', 'certain');

  // deduplicate by name
  const seen = new Set<string>();
  return techs.filter((t) => {
    const key = t.name.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Asset discovery — find URLs, endpoints, resources from the page
function discoverAssets(ctx: ScanContext): DiscoveredAsset[] {
  const { document: doc } = ctx;
  const assets: DiscoveredAsset[] = [];

  // Links as endpoints
  const links = Array.from(doc.querySelectorAll('a[href]'));
  for (const a of links.slice(0, 100)) {
    const href = a.getAttribute('href') || '';
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) continue;
    try {
      const resolved = new URL(href, ctx.finalUrl).href;
      assets.push({
        id: uuid(),
        type: 'endpoint',
        url: resolved,
        method: 'GET',
        status: undefined,
        authRequired: false,
      });
    } catch { /* ignore */ }
  }

  // JavaScript resources
  const scripts = Array.from(doc.querySelectorAll('script[src]'));
  for (const s of scripts) {
    const src = s.getAttribute('src') || '';
    try {
      const resolved = new URL(src, ctx.finalUrl).href;
      assets.push({
        id: uuid(),
        type: 'javascript',
        url: resolved,
        method: 'GET',
        authRequired: false,
      });
    } catch { /* ignore */ }
  }

  // API hints — look for fetch/ajax patterns in inline scripts
  const inlineScripts = Array.from(doc.querySelectorAll('script:not([src])')).map((s) => s.textContent || '').join('\n');
  const apiPatterns = inlineScripts.match(/(?:fetch|axios|XMLHttpRequest|\.ajax)\(['"]([^'"]+)['"]/g) || [];
  for (const p of apiPatterns.slice(0, 20)) {
    const match = p.match(/['"]([^'"]+)['"]/);
    if (match) {
      try {
        const resolved = new URL(match[1], ctx.finalUrl).href;
        assets.push({
          id: uuid(),
          type: 'api',
          url: resolved,
          method: 'GET',
          authRequired: true,
        });
      } catch { /* ignore */ }
    }
  }

  // Forms as endpoints
  const forms = Array.from(doc.querySelectorAll('form[action]'));
  for (const f of forms) {
    const action = f.getAttribute('action') || '';
    const method = (f.getAttribute('method') || 'GET').toUpperCase();
    try {
      const resolved = new URL(action, ctx.finalUrl).href;
      const inputs = Array.from(f.querySelectorAll('input, select, textarea'));
      const params = inputs.map((i) => i.getAttribute('name') || '').filter(Boolean);
      assets.push({
        id: uuid(),
        type: 'endpoint',
        url: resolved,
        method,
        authRequired: !!f.querySelector('input[type="password"]'),
        parameters: params,
      });
    } catch { /* ignore */ }
  }

  return assets;
}

// Endpoint mapping — detailed endpoint info from assets
function mapEndpoints(ctx: ScanContext, assets: DiscoveredAsset[]): EndpointInfo[] {
  return assets
    .filter((a) => a.type === 'endpoint' || a.type === 'api')
    .slice(0, 50)
    .map((a) => ({
      id: a.id,
      url: a.url,
      method: a.method || 'GET',
      parameters: a.parameters || [],
      headers: {},
      cookies: [],
      authRequired: a.authRequired,
      responseCode: a.status || 0,
      contentType: '',
      relatedEndpoints: [],
    }));
}

// DNS info from the fetch result — uses DNS-over-HTTPS data from the edge function
function extractDnsInfo(ctx: ScanContext, fetch: FetchResult): DnsInfo {
  let hostname = ctx.finalUrl;
  try {
    hostname = new URL(ctx.finalUrl).hostname;
  } catch { /* keep raw */ }

  return {
    hostname,
    ips: fetch.dns?.ips || [],
    nameservers: [],
    txtRecords: fetch.dns?.txtRecords || [],
  };
}

// JavaScript resources
function extractJsResources(ctx: ScanContext): string[] {
  const { document: doc } = ctx;
  return Array.from(doc.querySelectorAll('script[src]'))
    .map((s) => {
      try {
        return new URL(s.getAttribute('src') || '', ctx.finalUrl).href;
      } catch {
        return s.getAttribute('src') || '';
      }
    })
    .filter(Boolean);
}

// Public endpoints from robots.txt and sitemap
function extractPublicEndpoints(ctx: ScanContext): string[] {
  const endpoints: string[] = [];
  if (ctx.robots?.content) {
    const allowPaths = ctx.robots.content.match(/^(?:Allow|Disallow):\s*(.+)$/gim) || [];
    for (const line of allowPaths.slice(0, 20)) {
      const path = line.replace(/^(?:Allow|Disallow):\s*/i, '').trim();
      if (path && path !== '/' && !path.startsWith('*')) {
        try {
          endpoints.push(new URL(path, ctx.finalUrl).href);
        } catch { /* ignore */ }
      }
    }
  }
  if (ctx.sitemap?.content) {
    const urls = ctx.sitemap.content.match(/<loc>([^<]+)<\/loc>/gi) || [];
    for (const u of urls.slice(0, 20)) {
      const loc = u.replace(/<\/?loc>/gi, '').trim();
      if (loc) endpoints.push(loc);
    }
  }
  return [...new Set(endpoints)];
}

export function runRecon(ctx: ScanContext, _fetch: FetchResult): ReconResult {
  const technologies = detectTechnologies(ctx);
  const assets = discoverAssets(ctx);
  const endpoints = mapEndpoints(ctx, assets);
  const dnsInfo = extractDnsInfo(ctx, _fetch);
  const javascriptResources = extractJsResources(ctx);
  const publicEndpoints = extractPublicEndpoints(ctx);

  return {
    technologies,
    assets,
    endpoints,
    dnsInfo,
    javascriptResources,
    publicEndpoints,
  };
}
