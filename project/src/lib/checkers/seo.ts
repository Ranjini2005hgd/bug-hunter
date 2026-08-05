import type { Checker, Finding, ScanContext } from '../types';

function getMeta(doc: Document, name: string): string | null {
  const el = doc.querySelector(`meta[name="${name}"], meta[property="${name}"]`);
  return el?.getAttribute('content')?.trim() || null;
}

export const checkSeo: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc, robots, sitemap, finalUrl } = ctx;

  // 1. Missing meta description
  const description = getMeta(doc, 'description');
  if (!description) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-meta-description',
      category: 'seo',
      severity: 'high',
      title: 'Missing meta description',
      description: 'The page has no <meta name="description">. Search engines use this as the snippet text in results; without it they guess from page content, often poorly.',
      impact: 'Lower click-through rates from search results and less control over how the page appears.',
      recommendation: 'Add a unique, compelling meta description (120-160 characters) for every indexable page.',
      fixSteps: [
        'Write a 120-160 character description of the page that includes the primary keyword.',
        'Add <meta name="description" content="..."> inside <head>.',
        'Make each page\u2019s description unique \u2014 avoid site-wide duplicates.',
      ],
      codeBefore: '(no meta description)',
      codeAfter: '<meta name="description" content="Acme\u2019s cloud backup keeps your files safe with end-to-end encryption and automatic syncing across all devices.">',
      references: [{ label: 'Google: Manage your snippet in search results', url: 'https://developers.google.com/search/docs/appearance/snippet' }],
      confidence: 'certain',
    });
  } else if (description.length < 70) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'short-meta-description',
      category: 'seo',
      severity: 'low',
      title: 'Meta description is very short',
      description: `The meta description is only ${description.length} characters. Descriptions under ~120 characters underuse the available snippet space in search results.`,
      impact: 'Underutilized search snippets may reduce click-through.',
      recommendation: 'Expand the description to 120-160 characters with relevant keywords and a call to action.',
      fixSteps: [
        'Expand the description to 120-160 characters.',
        'Include the primary keyword and a reason to click.',
      ],
      codeBefore: `<meta name="description" content="${description}">`,
      codeAfter: '<meta name="description" content="120-160 char description with keywords and value proposition.">',
      references: [{ label: 'Google Search Central: Snippets', url: 'https://developers.google.com/search/docs/appearance/snippet' }],
      confidence: 'high',
    });
  } else if (description.length > 170) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'long-meta-description',
      category: 'seo',
      severity: 'info',
      title: 'Meta description exceeds recommended length',
      description: `The meta description is ${description.length} characters. Search engines typically truncate snippets around 160 characters.`,
      impact: 'The description may be cut off in search results.',
      recommendation: 'Trim the description to ~160 characters.',
      fixSteps: ['Edit the description to 120-160 characters.', 'Front-load the most important words.'],
      codeBefore: `<meta name="description" content="${description.slice(0, 60)}...">`,
      codeAfter: '<meta name="description" content="Concise 150-char description.">',
      references: [{ label: 'Google Search Central: Snippets', url: 'https://developers.google.com/search/docs/appearance/snippet' }],
      confidence: 'high',
    });
  }

  // 2. Missing canonical link
  if (!doc.querySelector('link[rel="canonical"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-canonical',
      category: 'seo',
      severity: 'medium',
      title: 'Missing canonical link tag',
      description: 'The page has no <link rel="canonical">. Without it, search engines may treat duplicate URLs (with/without trailing slash, query params, http/https) as separate pages, splitting ranking signals.',
      impact: 'Duplicate content issues dilute search ranking across URL variants.',
      recommendation: 'Add a canonical link tag pointing to the preferred URL for each page.',
      fixSteps: [
        'Determine the preferred (canonical) URL for each page.',
        'Add <link rel="canonical" href="https://example.com/page"> inside <head>.',
        'Ensure the canonical URL uses HTTPS and the www/non-www form you prefer.',
      ],
      codeBefore: '(no canonical link)',
      codeAfter: '<link rel="canonical" href="https://example.com/page">',
      references: [{ label: 'Google: Consolidate duplicate URLs', url: 'https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls' }],
      confidence: 'certain',
    });
  }

  // 3. Missing Open Graph tags
  const ogTitle = getMeta(doc, 'og:title');
  const ogDesc = getMeta(doc, 'og:description');
  const ogImage = getMeta(doc, 'og:image');
  const ogUrl = getMeta(doc, 'og:url');
  const missingOg: string[] = [];
  if (!ogTitle) missingOg.push('og:title');
  if (!ogDesc) missingOg.push('og:description');
  if (!ogImage) missingOg.push('og:image');
  if (!ogUrl) missingOg.push('og:url');
  if (missingOg.length >= 2) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-open-graph',
      category: 'seo',
      severity: 'medium',
      title: `Missing Open Graph tags: ${missingOg.join(', ')}`,
      description: 'The page is missing key Open Graph tags. Without them, social media link previews show no title, description, or image, dramatically reducing click-through.',
      impact: 'Shared links on Facebook, LinkedIn, Slack, etc. show a bare URL with no preview, reducing engagement.',
      recommendation: 'Add the core Open Graph tags: og:title, og:description, og:image, og:url, and og:type.',
      fixSteps: [
        'Add <meta property="og:title" content="Page Title">.',
        'Add <meta property="og:description" content="Page description">.',
        'Add <meta property="og:image" content="https://example.com/og-image.jpg"> (1200x630px).',
        'Add <meta property="og:url" content="https://example.com/page">.',
        'Add <meta property="og:type" content="website">.',
      ],
      codeBefore: '(no Open Graph tags)',
      codeAfter: '<meta property="og:title" content="Acme Backup">\n<meta property="og:description" content="Encrypted cloud backup for everyone.">\n<meta property="og:image" content="https://example.com/og.jpg">\n<meta property="og:url" content="https://example.com">\n<meta property="og:type" content="website">',
      references: [{ label: 'The Open Graph protocol', url: 'https://ogp.me/' }],
      confidence: 'certain',
    });
  }

  // 4. Missing Twitter Card tags
  if (!getMeta(doc, 'twitter:card') && !getMeta(doc, 'twitter:title')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-twitter-card',
      category: 'seo',
      severity: 'low',
      title: 'Missing Twitter Card meta tags',
      description: 'The page has no Twitter Card meta tags. Links shared on X/Twitter show no preview card, reducing click-through.',
      impact: 'Shared links on X show a plain URL instead of a rich card with image and summary.',
      recommendation: 'Add at minimum twitter:card and twitter:title (or rely on Open Graph tags as fallback).',
      fixSteps: [
        'Add <meta name="twitter:card" content="summary_large_image">.',
        'Add <meta name="twitter:title" content="..."> and <meta name="twitter:description" content="...">.',
        'Add <meta name="twitter:image" content="https://example.com/card.jpg">.',
      ],
      codeBefore: '(no Twitter Card tags)',
      codeAfter: '<meta name="twitter:card" content="summary_large_image">\n<meta name="twitter:title" content="Acme Backup">\n<meta name="twitter:description" content="Encrypted cloud backup.">\n<meta name="twitter:image" content="https://example.com/card.jpg">',
      references: [{ label: 'X: Card documentation', url: 'https://developer.x.com/en/docs/twitter-for-websites/cards' }],
      confidence: 'certain',
    });
  }

  // 5. Missing structured data (JSON-LD)
  const jsonLd = doc.querySelectorAll('script[type="application/ld+json"]');
  if (jsonLd.length === 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-structured-data',
      category: 'seo',
      severity: 'low',
      title: 'No structured data (JSON-LD) found',
      description: 'The page has no JSON-LD structured data. Schema.org markup enables rich results (reviews, FAQs, breadcrumbs, sitelinks) in search engines.',
      impact: 'Missed opportunity for rich search results that increase visibility and click-through.',
      recommendation: 'Add JSON-LD structured data appropriate to the page type (Organization, Product, Article, FAQ, BreadcrumbList).',
      fixSteps: [
        'Identify the page type (e.g. product, article, FAQ, organization).',
        'Generate the matching schema.org JSON-LD at schema.org or with Google\u2019s Structured Data Markup Helper.',
        'Add it as <script type="application/ld+json">{ ... }</script> in <head>.',
        'Validate with Google\u2019s Rich Results Test.',
      ],
      codeBefore: '(no structured data)',
      codeAfter: '<script type="application/ld+json">\n{"@context":"https://schema.org","@type":"Organization","name":"Acme","url":"https://example.com"}\n</script>',
      references: [{ label: 'schema.org', url: 'https://schema.org/' }, { label: 'Google Rich Results Test', url: 'https://search.google.com/test/rich-results' }],
      confidence: 'high',
    });
  }

  // 6. Missing robots.txt
  if (!robots || robots.status === 404) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-robots-txt',
      category: 'seo',
      severity: 'medium',
      title: 'robots.txt not found or inaccessible',
      description: 'The site has no robots.txt file at the root. Search engines expect this file to learn what they may crawl. Its absence can cause crawl inefficiency or unwanted indexing.',
      impact: 'Search engines may crawl and index pages you intended to keep private, or waste crawl budget.',
      recommendation: 'Add a robots.txt file at the site root with appropriate rules.',
      fixSteps: [
        'Create a robots.txt file at https://yourdomain.com/robots.txt.',
        'Allow crawling of public content: User-agent: *  Allow: /',
        'Disallow private or thin pages (e.g. /admin/, /cart/).',
        'Reference your sitemap: Sitemap: https://yourdomain.com/sitemap.xml.',
      ],
      codeBefore: '(404 Not Found)',
      codeAfter: 'User-agent: *\nAllow: /\nDisallow: /admin/\nSitemap: https://example.com/sitemap.xml',
      references: [{ label: 'Google: robots.txt specifications', url: 'https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt' }],
      confidence: 'certain',
    });
  }

  // 7. Missing sitemap.xml
  if (!sitemap || sitemap.status === 404) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-sitemap',
      category: 'seo',
      severity: 'medium',
      title: 'sitemap.xml not found',
      description: 'The site has no XML sitemap at the root. Sitemaps help search engines discover and prioritize all indexable pages, especially on large or new sites.',
      impact: 'Search engines may take longer to discover new or deep pages.',
      recommendation: 'Generate and submit an XML sitemap, and reference it in robots.txt.',
      fixSteps: [
        'Generate an XML sitemap listing all indexable URLs (use a generator or CMS plugin).',
        'Host it at https://yourdomain.com/sitemap.xml.',
        'Add the sitemap URL to robots.txt: Sitemap: https://yourdomain.com/sitemap.xml.',
        'Submit it in Google Search Console and Bing Webmaster Tools.',
      ],
      codeBefore: '(404 Not Found)',
      codeAfter: '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>https://example.com/</loc></url>\n</urlset>',
      references: [{ label: 'sitemaps.org protocol', url: 'https://www.sitemaps.org/protocol.html' }],
      confidence: 'certain',
    });
  }

  // 8. Noindex / nofollow check
  const robotsMeta = getMeta(doc, 'robots');
  if (robotsMeta && /noindex|none/i.test(robotsMeta)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'noindex-directive',
      category: 'seo',
      severity: 'info',
      title: 'Page is blocked from indexing (noindex)',
      description: `The page has <meta name="robots" content="${robotsMeta}">. Search engines will not include this page in results. Confirm this is intentional.`,
      impact: 'The page will not appear in search results. This is intentional for some pages (thank-you, login, admin) but a mistake on content pages.',
      recommendation: 'If this page should be indexed, remove the noindex directive. Otherwise, confirm it is intentional.',
      fixSteps: [
        'Confirm whether the page should be indexed.',
        'If yes, remove <meta name="robots" content="noindex">.',
        'If no, leave it and ensure internal links to it use rel="nofollow" where appropriate.',
      ],
      codeBefore: `<meta name="robots" content="${robotsMeta}">`,
      codeAfter: '(remove if the page should be indexed)',
      references: [{ label: 'Google: Block indexing with noindex', url: 'https://developers.google.com/search/docs/crawling-indexing/block-indexing' }],
      confidence: 'certain',
    });
  }

  // 9. Links without descriptive text (e.g. "click here")
  const genericLinkText = Array.from(doc.querySelectorAll('a[href]')).filter((a) => {
    const text = (a.textContent || '').trim().toLowerCase();
    return ['click here', 'read more', 'more', 'here', 'link', 'learn more', 'continue'].includes(text);
  });
  if (genericLinkText.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'generic-link-text',
      category: 'seo',
      severity: 'low',
      title: `${genericLinkText.length} link${genericLinkText.length > 1 ? 's' : ''} with generic anchor text ("click here", "read more")`,
      description: 'Generic anchor text like "click here" or "read more" gives search engines no context about the destination and is poor for accessibility.',
      impact: 'Search engines lose keyword context for the linked page; screen reader users have uninformative link lists.',
      recommendation: 'Use descriptive anchor text that describes the destination.',
      fixSteps: [
        'Replace "click here" and "read more" with text describing the destination (e.g. "Read our pricing guide").',
        'If text must be short, add aria-label for a longer accessible name.',
      ],
      codeBefore: '<a href="/guide">Read more</a>',
      codeAfter: '<a href="/guide">Read our pricing guide</a>',
      references: [{ label: 'Google: Link text', url: 'https://developers.google.com/search/docs/appearance/write-titles-descriptions' }],
      confidence: 'high',
    });
  }

  // 10. Broken internal link heuristic (relative links that look broken)
  // Check for href="#" or empty href
  const emptyLinks = Array.from(doc.querySelectorAll('a[href="#"], a[href=""], a:not([href])')).filter((a) => (a.textContent || '').trim().length > 0);
  if (emptyLinks.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'empty-href',
      category: 'seo',
      severity: 'low',
      title: `${emptyLinks.length} link${emptyLinks.length > 1 ? 's' : ''} with empty or "#" href`,
      description: 'Links with href="#" or no href do not navigate anywhere. They are often placeholder links that confuse crawlers and users.',
      impact: 'Search engines may waste crawl budget; users click links that do nothing.',
      recommendation: 'Replace placeholder href="#" with real destination URLs, or convert to <button> if they trigger an action.',
      fixSteps: [
        'For each href="#" link, either add the real destination URL or convert it to a <button>.',
        'If it triggers JavaScript, use <button type="button"> instead of <a href="#">.',
      ],
      codeBefore: '<a href="#">Read more</a>',
      codeAfter: '<a href="/blog/post">Read more</a>  or  <button type="button" id="readMore">Read more</button>',
      references: [{ label: 'MDN: <a> element', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a' }],
      confidence: 'high',
    });
  }

  // 11. Missing hreflang (only relevant if multi-locale; flag as info if lang present)
  if (doc.documentElement.getAttribute('lang') && !doc.querySelector('link[rel="alternate"][hreflang]')) {
    // Only flag if the site appears to have international content (heuristic: skip)
    // We skip to avoid false positives on single-language sites.
  }

  // 12. URL structure: uppercase letters or underscores
  try {
    const u = new URL(finalUrl);
    if (/[A-Z]/.test(u.pathname) || u.pathname.includes('_')) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'url-structure',
        category: 'seo',
        severity: 'low',
        title: 'URL path contains uppercase letters or underscores',
        description: 'The URL path uses uppercase letters or underscores. Search engines prefer lowercase, hyphen-separated URLs for consistency and readability.',
        impact: 'Inconsistent URL casing can cause duplicate-content issues; underscores hide words from search engines.',
        recommendation: 'Use lowercase URLs with hyphens (not underscores) to separate words.',
        fixSteps: [
          'Change uppercase letters in URLs to lowercase.',
          'Replace underscores with hyphens.',
          'Add 301 redirects from old to new URLs.',
          'Update internal links and the XML sitemap.',
        ],
        codeBefore: 'https://example.com/Our_Products/Best_Items',
        codeAfter: 'https://example.com/our-products/best-items',
        references: [{ label: 'Google: URL structure', url: 'https://developers.google.com/search/docs/crawling-indexing/url-structure' }],
        confidence: 'high',
      });
    }
  } catch {
    // ignore URL parse errors
  }

  // 13. Low text-to-HTML ratio
  const text = (doc.body?.textContent || '').replace(/\s+/g, ' ').trim();
  const htmlSize = ctx.html.length;
  if (htmlSize > 0 && text.length / htmlSize < 0.1 && text.length < 500) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'low-text-ratio',
      category: 'seo',
      severity: 'info',
      title: 'Low text-to-HTML ratio',
      description: `The page has very little visible text relative to its HTML size (${text.length} chars of text / ${Math.round(htmlSize / 1024)}KB HTML). Thin content pages rank poorly.`,
      impact: 'Search engines may consider the page thin content and rank it lower.',
      recommendation: 'Add substantive, relevant text content that serves the user\u2019s intent.',
      fixSteps: [
        'Add helpful text content that addresses the page\u2019s topic in depth.',
        'Remove unnecessary markup and inline scripts that inflate HTML size.',
      ],
      codeBefore: '(mostly markup, little text)',
      codeAfter: '(add 300+ words of relevant content)',
      references: [{ label: 'Google: Thin content', url: 'https://developers.google.com/search/docs/essentials/spam-policies' }],
      confidence: 'medium',
    });
  }

  // 14. Missing favicon
  if (!doc.querySelector('link[rel="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-favicon',
      category: 'seo',
      severity: 'low',
      title: 'No favicon specified',
      description: 'The page has no favicon link. Browsers show a default icon in tabs and bookmarks, reducing brand recognition.',
      impact: 'Lower brand visibility in browser tabs, bookmarks, and history.',
      recommendation: 'Add a favicon link pointing to an icon file.',
      fixSteps: [
        'Create a favicon (favicon.ico and/or PNG icons at 16x16, 32x32, 180x180).',
        'Add <link rel="icon" href="/favicon.ico"> and <link rel="apple-touch-icon" href="/apple-touch-icon.png">.',
      ],
      codeBefore: '(no favicon)',
      codeAfter: '<link rel="icon" href="/favicon.ico" sizes="any">\n<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
      references: [{ label: 'MDN: Link types: icon', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/icon' }],
      confidence: 'high',
    });
  }

  return findings;
};
