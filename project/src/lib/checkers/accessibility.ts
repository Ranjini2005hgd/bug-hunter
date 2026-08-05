import type { Checker, Finding, ScanContext } from '../types';

export const checkAccessibility: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc } = ctx;

  // 1. Missing document language
  const htmlEl = doc.documentElement;
  if (!htmlEl.getAttribute('lang') || htmlEl.getAttribute('lang')?.trim() === '') {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-lang',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: 'Document missing a language attribute',
      description: 'The <html> element has no lang attribute. Screen readers cannot determine the page\u2019s language and may use the wrong pronunciation and voice.',
      impact: 'Screen reader users hear content mispronounced, and translation tools cannot auto-detect the language.',
      recommendation: 'Add a lang attribute to the <html> element with the correct language code.',
      fixSteps: [
        'Add lang="en" (or the appropriate ISO 639-1 code) to the <html> tag.',
        'For mixed-language content, use lang on the specific elements that differ.',
      ],
      codeBefore: '<html>',
      codeAfter: '<html lang="en">',
      references: [{ label: 'WCAG 3.1.1 Language of Page (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/language-of-page.html' }],
      confidence: 'certain',
    });
  }

  // 2. Missing <title>
  if (!doc.querySelector('title')?.textContent?.trim()) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-title',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: 'Page missing a <title> element',
      description: 'The page has no <title> element. The title is read first by screen readers and shown in browser tabs, bookmarks, and search results.',
      impact: 'Screen reader users cannot identify the page; browser tabs and bookmarks show no label.',
      recommendation: 'Add a concise, descriptive <title> inside <head>.',
      fixSteps: [
        'Add <title>Descriptive Page Name \u2014 Site Name</title> within <head>.',
        'Keep titles under 60 characters for readability in tabs and search results.',
      ],
      codeBefore: '<head>\n  <meta charset="utf-8">\n</head>',
      codeAfter: '<head>\n  <meta charset="utf-8">\n  <title>Checkout \u2014 Acme Store</title>\n</head>',
      references: [{ label: 'WCAG 2.4.2 Page Titled (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/page-titled.html' }],
      confidence: 'certain',
    });
  }

  // 3. Images without alt text
  const imgs = Array.from(doc.querySelectorAll('img'));
  const noAlt = imgs.filter((img) => !img.hasAttribute('alt'));
  if (noAlt.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'img-missing-alt',
      category: 'accessibility',
      severity: 'high',
      wcagLevel: 'A',
      title: `${noAlt.length} image${noAlt.length > 1 ? 's' : ''} without alt attribute`,
      description: 'Images without an alt attribute are invisible to screen readers and have no text alternative. Decorative images should use alt="" explicitly; informational images need descriptive text.',
      evidence: noAlt.slice(0, 3).map((img) => img.getAttribute('src')?.slice(0, 80) || '').join('\n'),
      impact: 'Screen reader users miss all information conveyed by these images.',
      recommendation: 'Add an alt attribute to every <img>. Use descriptive text for informational images and alt="" for purely decorative ones.',
      fixSteps: [
        'For each <img>, decide if it is informational or decorative.',
        'Informational: add alt="description of the image".',
        'Decorative: add alt="" (empty) so screen readers skip it.',
        'Never omit the attribute entirely \u2014 omitting it can cause screen readers to read the filename.',
      ],
      codeBefore: '<img src="chart.png">',
      codeAfter: '<img src="chart.png" alt="Bar chart showing 40% revenue growth in Q3">',
      references: [{ label: 'WCAG 1.1.1 Non-text Content (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/non-text-content.html' }],
      confidence: 'certain',
    });
  }

  // 4. Suspicious alt text (filename, "image", placeholder)
  const badAlt = imgs.filter((img) => {
    const alt = img.getAttribute('alt');
    if (alt === null) return false;
    if (alt === '') return false;
    const lower = alt.toLowerCase();
    return (
      lower === 'image' || lower === 'photo' || lower === 'picture' || lower === 'icon' ||
      lower === 'graphic' || lower === 'img' || lower === 'undefined' ||
      /\.(png|jpe?g|gif|svg|webp)$/i.test(alt) || alt.length > 125
    );
  });
  if (badAlt.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'img-bad-alt',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: `${badAlt.length} image${badAlt.length > 1 ? 's' : ''} with unhelpful alt text`,
      description: 'Some images have alt text that is a filename, a generic word ("image", "photo"), or excessively long. These do not convey the image\u2019s meaning.',
      evidence: badAlt.slice(0, 3).map((img) => `alt="${img.getAttribute('alt')?.slice(0, 60)}"`).join('\n'),
      impact: 'Screen reader users hear useless labels instead of meaningful descriptions.',
      recommendation: 'Replace generic or filename alt text with a concise description of the image\u2019s purpose.',
      fixSteps: [
        'Review each flagged image and write alt text that describes its function or content.',
        'Keep alt text under ~125 characters; use longdesc or a caption for complex images.',
        'For purely decorative images, use alt="" instead of placeholder text.',
      ],
      codeBefore: '<img src="hero.jpg" alt="image">',
      codeAfter: '<img src="hero.jpg" alt="Customer using the mobile app to track a delivery">',
      references: [{ label: 'WCAG 1.1.1 Non-text Content', url: 'https://www.w3.org/WAI/WCAG21/Understanding/non-text-content.html' }],
      confidence: 'high',
    });
  }

  // 5. Form inputs without labels
  const inputs = Array.from(doc.querySelectorAll('input, select, textarea'));
  const noLabel = inputs.filter((el) => {
    if (el.getAttribute('type') === 'hidden' || el.getAttribute('type') === 'submit' || el.getAttribute('type') === 'button') return false;
    const id = el.getAttribute('id');
    if (id && doc.querySelector(`label[for="${CSS.escape(id)}"]`)) return false;
    const ariaLabel = el.getAttribute('aria-label');
    if (ariaLabel && ariaLabel.trim()) return false;
    const ariaLabelledby = el.getAttribute('aria-labelledby');
    if (ariaLabelledby && doc.getElementById(ariaLabelledby)) return false;
    if (el.closest('label')) return false;
    if (el.getAttribute('title')?.trim()) return false;
    return true;
  });
  if (noLabel.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'input-missing-label',
      category: 'accessibility',
      severity: 'high',
      wcagLevel: 'A',
      title: `${noLabel.length} form control${noLabel.length > 1 ? 's' : ''} without an accessible label`,
      description: 'Form inputs (text, email, password, select, textarea) have no associated <label>, aria-label, or aria-labelledby. Screen readers announce them as unlabeled and voice-control users cannot target them by name.',
      evidence: noLabel.slice(0, 3).map((el) => `<${el.tagName.toLowerCase()} type="${el.getAttribute('type') || 'text'}" name="${el.getAttribute('name') || ''}">`).join('\n'),
      impact: 'Screen reader and voice-control users cannot identify or operate these fields. Mobile users get no clear prompt.',
      recommendation: 'Associate a <label> with each input using for/id, or provide an aria-label/aria-labelledby attribute.',
      fixSteps: [
        'Add a <label for="fieldId">Label text</label> next to each input.',
        'Ensure the input\u2019s id matches the label\u2019s for attribute.',
        'If a visible label is not possible, use aria-label="Field name".',
        'For grouped fields (radios/checkboxes), use <fieldset> and <legend>.',
      ],
      codeBefore: '<input type="email" name="email" id="email">',
      codeAfter: '<label for="email">Email address</label>\n<input type="email" name="email" id="email" autocomplete="email">',
      references: [{ label: 'WCAG 3.3.2 Labels or Instructions (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/labels-or-instructions.html' }, { label: 'WCAG 4.1.2 Name, Role, Value (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/name-role-value.html' }],
      confidence: 'high',
    });
  }

  // 6. Buttons without accessible text
  const buttons = Array.from(doc.querySelectorAll('button, [role="button"]'));
  const noTextButtons = buttons.filter((b) => {
    const text = (b.textContent || '').trim();
    if (text) return false;
    const ariaLabel = b.getAttribute('aria-label')?.trim();
    if (ariaLabel) return false;
    const ariaLabelledby = b.getAttribute('aria-labelledby');
    if (ariaLabelledby && doc.getElementById(ariaLabelledby)) return false;
    const title = b.getAttribute('title')?.trim();
    if (title) return false;
    const img = b.querySelector('img[alt]');
    if (img && img.getAttribute('alt')?.trim()) return false;
    return true;
  });
  if (noTextButtons.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'button-no-text',
      category: 'accessibility',
      severity: 'high',
      wcagLevel: 'A',
      title: `${noTextButtons.length} button${noTextButtons.length > 1 ? 's' : ''} without accessible text`,
      description: 'Buttons have no text, aria-label, or image alt text. They are announced as "button" with no name and cannot be activated by voice control.',
      impact: 'Screen reader and voice-control users cannot identify or use these buttons.',
      recommendation: 'Add visible text, an aria-label, or alt text on a contained image to every button.',
      fixSteps: [
        'Add text content inside the <button>, or an aria-label if the button is icon-only.',
        'If the button contains only an icon image, ensure the <img> has a descriptive alt.',
        'Avoid using <div> or <span> as buttons; use <button> for keyboard accessibility.',
      ],
      codeBefore: '<button><svg>...</svg></button>',
      codeAfter: '<button aria-label="Close dialog"><svg aria-hidden="true">...</svg></button>',
      references: [{ label: 'WCAG 4.1.2 Name, Role, Value', url: 'https://www.w3.org/WAI/WCAG21/Understanding/name-role-value.html' }],
      confidence: 'high',
    });
  }

  // 7. Links without discernible text
  const links = Array.from(doc.querySelectorAll('a[href]'));
  const noTextLinks = links.filter((a) => {
    const text = (a.textContent || '').trim();
    if (text) return false;
    const ariaLabel = a.getAttribute('aria-label')?.trim();
    if (ariaLabel) return false;
    const title = a.getAttribute('title')?.trim();
    if (title) return false;
    const img = a.querySelector('img[alt]');
    if (img && img.getAttribute('alt')?.trim()) return false;
    return true;
  });
  if (noTextLinks.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'link-no-text',
      category: 'accessibility',
      severity: 'high',
      wcagLevel: 'A',
      title: `${noTextLinks.length} link${noTextLinks.length > 1 ? 's' : ''} without accessible text`,
      description: 'Links contain no text, aria-label, title, or image alt. Screen readers announce only the URL, which is often meaningless.',
      impact: 'Screen reader users cannot determine where a link goes; keyboard users may not realize it is a link.',
      recommendation: 'Add descriptive link text, an aria-label, or alt text on a contained image.',
      fixSteps: [
        'Add visible text inside the <a> that describes the destination.',
        'For icon-only links (e.g. social icons), add aria-label="Link to Twitter profile".',
        'Avoid "click here" and "read more" \u2014 use descriptive text like "Read our pricing guide".',
      ],
      codeBefore: '<a href="/blog/post-1"></a>',
      codeAfter: '<a href="/blog/post-1">How we cut load time by 60%</a>',
      references: [{ label: 'WCAG 2.4.4 Link Purpose (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/link-purpose-in-context.html' }],
      confidence: 'high',
    });
  }

  // 8. Duplicate IDs
  const allIds = Array.from(doc.querySelectorAll('[id]')).map((el) => el.getAttribute('id') || '');
  const idCounts: Record<string, number> = {};
  for (const id of allIds) {
    if (id) idCounts[id] = (idCounts[id] || 0) + 1;
  }
  const dupIds = Object.entries(idCounts).filter(([, count]) => count > 1).slice(0, 5);
  if (dupIds.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'duplicate-id',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: `${dupIds.length} duplicate id attribute${dupIds.length > 1 ? 's' : ''}`,
      description: 'Multiple elements share the same id. IDs must be unique; assistive technologies and labels that reference an id may target the wrong element.',
      evidence: dupIds.map(([id, count]) => `id="${id}" appears ${count} times`).join('\n'),
      impact: 'Label associations, aria-labelledby references, and in-page links may point to the wrong element.',
      recommendation: 'Give each element a unique id, or use classes for shared styling.',
      fixSteps: [
        'Identify every element with a duplicated id.',
        'Change each to a unique id, or remove the id if it is only used for styling (use a class instead).',
        'Update any label[for] or aria-labelledby references that pointed to the old id.',
      ],
      codeBefore: '<div id="main">...</div>\n<div id="main">...</div>',
      codeAfter: '<div id="main">...</div>\n<div id="secondary">...</div>',
      references: [{ label: 'WCAG 4.1.1 Parsing (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/parsing.html' }],
      confidence: 'certain',
    });
  }

  // 9. Missing skip-to-main-content link
  const firstLink = doc.querySelector('a[href]');
  const hasSkipLink = firstLink && /skip|jump|main|#main/i.test(firstLink.getAttribute('href') || '');
  const hasMain = doc.querySelector('main, [role="main"]');
  if (!hasSkipLink && hasMain) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-skip-link',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: 'No "skip to main content" link found',
      description: 'The page has no skip link before the main content. Keyboard users must tab through the entire navigation on every page before reaching content.',
      impact: 'Keyboard and screen reader users waste time navigating repetitive content on every page view.',
      recommendation: 'Add a skip link as the first focusable element that jumps to the main content region.',
      fixSteps: [
        'Add <a href="#main" class="skip-link">Skip to main content</a> as the first element in <body>.',
        'Ensure the <main> element (or role="main" container) has id="main".',
        'Style the skip link to be visible on focus and visually hidden otherwise.',
      ],
      codeBefore: '<body>\n  <header>nav...</header>\n  <main>content</main>',
      codeAfter: '<body>\n  <a href="#main" class="skip-link">Skip to main content</a>\n  <header>nav...</header>\n  <main id="main">content</main>',
      references: [{ label: 'WCAG 2.4.1 Bypass Blocks (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/bypass-blocks.html' }],
      confidence: 'medium',
    });
  }

  // 10. Missing main landmark
  if (!hasMain) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-main-landmark',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: 'No main landmark on the page',
      description: 'The page has no <main> element or role="main". Screen reader users rely on landmarks to navigate quickly to the primary content.',
      impact: 'Screen reader users cannot jump to the main content and must navigate the entire page linearly.',
      recommendation: 'Wrap the primary content in a <main> element.',
      fixSteps: [
        'Identify the primary content area of the page.',
        'Wrap it in <main> (only one per page).',
        'Ensure there is exactly one <main> element and no other element with role="main".',
      ],
      codeBefore: '<div class="content">...</div>',
      codeAfter: '<main id="main">...</main>',
      references: [{ label: 'WCAG 1.3.1 Info and Relationships', url: 'https://www.w3.org/WAI/WCAG21/Understanding/info-and-relationships.html' }],
      confidence: 'high',
    });
  }

  // 11. Heading hierarchy
  const headings = Array.from(doc.querySelectorAll('h1, h2, h3, h4, h5, h6'));
  const h1s = headings.filter((h) => h.tagName === 'H1');
  if (h1s.length === 0 && headings.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-h1',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'A',
      title: 'No h1 heading on the page',
      description: 'The page has headings but no h1. The h1 is the primary heading and the main navigational anchor for screen reader users.',
      impact: 'Screen reader users lose the primary orientation point for the page\u2019s content structure.',
      recommendation: 'Add a single, descriptive h1 that describes the page\u2019s purpose.',
      fixSteps: [
        'Add one <h1> as the main page heading, typically matching the <title>.',
        'Ensure there is exactly one h1 per page.',
        'Nest subsequent headings (h2, h3) without skipping levels.',
      ],
      codeBefore: '<h2>About Us</h2>',
      codeAfter: '<h1>About Acme</h1>\n<h2>Our story</h2>',
      references: [{ label: 'WCAG 1.3.1 Info and Relationships', url: 'https://www.w3.org/WAI/WCAG21/Understanding/info-and-relationships.html' }],
      confidence: 'high',
    });
  }
  if (h1s.length > 1) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'multiple-h1',
      category: 'accessibility',
      severity: 'low',
      wcagLevel: 'A',
      title: `${h1s.length} h1 headings on the page (should be one)`,
      description: 'The page has multiple h1 elements. A page should have exactly one h1 that describes its primary topic.',
      impact: 'Multiple h1s dilute the heading hierarchy and confuse screen reader navigation.',
      recommendation: 'Keep a single h1 per page; demote the others to h2 or lower.',
      fixSteps: [
        'Keep the most descriptive h1 and change the others to h2 or the appropriate level.',
        'Verify the heading outline still reflects the content hierarchy.',
      ],
      codeBefore: '<h1>Welcome</h1>\n...\n<h1>Products</h1>',
      codeAfter: '<h1>Welcome to Acme</h1>\n<h2>Our products</h2>',
      references: [{ label: 'WCAG 1.3.1 Info and Relationships', url: 'https://www.w3.org/WAI/WCAG21/Understanding/info-and-relationships.html' }],
      confidence: 'high',
    });
  }
  // Skipped heading levels
  const headingLevels = headings.map((h) => parseInt(h.tagName[1], 10));
  for (let i = 1; i < headingLevels.length; i++) {
    if (headingLevels[i] > headingLevels[i - 1] + 1) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'skipped-heading-level',
        category: 'accessibility',
        severity: 'medium',
        wcagLevel: 'A',
        title: 'Heading levels are skipped in the document outline',
        description: `The heading hierarchy jumps from h${headingLevels[i - 1]} to h${headingLevels[i]}, skipping intermediate levels. Screen reader users navigate by heading level and expect a logical outline.`,
        impact: 'Screen reader users cannot understand the content structure and may miss sections.',
        recommendation: 'Use headings in order without skipping levels (h1 \u2192 h2 \u2192 h3).',
        fixSteps: [
          'Review the heading outline of the page.',
          'Change any skipped heading to the next sequential level.',
          'Use CSS to control visual size, not heading level.',
        ],
        codeBefore: '<h1>Welcome</h1>\n<h3>Our team</h3>',
        codeAfter: '<h1>Welcome</h1>\n<h2>Our team</h2>',
        references: [{ label: 'WCAG 1.3.1 Info and Relationships', url: 'https://www.w3.org/WAI/WCAG21/Understanding/info-and-relationships.html' }],
        confidence: 'high',
      });
      break;
    }
  }

  // 12. Missing viewport meta (mobile accessibility)
  const viewport = doc.querySelector('meta[name="viewport"]');
  if (!viewport) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-viewport',
      category: 'accessibility',
      severity: 'medium',
      wcagLevel: 'AA',
      title: 'Missing viewport meta tag',
      description: 'The page has no <meta name="viewport"> tag. Without it, mobile browsers render at a desktop width and scale down, making text tiny and requiring zoom to read.',
      impact: 'Mobile users cannot read or interact with the page comfortably; text is too small and controls are hard to tap.',
      recommendation: 'Add a viewport meta tag that sets the width to the device width.',
      fixSteps: [
        'Add <meta name="viewport" content="width=device-width, initial-scale=1"> to <head>.',
        'Avoid maximum-scale=1 or user-scalable=no, which prevent zooming (a WCAG AA failure).',
      ],
      codeBefore: '(no viewport meta)',
      codeAfter: '<meta name="viewport" content="width=device-width, initial-scale=1">',
      references: [{ label: 'WCAG 1.4.4 Resize Text (Level AA)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/resize-text.html' }],
      confidence: 'certain',
    });
  } else {
    const content = viewport.getAttribute('content') || '';
    if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1/i.test(content)) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'viewport-no-zoom',
        category: 'accessibility',
        severity: 'medium',
        wcagLevel: 'AA',
        title: 'Viewport disables user zoom',
        description: 'The viewport meta tag sets user-scalable=no or maximum-scale=1, preventing users from zooming in. This fails WCAG AA and harms low-vision users.',
        impact: 'Users with low vision cannot zoom to read text, a direct WCAG 1.4.4 failure.',
        recommendation: 'Remove user-scalable=no and maximum-scale restrictions from the viewport meta.',
        fixSteps: [
          'Remove user-scalable=no and maximum-scale=1 from the viewport content.',
          'Keep width=device-width, initial-scale=1 only.',
        ],
        codeBefore: '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">',
        codeAfter: '<meta name="viewport" content="width=device-width, initial-scale=1">',
        references: [{ label: 'WCAG 1.4.4 Resize Text (Level AA)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/resize-text.html' }],
        confidence: 'certain',
      });
    }
  }

  // 13. Tabindex > 0 (anti-pattern)
  const positiveTabindex = Array.from(doc.querySelectorAll('[tabindex]')).filter((el) => {
    const v = parseInt(el.getAttribute('tabindex') || '0', 10);
    return v > 0;
  });
  if (positiveTabindex.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'positive-tabindex',
      category: 'accessibility',
      severity: 'low',
      wcagLevel: 'A',
      title: `${positiveTabindex.length} element${positiveTabindex.length > 1 ? 's' : ''} with positive tabindex`,
      description: 'Elements use tabindex values greater than 0, which forces a custom tab order that diverges from the visual/DOM order. This confuses keyboard users.',
      impact: 'Keyboard users tab through the page in an unexpected order, missing or skipping content.',
      recommendation: 'Use tabindex="0" to make an element focusable in DOM order, or tabindex="-1" to make it programmatically focusable. Avoid positive values.',
      fixSteps: [
        'Remove positive tabindex values.',
        'Rearrange the DOM order to match the desired visual/keyboard order.',
        'Use tabindex="0" only for custom widgets that need to be in the tab order.',
      ],
      codeBefore: '<a href="/x" tabindex="3">X</a>\n<a href="/y" tabindex="1">Y</a>',
      codeAfter: '<a href="/y">Y</a>\n<a href="/x">X</a>  (DOM order matches visual order)',
      references: [{ label: 'WCAG 2.4.3 Focus Order (Level A)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/focus-order.html' }],
      confidence: 'high',
    });
  }

  // 14. Color contrast heuristic on inline styles (limited; flagged as info)
  // We can't fully compute contrast without rendering, so we flag very light grays.
  const lightTextEls = Array.from(doc.querySelectorAll('[style*="color: #"], [style*="color:#"]')).filter((el) => {
    const style = el.getAttribute('style') || '';
    return /#(eee|ddd|ccc|f[0-9a-f]f[0-9a-f]f[0-9a-f]|fff)/i.test(style) && !/background/i.test(style);
  });
  if (lightTextEls.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'low-contrast-heuristic',
      category: 'accessibility',
      severity: 'low',
      wcagLevel: 'AA',
      title: `${lightTextEls.length} element${lightTextEls.length > 1 ? 's' : ''} with potentially low-contrast text color`,
      description: 'Some elements use very light text colors (near-white or light gray) via inline styles. Without a sufficiently dark background, these may fail the 4.5:1 contrast ratio required by WCAG AA.',
      impact: 'Low-vision users and users in bright environments may be unable to read the text.',
      recommendation: 'Verify text/background contrast ratios with a contrast checker; ensure at least 4.5:1 for normal text.',
      fixSteps: [
        'Use a contrast checker (WebAIM Contrast Checker) on every text/background pair.',
        'Ensure normal text meets 4.5:1 and large text (18pt+) meets 3:1.',
        'Move colors to CSS classes so they can be audited and themed consistently.',
      ],
      codeBefore: '<p style="color: #ccc;">Terms apply</p>',
      codeAfter: '<p style="color: #4b5563;">Terms apply</p>  (gray-600, 7:1 on white)',
      references: [{ label: 'WCAG 1.4.3 Contrast (Minimum) (Level AA)', url: 'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html' }],
      confidence: 'medium',
    });
  }

  // 15. Autofocus on non-input
  const autofocus = doc.querySelector('[autofocus]');
  if (autofocus && !['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(autofocus.tagName)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'autofocus-misuse',
      category: 'accessibility',
      severity: 'low',
      wcagLevel: 'A',
      title: 'autofocus attribute on a non-form element',
      description: 'The autofocus attribute is used on an element that is not a form control. This can trap keyboard focus and disorient screen reader users.',
      impact: 'Screen reader users are moved to an unexpected location on page load.',
      recommendation: 'Only use autofocus on form inputs; remove it from other elements.',
      fixSteps: [
        'Remove autofocus from non-form elements.',
        'If focus management is needed, use JavaScript to focus a logical element after page load.',
      ],
      codeBefore: '<div autofocus>...</div>',
      codeAfter: '<input type="text" autofocus>',
      references: [{ label: 'WCAG 2.4.3 Focus Order', url: 'https://www.w3.org/WAI/WCAG21/Understanding/focus-order.html' }],
      confidence: 'high',
    });
  }

  return findings;
};
