# Cross-Site Scripting (XSS)
CWE-79 · OWASP A03:2021 · ASVS V5.3.3

## What it is
Untrusted data is placed into HTML, JavaScript or a URL in a page without context-appropriate encoding, so an attacker's script runs in a victim's browser.

## Where to look
- Sources: request params, stored user content (comments, names, bios), headers, URL fragments read by client code, third-party API data, LLM output.
- Server sinks: string-built HTML (``res.send(`<h1>${q}</h1>`)``), template "raw" output (`{{{ }}}`, `|safe`, `mark_safe`, `{!! !!}`, `<%- %>`, `html_safe`, `Html.Raw`).
- Client sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `href`/`src` set from data (`javascript:` URLs), `eval`, `new Function`, `setTimeout(string)`.

## How to confirm
Show the data path from source to sink and that no encoder, sanitizer (e.g. DOMPurify) or auto-escaping template sits between them. For stored XSS, show both the write and the render.

## False-positive traps
- Auto-escaping templates (React JSX text, Jinja2 with autoescape, Django templates, Blade `{{ }}`, ERB `<%= %>`) are safe unless the raw form above is used.
- `textContent`, `innerText`, `setAttribute` on non-URL attributes are safe.
- A JSON API response with `Content-Type: application/json` is not XSS by itself.
- Sanitizing for HTML does not make data safe inside a `<script>` block, an event handler attribute or a URL.

## Safe patterns
```js
const escape = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
res.send(`<h1>Results for ${escape(q)}</h1>`);
```

## Fix guidance
Use the framework's auto-escaping output; encode for the exact context (HTML body, attribute, JS string, URL); sanitize with DOMPurify when HTML must be allowed; validate URL schemes (`http`, `https` only). Add a Content-Security-Policy as defense in depth.

## Severity guide
- Impact `high`: stored XSS seen by admins or by all users of an authenticated app, or reflected XSS on authenticated pages without a CSP.
- Impact `medium`: stored XSS in less privileged views, or pages with little sensitive functionality.
- Impact `low`: blocked in practice by a strict Content-Security-Policy.
- Exploitability: `high` for stored XSS any user can plant; `medium` for reflected XSS (the victim must open a crafted link) or when a specific role is needed.
