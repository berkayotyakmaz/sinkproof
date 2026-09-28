# Server-Side Request Forgery (SSRF)
CWE-918 · OWASP A10:2021 · ASVS V12.6.1

## What it is
The server makes an outbound request to a URL or host that the user controls, letting an attacker reach internal services, cloud metadata endpoints or other hosts from inside the network.

## Where to look
- Sinks: `fetch`, `axios`, `got`, `request`, `http.get`, `requests.get`, `urllib`, `httpx`, `curl_exec`, `file_get_contents(url)`, `HttpClient`, `RestTemplate`, headless browsers and PDF renderers loading URLs, image/URL "preview" and import features, webhook target URLs, XML parsers fetching external entities.
- Sources: body/query fields named `url`, `link`, `callback`, `webhook`, `avatarUrl`, `imageUrl`, `feed`; also host names or ports built into URLs.

## How to confirm
Show user input controlling scheme, host or port of the request, and that there is no allow-list of destination hosts. A deny-list of `localhost` or `127.0.0.1` alone does not count as protection.

## False-positive traps
- A fixed host with a user-controlled path (`https://api.example.com/users/${id}`) is not SSRF on its own (it may be path injection).
- An allow-list checked on the parsed hostname, with redirects disabled or re-checked, is safe.
- Checks done on the string before DNS resolution can be bypassed (DNS rebinding, `0x7f.1`, `[::1]`, redirects) — still report, with exploitability `medium`.

## Safe patterns
```js
const ALLOWED = new Set(["images.example.com"]);
const url = new URL(req.body.url);
if (url.protocol !== "https:" || !ALLOWED.has(url.hostname)) return res.sendStatus(400);
const response = await fetch(url, { redirect: "error" });
```

## Fix guidance
Allow-list destination hosts and schemes; disable redirects or re-validate each hop; resolve DNS and block private, loopback and link-local ranges (including `169.254.169.254`) when an allow-list is impossible; send the request from an isolated egress proxy.

## Severity guide
- Impact `high`: cloud metadata endpoints or internal admin services are reachable and the response is returned to the user.
- Impact `medium`: the internal network is reachable but the response is not returned (blind SSRF).
- Impact `low`: only port scanning or very limited internal reach.
- Exploitability: `high` for any anonymous or logged-in user; `medium` when a specific role is needed or a deny-list must be bypassed first.
