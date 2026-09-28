# XML External Entity Injection (XXE)
CWE-611 · OWASP A05:2021 · ASVS V5.5.2

## What it is
An XML parser resolves external entities or external DTDs from attacker-controlled XML, letting an attacker read local files, reach internal network endpoints (SSRF), or cause denial of service.

## Where to look
- Java: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SAXReader` without disabling DTDs/external entities.
- Python: `lxml.etree.parse`/`fromstring` with `resolve_entities=True`, `xml.dom.minidom`/`xml.sax` (external entities enabled by default in older configurations), `xmlrpc` libraries.
- PHP: `libxml_disable_entity_loader(false)` (or omitted on old PHP versions), `simplexml_load_string`, `DOMDocument->loadXML` without safe flags.
- Ruby: `Nokogiri::XML(input)` with `NOENT`/`DTDLOAD` options enabled, `REXML::Document.new` (older versions).
- Go: `encoding/xml` (safe by default, no external entity support) — rarely vulnerable.
- Also: any SOAP endpoint, file-upload handler accepting `.xml`, `.docx`/`.xlsx`/`.svg` (which contain embedded XML), or RSS/Atom parsers.

## How to confirm
Show that untrusted XML reaches a parser configured (or defaulted, for older library versions) to resolve external entities or external DTDs, with no explicit hardening call in between.

## False-positive traps
- Modern defaults are often already safe: Go's `encoding/xml` never resolves external entities; recent `lxml` disables them by default; Nokogiri is safe by default unless `NOENT`/`DTDLOAD` are explicitly set. `defusedxml` is a third-party package (not part of the Python 3 standard library) — its use, not Python 3 itself, is what makes parsing safe.
- JSON-based APIs and non-XML formats are not affected even if they historically wrapped XML.
- The reliable Java control is the `disallow-doctype-decl` feature set to `true` on the factory — `FEATURE_SECURE_PROCESSING` alone does not disable external entities/DTDs. `XMLConstants.ACCESS_EXTERNAL_DTD = ""` also needs `ACCESS_EXTERNAL_SCHEMA` set to be effective; setting only one leaves the other vector open.
- In PHP, `LIBXML_NOENT` explicitly enables entity substitution — flag it as a vulnerable configuration, not a hardening flag.
- Schema validation alone does not disable external entity resolution — check for the specific hardening flags, not just "validation is used."

## Safe patterns
```python
import defusedxml.ElementTree as ET
tree = ET.fromstring(untrusted_xml)  # external entities and DTDs rejected
```

## Fix guidance
Disable DTD processing and external entity resolution at the parser/factory level (or use a hardened library like `defusedxml`), reject documents containing a DOCTYPE where none is expected, and run the parser as a low-privilege process with no network egress if untrusted XML must be processed.

## Severity guide
- Impact `high`: local file disclosure of secrets, or SSRF reaching internal services.
- Impact `medium`: denial of service (entity expansion) or limited file disclosure.
- Impact `low`: parser reachable only with pre-validated, low-value XML.
- Exploitability: `high` when unauthenticated or ordinary users can submit XML; `medium` when a specific role is needed; `low` for admin-only input.
