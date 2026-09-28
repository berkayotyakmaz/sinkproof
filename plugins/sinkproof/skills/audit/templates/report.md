# Code Audit Report — {{project_name}}

- **Date:** {{date}}
- **Scope:** {{scope}} <!-- full project | path <p> | changes since <ref> -->
- **Tool:** sinkproof {{version}}

## 1. Summary

**Security** (SEC, LOG, DEP)

| Critical | High | Medium | Low |
|---|---|---|---|
| {{sec_critical}} | {{sec_high}} | {{sec_medium}} | {{sec_low}} |

**Code quality** (ARC, PRI)

| Critical | High | Medium | Low |
|---|---|---|---|
| {{quality_critical}} | {{quality_high}} | {{quality_medium}} | {{quality_low}} |

{{summary}} <!-- 2–4 sentences: the most important risks and where they are -->

### Fix first

<!-- Up to 5 items, most important first. One item per distinct fix (a root-cause group counts once). Security before code quality. -->
1. **{{fix_title}}** — `{{file}}` ({{symbol}}) → closes {{ids}}

## 2. Scope

- **Files:** {{files_reviewed}} reviewed + {{files_skipped}} skipped = {{files_total}} total <!-- reviewed + skipped = total; if they differ, say which files are unaccounted for -->
- **Skipped:** {{skipped}} <!-- groups with reasons and file counts, e.g. "vendor/ (third-party code, 42 files)" -->
- **Stack:** {{stack}}
- **CVE data source:** {{cve_source}} <!-- e.g. "npm audit", "OSV.dev", "not performed: <reason>" -->
- **Refuted during verification:** {{n_refuted}}
- **Incomplete phases:** {{incomplete}} <!-- "none", or each failed phase with its error -->
- **Dimensions not reviewed:** {{dimensions_not_reviewed}} <!-- "none", or e.g. "Architecture, Code principles (not selected)" -->
- **Focus:** {{focus}} <!-- "none", or the selected focus areas; files outside them were reviewed less or skipped -->


## 3. Chains

Not analysed in this version.

## 4. Security findings

<!-- SEC, LOG and DEP findings, critical → low. Repeat this block per finding: -->

### {{id}} · {{severity}} · {{title}}

- **Where:** `{{file}}:{{line}}` (`{{symbol}}`)
- **Classification:** {{cwe}} · {{owasp}}
- **Verdict:** {{verdict}} — {{verdict_reason}}
- **Evidence:**
  1. {{evidence_item}}
- **Scenario:** {{scenario}}
- **Fix:** {{fix}}
- **Same fix closes:** {{related_ids}} <!-- omit the line when the finding has no root-cause group -->

## 5. Code quality & architecture

<!-- ARC and PRI findings, same block without Classification and Scenario (keep "Same fix closes"). -->

## 6. Disclaimer

This report was produced by an automated, AI-assisted review. It can miss issues and it can be wrong. It is not a substitute for a professional penetration test or a human security review.

## 7. Fix log

<!-- Filled during the fix phase, one line per finding: ID · change made · tests run and result · re-check verdict. "No fixes applied." if none. -->
