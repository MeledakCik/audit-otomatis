# Sentinel-ID.net — Passive-Only Security Auditor

[[EN](https://img.shields.io/badge/lang-EN-blue.svg)](#) [[ID](https://img.shields.io/badge/lang-ID-red.svg)](./README_ID.md)

> ⚠️ For your own domain only. 100% passive, GET-only, no exploit, no payload.

**Live:** https://www.sentinel-id.net | Previously: kasyaf-cv.my.id

### What is this?

Most security audit tools are too aggressive. They fire payloads, submit forms, and trigger WAF. Sentinel-ID is designed for website owners who want to check basic security hygiene without risking their own site going down.

### Core Principles

**Same-Origin Only.** The scanner will never leave the target domain. External links are automatically skipped.

**GET Only.** No login attempts, no form submissions, no payload injection. POST endpoints found are only displayed for manual cURL testing.

**Request Budget.** Every scan is limited to a maximum of 100 requests to stay respectful.

**Cloudflare Aware.** If a Cloudflare Challenge is detected, the scan stops gracefully and shows instructions instead of trying to bypass.

### New Architecture v2

After refactor, the lib folder is now modular:

**discovery** - Responsible for site exploration. Runs a BFS crawl up to 50 pages to map internal pages, JS files, and endpoints. Includes well-known files check (robots.txt, sitemap.xml).

**parsers** - Responsible for unpacking JavaScript. Hidden endpoints and API paths are often found inside JS files that are not visible in HTML.

**fingerprint** - The identification layer. It scans for leaked secrets like API keys or tokens inside JS, and detects library versions to check against known CVEs.

**vuln** - New module from trout-with-passive-audit. It does not exploit, it only detects POTENTIAL patterns such as open-redirect patterns, IDOR patterns in URL parameters, or dangerous DOM sinks (innerHTML, location.search) in JavaScript. All findings are marked as POTENTIAL and require manual review.

**fuzzer** - Module for passive parameter discovery. It only guesses common parameter names without sending any malicious payload to find hidden API params.

**scan-runner** - The main brain. It orchestrates the order: discovery -> parsers -> fingerprint -> vuln -> fuzzer. All findings are collected via addFinding store.

### Scan Logic Flow

Start from the main URL, discovery builds the site map. The map is passed to parsers to extract JS endpoints. Once links and files are collected, fingerprint checks for secrets and libraries. Finally, vuln and fuzzer look for potential patterns. All results are stored in scan-store and displayed as Findings Table, Graph View (14 nodes / 13 edges), and QC Score, and can be exported to Markdown Pentest Report.

### Current Scan Result Example (kasyaf-cv.my.id)

- 1 URL Crawled, 11 JS Scanned, 29 Requests
- 0 CRITICAL, 0 HIGH, 6 MEDIUM (expected Next.js chunks false-positive), 4 LOW, 2 INFO
- Note: MEDIUM findings on `/_next/static/chunks/*.js` with `innerHTML` pattern are expected from React/Next.js internal renderer and flagged as POTENTIAL only by regex pattern-matching, not confirmed exploitability.

### Ethical Limitation

This tool is intentionally not usable for aggressive testing of other people's websites. There is no WAF bypass, no brute force, no exploit. Make sure you own the domain you are scanning.

---
Also available in: [Bahasa Indonesia](./README_ID.md)