# CL.0 Victim Scan — Design

Date: 2026-07-22
Status: Approved (pending spec review)

## Goal

Add a new scan to desynchronize that **applies the same vectors as `ImplicitZeroScan`**
(the CL.0 scan) but detects desync using the **victim-based detection logic ported from
`../validator2/`'s `VictimScan`**, rather than ImplicitZero's self-poisoning check.

The two scans are complementary:

- **`ImplicitZeroScan`** detects **self-poisoning**: it smuggles a gadget request in the
  body and checks whether *its own* follow-up response was poisoned (`gadget.worked(resp)`).
- **New `VictimZeroScan`** detects **victim inconsistency**: it interleaves *attack* requests
  with clean *victim* (baseline) requests and watches whether the **victim** requests come
  back with inconsistent status codes — evidence the attack poisoned a shared connection that
  a victim later reused. It additionally reports **canary reflections** (a canary from an
  attack's smuggled body appearing in a victim/subsequent response).

"Same vectors" means: the same permutation/technique set (`sharedPermutations` +
`clPermutations` + `h2Permutations` + `h1Permutations`) applied via
`DesyncBox.applyDesync(req, "Content-Length", technique)`, using the same request-setup path
as ImplicitZero. The only construction difference is that the smuggled body is a
canary-bearing `ProbePayload` instead of ImplicitZero's per-host gadget.

## Scope

**Ported from validator2 (full detection port):** Phase 1 victim check, Phase 2
erratic-domain detection, Phase 3 followup-payload third-code hunt, Phase 4 reproduction
retries, the correlation-check gate, severity tiers, and **canary reflection**.

**Dropped from validator2:** `DatabaseService` (→ in-memory per-host state), the permutation
pipeline, `ValidationService`, and `ProbePayloads`' canary-injection/body-padding internals
(a slim payload list is kept).

## Architecture (Approach A: Montoya-core engine + thin SmuggleScanBox shell)

Chosen over (B) a single self-contained scan class and (C) porting validator2's
`BaseScanStrategy` hierarchy wholesale. A keeps the desynchronize-specific glue small and the
detection engine cohesive, mirroring validator2's own strategy/framework split.

### Files

```
NEW  src/burp/VictimZeroScan.java    extends SmuggleScanBox — vector enumeration,
                                     attack/victim construction, reporting
NEW  src/burp/VictimDetector.java    Montoya detection engine (the ported phases)
NEW  src/burp/ProbePayloads.java     slim static payload list (id + body + supports0CL)
NEW  src/burp/CanaryUtils.java       ported ~verbatim (canary prefix `wrtzllsk`)
NEW  src/burp/ReflectionResult.java  ported ~verbatim (reflection finding value object)
NEW  src/burp/CorrelationCheck.java  ported verbatim (5 cycles, gap, repro threshold 3)
EDIT src/burp/BurpExtender.java      register `new VictimZeroScan("CL.0 victim");`
                                     immediately after `new ImplicitZeroScan("CL.0");`
```

### Reused from the existing desynchronize / bulkScan-all.jar (no port needed)

- `MontoyaRequestResponse` (jar) — response wrapper with `.status()` / `.response()`.
- `Utilities.buildMontoyaReq(byte[], IHttpService)` — the `byte[]` → Montoya `HttpRequest` bridge.
- `Utilities.montoyaApi.http().sendRequests(list, HttpMode)` — the transport (per user's choice).
- `PermutationResult.isWAF(MontoyaRequestResponse)` — WAF-skip filter.
- `DesyncBox.applyDesync(...)` — the CL.0 desync vectors.
- The `Report` class → `AuditIssueSeverity` — severity-carrying reporting.
- `ContaminationTest.java` is an existing precedent of a victim-style detector using Montoya types.

## Component design

### VictimZeroScan (scan shell)

- Constructor imports the **same** settings as `ImplicitZeroScan` so `SmuggleScanBox.doScan`
  enumerates the same vectors and calls `doConfiguredScan(baseReq, service, {technique})` once
  per technique. Also registers the victim-specific settings (below).
- `doConfiguredScan`:
  1. Reproduce ImplicitZero's construction: `addCacheBuster` → `setupRequest` → HTTP/1
     downgrade + `Connection:`→`X-Connection:` handling → `forceHTTP1`/`forceHTTP2` from
     `h1Permutations`/`h2Permutations` membership (incl. the h2-availability probe) → the
     skip-if-no-effect guard (`applyDesync(...) == null → return false`).
  2. Smuggle body = a `ProbePayload` body with a canary injected into its request path/query
     (`CanaryUtils.injectCanaryIntoPayload`), then `fixContentLength`.
  3. `attackBytes = DesyncBox.applyDesync(attack, "Content-Length", technique)`.
  4. `victimBytes` = clean, cache-busted `baseReq` (no smuggle, no desync).
  5. Convert both via `Utilities.buildMontoyaReq(...)`; tag HTTP/2 vectors for `HttpMode.AUTO`,
     others for `HttpMode.HTTP_1`.
  6. Delegate to `VictimDetector.validate(...)`. Return `true` iff a finding was reported (so
     `SmuggleScanBox` records the host/permutation as done, matching ImplicitZero).

**Canary technique-id:** the canary encodes an int technique id; desynchronize techniques are
permutation-name strings, so map each permutation to a **stable int = its index in a canonical
ordered permutation list**. This makes cross-technique reflection detection meaningful within a
host's scan session.

### VictimDetector (detection engine, Montoya types)

`validate(attackReq, victimReq, service, techniqueId, payload)` runs the full pipeline:

- **Phase 1 — victim check (canary variant).** Send `A,V,A,V` then `A,V,A,V,V` via
  `sendRequests`. Each attack carries a unique canary. Collect **victim** status codes only
  (normalize → drop boring → bucket). Check *all* responses for canary reflections.
  Inconsistency = **≥2 distinct non-boring bucketed victim codes**. No inconsistency → fail
  (any reflections still reported).
- **Phase 2 — erratic-domain check.** Sleep, flush burst (9 baselines), check burst (20
  baselines). If the differing code appears attack-free, or baselines are themselves
  inconsistent → mark host erratic (in-memory) and bail.
- **Phase 3 — followup payloads.** Iterate the `ProbePayloads` list (sleep between each),
  victim-check per payload. A victim code **not** in the Phase-1 set and **≠** the Phase-2
  baseline = **third code → Confirmed HIGH**. Track unique *attack* codes for the MEDIUM tier.
- **Phase 4 — reproduction.** If no third code, retry Phase 1 up to N times; never reproduced
  → drop as a server blip. Suppress "Unconfirmed" if Phase 1 included a bucketed 5xx-origin code.
- **Correlation gate** (toggleable). 5 cycles of attack-run vs attack-free control-run:
  dirty control → **DISCARD**; ≥3 dirty attack runs → **VERIFIED**; else **UNREPLICABLE →
  demote to LOW**.

**Severity tiers:** Confirmed `HIGH` / Attack-variation `MEDIUM` / Unconfirmed `LOW`.
Reflections reported independently: victim/cross-technique `HIGH`, attack `MEDIUM`.

### Noise filtering & per-host state

- Ported helpers: `normalizeStatusCode` (handles 100-continue nesting, `code*10`),
  `isBoringStatusCode` (0/429/100), `bucketStatusCode` (502/503/504/520-530 → synthetic 599).
  WAF responses skipped via `PermutationResult.isWAF`.
- **State is in-memory on the scan instance** (replacing the DB): `erraticHosts` (Set),
  `reflectionCountByHost` (cap 2/domain), plus `SmuggleScanBox`'s existing `hostsToSkip` for
  per-permutation dedup.

### ProbePayloads (slim)

Static list of `{id, body, supports0CL}` smuggled-request prefixes, ported from validator2
(e.g. `TRACE /asdf HTTP/1.1\r\nA: B` (default), `GET /favicon.ico HTTP/1.1`,
`GET /0-9 HTTP/0.9`, `CONNECT ...psres.net:443`, ~13 total). No canary injection or padding
built in — canary injection is applied externally by the shell/detector via `CanaryUtils`.

### Reporting

Via the `Report` class → `AuditIssueSeverity` (map internal `HIGH/MEDIUM/LOW`). Titles/details
mirror validator2's wording, dropping DB payload-IDs and keeping the permutation name + observed
status codes. Evidence = Montoya `HttpRequestResponse` list: attack + two distinct victims
(+ third-code responses; + reflection evidence for reflection findings).

## Settings (registered in the VictimZeroScan constructor)

| Setting | Default | Notes |
|---|---|---|
| `victim: phase delay ms` | 5000 | inter-phase sleep |
| `victim: followup delay ms` | 5000 | between Phase-3 payloads |
| `victim: phase4 retries` | 5 | reproduction attempts |
| `victim: enable correlation check` | true | toggles the correlation gate |
| `victim: correlation gap ms` | 5000 | gap inside a correlation cycle |

Defaults reproduce validator2 behavior **except** the sleeps, dropped from ~10s to 5s per the
user. Note: validator2's correlation gap was originally 12s ("past the ~11s attack-poison
clearing time"); it is defaulted to 5s here but left configurable in case 5s proves too short.

## Testing & verification

- **No unit-test harness** (matches existing desynchronize style). The ported pure-logic
  classes (`CanaryUtils`, `CorrelationCheck`, status helpers, the ≥2-distinct-codes decision)
  are kept pure/self-contained for clarity, but not covered by automated tests.
- **End-to-end lab verification** against a known-vulnerable target is the acceptance check,
  and also where the byte-accuracy risk (below) is confirmed.

## Risks / open integration points (resolve during implementation)

1. **Byte-accuracy through Montoya `sendRequests` (HTTP_1 mode):** confirm the desync'd attack
   bytes (odd `Content-Length`/`Transfer-Encoding`, whitespace tricks) are transmitted verbatim
   and `Content-Length` is not silently re-normalized. validator2 sends desync'd requests this
   way, so likely fine — verify against a lab target early.
2. **Jar `MontoyaRequestResponse` API surface:** whether it exposes `effectiveStatusCode()`
   (used by `normalizeStatusCode`) or only `.status()`; if the former is absent, derive
   normalization from `.response()`.
3. **`Severity` enum:** whether validator2's `Severity` exists in desynchronize or the ported
   `ReflectionResult` should map straight to `AuditIssueSeverity`.
4. **Batch send:** whether `Scan` exposes a batch send helper or the detector calls
   `Utilities.montoyaApi.http().sendRequests(...)` directly.

## Non-goals

- No changes to `ImplicitZeroScan` (this scan accompanies it).
- No database, canary-DB dedup, permutation pipeline, or `ValidationService` port.
- No new unit-test framework.
