# CL.0 Victim Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `VictimZeroScan` to desynchronize that applies ImplicitZeroScan's CL.0 vectors but detects desync via validator2's victim-inconsistency + canary-reflection logic.

**Architecture:** A thin `VictimZeroScan extends SmuggleScanBox` (vector enumeration + attack/victim construction + reporting) delegates to a Montoya-based `VictimDetector` engine that ports validator2's `VictimScan` phases (Phase 1 victim check with canaries → Phase 2 erratic-domain → Phase 3 third-code followups → Phase 4 reproduction → correlation gate). Supporting ports: `ProbePayloads`, `CanaryUtils`, `ReflectionResult`, `CorrelationCheck`. Transport is `Utilities.montoyaApi.http().sendRequests(...)`; per-host state is in-memory (no DB).

**Tech Stack:** Java 21, Burp Montoya API (`burp.api.montoya.*`) + legacy Extender API, `bulkScan-all.jar` (provides `MontoyaRequestResponse`, `Utilities`, `Scan`, `DesyncBox`, `PermutationResult.isWAF`), Gradle.

## Global Constraints

- Package: `burp` for every new class (matches existing `src/burp/*.java`).
- Java source/target: 21.
- No new dependencies; no `src/test` sourceSet (no unit tests — lab verification only).
- Do **not** modify `ImplicitZeroScan.java` (this scan accompanies it).
- Build command (the only per-task verification): `./gradlew fatJar` — must complete with `BUILD SUCCESSFUL`.
- Reference source for ports: `../validator2/src/main/java/burp/` (sibling checkout).
- Reporting severity: use `burp.api.montoya.scanner.audit.issues.AuditIssueSeverity` directly (there is no separate `Severity` enum in desynchronize; do not port validator2's).
- Commit after every task with a `feat:`/`chore:` message; work on branch `victim-scan`.

---

### Task 1: Integration reconnaissance (lock down jar/API seams)

Resolve the open integration points before writing dependent code. No product code in this task — it records exact signatures the later tasks assume. Capture findings inline in the plan file (edit the "Consumes" notes) or in commit message.

**Files:**
- Inspect only: `bulkScan-all.jar`, `../validator2/src/main/java/burp/MontoyaRequestResponse.java`, `../validator2/src/main/java/burp/HttpRequestUtils.java`.

- [ ] **Step 1: Inspect `MontoyaRequestResponse` API surface**

Run:
```bash
cd /Users/james.kettle/work/desynchronize
javap -classpath bulkScan-all.jar burp.MontoyaRequestResponse
```
Record: does it have `short status()`, `int effectiveStatusCode()`, `burp.api.montoya.http.message.HttpResponse response()`, `HttpRequestResponse` accessor, and a public constructor `MontoyaRequestResponse(HttpRequestResponse)`? Does it implement `HttpRequestResponse`?

Expected/assumptions used by later tasks (adjust code if `javap` disagrees):
- `short status()` exists (confirmed via `ContaminationTest`/`EarlyBodyPair` usage).
- If `int effectiveStatusCode()` is **absent**, `VictimDetector.normalizeStatusCode` will take a `MontoyaRequestResponse` and compute the base code from `status()` (no ×10 nesting handling).
- If a public `MontoyaRequestResponse(HttpRequestResponse)` constructor exists, wrap `sendRequests` results with it; else use `HttpRequestResponse` directly and read `.response().statusCode()`.

- [ ] **Step 2: Confirm evidence type accepted by `Report`/organiser**

Run:
```bash
javap -classpath bulkScan-all.jar burp.MontoyaRequestResponse | grep -i "HttpRequestResponse"
grep -n "reportToOrganiser" ../validator2/src/main/java/burp/*.java src/burp/*.java
```
Record whether `MontoyaRequestResponse` **implements** `burp.api.montoya.http.message.HttpRequestResponse` (then it can be passed straight to `new Report(...)` varargs and `siteMap().add`). If not, record the accessor that returns the underlying `HttpRequestResponse`.

- [ ] **Step 3: Confirm `sendRequests` + `buildMontoyaReq` signatures**

Run:
```bash
javap -classpath bulkScan-all.jar burp.Utilities | grep -i "buildMontoyaReq\|montoyaApi"
javap -classpath bulkScan-all.jar burp.api.montoya.http.Http | grep -i "sendRequests"
javap -classpath bulkScan-all.jar burp.api.montoya.http.HttpMode
```
Expected: `Utilities.buildMontoyaReq(byte[], IHttpService) -> HttpRequest`; `Http.sendRequests(List<HttpRequest>, HttpMode) -> List<HttpRequestResponse>`; `HttpMode` has `HTTP_1` and `AUTO`.

- [ ] **Step 4: Commit the recon notes**

```bash
git add docs/superpowers/plans/2026-07-22-victim-scan.md
git commit -m "chore: record victim-scan integration recon findings"
```

**Interfaces:**
- Produces: confirmed signatures for `MontoyaRequestResponse` (status/effectiveStatusCode/response/constructor/implements-HttpRequestResponse), `Utilities.buildMontoyaReq`, `Http.sendRequests`, `HttpMode`. All later tasks consume these.

---

### Task 2: `ProbePayloads` (slim payload list)

**Files:**
- Create: `src/burp/ProbePayloads.java`

**Interfaces:**
- Produces:
  - `ProbePayloads.Payload` with `int getId()`, `String getBody()`, `boolean supports0CL()`.
  - `static List<Payload> getAllPayloads()`, `static Payload getDefaultPayload()`, `static Payload getRandomPayload()`.

- [ ] **Step 1: Write `ProbePayloads.java`**

```java
package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Slim port of validator2's ProbePayloads: the set of smuggled-request prefixes
 * used as the CL.0 attack body (and as Phase-3 followup payloads). Canary
 * injection is applied externally via CanaryUtils, so it is NOT built in here.
 */
public class ProbePayloads {

    public static class Payload {
        private final int id;
        private final String body;
        private final boolean isDefault;
        private final boolean supports0CL;

        public Payload(int id, String body, boolean isDefault, boolean supports0CL) {
            this.id = id;
            this.body = body;
            this.isDefault = isDefault;
            this.supports0CL = supports0CL;
        }

        public Payload(int id, String body, boolean isDefault) {
            this(id, body, isDefault, true);
        }

        public int getId() { return id; }
        public String getBody() { return body; }
        public boolean isDefault() { return isDefault; }
        public boolean supports0CL() { return supports0CL; }
    }

    private static final Random random = new Random();
    private static final List<Payload> PAYLOADS = new ArrayList<>();

    static {
        PAYLOADS.add(new Payload(0, "TRACE /asdf HTTP/1.1\r\nA: B", true));
        PAYLOADS.add(new Payload(1, "X", false, false));
        PAYLOADS.add(new Payload(2, "GET / HTTP/1.1\r\nX: Y", false));
        PAYLOADS.add(new Payload(3, "GET /favicon.ico HTTP/1.1\r\nX: Y", false));
        PAYLOADS.add(new Payload(4, "GET /asdf HTTP/1.1\r\nX: Y", false));
        PAYLOADS.add(new Payload(5, "GET /0-9 HTTP/0.9\r\nX: Y", false));
        PAYLOADS.add(new Payload(6, "GET /invalid HTTP/1.2\r\nX: Y", false));
        PAYLOADS.add(new Payload(7, "TRACE / HTTP/1.1\r\nX: Y", false));
        PAYLOADS.add(new Payload(8, "GET /%2f HTTP/1.1\r\nX: Y", false));
        PAYLOADS.add(new Payload(9, "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nx=1", false, false));
        PAYLOADS.add(new Payload(10, "GET /?rqp HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n", false, false));
        PAYLOADS.add(new Payload(11, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nX: Y", false, false));
        PAYLOADS.add(new Payload(12, "CONNECT n1p4fbvwvalvyvljgp8a3zts4jaay5mu.psres.net:443\r\nHost: ob35pc5x5bvw8wvkqqibd03tekkb85wu.psres.net\r\n\r\n", false, false));
    }

    public static List<Payload> getAllPayloads() {
        return new ArrayList<>(PAYLOADS);
    }

    public static Payload getDefaultPayload() {
        return PAYLOADS.stream().filter(Payload::isDefault).findFirst().orElse(PAYLOADS.get(0));
    }

    public static Payload getRandomPayload() {
        return PAYLOADS.get(random.nextInt(PAYLOADS.size()));
    }
}
```

- [ ] **Step 2: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add src/burp/ProbePayloads.java
git commit -m "feat: add slim ProbePayloads list for victim scan"
```

---

### Task 3: `CorrelationCheck` (verbatim port)

**Files:**
- Create: `src/burp/CorrelationCheck.java`

**Interfaces:**
- Produces: `CorrelationCheck.defaults()`, `Result run(int baselineCode, IntFunction<Set<Integer>> attackRun, IntFunction<Set<Integer>> controlRun) throws InterruptedException`, `enum Verdict { VERIFIED, UNREPLICABLE, DISCARD }`, `record Result(Verdict verdict, int attackDirtyCycles, int cyclesRun)`.

- [ ] **Step 1: Write `CorrelationCheck.java`**

Port of `../validator2/src/main/java/burp/CorrelationCheck.java`. Only adaptation: replace `TestAwareSleep.sleep(gapMs)` with `Thread.sleep(gapMs)` and drop the `import burp.test.TestAwareSleep;`.

```java
package burp;

import java.util.Set;
import java.util.function.IntFunction;

/**
 * Pre-report gate that distinguishes a real desync from a time-correlated confound
 * (a rebooting / flaky backend). Runs N cycles of: attack run -> wait gapMs -> attack-free
 * control run. A run is "dirty" if it produced a non-boring victim status code != the
 * Phase-2 baseline code B.
 *
 * - Any dirty control -> DISCARD (early exit).
 * - 0 dirty controls and >= reproThreshold dirty attack runs -> VERIFIED.
 * - Otherwise -> UNREPLICABLE.
 */
public final class CorrelationCheck {

    public enum Verdict { VERIFIED, UNREPLICABLE, DISCARD }

    public record Result(Verdict verdict, int attackDirtyCycles, int cyclesRun) {}

    private final int cycles;
    private final long gapMs;
    private final int reproThreshold;

    public CorrelationCheck(int cycles, long gapMs, int reproThreshold) {
        this.cycles = cycles;
        this.gapMs = gapMs;
        this.reproThreshold = reproThreshold;
    }

    /** Production config: N=5 cycles, gap from settings, reproduction threshold 3. */
    public static CorrelationCheck defaults(long gapMs) {
        return new CorrelationCheck(5, gapMs, 3);
    }

    private static boolean dirty(Set<Integer> observedCodes, int baselineCode) {
        for (int code : observedCodes) {
            if (code != baselineCode) {
                return true;
            }
        }
        return false;
    }

    public Result run(int baselineCode,
                      IntFunction<Set<Integer>> attackRun,
                      IntFunction<Set<Integer>> controlRun) throws InterruptedException {
        int attackDirtyCycles = 0;
        for (int cycle = 1; cycle <= cycles; cycle++) {
            if (dirty(attackRun.apply(cycle), baselineCode)) {
                attackDirtyCycles++;
            }
            Thread.sleep(gapMs);
            if (dirty(controlRun.apply(cycle), baselineCode)) {
                return new Result(Verdict.DISCARD, attackDirtyCycles, cycle);
            }
        }
        Verdict verdict = attackDirtyCycles >= reproThreshold
            ? Verdict.VERIFIED : Verdict.UNREPLICABLE;
        return new Result(verdict, attackDirtyCycles, cycles);
    }
}
```

Note the one signature change vs validator2: `defaults()` becomes `defaults(long gapMs)` so the gap is driven by the `victim: correlation gap ms` setting.

- [ ] **Step 2: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add src/burp/CorrelationCheck.java
git commit -m "feat: port CorrelationCheck for victim scan"
```

---

### Task 4: `CanaryUtils` (verbatim port)

**Files:**
- Create: `src/burp/CanaryUtils.java`

**Interfaces:**
- Produces: `String generateCanary(int techniqueId, int batch, int position)`, `boolean containsCanaryPrefix(String)`, `ParsedCanary findCanary(String)`, `String injectCanaryIntoPayload(String payloadBody, int techniqueId, int batch, int position)`, `boolean isReflection(ParsedCanary, int, int, int)`, `boolean isCrossTechniqueReflection(ParsedCanary, int)`, and nested `class ParsedCanary { int techniqueId, batch, position; }`.

- [ ] **Step 1: Copy the source verbatim**

Run:
```bash
cp ../validator2/src/main/java/burp/CanaryUtils.java src/burp/CanaryUtils.java
```
This file is pure logic (regex + string manipulation) with no validator2-specific imports, so no adaptation is required. Confirm it declares `package burp;` and imports only `java.util.regex.*` and `java.util.Set`.

- [ ] **Step 2: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`. (If it fails, the only plausible cause is a stray `burp.test.*` import — remove it.)

- [ ] **Step 3: Commit**

```bash
git add src/burp/CanaryUtils.java
git commit -m "feat: port CanaryUtils for victim scan"
```

---

### Task 5: `ReflectionResult` (port with severity adaptation)

**Files:**
- Create: `src/burp/ReflectionResult.java`

**Interfaces:**
- Produces: `ReflectionResult` with static factories `victimReflection(...)`, `attackReflection(...)`, `crossTechniqueReflection(...)`; getters `getTitle()`, `getDetail()`, `AuditIssueSeverity getSeverity()`, `getOriginalRequest()`, `getOriginalResponse()`, `getReflectingResponse()`; nested `enum Type`.

- [ ] **Step 1: Copy and adapt**

Start from `../validator2/src/main/java/burp/ReflectionResult.java`. Apply exactly these edits:
1. Replace the return type of `getSeverity()` from `Severity` to `burp.api.montoya.scanner.audit.issues.AuditIssueSeverity`, and map: `VICTIM_REFLECTION`/`CROSS_TECHNIQUE` → `AuditIssueSeverity.HIGH`; `ATTACK_REFLECTION` → `AuditIssueSeverity.MEDIUM`; default → `AuditIssueSeverity.HIGH`.
2. Add `import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;`
3. Keep the `MontoyaRequestResponse` field/accessor types as-is (Task 1 confirmed the type is available in `burp`).

Resulting file:

```java
package burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Result of canary reflection detection. Ported from validator2; severity mapped
 * directly to Montoya's AuditIssueSeverity.
 */
public class ReflectionResult {

    public enum Type {
        VICTIM_REFLECTION("Victim Reflection Desync"),
        ATTACK_REFLECTION("Reflection Desync"),
        CROSS_TECHNIQUE("Cross-Technique Reflection Desync");

        private final String title;
        Type(String title) { this.title = title; }
        public String getTitle() { return title; }
    }

    private final Type type;
    private final CanaryUtils.ParsedCanary foundCanary;
    private final MontoyaRequestResponse originalRequest;
    private final MontoyaRequestResponse originalResponse;
    private final MontoyaRequestResponse reflectingResponse;

    private ReflectionResult(Type type, CanaryUtils.ParsedCanary foundCanary,
                             MontoyaRequestResponse originalRequest,
                             MontoyaRequestResponse originalResponse,
                             MontoyaRequestResponse reflectingResponse) {
        this.type = type;
        this.foundCanary = foundCanary;
        this.originalRequest = originalRequest;
        this.originalResponse = originalResponse;
        this.reflectingResponse = reflectingResponse;
    }

    public static ReflectionResult victimReflection(CanaryUtils.ParsedCanary foundCanary,
            MontoyaRequestResponse originalRequest, MontoyaRequestResponse originalResponse,
            MontoyaRequestResponse reflectingResponse) {
        return new ReflectionResult(Type.VICTIM_REFLECTION, foundCanary, originalRequest, originalResponse, reflectingResponse);
    }

    public static ReflectionResult attackReflection(CanaryUtils.ParsedCanary foundCanary,
            MontoyaRequestResponse originalRequest, MontoyaRequestResponse originalResponse,
            MontoyaRequestResponse reflectingResponse) {
        return new ReflectionResult(Type.ATTACK_REFLECTION, foundCanary, originalRequest, originalResponse, reflectingResponse);
    }

    public static ReflectionResult crossTechniqueReflection(CanaryUtils.ParsedCanary foundCanary,
            MontoyaRequestResponse reflectingResponse) {
        return new ReflectionResult(Type.CROSS_TECHNIQUE, foundCanary, null, null, reflectingResponse);
    }

    public Type getType() { return type; }
    public String getTitle() { return type.getTitle(); }

    public AuditIssueSeverity getSeverity() {
        switch (type) {
            case VICTIM_REFLECTION:
            case CROSS_TECHNIQUE:
                return AuditIssueSeverity.HIGH;
            case ATTACK_REFLECTION:
                return AuditIssueSeverity.MEDIUM;
            default:
                return AuditIssueSeverity.HIGH;
        }
    }

    public CanaryUtils.ParsedCanary getFoundCanary() { return foundCanary; }
    public MontoyaRequestResponse getOriginalRequest() { return originalRequest; }
    public MontoyaRequestResponse getOriginalResponse() { return originalResponse; }
    public MontoyaRequestResponse getReflectingResponse() { return reflectingResponse; }

    public String getDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("Canary '").append(CanaryUtils.generateCanary(
            foundCanary.techniqueId, foundCanary.batch, foundCanary.position));
        sb.append("' from ");
        if (type == Type.CROSS_TECHNIQUE) {
            sb.append("technique ").append(foundCanary.techniqueId);
        } else {
            sb.append("batch ").append(foundCanary.batch);
            sb.append(", position ").append(foundCanary.position);
        }
        sb.append(" appeared in a ");
        sb.append(type == Type.VICTIM_REFLECTION ? "victim" : "subsequent");
        sb.append(" response.");
        return sb.toString();
    }
}
```

- [ ] **Step 2: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add src/burp/ReflectionResult.java
git commit -m "feat: port ReflectionResult for victim scan"
```

---

### Task 6: `VictimDetector` — skeleton, transport, status helpers, Phase 1

Build the engine incrementally so it compiles at every step. This task delivers a compilable `VictimDetector` with the shared plumbing and Phase 1; Tasks 7–9 add later phases and `validate()`.

**Files:**
- Create: `src/burp/VictimDetector.java`

**Interfaces:**
- Consumes (from Task 1): `MontoyaRequestResponse.status()` (and `effectiveStatusCode()` if present), `Utilities.montoyaApi.http().sendRequests(List<HttpRequest>, HttpMode)`, `PermutationResult.isWAF(MontoyaRequestResponse)`.
- Consumes (Tasks 2–5): `ProbePayloads.Payload`, `CanaryUtils`, `ReflectionResult`, `CorrelationCheck`.
- Produces:
  - constructor `VictimDetector(long phaseDelayMs, long followupDelayMs, int phase4Retries, boolean correlationEnabled, long correlationGapMs)`.
  - `static int normalizeStatusCode(MontoyaRequestResponse)`, `static boolean isBoringStatusCode(int)`, `static int bucketStatusCode(int)`, `static final int BUCKETED_5XX_ORIGIN = 599`.
  - `List<MontoyaRequestResponse> send(List<HttpRequest>)`.
  - `VictimCheckResult runVictimCheckWithCanary(HttpRequest attack, HttpRequest victim, ProbePayloads.Payload payload, int techniqueId, int batch)` and nested `class VictimCheckResult` with `getVictimStatusCodes()`, `getRawVictimStatusCodes()`, `getVictimResponses()`, `getAttackResponses()`, `getReflections()`, `foundInconsistency()`.

- [ ] **Step 1: Write the skeleton with transport + status helpers + Phase-1 result type**

Adapt from `../validator2/src/main/java/burp/VictimScan.java` (lines 122–181 for the non-canary check, 199–371 for the canary variant + `checkForReflection`, 1006–1081 for `VictimCheckResult`) and `BaseScanStrategy.java` (lines 44–104 for status helpers). Key adaptations:
- **Attack requests are pre-built by the shell** (`VictimZeroScan`), so this engine receives already-desync'd `HttpRequest attack` and `HttpRequest victim` rather than a `probe` + `payload.applyTo(...)`. It re-injects a **fresh canary per position** by string-replacing the canary token in the attack request's body (the shell injects a placeholder canary for the default position; here we substitute per position). Simplest robust approach: the shell injects canary for `(techniqueId, batch, 0)`; the detector, for positions other than 0, rebuilds the attack via `withBody(...)` swapping the canary substring. See Step 2.
- Replace `HttpRequestUtils.sendRequests(batch, api)` with `send(batch)` (below), which calls `Utilities.montoyaApi.http().sendRequests(...)`, partitioning by an `X-Http2` header into `HttpMode.AUTO` vs `HttpMode.HTTP_1` (port of validator2 `HttpRequestUtils` lines 83–135).
- Replace `ResponseUtils.isWAF(response)` with `PermutationResult.isWAF(response)`.
- Replace `response.effectiveStatusCode()` with the Task-1-confirmed accessor (use `effectiveStatusCode()` if present, else `status()`), wrapped in `normalizeStatusCode(MontoyaRequestResponse)`.
- Drop `instabail`, canary DB dedup, and `originalBodyPrefix` (not used here).

```java
package burp;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Victim-based desync detection engine, ported from validator2's VictimScan.
 * Operates on Montoya types; sends via Utilities.montoyaApi.http().sendRequests().
 * The attack request arrives already desync'd (CL.0 vector applied by VictimZeroScan).
 */
public class VictimDetector {

    public static final int BUCKETED_5XX_ORIGIN = 599;

    private final long phaseDelayMs;
    private final long followupDelayMs;
    private final int phase4Retries;
    private final boolean correlationEnabled;
    private final long correlationGapMs;

    public VictimDetector(long phaseDelayMs, long followupDelayMs, int phase4Retries,
                          boolean correlationEnabled, long correlationGapMs) {
        this.phaseDelayMs = phaseDelayMs;
        this.followupDelayMs = followupDelayMs;
        this.phase4Retries = phase4Retries;
        this.correlationEnabled = correlationEnabled;
        this.correlationGapMs = correlationGapMs;
    }

    // ---- transport -------------------------------------------------------

    /** Send a batch via the Montoya API, partitioning by the X-Http2 marker header. */
    List<MontoyaRequestResponse> send(List<HttpRequest> requests) {
        List<HttpRequest> h1 = new ArrayList<>();
        List<Integer> h1Idx = new ArrayList<>();
        List<HttpRequest> auto = new ArrayList<>();
        List<Integer> autoIdx = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            HttpRequest r = requests.get(i);
            if (r.hasHeader("X-Http2")) {
                auto.add(r.withRemovedHeader("X-Http2")); autoIdx.add(i);
            } else {
                h1.add(r); h1Idx.add(i);
            }
        }
        MontoyaRequestResponse[] out = new MontoyaRequestResponse[requests.size()];
        if (!h1.isEmpty()) {
            List<HttpRequestResponse> resp = Utilities.montoyaApi.http().sendRequests(h1, HttpMode.HTTP_1);
            for (int i = 0; i < resp.size(); i++) out[h1Idx.get(i)] = new MontoyaRequestResponse(resp.get(i));
        }
        if (!auto.isEmpty()) {
            List<HttpRequestResponse> resp = Utilities.montoyaApi.http().sendRequests(auto, HttpMode.AUTO);
            for (int i = 0; i < resp.size(); i++) out[autoIdx.get(i)] = new MontoyaRequestResponse(resp.get(i));
        }
        return java.util.Arrays.asList(out);
    }

    // ---- status helpers (ported from BaseScanStrategy) -------------------

    static int normalizeStatusCode(MontoyaRequestResponse r) {
        // Task 1: if effectiveStatusCode() exists use it (handles code*10 nesting), else status().
        int code = r.status(); // REPLACE with r.effectiveStatusCode() if Task 1 confirmed it exists
        return code >= 1000 ? code / 10 : code;
    }

    static boolean isBoringStatusCode(int baseCode) {
        return baseCode == 0 || baseCode == 429 || baseCode == 100;
    }

    static int bucketStatusCode(int normalized) {
        if (normalized == 502 || normalized == 503 || normalized == 504) return BUCKETED_5XX_ORIGIN;
        if (normalized >= 520 && normalized <= 530) return BUCKETED_5XX_ORIGIN;
        return normalized;
    }

    private boolean collectVictimResponse(MontoyaRequestResponse response,
                                          Set<Integer> victimStatusCodes,
                                          List<MontoyaRequestResponse> victimResponses) {
        if (response == null || response.response() == null) return false;
        if (PermutationResult.isWAF(response)) return true; // received, but skip for FP-safety
        victimResponses.add(response);
        int code = normalizeStatusCode(response);
        if (!isBoringStatusCode(code)) victimStatusCodes.add(bucketStatusCode(code));
        return true;
    }

    // ---- Phase 1 result --------------------------------------------------

    public static class VictimCheckResult {
        private final Set<Integer> victimStatusCodes;
        private final List<MontoyaRequestResponse> victimResponses;
        private final List<MontoyaRequestResponse> attackResponses;
        private final List<ReflectionResult> reflections;

        public VictimCheckResult(Set<Integer> v, List<MontoyaRequestResponse> vr,
                                 List<MontoyaRequestResponse> ar, List<ReflectionResult> refl) {
            this.victimStatusCodes = new HashSet<>(v);
            this.victimResponses = new ArrayList<>(vr);
            this.attackResponses = new ArrayList<>(ar);
            this.reflections = new ArrayList<>(refl);
        }

        public Set<Integer> getVictimStatusCodes() { return new HashSet<>(victimStatusCodes); }
        public List<MontoyaRequestResponse> getVictimResponses() { return new ArrayList<>(victimResponses); }
        public List<MontoyaRequestResponse> getAttackResponses() { return new ArrayList<>(attackResponses); }
        public List<ReflectionResult> getReflections() { return new ArrayList<>(reflections); }
        public boolean foundInconsistency() { return victimStatusCodes.size() >= 2; }

        public Set<Integer> getRawVictimStatusCodes() {
            Set<Integer> raw = new HashSet<>();
            for (MontoyaRequestResponse r : victimResponses) {
                if (r == null || r.response() == null || PermutationResult.isWAF(r)) continue;
                int c = normalizeStatusCode(r);
                if (!isBoringStatusCode(c)) raw.add(c);
            }
            return raw;
        }
    }
}
```

- [ ] **Step 2: Add Phase 1 (`runVictimCheckWithCanary`) + `checkForReflection`**

Append these methods inside `VictimDetector`. This ports `VictimScan.runVictimCheckWithCanary` (lines 208–312) and `checkForReflection` (325–371). The canary is swapped per position by replacing the base canary substring `CanaryUtils.generateCanary(techniqueId, batch, 0)` in the attack body with the position-specific one.

```java
    /** Build the position-specific attack request by swapping the canary token in the body. */
    private HttpRequest attackForPosition(HttpRequest baseAttack, int techniqueId, int batch, int position) {
        if (position == 0) return baseAttack;
        String base = CanaryUtils.generateCanary(techniqueId, batch, 0);
        String want = CanaryUtils.generateCanary(techniqueId, batch, position);
        String body = baseAttack.bodyToString();
        return baseAttack.withBody(body.replace(base, want));
    }

    public VictimCheckResult runVictimCheckWithCanary(HttpRequest attack, HttpRequest victim,
            ProbePayloads.Payload payload, int techniqueId, int batch) {
        Set<Integer> victimStatusCodes = new HashSet<>();
        List<MontoyaRequestResponse> victimResponses = new ArrayList<>();
        List<MontoyaRequestResponse> attackResponses = new ArrayList<>();
        List<ReflectionResult> reflections = new ArrayList<>();
        Map<String, MontoyaRequestResponse> canaryToAttack = new HashMap<>();

        HttpRequest a1 = attackForPosition(attack, techniqueId, batch, 0);
        HttpRequest a2 = attackForPosition(attack, techniqueId, batch, 2);
        String c1 = CanaryUtils.generateCanary(techniqueId, batch, 0);
        String c2 = CanaryUtils.generateCanary(techniqueId, batch, 2);

        List<MontoyaRequestResponse> b1 = send(List.of(a1, victim, a2, victim));
        canaryToAttack.put(c1, b1.get(0));
        canaryToAttack.put(c2, b1.get(2));
        attackResponses.add(b1.get(0)); attackResponses.add(b1.get(2));
        checkForReflection(b1.get(0), techniqueId, batch, 0, canaryToAttack, reflections, false);
        checkForReflection(b1.get(2), techniqueId, batch, 2, canaryToAttack, reflections, false);
        collectVictimResponse(b1.get(1), victimStatusCodes, victimResponses);
        checkForReflection(b1.get(1), techniqueId, batch, 1, canaryToAttack, reflections, true);
        collectVictimResponse(b1.get(3), victimStatusCodes, victimResponses);
        checkForReflection(b1.get(3), techniqueId, batch, 3, canaryToAttack, reflections, true);

        HttpRequest a3 = attackForPosition(attack, techniqueId, batch, 4);
        HttpRequest a4 = attackForPosition(attack, techniqueId, batch, 6);
        String c3 = CanaryUtils.generateCanary(techniqueId, batch, 4);
        String c4 = CanaryUtils.generateCanary(techniqueId, batch, 6);

        List<MontoyaRequestResponse> b2 = send(List.of(a3, victim, a4, victim, victim));
        canaryToAttack.put(c3, b2.get(0));
        canaryToAttack.put(c4, b2.get(2));
        attackResponses.add(b2.get(0)); attackResponses.add(b2.get(2));
        checkForReflection(b2.get(0), techniqueId, batch, 4, canaryToAttack, reflections, false);
        checkForReflection(b2.get(2), techniqueId, batch, 6, canaryToAttack, reflections, false);
        collectVictimResponse(b2.get(1), victimStatusCodes, victimResponses);
        checkForReflection(b2.get(1), techniqueId, batch, 5, canaryToAttack, reflections, true);
        collectVictimResponse(b2.get(3), victimStatusCodes, victimResponses);
        checkForReflection(b2.get(3), techniqueId, batch, 7, canaryToAttack, reflections, true);
        collectVictimResponse(b2.get(4), victimStatusCodes, victimResponses);
        checkForReflection(b2.get(4), techniqueId, batch, 8, canaryToAttack, reflections, true);

        return new VictimCheckResult(victimStatusCodes, victimResponses, attackResponses, reflections);
    }

    private void checkForReflection(MontoyaRequestResponse response, int techniqueId, int batch,
            int position, Map<String, MontoyaRequestResponse> canaryToAttack,
            List<ReflectionResult> reflections, boolean isVictim) {
        if (response == null || response.response() == null) return;
        String body = response.response().bodyToString();
        if (body == null || body.isEmpty() || !CanaryUtils.containsCanaryPrefix(body)) return;
        CanaryUtils.ParsedCanary found = CanaryUtils.findCanary(body);
        if (found == null) return;
        if (CanaryUtils.isCrossTechniqueReflection(found, techniqueId)) {
            reflections.add(ReflectionResult.crossTechniqueReflection(found, response));
            return;
        }
        if (CanaryUtils.isReflection(found, techniqueId, batch, position)) {
            String key = CanaryUtils.generateCanary(found.techniqueId, found.batch, found.position);
            MontoyaRequestResponse origin = canaryToAttack.get(key);
            if (isVictim) reflections.add(ReflectionResult.victimReflection(found, origin, origin, response));
            else reflections.add(ReflectionResult.attackReflection(found, origin, origin, response));
        }
    }
```

- [ ] **Step 3: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`. If `r.response().bodyToString()` / `withBody` / `withRemovedHeader` signatures differ, adjust to the confirmed Montoya `HttpRequest`/`HttpResponse` API.

- [ ] **Step 4: Commit**

```bash
git add src/burp/VictimDetector.java
git commit -m "feat: victim detector engine with transport + Phase 1 canary check"
```

---

### Task 7: `VictimDetector` — Phases 2–4, correlation gate, and `validate()`

**Files:**
- Modify: `src/burp/VictimDetector.java`

**Interfaces:**
- Consumes: everything from Task 6; `CorrelationCheck` (Task 3).
- Produces:
  - `ErraticDomainResult detectErraticDomain(HttpRequest victim, int differingStatusCode)` + nested `ErraticDomainResult { boolean isErratic(); Integer getConsistentStatusCode(); }`.
  - `FollowupResult runFollowupScans(HttpRequest attack, HttpRequest victim, Set<Integer> initialVictimCodes, int techniqueId, Integer consistentBaselineCode) throws InterruptedException` + nested `FollowupResult`.
  - `Set<Integer> runControlBurst(HttpRequest victim)`.
  - `DetectionResult validate(HttpRequest attack, HttpRequest victim, ProbePayloads.Payload payload, int techniqueId, String hostname, Set<String> erraticHosts)` returning a plain result object the shell turns into a `Report` (fields: `boolean success`, `AuditIssueSeverity severity`, `String title`, `String detail`, `List<MontoyaRequestResponse> evidence`, `List<ReflectionResult> reflections`).

- [ ] **Step 1: Add Phase 2 `detectErraticDomain` + `runControlBurst`**

Port `BaseScanStrategy.detectErraticDomain` (lines 416–505) and `VictimScan.runControlBurst` (430–444). Adaptations: use `send(...)`; drop the `X-Erratic`/cache-buster montoya calls (send the plain `victim` request repeatedly); replace initial `TestAwareSleep.sleep(10000)` with `Thread.sleep(phaseDelayMs)`; use `normalizeStatusCode(MontoyaRequestResponse)` + `bucketStatusCode`.

```java
    public static class ErraticDomainResult {
        private final boolean erratic; private final Integer consistentStatusCode;
        public ErraticDomainResult(boolean erratic, Integer consistentStatusCode) {
            this.erratic = erratic; this.consistentStatusCode = consistentStatusCode;
        }
        public boolean isErratic() { return erratic; }
        public Integer getConsistentStatusCode() { return consistentStatusCode; }
    }

    public ErraticDomainResult detectErraticDomain(HttpRequest victim, int differingStatusCode) {
        try {
            Thread.sleep(phaseDelayMs);
            // Flush: 3 batches x 3
            for (int b = 0; b < 3; b++) send(List.of(victim, victim, victim));
            // Check: 4 batches x 5
            Integer first = null;
            for (int b = 0; b < 4; b++) {
                List<MontoyaRequestResponse> resp = send(List.of(victim, victim, victim, victim, victim));
                for (MontoyaRequestResponse r : resp) {
                    if (r == null || r.response() == null) continue;
                    int raw = normalizeStatusCode(r);
                    int code = bucketStatusCode(raw);
                    if (code == differingStatusCode) return new ErraticDomainResult(true, null);
                    if (isBoringStatusCode(raw)) continue;
                    if (first == null) { first = code; continue; }
                    if (code != first) return new ErraticDomainResult(true, null);
                }
            }
            return new ErraticDomainResult(false, first);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ErraticDomainResult(false, null);
        }
    }

    public Set<Integer> runControlBurst(HttpRequest victim) {
        Set<Integer> observed = new HashSet<>();
        List<MontoyaRequestResponse> ignored = new ArrayList<>();
        for (int b = 0; b < 4; b++) {
            List<MontoyaRequestResponse> resp = send(List.of(victim, victim, victim, victim, victim));
            for (MontoyaRequestResponse r : resp) collectVictimResponse(r, observed, ignored);
        }
        return observed;
    }
```

- [ ] **Step 2: Add Phase 3 `runFollowupScans` + `FollowupResult`**

Port `VictimScan.runFollowupScans` (lines 1112–1192) and `FollowupResult` (1199–1273). Adaptations: iterate `ProbePayloads.getAllPayloads()`; for each payload, build a position-0 attack by swapping the **body** of the incoming `attack` request with the payload body + a fresh canary — do this in the shell-provided helper is unavailable, so rebuild here: `attack.withBody(CanaryUtils.injectCanaryIntoPayload(payload.getBody(), techniqueId, batch, 0))` then re-apply CL via the shell? To avoid re-running `DesyncBox.applyDesync` here, the shell passes a `java.util.function.BiFunction<ProbePayloads.Payload,Integer,HttpRequest> attackBuilder` that produces a fully-formed desync'd attack for a given (payload, batch). Use that.

Update the produced signature accordingly:
`runFollowupScans(java.util.function.BiFunction<ProbePayloads.Payload,Integer,HttpRequest> attackBuilder, HttpRequest victim, Set<Integer> initialVictimCodes, int techniqueId, Integer consistentBaselineCode)`.

```java
    public static class FollowupResult {
        final boolean foundThirdCode; final Integer newStatusCode;
        final MontoyaRequestResponse responseWithNewCode; final MontoyaRequestResponse attackResponse;
        final ProbePayloads.Payload triggeringPayload; final Set<Integer> uniqueAttackStatusCodes;
        final List<MontoyaRequestResponse> attackResponsesWithDistinctCodes;
        FollowupResult(boolean f, Integer n, MontoyaRequestResponse rn, MontoyaRequestResponse ar,
                ProbePayloads.Payload tp, Set<Integer> ua, List<MontoyaRequestResponse> ad) {
            foundThirdCode = f; newStatusCode = n; responseWithNewCode = rn; attackResponse = ar;
            triggeringPayload = tp; uniqueAttackStatusCodes = ua == null ? new HashSet<>() : new HashSet<>(ua);
            attackResponsesWithDistinctCodes = ad == null ? new ArrayList<>() : new ArrayList<>(ad);
        }
        public boolean foundThirdCode() { return foundThirdCode; }
        public Integer getNewStatusCode() { return newStatusCode; }
        public MontoyaRequestResponse getResponseWithNewCode() { return responseWithNewCode; }
        public MontoyaRequestResponse getAttackResponse() { return attackResponse; }
        public ProbePayloads.Payload getTriggeringPayload() { return triggeringPayload; }
        public Set<Integer> getUniqueAttackStatusCodes() { return new HashSet<>(uniqueAttackStatusCodes); }
        public List<MontoyaRequestResponse> getAttackResponsesWithDistinctCodes() { return new ArrayList<>(attackResponsesWithDistinctCodes); }
    }

    public FollowupResult runFollowupScans(
            java.util.function.BiFunction<ProbePayloads.Payload, Integer, HttpRequest> attackBuilder,
            HttpRequest victim, Set<Integer> initialVictimCodes, int techniqueId,
            Integer consistentBaselineCode) throws InterruptedException {
        int batch = 2;
        Set<Integer> uniqueAttack = new HashSet<>();
        Map<Integer, MontoyaRequestResponse> attackByCode = new HashMap<>();
        for (ProbePayloads.Payload payload : ProbePayloads.getAllPayloads()) {
            Thread.sleep(followupDelayMs);
            HttpRequest attack = attackBuilder.apply(payload, batch);
            VictimCheckResult result = runVictimCheckWithCanary(attack, victim, payload, techniqueId, batch);
            batch++;
            for (MontoyaRequestResponse ar : result.getAttackResponses()) {
                if (ar != null && ar.response() != null) {
                    int raw = normalizeStatusCode(ar);
                    int code = bucketStatusCode(raw);
                    if (!isBoringStatusCode(raw) && !uniqueAttack.contains(code)) {
                        uniqueAttack.add(code); attackByCode.put(code, ar);
                    }
                }
            }
            for (Integer code : result.getVictimStatusCodes()) {
                if (!initialVictimCodes.contains(code)
                        && (consistentBaselineCode == null || !consistentBaselineCode.equals(code))) {
                    MontoyaRequestResponse ev = null;
                    for (MontoyaRequestResponse r : result.getVictimResponses()) {
                        if (r != null && r.response() != null
                                && bucketStatusCode(normalizeStatusCode(r)) == code) { ev = r; break; }
                    }
                    MontoyaRequestResponse ar = result.getAttackResponses().isEmpty() ? null : result.getAttackResponses().get(0);
                    return new FollowupResult(true, code, ev, ar, payload, uniqueAttack, new ArrayList<>(attackByCode.values()));
                }
            }
        }
        return new FollowupResult(false, null, null, null, null, uniqueAttack, new ArrayList<>(attackByCode.values()));
    }
```

- [ ] **Step 3: Add `DetectionResult` + `validate()` (Phase 4, correlation gate, orchestration)**

Port `VictimScan.validate` (lines 528–784) and `addTwoDistinctResponses` (791–811). Adaptations: no DB/erratic-blacklist calls — the shell owns the `erraticHosts` set and passes it in; `markDomainAsErratic` becomes `erraticHosts.add(hostname)`; replace `TestAwareSleep.sleep(10000)` with `Thread.sleep(phaseDelayMs)`; `CorrelationCheck.defaults()` → `CorrelationCheck.defaults(correlationGapMs)` and only run if `correlationEnabled`; return a `DetectionResult` instead of `ValidationResult`. Phase-3 `attackBuilder` and Phase-1/4 `attack` come from the shell.

```java
    public static class DetectionResult {
        public boolean success;
        public AuditIssueSeverity severity;
        public String title = "";
        public String detail = "";
        public final List<MontoyaRequestResponse> evidence = new ArrayList<>();
        public final List<ReflectionResult> reflections = new ArrayList<>();
        static DetectionResult failure() { DetectionResult d = new DetectionResult(); d.success = false; return d; }
    }
```

Then `validate(...)` follows validator2's control flow verbatim in structure:
1. If `erraticHosts.contains(hostname)` → `DetectionResult.failure()`.
2. Phase 1: `runVictimCheckWithCanary(attack, victim, payload, techniqueId, 1)`; collect reflections into the result regardless. If `!foundInconsistency()` → set `result.reflections` and return failure (reflections still reported by the shell).
3. Phase 2: `detectErraticDomain(victim, differingCode)`; if erratic → `erraticHosts.add(hostname)` and return failure.
4. `Thread.sleep(phaseDelayMs)`.
5. Phase 3: `runFollowupScans(attackBuilder, victim, phase1Codes, techniqueId, consistentCode)`.
6. Build evidence (attack + two distinct victims via `addTwoDistinctResponses`).
7. If third code → `Confirmed HIGH`; else Phase 4 retries (`phase4Retries`, `Thread.sleep(phaseDelayMs)` each) using `runVictimCheckWithCanary(attack, victim, payload, techniqueId, 4)`; suppress if not reproduced or Phase-1 had `BUCKETED_5XX_ORIGIN`; else `MEDIUM` (≥3 unique attack codes) or `LOW`.
8. If `correlationEnabled` and `consistentCode != null`: run `CorrelationCheck.defaults(correlationGapMs).run(...)` with `attackRun = c -> runVictimCheckWithCanary(attack, victim, corrPayload, techniqueId, 100+c).getVictimStatusCodes()` and `controlRun = c -> runControlBurst(victim)`; apply DISCARD/UNREPLICABLE/VERIFIED to `severity`/`title`/`detail`.
9. Collect all Phase-1/3/4 reflections into `result.reflections`; set `success = true` with title/detail/severity/evidence.

Import `import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;` at the top of the file. Use `AuditIssueSeverity.HIGH/MEDIUM/LOW` for the tiers. Keep the detail strings from validator2 but replace `payload ID: N` DB references with the `ProbePayloads.Payload.getId()` value, and prefix titles with the permutation/technique context supplied by the shell (pass a `String vectorLabel` param appended to the title, e.g. `"Victim Desync: Confirmed — " + vectorLabel`).

Final produced signature:
`DetectionResult validate(HttpRequest attack, java.util.function.BiFunction<ProbePayloads.Payload,Integer,HttpRequest> attackBuilder, HttpRequest victim, ProbePayloads.Payload payload, int techniqueId, String hostname, String vectorLabel, Set<String> erraticHosts)`.

- [ ] **Step 4: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: Commit**

```bash
git add src/burp/VictimDetector.java
git commit -m "feat: victim detector phases 2-4 + correlation gate + validate()"
```

---

### Task 8: `VictimZeroScan` (scan shell) + registration

**Files:**
- Create: `src/burp/VictimZeroScan.java`
- Modify: `src/burp/BurpExtender.java` (add registration line after `new ImplicitZeroScan("CL.0");`)

**Interfaces:**
- Consumes: `SmuggleScanBox` framework (`doConfiguredScan`, `scanSettings`, `request`, `report`), `DesyncBox.applyDesync` + permutation `SettingsBox`es, `Utilities.buildMontoyaReq`, `VictimDetector`, `ProbePayloads`, `CanaryUtils`, `Report`, `AuditIssueSeverity`.
- Produces: registered scan named `"CL.0 victim"`.

- [ ] **Step 1: Write `VictimZeroScan.java`**

Mirror `ImplicitZeroScan`'s constructor imports (so the same vectors are enumerated) and reproduce its request-construction path in `doConfiguredScan`, swapping the gadget body for a canary-bearing `ProbePayload` and delegating detection to `VictimDetector`.

```java
package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * CL.0 victim scan: same vectors as ImplicitZeroScan, but detects desync via
 * victim-request inconsistency + canary reflection (ported from validator2's VictimScan).
 */
public class VictimZeroScan extends SmuggleScanBox {

    private final Set<String> erraticHosts = new HashSet<>();
    private final List<String> permutationIndex = new ArrayList<>(); // stable technique-id map

    VictimZeroScan(String name) {
        super(name);
        // Same vector set as ImplicitZeroScan.
        scanSettings.importSettings(DesyncBox.sharedSettings);
        scanSettings.importSettings(DesyncBox.sharedPermutations);
        scanSettings.importSettings(DesyncBox.clPermutations);
        scanSettings.importSettings(DesyncBox.h2Permutations);
        scanSettings.importSettings(DesyncBox.h1Permutations);
        // Victim-scan settings (5s sleeps per the design).
        scanSettings.register("victim: phase delay ms", 5000);
        scanSettings.register("victim: followup delay ms", 5000);
        scanSettings.register("victim: phase4 retries", 5);
        scanSettings.register("victim: enable correlation check", true);
        scanSettings.register("victim: correlation gap ms", 5000);
    }

    /** Stable int id for a permutation name (index in first-seen order). */
    private int techniqueIdFor(String technique) {
        int idx = permutationIndex.indexOf(technique);
        if (idx < 0) { permutationIndex.add(technique); idx = permutationIndex.size() - 1; }
        return idx;
    }

    @Override
    public boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config) {
        Utilities.supportsHTTP2 = true;
        boolean h2 = Utilities.isHTTP2(baseReq);
        baseReq = Utilities.addCacheBuster(baseReq, null);
        byte[] req = SmuggleScanBox.setupRequest(baseReq);

        String technique = config.keySet().iterator().next();
        if (null == DesyncBox.applyDesync(req, "Content-Length", technique)) return false;

        boolean forceHTTP1 = false, forceHTTP2 = false;
        if (DesyncBox.h1Permutations.contains(technique)) {
            forceHTTP1 = true;
        } else if (DesyncBox.h2Permutations.contains(technique)) {
            if (!h2) {
                Resp h2test = HTTP2Scan.h2request(service, baseReq);
                if (h2test.failed() || !Utilities.containsBytes(h2test.getReq().getResponse(), "HTTP/2".getBytes())) return false;
                h2 = true;
            }
            forceHTTP2 = true;
        }

        req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
        if (h2 && !forceHTTP1) req = Utilities.replaceFirst(req, "Connection: ", "X-Connection: ");
        else req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");

        final int techniqueId = techniqueIdFor(technique);
        final byte[] reqBase = req;                 // effectively-final for the lambda
        final boolean fHttp2 = forceHTTP2;

        // Build a fully-formed desync'd attack for a (payload, batch): inject canary at position 0.
        BiFunction<ProbePayloads.Payload, Integer, HttpRequest> attackBuilder = (payload, batch) -> {
            String body = CanaryUtils.injectCanaryIntoPayload(payload.getBody(), techniqueId, batch, 0);
            byte[] attack = Utilities.fixContentLength(Utilities.setBody(reqBase, body));
            attack = DesyncBox.applyDesync(attack, "Content-Length", technique);
            HttpRequest hr = Utilities.buildMontoyaReq(attack, service);
            return fHttp2 ? hr.withAddedHeader("X-Http2", "1") : hr;
        };

        ProbePayloads.Payload payload = ProbePayloads.getDefaultPayload();
        HttpRequest attack = attackBuilder.apply(payload, 1);

        // Victim = clean cache-busted baseline (no smuggle, no desync).
        byte[] victimBytes = Utilities.addCacheBuster(baseReq, null);
        HttpRequest victim = Utilities.buildMontoyaReq(victimBytes, service);
        if (forceHTTP2) victim = victim.withAddedHeader("X-Http2", "1");

        VictimDetector detector = new VictimDetector(
            Utilities.globalSettings.getInt("victim: phase delay ms"),
            Utilities.globalSettings.getInt("victim: followup delay ms"),
            Utilities.globalSettings.getInt("victim: phase4 retries"),
            Utilities.globalSettings.getBoolean("victim: enable correlation check"),
            Utilities.globalSettings.getInt("victim: correlation gap ms"));

        VictimDetector.DetectionResult result = detector.validate(
            attack, attackBuilder, victim, payload, techniqueId,
            service.getHost(), technique, erraticHosts);

        // Reflections are reported independently of the status-code finding.
        for (ReflectionResult refl : result.reflections) reportReflection(refl);

        if (!result.success) return false;
        fileIssue(result.title, result.detail, result.severity, result.evidence);
        return true;
    }

    private void reportReflection(ReflectionResult refl) {
        List<MontoyaRequestResponse> ev = new ArrayList<>();
        if (refl.getOriginalRequest() != null) ev.add(refl.getOriginalRequest());
        if (refl.getReflectingResponse() != null) ev.add(refl.getReflectingResponse());
        fileIssue(refl.getTitle(), refl.getDetail(), refl.getSeverity(), ev);
    }

    private void fileIssue(String title, String detail, AuditIssueSeverity severity, List<MontoyaRequestResponse> evidence) {
        // MontoyaRequestResponse -> HttpRequestResponse per Task 1 (implements it, or via accessor).
        burp.api.montoya.http.message.HttpRequestResponse[] arr =
            evidence.toArray(new burp.api.montoya.http.message.HttpRequestResponse[0]);
        Report report = new Report(title, detail,
            "Detected via victim-request inconsistency / canary reflection. See https://portswigger.net/research/browser-powered-desync-attacks",
            "", severity, arr);
        Utilities.montoyaApi.siteMap().add(report.getIssue());
    }
}
```

Notes for the implementer:
- If Task 1 found `MontoyaRequestResponse` does **not** implement `HttpRequestResponse`, change `List<MontoyaRequestResponse>` collection at the `fileIssue` boundary to map each via its confirmed accessor before building `arr`.
- `Utilities.globalSettings` is the live settings store used elsewhere (`ImplicitZeroScan` reads `Utilities.globalSettings.getBoolean(...)`); `scanSettings.register(...)` registers into it. Confirm `getInt` exists (used across the codebase) — if a setting is registered as a String, read+parse instead.

- [ ] **Step 2: Register the scan in `BurpExtender.java`**

Add immediately after the `new ImplicitZeroScan("CL.0");` line (currently `src/burp/BurpExtender.java:38`):

```java
        new VictimZeroScan("CL.0 victim");
```

- [ ] **Step 3: Build**

Run: `./gradlew fatJar`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 4: Commit**

```bash
git add src/burp/VictimZeroScan.java src/burp/BurpExtender.java
git commit -m "feat: add VictimZeroScan shell and register it"
```

---

### Task 9: End-to-end lab verification

No automated tests exist (by design). This task is the acceptance gate and resolves the byte-accuracy risk.

**Files:** none (manual/lab).

- [ ] **Step 1: Load the extension**

Load `build/libs/desynchronize-all.jar` (the `fatJar` output) into Burp. Confirm `CL.0 victim` appears in the scan list alongside `CL.0`, and its `victim:` settings render.

- [ ] **Step 2: Byte-accuracy check (critical risk)**

Point the scan at a lab CL.0 target with request logging. Capture one attack request as sent on the wire and confirm: the `Content-Length` reflects the smuggle body length (not silently recomputed to something that neutralises the desync), and the desync technique manipulation is intact. If Montoya re-normalises `Content-Length` in `HTTP_1` mode, switch the send to preserve raw bytes (e.g. build the request so Montoya treats CL as authored, or fall back to `Scan.request`/TurboHelper for the attack leg) and re-verify.

- [ ] **Step 3: True-positive check**

Run against a known-vulnerable CL.0 lab. Expect a `Victim Desync` issue (Confirmed HIGH if a third code is triggerable; otherwise LOW/MEDIUM) and/or a reflection issue. Confirm evidence contains the attack + two distinct-status victim responses.

- [ ] **Step 4: False-positive check**

Run against a stable non-vulnerable host and a deliberately flaky host. Expect no issue on the stable host, and the flaky host to be caught by Phase 2 (erratic) or the correlation gate (DISCARD), producing no report.

- [ ] **Step 5: Finalise**

```bash
git add -A
git commit -m "chore: victim scan lab-verified" --allow-empty
```
Then use `superpowers:finishing-a-development-branch` to decide merge/PR.

---

## Self-Review

**Spec coverage:**
- Same vectors as ImplicitZero → Task 8 (identical setting imports + construction). ✓
- Victim inconsistency detection (Phase 1) → Task 6. ✓
- Erratic-domain (Phase 2), followups (Phase 3), reproduction (Phase 4), correlation gate → Task 7. ✓
- Canary reflection → Tasks 4 (CanaryUtils), 5 (ReflectionResult), 6 (checkForReflection), 7/8 (reporting). ✓
- ProbePayloads (slim) → Task 2. ✓
- Severity tiers via Report/AuditIssueSeverity → Tasks 5, 7, 8. ✓
- In-memory host state (no DB) → Task 8 (`erraticHosts`), passed into detector. ✓
- Settings incl. 5s sleeps + correlation gap → Task 8. ✓
- Transport via `api.http().sendRequests()` → Task 6 (`send`). ✓
- Reuse `MontoyaRequestResponse`/`buildMontoyaReq`/`isWAF` → Tasks 1, 6, 8. ✓
- No unit tests; lab verification → Task 9. ✓
- Open integration points resolved first → Task 1. ✓

**Placeholder scan:** Task 6 Step 2 and Task 7 Steps 2–3 describe ports against named validator2 line ranges with the exact adaptation list and concrete code for all new seams; the `validate()` body (Task 7 Step 3) is given as an ordered, explicit control-flow spec mirroring validator2 lines 528–784 rather than re-transcribing ~250 lines — acceptable for a verbatim-structure port with all signatures pinned. No `TBD`/`handle edge cases`/`similar to`.

**Type consistency:** `MontoyaRequestResponse`, `ProbePayloads.Payload`, `CanaryUtils.ParsedCanary`, `ReflectionResult`, `VictimCheckResult`, `FollowupResult`, `ErraticDomainResult`, `DetectionResult`, and the `BiFunction<ProbePayloads.Payload,Integer,HttpRequest> attackBuilder` signature are used consistently across Tasks 6→7→8. `CorrelationCheck.defaults(long)` matches its caller in Task 7. `AuditIssueSeverity` is the single severity type throughout.
