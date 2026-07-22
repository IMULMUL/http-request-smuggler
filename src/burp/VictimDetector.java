package burp;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

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

    /**
     * Builds a fully-formed, position-aware attack request. The CL desync MUST be
     * applied last (after the body/canary is set) so it is not recomputed away.
     */
    @FunctionalInterface
    public interface AttackBuilder {
        HttpRequest build(ProbePayloads.Payload payload, int batch, int position);
    }

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
        // Task 1 confirmed the bundled MontoyaRequestResponse has status() only
        // (no effectiveStatusCode()); the /10 guard preserves the nested-code
        // convention (e.g. 4040 -> 404) in case callers pre-multiply upstream.
        int code = r.status();
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

    // ---- Phase 1: canary victim check -------------------------------------

    public VictimCheckResult runVictimCheckWithCanary(AttackBuilder attackBuilder, HttpRequest victim,
            ProbePayloads.Payload payload, int techniqueId, int batch) {
        Set<Integer> victimStatusCodes = new HashSet<>();
        List<MontoyaRequestResponse> victimResponses = new ArrayList<>();
        List<MontoyaRequestResponse> attackResponses = new ArrayList<>();
        List<ReflectionResult> reflections = new ArrayList<>();
        Map<String, MontoyaRequestResponse> canaryToAttack = new HashMap<>();

        HttpRequest a1 = attackBuilder.build(payload, batch, 0);
        HttpRequest a2 = attackBuilder.build(payload, batch, 2);
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

        HttpRequest a3 = attackBuilder.build(payload, batch, 4);
        HttpRequest a4 = attackBuilder.build(payload, batch, 6);
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

    // ---- Phase 2: erratic-domain detection + control burst ----------------

    public static class ErraticDomainResult {
        private final boolean erratic; private final Integer consistentStatusCode;
        public ErraticDomainResult(boolean erratic, Integer consistentStatusCode) {
            this.erratic = erratic; this.consistentStatusCode = consistentStatusCode;
        }
        public boolean isErratic() { return erratic; }
        public Integer getConsistentStatusCode() { return consistentStatusCode; }
    }

    /**
     * Phase 2: decide whether the host itself is flaky. After a leading settle
     * (phaseDelayMs) and a flush burst, send 4x5 attack-free requests. If any
     * bucketed non-boring code equals the Phase-1 differing code, or two distinct
     * non-boring codes appear with no attack present, the host is erratic.
     */
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

    /**
     * Attack-free control burst (4x5). Returns the observed non-boring bucketed
     * victim codes. Used by the correlation gate to detect a time-correlated
     * confound: any off-baseline code seen here is not attack-caused.
     */
    public Set<Integer> runControlBurst(HttpRequest victim) {
        Set<Integer> observed = new HashSet<>();
        List<MontoyaRequestResponse> ignored = new ArrayList<>();
        for (int b = 0; b < 4; b++) {
            List<MontoyaRequestResponse> resp = send(List.of(victim, victim, victim, victim, victim));
            for (MontoyaRequestResponse r : resp) collectVictimResponse(r, observed, ignored);
        }
        return observed;
    }

    // ---- Phase 3: followup scans ------------------------------------------

    public static class FollowupResult {
        final boolean foundThirdCode; final Integer newStatusCode;
        final MontoyaRequestResponse responseWithNewCode; final MontoyaRequestResponse attackResponse;
        final ProbePayloads.Payload triggeringPayload; final Set<Integer> uniqueAttackStatusCodes;
        final List<MontoyaRequestResponse> attackResponsesWithDistinctCodes;
        final List<ReflectionResult> reflections;
        FollowupResult(boolean f, Integer n, MontoyaRequestResponse rn, MontoyaRequestResponse ar,
                ProbePayloads.Payload tp, Set<Integer> ua, List<MontoyaRequestResponse> ad,
                List<ReflectionResult> refl) {
            foundThirdCode = f; newStatusCode = n; responseWithNewCode = rn; attackResponse = ar;
            triggeringPayload = tp; uniqueAttackStatusCodes = ua == null ? new HashSet<>() : new HashSet<>(ua);
            attackResponsesWithDistinctCodes = ad == null ? new ArrayList<>() : new ArrayList<>(ad);
            reflections = refl == null ? new ArrayList<>() : new ArrayList<>(refl);
        }
        public boolean foundThirdCode() { return foundThirdCode; }
        public Integer getNewStatusCode() { return newStatusCode; }
        public MontoyaRequestResponse getResponseWithNewCode() { return responseWithNewCode; }
        public MontoyaRequestResponse getAttackResponse() { return attackResponse; }
        public ProbePayloads.Payload getTriggeringPayload() { return triggeringPayload; }
        public Set<Integer> getUniqueAttackStatusCodes() { return new HashSet<>(uniqueAttackStatusCodes); }
        public List<MontoyaRequestResponse> getAttackResponsesWithDistinctCodes() { return new ArrayList<>(attackResponsesWithDistinctCodes); }
        public List<ReflectionResult> getReflections() { return new ArrayList<>(reflections); }
    }

    /**
     * Phase 3: iterate all payloads, rebuilding a desync'd attack per payload via
     * {@code attackBuilder}. Returns on the first victim code that is neither an
     * initial Phase-1 code nor the Phase-2 baseline (the "third code"); otherwise
     * summarises the unique attack codes seen. Reflections across all payloads are
     * carried on the result so the caller can report them.
     */
    public FollowupResult runFollowupScans(
            AttackBuilder attackBuilder,
            HttpRequest victim, Set<Integer> initialVictimCodes, int techniqueId,
            Integer consistentBaselineCode) throws InterruptedException {
        int batch = 2;
        Set<Integer> uniqueAttack = new HashSet<>();
        Map<Integer, MontoyaRequestResponse> attackByCode = new HashMap<>();
        List<ReflectionResult> allReflections = new ArrayList<>();
        for (ProbePayloads.Payload payload : ProbePayloads.getAllPayloads()) {
            Thread.sleep(followupDelayMs);
            VictimCheckResult result = runVictimCheckWithCanary(attackBuilder, victim, payload, techniqueId, batch);
            batch++;
            allReflections.addAll(result.getReflections());
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
                    return new FollowupResult(true, code, ev, ar, payload, uniqueAttack,
                            new ArrayList<>(attackByCode.values()), allReflections);
                }
            }
        }
        return new FollowupResult(false, null, null, null, null, uniqueAttack,
                new ArrayList<>(attackByCode.values()), allReflections);
    }

    // ---- Phase 4 + correlation gate + orchestration -----------------------

    public static class DetectionResult {
        public boolean success;
        public AuditIssueSeverity severity;
        public String title = "";
        public String detail = "";
        public final List<MontoyaRequestResponse> evidence = new ArrayList<>();
        public final List<ReflectionResult> reflections = new ArrayList<>();
        static DetectionResult failure() { DetectionResult d = new DetectionResult(); d.success = false; return d; }
    }

    /**
     * Full CL.0 victim validation: Phase 1 (inconsistency) -> Phase 2 (erratic
     * gate) -> Phase 3 (third-code hunt) -> Phase 4 (reproduce) -> correlation
     * gate. Reflections from Phases 1/3/4 are collected onto the result regardless
     * of the status-code outcome; the caller reports them independently.
     */
    public DetectionResult validate(AttackBuilder attackBuilder, HttpRequest victim,
            ProbePayloads.Payload payload, int techniqueId, String hostname,
            String vectorLabel, Set<String> erraticHosts) {

        // Known-erratic host: skip (no Phase 1 run, so nothing to report).
        if (erraticHosts.contains(hostname)) {
            return DetectionResult.failure();
        }

        DetectionResult result = new DetectionResult();

        // Phase 1: victim check with canary injection (batch 1).
        VictimCheckResult victimResult = runVictimCheckWithCanary(attackBuilder, victim, payload, techniqueId, 1);
        result.reflections.addAll(victimResult.getReflections());
        if (!victimResult.foundInconsistency()) {
            return result; // no desync signal; reflections still delivered
        }

        int differingStatusCode = victimResult.getVictimStatusCodes().iterator().next();

        // Phase 2: erratic-domain detection (leading settle sleep is inside).
        ErraticDomainResult erraticResult = detectErraticDomain(victim, differingStatusCode);
        if (erraticResult.isErratic()) {
            // Set.add() is atomic: only the first thread to flag this host gets true,
            // so the informational note is filed exactly once per host.
            if (erraticHosts.add(hostname)) {
                List<MontoyaRequestResponse> erraticEvidence = new ArrayList<>();
                if (!victimResult.getAttackResponses().isEmpty() && victimResult.getAttackResponses().get(0) != null) {
                    erraticEvidence.add(victimResult.getAttackResponses().get(0));
                }
                addTwoDistinctResponses(victimResult.getVictimResponses(), victimResult.getVictimStatusCodes(), erraticEvidence);
                result.success = true;
                result.severity = AuditIssueSeverity.INFORMATION;
                result.title = "Victim Desync: Erratic Host — " + vectorLabel;
                result.detail = "When the victim request was sent alongside the attack, it received inconsistent status codes: "
                    + victimResult.getRawVictimStatusCodes() + "\n\n"
                    + "However, the same inconsistency also appeared in attack-free control bursts, so this host is too "
                    + "erratic to test reliably. The vector could not be evaluated; recorded for visibility.";
                result.evidence.addAll(erraticEvidence);
            }
            return result;
        }

        // Inter-phase sleep.
        try {
            Thread.sleep(phaseDelayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return result;
        }

        // Phase 3: followup scans across all payloads.
        FollowupResult followupResult;
        try {
            followupResult = runFollowupScans(attackBuilder, victim,
                    victimResult.getVictimStatusCodes(), techniqueId,
                    erraticResult.getConsistentStatusCode());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return result;
        }
        result.reflections.addAll(followupResult.getReflections());

        // Evidence: one attack response + two distinct victim responses from Phase 1.
        List<MontoyaRequestResponse> evidence = new ArrayList<>();
        if (!victimResult.getAttackResponses().isEmpty()) {
            MontoyaRequestResponse attackResponse = victimResult.getAttackResponses().get(0);
            if (attackResponse != null) evidence.add(attackResponse);
        }
        addTwoDistinctResponses(victimResult.getVictimResponses(), victimResult.getVictimStatusCodes(), evidence);

        String title;
        String detail;
        AuditIssueSeverity severity;

        // Raw codes for the report (e.g. "[521, 522]" not the synthetic bucket "[599]").
        String victimCodesStr = victimResult.getRawVictimStatusCodes().toString();
        Integer consistentCode = erraticResult.getConsistentStatusCode();
        String consistentCodeStr = consistentCode != null ? String.valueOf(consistentCode) : "unknown";
        boolean phase1HadBucketedCode = victimResult.getVictimStatusCodes().contains(BUCKETED_5XX_ORIGIN);

        if (followupResult.foundThirdCode()) {
            // Confirmed: a third unique victim code was triggered.
            title = "Victim Desync: Confirmed";
            String payloadDesc = "";
            ProbePayloads.Payload triggeringPayload = followupResult.getTriggeringPayload();
            if (triggeringPayload != null) {
                payloadDesc = " (payload ID: " + triggeringPayload.getId() + ")";
            }
            detail = "When the victim request was sent alongside the attack, it received inconsistent status codes: " + victimCodesStr + "\n\n" +
                "When the victim request was sent without the attack, it received a consistent status code of " + consistentCodeStr + "\n\n" +
                "Sending an attack with a different payload" + payloadDesc + " resulted in a third unique victim code of " + followupResult.getNewStatusCode();
            severity = AuditIssueSeverity.HIGH;
            if (followupResult.getAttackResponse() != null) evidence.add(followupResult.getAttackResponse());
            if (followupResult.getResponseWithNewCode() != null) evidence.add(followupResult.getResponseWithNewCode());
        } else {
            // Phase 4: verify the Phase 1 inconsistency reproduces (filter server blips).
            boolean inconsistencyReproduced = false;
            for (int retry = 1; retry <= phase4Retries; retry++) {
                try {
                    Thread.sleep(phaseDelayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return result;
                }
                // Batch 4 (Phase 1 was batch 1; Phase 3 iterated all payloads, batches 2..14).
                VictimCheckResult retryResult = runVictimCheckWithCanary(attackBuilder, victim, payload, techniqueId, 4);
                result.reflections.addAll(retryResult.getReflections());
                if (retryResult.foundInconsistency()) {
                    inconsistencyReproduced = true;
                    break;
                }
            }

            if (!inconsistencyReproduced) {
                // Phase-1 signal seen but not reproduced: most likely a transient blip.
                // Surface it as informational rather than discarding entirely.
                result.success = true;
                result.severity = AuditIssueSeverity.INFORMATION;
                result.title = "Victim Desync: Unreplicated — " + vectorLabel;
                result.detail = "When the victim request was sent alongside the attack, it received inconsistent status codes: " + victimCodesStr + "\n\n"
                    + "When sent without the attack, it received a consistent status code of " + consistentCodeStr + "\n\n"
                    + "The inconsistency did not reproduce across " + phase4Retries + " retries, so it was not confirmed as a "
                    + "desync (most likely a transient server blip). Recorded for visibility.";
                result.evidence.addAll(evidence);
                return result;
            }

            // Suppress weaker (non-Confirmed) findings when Phase 1 saw a bucketed
            // 5xx-origin code: too noisy to report without a third-code witness.
            if (phase1HadBucketedCode) {
                return result;
            }

            Set<Integer> uniqueAttackCodes = followupResult.getUniqueAttackStatusCodes();
            if (uniqueAttackCodes.size() >= 3) {
                // Attack variation: different payloads produced different attack responses.
                title = "Victim Desync: Unconfirmed (Attack Variation)";
                detail = "When the victim request was sent alongside the attack, it received inconsistent status codes: " + victimCodesStr + "\n\n" +
                    "When the victim request was sent without the attack, it received a consistent status code of " + consistentCodeStr + "\n\n" +
                    "We were unable to trigger a third unique victim status code. However, different attack payloads received different responses: " + uniqueAttackCodes + ", suggesting the server processes smuggling payloads differently.";
                severity = AuditIssueSeverity.MEDIUM;
                int addedAttackEvidence = 0;
                for (MontoyaRequestResponse attackResp : followupResult.getAttackResponsesWithDistinctCodes()) {
                    if (attackResp != null && addedAttackEvidence < 3) {
                        evidence.add(attackResp);
                        addedAttackEvidence++;
                    }
                }
            } else {
                // Unconfirmed: no third code, but Phase 1 inconsistency was reproduced.
                title = "Victim Desync: Unconfirmed";
                detail = "When the victim request was sent alongside the attack, it received inconsistent status codes: " + victimCodesStr + "\n\n" +
                    "When the victim request was sent without the attack, it received a consistent status code of " + consistentCodeStr + "\n\n" +
                    "We were unable to trigger a third unique victim status code by sending an attack with a different payload.";
                severity = AuditIssueSeverity.LOW;
            }
        }

        // Correlation gate (pre-report): distinguish a real desync from a
        // time-correlated confound (rebooting/flaky backend). Needs a Phase-2
        // baseline; if unknown we cannot score, so skip. Only runs if enabled.
        Integer baselineCode = erraticResult.getConsistentStatusCode();
        if (correlationEnabled && baselineCode != null) {
            final ProbePayloads.Payload correlationPayload =
                (followupResult.foundThirdCode() && followupResult.getTriggeringPayload() != null)
                    ? followupResult.getTriggeringPayload()
                    : payload;
            CorrelationCheck.Result correlation;
            try {
                correlation = CorrelationCheck.defaults(correlationGapMs).run(
                    baselineCode,
                    cycle -> {
                        VictimCheckResult cr = runVictimCheckWithCanary(
                            attackBuilder, victim, correlationPayload, techniqueId, 100 + cycle);
                        result.reflections.addAll(cr.getReflections());
                        return cr.getVictimStatusCodes();
                    },
                    cycle -> runControlBurst(victim));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return result;
            }

            switch (correlation.verdict()) {
                case DISCARD -> {
                    // Off-baseline code appeared in an attack-free control run.
                    return result;
                }
                case UNREPLICABLE -> {
                    severity = AuditIssueSeverity.LOW;
                    title = title + " (Unreplicable)";
                    detail = detail + "\n\nEnhanced validation: could not reproduce the anomaly under attack (" +
                        correlation.attackDirtyCycles() + "/" + correlation.cyclesRun() +
                        " cycles) and it never appeared in an attack-free control run. Demoted to LOW.";
                }
                case VERIFIED -> {
                    detail = detail + "\n\n✓ Attack-correlated (enhanced validation): the anomaly reproduced under " +
                        "attack in " + correlation.attackDirtyCycles() + "/" + correlation.cyclesRun() +
                        " cycles and never appeared in " + correlation.cyclesRun() + " attack-free control runs.";
                }
            }
        }

        result.success = true;
        result.severity = severity;
        result.title = title + " — " + vectorLabel;
        result.detail = detail;
        result.evidence.addAll(evidence);
        return result;
    }

    /**
     * Adds up to two victim responses with distinct bucketed status codes to the
     * evidence list. Buckets both sides so 5xx-origin codes (stored as
     * {@link #BUCKETED_5XX_ORIGIN}) still match.
     */
    private void addTwoDistinctResponses(List<MontoyaRequestResponse> victimResponses,
                                         Set<Integer> victimStatusCodes,
                                         List<MontoyaRequestResponse> evidence) {
        Set<Integer> addedCodes = new HashSet<>();
        for (MontoyaRequestResponse response : victimResponses) {
            if (response == null || response.response() == null) continue;
            int statusCode = bucketStatusCode(normalizeStatusCode(response));
            if (victimStatusCodes.contains(statusCode) && !addedCodes.contains(statusCode)) {
                evidence.add(response);
                addedCodes.add(statusCode);
                if (addedCodes.size() >= 2) return;
            }
        }
    }
}
