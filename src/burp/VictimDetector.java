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
