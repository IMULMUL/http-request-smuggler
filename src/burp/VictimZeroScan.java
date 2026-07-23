package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * CL.0 victim scan: same vectors as ImplicitZeroScan, but detects desync via
 * victim-request inconsistency + canary reflection (ported from validator2's VictimScan).
 */
public class VictimZeroScan extends SmuggleScanBox {

    private final Set<String> erraticHosts = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Integer> techniqueIds = new ConcurrentHashMap<>();
    private final AtomicInteger nextTechniqueId = new AtomicInteger(0);

    VictimZeroScan(String name) {
        super(name);
        // Same vector set as ImplicitZeroScan.
        scanSettings.importSettings(DesyncBox.sharedSettings);
        scanSettings.importSettings(DesyncBox.sharedPermutations);
        scanSettings.importSettings(DesyncBox.clPermutations);
        scanSettings.importSettings(DesyncBox.h2Permutations);
        scanSettings.importSettings(DesyncBox.h1Permutations);
        // Heavyweight-scan settings (5s sleeps per the design).
        scanSettings.register("heavyweight: phase delay ms", 5000);
        scanSettings.register("heavyweight: followup delay ms", 5000);
        scanSettings.register("heavyweight: phase4 retries", 5);
        scanSettings.register("heavyweight: enable correlation check", true);
        scanSettings.register("heavyweight: correlation gap ms", 5000);
    }

    /** Stable int id for a permutation name (index in first-seen order). */
    private int techniqueIdFor(String technique) {
        return techniqueIds.computeIfAbsent(technique, k -> nextTechniqueId.getAndIncrement());
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

        // Build a fully-formed desync'd attack per (payload, batch, position): inject the canary
        // at the given byte position, then apply the CL desync LAST so it is not recomputed away.
        VictimDetector.AttackBuilder attackBuilder = (p, batch, position) -> {
            String body = CanaryUtils.injectCanaryIntoPayload(p.getBody(), techniqueId, batch, position);
            byte[] attackBytes = Utilities.fixContentLength(Utilities.setBody(reqBase, body));
            attackBytes = DesyncBox.applyDesync(attackBytes, "Content-Length", technique);
            HttpRequest hr = Utilities.buildMontoyaReq(attackBytes, service);
            return fHttp2 ? hr.withAddedHeader("X-Http2", "1") : hr;
        };

        ProbePayloads.Payload payload = ProbePayloads.getDefaultPayload();

        // Victim = clean cache-busted baseline (no smuggle, no desync), built from reqBase so it
        // rides the SAME transport as the attack. reqBase already carries the HTTP/2 -> HTTP/1.1
        // request-line downgrade and the Connection handling; building from raw baseReq would leave
        // an HTTP/2 request line on an HTTP/1 send for HTTP/1 vectors (a broken victim).
        byte[] victimBytes = Utilities.addCacheBuster(reqBase, null);
        HttpRequest victim = Utilities.buildMontoyaReq(victimBytes, service);
        if (forceHTTP2) victim = victim.withAddedHeader("X-Http2", "1");

        VictimDetector detector = new VictimDetector(
            Utilities.globalSettings.getInt("heavyweight: phase delay ms"),
            Utilities.globalSettings.getInt("heavyweight: followup delay ms"),
            Utilities.globalSettings.getInt("heavyweight: phase4 retries"),
            Utilities.globalSettings.getBoolean("heavyweight: enable correlation check"),
            Utilities.globalSettings.getInt("heavyweight: correlation gap ms"));

        VictimDetector.DetectionResult result;
        try {
            result = detector.validate(
                attackBuilder, victim, payload, techniqueId,
                service.getHost(), technique, erraticHosts);
        } catch (Exception e) {
            Utilities.out("VictimZeroScan: unexpected error validating " + service.getHost() + " (" + technique + "): " + e);
            return false;
        }

        // Reflections are reported independently of the status-code finding.
        for (ReflectionResult refl : result.reflections) reportReflection(refl);

        if (!result.success) return false;
        fileIssue(result.title, result.detail, result.severity, result.evidence);
        // Informational findings are filed but must NOT mark the vector/host as "done":
        // returning true feeds BulkScan.hostsToSkip and, with "skip obsolete permutations"
        // enabled, breaks the permutation loop (SmuggleScanBox), which would let a weak
        // note short-circuit a later vector that could confirm a real desync.
        return result.severity != AuditIssueSeverity.INFORMATION;
    }

    private void reportReflection(ReflectionResult refl) {
        List<MontoyaRequestResponse> ev = new ArrayList<>();
        if (refl.getOriginalRequest() != null) ev.add(refl.getOriginalRequest());
        if (refl.getReflectingResponse() != null) ev.add(refl.getReflectingResponse());
        fileIssue(refl.getTitle(), refl.getDetail(), refl.getSeverity(), ev);
    }

    private void fileIssue(String title, String detail, AuditIssueSeverity severity, List<MontoyaRequestResponse> evidence) {
        // MontoyaRequestResponse implements HttpRequestResponse directly.
        burp.api.montoya.http.message.HttpRequestResponse[] arr =
            evidence.toArray(new burp.api.montoya.http.message.HttpRequestResponse[0]);
        String background = "The site appears vulnerable to HTTP request smuggling / desync: a crafted request can "
            + "interfere with other requests processed on the same upstream connection. Detected here via "
            + "victim-request status inconsistency and/or canary reflection.";
        String remediation = "Ensure the front-end and back-end agree on request boundaries (consistent "
            + "Content-Length / Transfer-Encoding handling). See "
            + "https://portswigger.net/research/http-terminator, "
            + "https://portswigger.net/research/browser-powered-desync-attacks and "
            + "https://portswigger.net/web-security/request-smuggling.";
        Report report = new Report(title, detail, background, remediation, severity, arr);
        Utilities.montoyaApi.siteMap().add(report.getIssue());
    }
}
