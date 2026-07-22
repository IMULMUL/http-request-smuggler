package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utilities for generating and detecting canary strings in HTTP responses.
 *
 * Canary format: wrtzllsk{techniqueId}x{batch}x{position}
 * - wrtzllsk: unique prefix for fast pre-check
 * - techniqueId: the technique being validated
 * - batch: batch number (1 for initial, 2+ for followups)
 * - position: 0-indexed position of attack request in batch
 */
public class CanaryUtils {

    public static final String CANARY_PREFIX = "wrtzllsk";

    private static final Pattern CANARY_PATTERN = Pattern.compile(
        CANARY_PREFIX + "(\\d+)x(\\d+)x(\\d+)"
    );

    // Paths that should use query parameter injection instead of path replacement
    private static final java.util.Set<String> SPECIAL_PATHS = java.util.Set.of(
        "/",           // Root path
        "/favicon.ico" // Well-known file
    );

    /**
     * Generate a canary string for the given technique, batch, and position.
     */
    public static String generateCanary(int techniqueId, int batch, int position) {
        return CANARY_PREFIX + techniqueId + "x" + batch + "x" + position;
    }

    /**
     * Fast pre-check: does text contain the canary prefix?
     * Use this before the more expensive regex parsing.
     */
    public static boolean containsCanaryPrefix(String text) {
        return text != null && text.contains(CANARY_PREFIX);
    }

    /**
     * Find and parse the first canary in the given text.
     * Returns null if no canary found.
     */
    public static ParsedCanary findCanary(String text) {
        if (text == null || !containsCanaryPrefix(text)) {
            return null;
        }

        Matcher matcher = CANARY_PATTERN.matcher(text);
        if (matcher.find()) {
            return new ParsedCanary(
                Integer.parseInt(matcher.group(1)),
                Integer.parseInt(matcher.group(2)),
                Integer.parseInt(matcher.group(3))
            );
        }
        return null;
    }

    /**
     * Inject canary into a payload body.
     *
     * Strategy depends on path type:
     * - Generic paths (/asdf, /invalid, /0-9): Replace path with /wrtzllsk{canary}
     * - Special paths (/, /favicon.ico, /%2f): Add ?xyz=wrtzllsk{canary}
     * - Paths with existing query: Append &xyz=wrtzllsk{canary}
     * - Payloads without recognizable path: Return unchanged
     *
     * @param payloadBody The payload body string
     * @param techniqueId The technique ID
     * @param batch The batch number
     * @param position The position in batch
     * @return Modified payload with canary injected
     */
    public static String injectCanaryIntoPayload(String payloadBody, int techniqueId, int batch, int position) {
        if (payloadBody == null || payloadBody.isEmpty()) {
            return payloadBody;
        }

        // Parse request line: METHOD PATH HTTP/VERSION
        int firstSpace = payloadBody.indexOf(' ');
        if (firstSpace < 0) {
            return payloadBody; // No space = no recognizable request line
        }

        int secondSpace = payloadBody.indexOf(' ', firstSpace + 1);
        if (secondSpace < 0) {
            // May have only METHOD PATH without HTTP version
            secondSpace = payloadBody.indexOf('\r');
            if (secondSpace < 0) {
                secondSpace = payloadBody.length();
            }
        }

        String method = payloadBody.substring(0, firstSpace);
        String pathPart = payloadBody.substring(firstSpace + 1, secondSpace);
        String rest = payloadBody.substring(secondSpace);

        // Check if it looks like a path (starts with /)
        if (!pathPart.startsWith("/")) {
            return payloadBody; // Not a recognizable path
        }

        String canary = generateCanary(techniqueId, batch, position);
        String newPath;

        // Check for existing query string
        int queryIndex = pathPart.indexOf('?');
        if (queryIndex >= 0) {
            // Has query string - append parameter
            newPath = pathPart + "&xyz=" + canary;
        } else {
            // No query string - check if special path or generic
            if (isSpecialPath(pathPart)) {
                // Special path - add query parameter
                newPath = pathPart + "?xyz=" + canary;
            } else {
                // Generic path - replace entirely
                newPath = "/" + canary;
            }
        }

        return method + " " + newPath + rest;
    }

    /**
     * Check if path is "special" (should use query param instead of replacement).
     */
    private static boolean isSpecialPath(String path) {
        // Check exact matches for special paths
        if (SPECIAL_PATHS.contains(path)) {
            return true;
        }
        // Also check paths containing URL encoding (% followed by hex)
        if (path.contains("%")) {
            return true;
        }
        return false;
    }

    /**
     * Determine if a found canary represents a reflection (from an earlier request).
     *
     * A canary is a reflection if:
     * - Same technique AND (batch < currentBatch OR (batch == currentBatch AND position < currentPosition))
     *
     * @param found The parsed canary found in a response
     * @param currentTechniqueId The technique ID of the current request
     * @param currentBatch The batch number of the current request
     * @param currentPosition The position of the current request in its batch
     * @return true if this is a reflection from an earlier request
     */
    public static boolean isReflection(ParsedCanary found, int currentTechniqueId, int currentBatch, int currentPosition) {
        if (found.techniqueId != currentTechniqueId) {
            return false; // Different technique - use isCrossTechniqueReflection instead
        }

        // Same technique - check if from earlier batch or earlier position in same batch
        if (found.batch < currentBatch) {
            return true;
        }
        if (found.batch == currentBatch && found.position < currentPosition) {
            return true;
        }
        return false;
    }

    /**
     * Determine if a found canary is from a different technique (cross-technique reflection).
     *
     * @param found The parsed canary found in a response
     * @param currentTechniqueId The technique ID of the current request
     * @return true if the canary is from a different technique
     */
    public static boolean isCrossTechniqueReflection(ParsedCanary found, int currentTechniqueId) {
        return found.techniqueId != currentTechniqueId;
    }

    /**
     * Parsed canary containing technique ID, batch, and position.
     */
    public static class ParsedCanary {
        public final int techniqueId;
        public final int batch;
        public final int position;

        public ParsedCanary(int techniqueId, int batch, int position) {
            this.techniqueId = techniqueId;
            this.batch = batch;
            this.position = position;
        }

        @Override
        public String toString() {
            return "ParsedCanary{techniqueId=" + techniqueId + ", batch=" + batch + ", position=" + position + "}";
        }
    }
}
