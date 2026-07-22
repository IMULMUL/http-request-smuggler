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
