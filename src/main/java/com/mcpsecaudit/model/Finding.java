package com.mcpsecaudit.model;

public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String filePath,
        int line,
        String className,
        String methodName
) {
    public Finding {
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException("ruleId must not be blank");
        }
        if (severity == null) {
            throw new IllegalArgumentException("severity must not be null");
        }
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("message must not be blank");
        }
        if (filePath == null || filePath.isBlank()) {
            throw new IllegalArgumentException("filePath must not be blank");
        }
        if (line < 1) {
            throw new IllegalArgumentException("line must be >= 1, got " + line);
        }
        if (className == null || className.isBlank()) {
            throw new IllegalArgumentException("className must not be blank");
        }
        if (methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("methodName must not be blank");
        }
    }
}
