package com.mcpsecaudit.scanner;

import com.github.javaparser.ast.body.MethodDeclaration;

import java.nio.file.Path;

public record ToolMethod(
        Path sourceFile,
        String filePath,
        String className,
        String methodName,
        int line,
        MethodDeclaration methodDeclaration
) {
    public ToolMethod {
        if (sourceFile == null) {
            throw new IllegalArgumentException("sourceFile must not be null");
        }
        if (filePath == null || filePath.isBlank()) {
            throw new IllegalArgumentException("filePath must not be blank");
        }
        if (className == null || className.isBlank()) {
            throw new IllegalArgumentException("className must not be blank");
        }
        if (methodName == null || methodName.isBlank()) {
            throw new IllegalArgumentException("methodName must not be blank");
        }
        if (line < 1) {
            throw new IllegalArgumentException("line must be >= 1, got " + line);
        }
        if (methodDeclaration == null) {
            throw new IllegalArgumentException("methodDeclaration must not be null");
        }
    }
}
