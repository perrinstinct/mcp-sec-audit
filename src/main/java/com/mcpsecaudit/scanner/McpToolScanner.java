package com.mcpsecaudit.scanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class McpToolScanner {

    private static final Set<String> TOOL_ANNOTATIONS = Set.of("McpTool", "Tool");

    public List<ToolMethod> scan(Path rootDirectory) throws IOException {
        try (Stream<Path> paths = Files.walk(rootDirectory)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .flatMap(javaFile -> findToolMethods(rootDirectory, javaFile).stream())
                    .collect(Collectors.toList());
        }
    }

    private List<ToolMethod> findToolMethods(Path rootDirectory, Path javaFile) {
        CompilationUnit compilationUnit;
        try {
            compilationUnit = StaticJavaParser.parse(javaFile);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to parse " + javaFile, e);
        }

        String relativePath = rootDirectory.relativize(javaFile).toString();

        return compilationUnit.findAll(MethodDeclaration.class).stream()
                .filter(this::isToolMethod)
                .map(method -> toToolMethod(relativePath, method))
                .collect(Collectors.toList());
    }

    private boolean isToolMethod(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .anyMatch(annotation -> TOOL_ANNOTATIONS.contains(annotation.getNameAsString()));
    }

    private ToolMethod toToolMethod(String relativePath, MethodDeclaration method) {
        String className = method.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("<unknown>");
        int line = method.getBegin().map(position -> position.line).orElse(-1);

        return new ToolMethod(relativePath, className, method.getNameAsString(), line, method);
    }
}
