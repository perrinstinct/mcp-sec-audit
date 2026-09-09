package com.mcpsecaudit.scanner;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class McpToolScanner {

    private static final Set<String> TOOL_ANNOTATIONS = Set.of("McpTool", "Tool");

    private static final Set<String> EXCLUDED_DIRECTORIES = Set.of("target", "build", "out", ".git");

    private final JavaParser javaParser = new JavaParser(
            new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
    );

    private final boolean includeTestSources;

    public McpToolScanner() {
        this(false);
    }

    public McpToolScanner(boolean includeTestSources) {
        this.includeTestSources = includeTestSources;
    }

    /** Accepts a directory to walk, or a single .java file named explicitly. */
    public List<ToolMethod> scan(Path target) throws IOException {
        if (Files.isRegularFile(target)) {
            Path file = target.toAbsolutePath();
            return findToolMethods(file.getParent(), file);
        }
        return scanDirectory(target);
    }

    private List<ToolMethod> scanDirectory(Path rootDirectory) throws IOException {
        try (Stream<Path> paths = Files.walk(rootDirectory)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> isScannable(rootDirectory.relativize(path)))
                    .flatMap(javaFile -> findToolMethods(rootDirectory, javaFile).stream())
                    .collect(Collectors.toList());
        }
    }

    private boolean isScannable(Path relativePath) {
        for (Path segment : relativePath) {
            if (EXCLUDED_DIRECTORIES.contains(segment.toString())) {
                return false;
            }
        }
        return includeTestSources || !isTestSource(relativePath);
    }

    private boolean isTestSource(Path relativePath) {
        String normalized = relativePath.toString().replace('\\', '/');
        return normalized.contains("src/test/");
    }

    private List<ToolMethod> findToolMethods(Path rootDirectory, Path javaFile) {
        ParseResult<CompilationUnit> result;
        try {
            result = javaParser.parse(javaFile);
        } catch (IOException e) {
            System.err.println("Skipping " + javaFile + ": " + e.getMessage());
            return List.of();
        }

        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            System.err.println("Skipping " + javaFile + ": " + result.getProblems());
            return List.of();
        }

        CompilationUnit compilationUnit = result.getResult().get();
        String relativePath = rootDirectory.relativize(javaFile).toString();

        return compilationUnit.findAll(MethodDeclaration.class).stream()
                .filter(this::isToolMethod)
                .map(method -> toToolMethod(javaFile.toAbsolutePath(), relativePath, method))
                .collect(Collectors.toList());
    }

    private boolean isToolMethod(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .anyMatch(annotation -> TOOL_ANNOTATIONS.contains(annotation.getNameAsString()));
    }

    private ToolMethod toToolMethod(Path sourceFile, String relativePath, MethodDeclaration method) {
        String className = method.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("<unknown>");
        int line = method.getBegin().map(position -> position.line).orElse(-1);

        return new ToolMethod(sourceFile, relativePath, className, method.getNameAsString(), line, method);
    }
}
