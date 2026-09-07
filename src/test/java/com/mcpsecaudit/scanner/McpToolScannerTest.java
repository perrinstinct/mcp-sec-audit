package com.mcpsecaudit.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpToolScannerTest {

    @Test
    void findsMethodsAnnotatedWithToolOrMcpTool(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("FileTool.java"), """
                package com.example;

                public class FileTool {

                    @Tool
                    public String readFile(String path) {
                        return path;
                    }

                    @McpTool
                    public void deleteFile(String path) {
                    }

                    public void notATool() {
                    }
                }
                """);

        McpToolScanner scanner = new McpToolScanner();
        List<ToolMethod> toolMethods = scanner.scan(tempDir);

        assertEquals(2, toolMethods.size());
        assertTrue(toolMethods.stream().anyMatch(t -> t.methodName().equals("readFile")));
        assertTrue(toolMethods.stream().anyMatch(t -> t.methodName().equals("deleteFile")));
        assertTrue(toolMethods.stream().noneMatch(t -> t.methodName().equals("notATool")));
    }

    @Test
    void capturesClassNameAndLineNumber(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Sample.java"), """
                package com.example;

                public class Sample {

                    @Tool
                    public void doSomething() {
                    }
                }
                """);

        McpToolScanner scanner = new McpToolScanner();
        List<ToolMethod> toolMethods = scanner.scan(tempDir);

        assertEquals(1, toolMethods.size());
        ToolMethod found = toolMethods.get(0);
        assertEquals("Sample", found.className());
        assertEquals("doSomething", found.methodName());
        assertEquals(5, found.line());
        assertEquals("Sample.java", found.filePath());
    }

    @Test
    void ignoresFilesWithNoToolAnnotations(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Plain.java"), """
                package com.example;

                public class Plain {
                    public void hello() {
                    }
                }
                """);

        McpToolScanner scanner = new McpToolScanner();
        List<ToolMethod> toolMethods = scanner.scan(tempDir);

        assertTrue(toolMethods.isEmpty());
    }

    @Test
    void skipsUnparseableFilesInsteadOfFailingTheWholeScan(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Broken.java"), "this is not valid java {{{ @@@");

        Files.writeString(tempDir.resolve("Valid.java"), """
                package com.example;

                public class Valid {

                    @Tool
                    public void doSomething() {
                    }
                }
                """);

        McpToolScanner scanner = new McpToolScanner();
        List<ToolMethod> toolMethods = scanner.scan(tempDir);

        assertEquals(1, toolMethods.size());
        assertEquals("doSomething", toolMethods.get(0).methodName());
    }

    @Test
    void skipsTestSourcesAndBuildOutputByDefault(@TempDir Path tempDir) throws IOException {
        String toolSource = """
                package com.example;

                public class SomeTool {

                    @Tool
                    public void doSomething() {
                    }
                }
                """;

        writeJava(tempDir.resolve("src/main/java/com/example/SomeTool.java"), toolSource);
        writeJava(tempDir.resolve("src/test/java/com/example/SomeToolTest.java"), toolSource);
        writeJava(tempDir.resolve("target/generated-sources/com/example/Generated.java"), toolSource);
        writeJava(tempDir.resolve("build/generated/com/example/Generated.java"), toolSource);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);

        assertEquals(1, toolMethods.size());
        assertTrue(toolMethods.get(0).filePath().contains("src/main/java"));
    }

    @Test
    void includesTestSourcesWhenAskedTo(@TempDir Path tempDir) throws IOException {
        String toolSource = """
                package com.example;

                public class SomeTool {

                    @Tool
                    public void doSomething() {
                    }
                }
                """;

        writeJava(tempDir.resolve("src/main/java/com/example/SomeTool.java"), toolSource);
        writeJava(tempDir.resolve("src/test/java/com/example/SomeToolTest.java"), toolSource);

        List<ToolMethod> toolMethods = new McpToolScanner(true).scan(tempDir);

        assertEquals(2, toolMethods.size());
    }

    private void writeJava(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
