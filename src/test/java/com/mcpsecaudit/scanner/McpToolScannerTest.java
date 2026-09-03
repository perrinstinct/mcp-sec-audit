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
}
