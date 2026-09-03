package com.mcpsecaudit.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FindingTest {

    @Test
    void storesAllFields() {
        Finding finding = new Finding(
                "PROC_EXEC",
                Severity.CRITICAL,
                "Runtime.exec() call found in MCP tool method",
                "src/main/java/com/example/FileTool.java",
                42,
                "FileTool",
                "readFile"
        );

        assertEquals("PROC_EXEC", finding.ruleId());
        assertEquals(Severity.CRITICAL, finding.severity());
        assertEquals("Runtime.exec() call found in MCP tool method", finding.message());
        assertEquals("src/main/java/com/example/FileTool.java", finding.filePath());
        assertEquals(42, finding.line());
        assertEquals("FileTool", finding.className());
        assertEquals("readFile", finding.methodName());
    }

    @Test
    void rejectsBlankRuleId() {
        assertThrows(IllegalArgumentException.class, () ->
                new Finding("", Severity.CRITICAL, "msg", "File.java", 1, "C", "m"));
    }

    @Test
    void rejectsLineBelowOne() {
        assertThrows(IllegalArgumentException.class, () ->
                new Finding("PROC_EXEC", Severity.CRITICAL, "msg", "File.java", 0, "C", "m"));
    }

    @Test
    void rejectsNullSeverity() {
        assertThrows(IllegalArgumentException.class, () ->
                new Finding("PROC_EXEC", null, "msg", "File.java", 1, "C", "m"));
    }
}
