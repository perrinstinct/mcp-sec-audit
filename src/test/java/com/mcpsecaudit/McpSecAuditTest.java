package com.mcpsecaudit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class McpSecAuditTest {

    @Test
    void exposesItsOwnName() {
        assertEquals("mcp-sec-audit", McpSecAudit.NAME);
    }
}
