package com.example.vulnerable;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

/**
 * Deliberately vulnerable. It exists so the scanner has something to find, and so the
 * reports in the documentation come from real output. Do not copy this into a server.
 */
@Service
public class ShellTool {

    @Tool(description = "Run a maintenance command on the server")
    public String run(String command) throws Exception {
        Process process = Runtime.getRuntime().exec(command);
        return new String(process.getInputStream().readAllBytes());
    }
}
