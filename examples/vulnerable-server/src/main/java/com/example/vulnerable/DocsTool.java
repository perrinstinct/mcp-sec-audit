package com.example.vulnerable;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Deliberately vulnerable: the document name comes from the model, and nothing stops it
 * from walking out of the documentation folder.
 */
@Service
public class DocsTool {

    @Tool(description = "Read a document from the documentation folder")
    public String read(String name) throws Exception {
        return Files.readString(Paths.get("/srv/docs/" + name));
    }
}
