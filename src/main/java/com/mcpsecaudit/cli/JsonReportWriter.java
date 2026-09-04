package com.mcpsecaudit.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.mcpsecaudit.model.ScanReport;

import java.io.IOException;
import java.nio.file.Path;

public class JsonReportWriter {

    private final ObjectMapper mapper;

    public JsonReportWriter() {
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public void write(ScanReport report, Path outputFile) throws IOException {
        mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile.toFile(), report);
    }
}
