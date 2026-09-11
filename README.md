# mcp-sec-audit

[![CI](https://github.com/perrinstinct/mcp-sec-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/perrinstinct/mcp-sec-audit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Static analysis for Spring AI MCP servers. It finds `@Tool` methods that expose risky
capabilities — shelling out, reading the filesystem, calling the network — and tells you
which of them a model can actually steer.

Think `npm audit`, but for the tools your MCP server hands to a model.

```
$ mcp-sec-audit ./my-mcp-server

Scanned: ./my-mcp-server
At: 2026-09-11T11:57:19Z

3 finding(s), grouped by tool method:

[CRITICAL] PROC_EXEC  src/main/java/com/example/ShellTool.java:7  ShellTool#run
  Runtime.exec() runs a command built from tool parameter 'command' - the model chooses what is executed

[HIGH] MISSING_AUTH  src/main/java/com/example/ShellTool.java:5  ShellTool#run
  MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed, and the project is reachable over HTTP (spring-ai-starter-mcp-server-webmvc dependency in my-mcp-server/pom.xml)

[MEDIUM] FS_ACCESS  src/main/java/com/example/DocsTool.java:8  DocsTool#changelog
  Files.readString() gives direct filesystem access

Summary: 1 CRITICAL, 1 HIGH, 1 MEDIUM
```

[Why](#why) · [Install](#install) · [Usage](#usage) · [Use in CI](#use-in-ci) ·
[Rules](#rules) · [Existing codebases](#adopting-it-on-an-existing-codebase) ·
[Suppressing findings](#suppressing-findings) · [Limits](#what-it-deliberately-does-not-do) ·
[Building](#building)

## Why

The parameters of an MCP tool are filled in by **the model** — and the model reads your
tickets, your documents, the web pages you hand it. A tool parameter is therefore exactly
as trustworthy as an HTTP request parameter. Almost nobody treats it that way.

On top of that, the Model Context Protocol does not require authentication, and Spring AI
tools are just annotated methods. Nothing in the framework stops a `@Tool` that runs
`Runtime.exec()` from being reachable by any client that can talk to the server. That is
fine on a local stdio process and considerably less fine once the same code ships behind
`spring-ai-starter-mcp-server-webmvc`.

Existing MCP security products are gateways aimed at enterprises. This is the small end of
the market: a single binary you run in CI, no platform to adopt.

## Install

Download the binary for your platform from the [latest release](../../releases/latest):

```bash
chmod +x mcp-sec-audit && sudo mv mcp-sec-audit /usr/local/bin/
```

Linux x86_64 and macOS on both architectures get a native binary. Every release also ships
`mcp-sec-audit.jar`, which runs anywhere with Java 21 or later:

```bash
java -jar mcp-sec-audit.jar <path>
```

Or build it yourself — see [Building](#building).

## Usage

```bash
mcp-sec-audit <dir>                              # scan a source tree
mcp-sec-audit <file>.java                        # scan a single file
mcp-sec-audit <path> --json report.json          # also write a structured report
mcp-sec-audit <path> --sarif out.sarif           # SARIF 2.1.0, for GitHub Code Scanning
mcp-sec-audit <path> --fail-on-critical          # exit 1 on any CRITICAL finding (for CI)
mcp-sec-audit <path> --write-baseline .baseline  # record what is already there
mcp-sec-audit <path> --baseline .baseline        # then report only what is new
```

| Option | Effect |
| --- | --- |
| `--json <file>` | Write the full report as JSON |
| `--sarif <file>` | Write a SARIF 2.1.0 report for GitHub Code Scanning |
| `--baseline <file>` | Ignore findings recorded in this baseline |
| `--write-baseline <file>` | Record the current findings as a baseline and exit |
| `--fail-on-critical` | Exit with status 1 if any CRITICAL finding is present |
| `--include-tests` | Scan `src/test` sources too |
| `-V`, `--version` | Print the version |
| `-h`, `--help` | Print usage |

Exit codes: `0` success, `1` the `--fail-on-critical` gate tripped, `2` bad input.

`target/`, `build/`, `out/` and `.git/` are always skipped, as is `src/test` unless you ask
for it — though a file named explicitly on the command line is always scanned.

The console groups findings of the same rule within one tool method, since validating a
parameter once usually clears all of them. The JSON and SARIF reports always keep every
location.

## Use in CI

The action downloads the right binary for the runner and runs it:

```yaml
- uses: actions/checkout@v7

- uses: perrinstinct/mcp-sec-audit@v0.1.4
  with:
    path: .
    fail-on-critical: true
```

| Input | Default | Effect |
| --- | --- | --- |
| `path` | `.` | Directory or `.java` file to scan |
| `version` | `latest` | Release to download — pin it for reproducible builds |
| `fail-on-critical` | `false` | Fail the job on any CRITICAL finding |
| `include-tests` | `false` | Also scan `src/test` |
| `baseline-file` | — | Ignore findings recorded in this baseline |
| `sarif-file` | — | Write a SARIF report to this path |
| `json-file` | — | Write a JSON report to this path |

To surface findings in the Security tab and as inline pull request annotations:

```yaml
- uses: perrinstinct/mcp-sec-audit@v0.1.4
  with:
    sarif-file: mcp-sec-audit.sarif

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-sec-audit.sarif
```

CRITICAL and HIGH map to SARIF `error`, MEDIUM to `warning`, LOW to `note`; on GitHub,
`error` alerts can fail a pull request check. Code scanning is free on public repositories;
private ones need GitHub Advanced Security.

Run the tool from the repository root so the paths in the report match your checkout — URIs
are made relative to the working directory.

On a runner with no native binary — Linux arm64, Windows — the action falls back to the jar,
which needs a JDK in the job:

```yaml
- uses: actions/setup-java@v6
  with: { distribution: temurin, java-version: '21' }

- uses: perrinstinct/mcp-sec-audit@v0.1.4
```

Without the action, call the binary directly:

```yaml
- run: mcp-sec-audit . --fail-on-critical --sarif mcp-sec-audit.sarif
```

## Rules

| Rule | Model-controlled | Hardcoded | What it flags |
| --- | --- | --- | --- |
| `PROC_EXEC` | CRITICAL | HIGH | `Runtime.getRuntime().exec(...)`, `new ProcessBuilder(...)` |
| `FS_ACCESS` | HIGH | MEDIUM | `new File(...)` and friends, `Files.*`, `Paths.*` |
| `NET_ACCESS` | HIGH | MEDIUM | `Socket`, `URL`, `HttpClient`, and Spring's `RestClient` / `RestTemplate` / `WebClient` — including clients injected as fields |
| `MISSING_AUTH` | HIGH / LOW | — | No `@PreAuthorize`, `@Secured` or `@RolesAllowed` on the method or its class |

### Severity follows exploitability

Because tool parameters come from the model, the scanner asks whether one of them actually
**reaches** the risky call, propagating through local variables along the way:

```java
@Tool String read(String path) {
    return Files.readString(Paths.get(path));                  // HIGH   - the model picks the file
}

@Tool String changelog() {
    return Files.readString(Paths.get("/opt/CHANGELOG.md"));   // MEDIUM - hardcoded
}
```

Both touch the filesystem; only the first is an arbitrary file read. The finding names the
parameter responsible, even when it arrives through intermediate variables.

### MISSING_AUTH follows deployment

An unprotected tool only matters if something can reach it. For each tool, the scanner reads
**its own module's** build file and Spring configuration for evidence of HTTP exposure — a
web starter dependency, `spring.ai.mcp.server.stdio=false` — then its ancestor modules, but
never its siblings, since one module's dependencies say nothing about another's.

With evidence, an unprotected tool is **HIGH**. Without it, the server is most likely a
local stdio process where `@PreAuthorize` would not apply anyway, so the finding drops to
**LOW** and names the module the evidence came from.

## Adopting it on an existing codebase

Turning the tool on a mature project usually means a wall of findings and a red build on day
one. Record what is already there, then gate only on what comes next:

```bash
mcp-sec-audit . --write-baseline .mcp-sec-audit-baseline
```

Commit that file, and pass it from then on:

```bash
mcp-sec-audit . --baseline .mcp-sec-audit-baseline --fail-on-critical
```

Existing findings stay quiet; anything new fails the build. Entries look like this, so a
reviewer can see what a pull request is asking to ignore:

```
FS_ACCESS|HIGH|src/main/java/com/example/DocumentProvider.java|DocumentProvider#readDocContents
```

Line numbers are deliberately absent — an edit above a finding would otherwise invalidate
the whole file. Severity is part of the entry, so a finding escalating from MEDIUM to HIGH,
meaning a tool parameter now reaches the sink, resurfaces despite the baseline.

## Suppressing findings

Put a marker in a comment on — or inside — the tool method:

```java
// mcp-sec-audit:ignore PROC_EXEC - argument is a fixed allowlisted binary
@Tool
public String runBackup() {
    return Runtime.getRuntime().exec("/usr/local/bin/backup").toString();
}
```

A bare `// mcp-sec-audit:ignore` suppresses every rule on that method. Listing rule ids
suppresses only those.

## What it deliberately does not do

This is syntactic analysis of your sources. Findings are a starting point for review, not a
verdict, and the boundaries are worth stating plainly:

- **It only sees your code.** If a tool calls a library that shells out internally, the
  scanner cannot see it. Catching that would mean analysing the whole dependency graph.
- **It matches annotations by simple name.** `@Tool` is `@Tool` regardless of which package
  it came from, so an unrelated annotation with the same name will be picked up. Symbol
  resolution would fix this at the cost of needing your full classpath.
- **Deployment detection reads text, not a resolved build.** Markers are matched as
  substrings, so a dependency only listed under `dependencyManagement`, or inherited from a
  parent resolved through the repository rather than the directory above, is read the same
  way or missed entirely.
- **It reasons about one method at a time.** Taint is tracked inside the tool method only.
  A tool that delegates its risky work to a private helper is not followed, and neither is a
  parameter stored in a field and used later.
- **It does not detect sanitizers.** Code that validates a parameter against an allowlist
  before using it is still reported. This is deliberate: wrongly assuming a value was
  validated would hide a real vulnerability, while a false alarm only costs you a
  `mcp-sec-audit:ignore` comment.

## Building

Requires JDK 21 and Maven. For the native binary, GraalVM 21.

```bash
mvn test                # run the test suite
mvn package             # jar, including the portable target/*-all.jar
mvn -Pnative package    # native binary at target/mcp-sec-audit (needs GraalVM)
```

Reflection metadata for the native image lives in
`src/main/resources/META-INF/native-image/`, generated by GraalVM's `native-image-agent`
against real scans — regenerate it rather than editing it by hand. The JavaParser AST
classes are the exception: they are registered wholesale, because JavaParser reflects over
its own metamodel and any syntax a trace never saw would build fine and then crash at
runtime. Re-register them when bumping JavaParser.

## Roadmap

- Optional symbol resolution, for projects willing to supply a classpath
- More sinks: SQL, deserialization, reflection
- Native binaries for Linux arm64 and Windows, which the jar currently serves

## License

Apache-2.0. See [LICENSE](LICENSE).
