# mcp-sec-audit

Static analysis for Spring AI MCP servers. It finds `@Tool` methods that expose risky
capabilities — shelling out, reading the filesystem, calling the network — and tells you
which of them are reachable without any authorization.

Think `npm audit`, but for the tools your MCP server hands to a model.

```
$ mcp-sec-audit ./my-mcp-server

Scanned: ./my-mcp-server
At: 2026-09-05T09:38:48Z

3 finding(s):

[CRITICAL] PROC_EXEC  src/main/java/com/example/ShellTool.java:24  ShellTool#run
  Runtime.exec() call allows arbitrary OS command execution

[HIGH] MISSING_AUTH  src/main/java/com/example/ShellTool.java:22  ShellTool#run
  MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed, and the project is
  reachable over HTTP (spring-ai-starter-mcp-server-webmvc dependency in pom.xml)

[MEDIUM] FS_ACCESS  src/main/java/com/example/DocsTool.java:41  DocsTool#read
  Files.readString() gives direct filesystem access

Summary: 1 CRITICAL, 1 HIGH, 1 MEDIUM
```

## Why

The Model Context Protocol does not require authentication, and Spring AI tools are just
annotated methods. Nothing in the framework stops a `@Tool` that runs `Runtime.exec()` from
being reachable by any client that can talk to the server. That is fine on a local stdio
process and considerably less fine once the same code ships behind
`spring-ai-starter-mcp-server-webmvc`.

Existing MCP security products are gateways aimed at enterprises. This is the small end of
the market: a single binary you run in CI, no platform to adopt.

## Install

Download the binary for your platform from the [latest release](../../releases/latest), then:

```bash
chmod +x mcp-sec-audit && sudo mv mcp-sec-audit /usr/local/bin/
```

Or build it yourself — see [Building](#building).

## Usage

```bash
mcp-sec-audit <path>                       # scan a source tree
mcp-sec-audit <path> --json report.json    # also write a structured report
mcp-sec-audit <path> --fail-on-critical    # exit 1 on any CRITICAL finding (for CI)
mcp-sec-audit <path> --include-tests       # also scan src/test (skipped by default)
```

| Option | Effect |
| --- | --- |
| `--json <file>` | Write the full report as JSON |
| `--fail-on-critical` | Exit with status 1 if any CRITICAL finding is present |
| `--include-tests` | Scan `src/test` sources too |
| `-V`, `--version` | Print the version |
| `-h`, `--help` | Print usage |

`target/`, `build/`, `out/` and `.git/` are always skipped.

## Rules

| Rule | Severity | What it flags |
| --- | --- | --- |
| `PROC_EXEC` | CRITICAL | `Runtime.getRuntime().exec(...)`, `new ProcessBuilder(...)` |
| `MISSING_AUTH` | HIGH / LOW | No `@PreAuthorize`, `@Secured` or `@RolesAllowed` on the method or its class |
| `FS_ACCESS` | MEDIUM | `new File(...)` and friends, `Files.*`, `Paths.*` |
| `NET_ACCESS` | MEDIUM | `Socket`, `URL`, `HttpClient`, and Spring's `RestClient` / `RestTemplate` / `WebClient` — including clients injected as fields |

`MISSING_AUTH` is graded on how the server is actually exposed. The scanner reads your build
files and Spring configuration for evidence of HTTP exposure (a web starter dependency,
`spring.ai.mcp.server.stdio=false`). With evidence, an unprotected tool is **HIGH**. Without
it, the server is most likely a local stdio process where `@PreAuthorize` would not apply
anyway, so the finding drops to **LOW** and says so.

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

## Use in CI

```yaml
- name: Audit MCP tools
  run: mcp-sec-audit . --fail-on-critical --json mcp-sec-audit.json
```

## What it deliberately does not do

This is syntactic analysis of your sources. Being explicit about the boundaries:

- **It only sees your code.** If a tool calls a library that shells out internally, the
  scanner cannot see it. Catching that would mean analysing the whole dependency graph.
- **It matches annotations by simple name.** `@Tool` is `@Tool` regardless of which package
  it came from, so an unrelated annotation with the same name will be picked up. Symbol
  resolution would fix this at the cost of needing your full classpath.
- **Deployment detection is a heuristic.** A repository that contains a web starter anywhere
  is treated as HTTP-exposed, even if the MCP server module itself is stdio-only.
- **It reasons about one method at a time.** A tool that delegates its risky work to a
  private helper in the same class is not followed.

Findings are a starting point for review, not a verdict.

## Building

Requires JDK 21 and Maven. For the native binary, GraalVM 21.

```bash
mvn test                                  # run the test suite
mvn -Pnative package                      # build target/mcp-sec-audit (needs GraalVM)
```

Reflection metadata for the native image lives in
`src/main/resources/META-INF/native-image/`. It was generated by running the tool under
GraalVM's `native-image-agent` against a real scan; regenerate it rather than editing it by
hand if you add a library that reflects.

## Roadmap

- Publish as a reusable GitHub Action
- Per-module deployment detection instead of per-repository
- Configurable severity thresholds and a findings baseline file
- Optional symbol resolution for projects willing to supply a classpath

## License

Apache-2.0. See [LICENSE](LICENSE).
