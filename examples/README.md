# Examples

`vulnerable-server` is a deliberately insecure Spring AI MCP server: a tool that shells out
with a parameter the model chooses, a tool that reads a file path the model chooses, and no
authorization anywhere. It is never built.

It exists for two reasons: the scanner needs something to find when it runs on its own
repository, so the reports shown in the documentation are real output, and it gives the
GitHub Code Scanning integration something to display.

```bash
mcp-sec-audit examples/vulnerable-server
```

Do not copy any of it into a real server.
