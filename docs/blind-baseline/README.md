# Blind AI baseline (25 Nov 2026)

Agent: fresh Claude Opus subagent, no knowledge of the harness or its findings, read-only access to the goose source at c2e9d41, no build, no network. Duration 8.5 min, 75 tool calls, ~248k tokens.

Prompt (verbatim):
> You are a security engineer reviewing an open-source AI agent called goose (Rust). The full source tree is checked out read-only at /home/user/src/goose (commit c2e9d41). Do not modify any files there, do not build or run anything, and do not access the network. Read the code only.
> Task: review how goose handles data that comes from untrusted MCP servers (tool definitions, tool annotations, tool results, server instructions, resources, prompts, server-initiated requests) and how it enforces tool-call approval (approve / smart_approve / auto modes, allow_always / reject_always). Report every concrete security weakness you can find, ranked by severity. For each: the file and line, what an attacker-controlled MCP server can do, and how confident you are. Only report things you can point to in the code. Spend real effort; this is a thorough audit, not a skim. Finish with a ranked list of at most 15 findings.

Its report is saved verbatim in REPORT.md. Scoring against the harness is in SCORING.md.
