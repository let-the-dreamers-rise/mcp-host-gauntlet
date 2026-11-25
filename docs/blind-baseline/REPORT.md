# Blind Opus audit of goose c2e9d41 (verbatim report, 25 Nov 2026)

Paths relative to crates/ unless they start with ui/.

1. HIGH: In SmartApprove mode, a server's own `readOnlyHint: true` annotation auto-approves its tools. goose/src/permission/permission_inspector.rs:52-64, 172-175; goose/src/agents/state_machine/inference_preparation.rs:54-57. Confidence high.
2. HIGH: Approvals are keyed only by "<extension name>__<tool>", not bound to the server or tool definition (goose/src/agents/state_machine/tool_approval.rs:109-119; goose/src/config/permission.rs:77-194). (a) rug pull after Always Allow via tools/list_changed; (b) name squatting inherits always_allow grants; (c) stale grants: removing an extension over ACP (goose/src/acp/server/extensions.rs:81-87) does not clear permissions, only the CLI path (goose-cli/src/commands/configure.rs:1443-1444) does.
3. HIGH (Auto) / MEDIUM: MCP App UI can inject user-role chat messages without user action (ui/desktop/src/components/McpApps/McpAppRenderer.tsx:747-763). Confidence medium-high.
4. MEDIUM-HIGH: server `instructions` go verbatim into the system prompt, no length cap, no untrusted delimiting (oi-kit-agent/src/mcp/lease.rs:454-474; goose/src/agents/state_machine/ops_toolcalling.rs:591-600; goose/src/agents/prompt_manager.rs:116-122). Design choice.
5. MEDIUM: permission check and dispatch use different tool names, so "never allow" can be sidestepped with a mangled name like `github.delete_repo` (permission_inspector.rs:157-163 vs oi-kit-agent/src/mcp/operation.rs:98-113, mcp/mod.rs:425-465). Confidence high on the code.
6. MEDIUM: Auto mode ignores Always Deny (permission_inspector.rs:160) while ACP on_get_tools still shows NeverAllow (goose/src/acp/server/tools.rs:31-46); MCP App on_call_tool (tools.rs:118-133) skips every inspector in Auto mode.
7. MEDIUM: SmartApprove LLM judge sees only the server-chosen tool name and arguments, no description or annotations (goose/src/permission/permission_judge.rs:92-117); fails closed on errors.
8. MEDIUM: MCP prompts hidden from the user and prompt names shadowable across extensions via HashMap iteration order (goose/src/agents/state_machine/ops_mcp_prompts.rs:126-131, 212; lease.rs:373-399); embedded resource text in prompts not tag-sanitized (oi-kit-provider-types/src/conversation/message.rs:757-759).
9. [withheld: reported privately to the goose maintainers; published after a fix or agreed disclosure]
10. MEDIUM-LOW: hidden Unicode tags stripped inconsistently: tool descriptions, input schemas and annotation titles go to the provider unchanged (goose/src/agents/reply_parts.rs:206-234); only Bedrock sanitizes.
11. MEDIUM-LOW: stdio server stderr buffered without limit (oi-kit-agent/src/mcp/stdio.rs:78-85).
12. LOW-MEDIUM: server can forge `platform_notification` in tool-result _meta (ops_toolcalling.rs:98-107,611; not stripped by extension_manager/mod.rs:208-211 or mcp/mod.rs:481-505), desktop then launches/refreshes/closes apps (ui/desktop/src/utils/platform_events.ts:27-53).
13. LOW-MEDIUM: all MCP App HTML served from one origin with allow-same-origin (goose/src/acp/mcp_app_proxy.rs:351-374; templates/mcp_app_proxy.html:204).
14. LOW: elicitation routing trusts server-supplied session and tool-call IDs (oi-kit-agent/src/mcp/client.rs:252-256,277-282; action_required_manager.rs:122-142).
15. LOW: fail-open checks: erroring inspector skipped (goose/src/tool_inspection.rs:107-114); only text blocks size-capped in large_response_handler.rs:22-56, spill files never deleted; malware_check.rs:85-96 checks the first positional npx arg, so `npx --package=evil-pkg bin` checks `bin`.

Held up (per the agent): extension-mutation / subagent meta stripped; trusted MCP-App meta removed; goose_extension owner meta overwritten; platform tools win over same-named MCP tools; expired tool lists rejected; sampling not implemented; tool-result text and resources tag-sanitized.
Out of scope notes: docker_exec passes secrets as -e KEY=VALUE (stdio.rs:50-56); session ID and working dir sent in _meta to every server (client.rs:1013-1060).
