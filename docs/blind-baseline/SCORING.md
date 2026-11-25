# Blind AI audit vs. the harness (goose c2e9d41, 25 Nov 2026)

The question Ash's past rejections raise: "couldn't they just run AI on it themselves?" So a fresh Opus agent got the same code and an audit prompt, with no knowledge of the harness (README.md has the prompt; REPORT.md has its verbatim output). Each of its 15 findings is scored below against what the real goose binary did under the harness.

| # | Blind finding (its severity) | Harness scenario | Result on the real binary | Verdict |
|---|---|---|---|---|
| 1 | smart_approve trusts `readOnlyHint` (HIGH) | A08 | FAIL | Real, but already known and declined upstream (#10970) |
| 2a | allow_always survives a rug pull (HIGH) | A03 | FAIL | Real, already known and declined (#10094) |
| 2b | name squatting inherits grants (HIGH) | A10 | PASS: the call routes to the tool the user approved | Not reproduced in the tested form |
| 2c | ACP extension removal keeps grants (HIGH) | none | not tested | Unverified (upstream PR #11481 touches this) |
| 3 | MCP App UI injects chat messages | none (desktop UI) | not tested | Unverified |
| 4 | server instructions verbatim in system prompt | B02 (tags only) | PASS for hidden tags | Design choice, not a host bug |
| 5 | "never allow" sidestepped by a mangled name (MEDIUM, confidence high) | A11 | **PASS**: goose recovers the name before the permission check (ops_llm.rs) | **Refuted** |
| 6 | auto mode ignores Always Deny (MEDIUM) | D02 | **FAIL, 5/5** | **Confirmed, new** (no upstream issue found) |
| 7 | smart_approve judge sees name only | none | not tested | Unverified |
| 8 | prompts hidden / shadowable | none | not tested | Unverified |
| 9 | [withheld] | embargoed scenario | **FAIL, 5/5**; control passes | **Confirmed, new**, reported privately |
| 10 | hidden Unicode tags in tool definitions (MEDIUM-LOW) | A05, B01 | **FAIL**: 45/45 characters reach the model, OpenAI and Anthropic paths | **Confirmed, new** (Bedrock-only fix in #11121) |
| 11 | unbounded stderr buffer | none | not tested | Unverified |
| 12 | forged `platform_notification` | none (desktop UI) | not tested | Unverified |
| 13 | MCP Apps share one origin | none (desktop UI) | not tested | Unverified |
| 14 | elicitation routing trusts server ids | A12 (different property) | A12 PASS | Unverified as stated |
| 15 | assorted fail-open checks | none | not tested | Unverified |

Found by the harness and not by the blind audit: C01 (an external server named `developer` gets an approval card reading "developer: shell", the namespace of goose's built-in). It is low severity. The harness also checked 19 promises that hold on the real binary. A code reading can only claim those; it cannot show them.

## What this says, honestly

1. **AI reading does find these bugs.** All three new results (Unicode in definitions, a withheld one, Never Allow in auto mode) are on the blind list. Spiral's Loupe already runs this kind of audit (148 merged goose PRs credit it). The proposal must not claim the harness finds things AI can't.
2. **AI reading cannot tell which findings are real.** One of its "confidence high" findings (#5) is false on the real binary. Ten of its 15 are unverified hypotheses. A maintainer still has to reproduce each one.
3. **AI reading misranks.** The two findings it ranked HIGH and could be tested (#1, #2a) are already known and declined upstream. The three that turned out new and real were ranked MEDIUM to MEDIUM-LOW (#6, #9, #10).
4. **The harness turns a hypothesis into a one-command reproduction and a permanent regression check.** It took about 1 to 4 s per scenario to confirm or refute each one. Every fix then stays checked on every commit, on every provider path.

The pitch therefore pairs the two: AI (Loupe, or anyone's) proposes, and the gauntlet executes, confirms or refutes, and keeps the fix from regressing.
