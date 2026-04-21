# AI Working Rules

Use this as the shared low-token entry point for Claude Code, Codex, and other AI coding assistants working in PacMap.

## Read Order

1. Read `CODEX.md`.
2. Read `PROJECT_CONTEXT.md`.
3. Read `FILE_MAP.md`.
4. Inspect the likely files from `FILE_MAP.md` first.
5. Broaden search only when the file map does not cover the task.

## Working Rules

- Prefer minimal, surgical edits over rewrites.
- Inspect the current implementation before changing behavior.
- Preserve existing behavior unless the user explicitly asks for a behavior change.
- Use `FILE_MAP.md` to avoid broad codebase searches when likely locations are already known.
- Keep summaries concise and focused on decisions, changed files, and verification.
- Do not add databases, vector search, embeddings, RAG servers, MCPs, or external AI tooling for this context layer.
- Treat `README.md` as product/user documentation and these AI files as assistant workflow context.
- Follow `AGENTS.md` / `CLAUDE.md` GitNexus rules when editing code symbols: run impact analysis before symbol edits and detect changes before committing when tools are available.
- If GitNexus MCP tools are unavailable, state that explicitly before code edits and use normal repo inspection.

## Claude Code And Codex

Claude Code and Codex can both use these files. To avoid conflicts, do not have both agents editing the same files at the same time.

Safe patterns:

- Use Claude Code for implementation and Codex for audit, review, or scoped patch planning.
- Put agents on separate branches when both need to edit code.
- Split work by file ownership when running agents in parallel.
- Before merging parallel work, review diffs for overlapping changes in `client/src/App.jsx`, which currently holds most app orchestration.
