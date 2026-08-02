# AGENTS.md

These rules are MANDATORY for opencode and any AI agent operating in this repository. Read this file before executing any command.

## Non-Negotiable Rules

- **High-Care Processing Standard** — Every task must be processed with the highest standard of care and caution. Double-check before acting.
- **No Unauthorized Changes** — Never destroy, delete, rearrange, or modify anything without explicit user approval. This includes files, directories, git history, and configuration.
- **No Over-Assumption** — Stay strictly focused on the user's request. Do NOT assume the user wants changes to other parts of the system beyond the explicit request. When in doubt, ask first.
- **Never Reduce or Break Features** — Reducing existing features, causing features to stop working, or introducing regressions is STRICTLY FORBIDDEN. All changes must be backward-compatible and additive only, unless the user explicitly approves a breaking change.
- **Git Operations Require Explicit Permission** — `git add`, `git commit`, `git push`, and pushing tags (e.g. `git push origin <tag>`) may ONLY be performed when the user explicitly requests them. Never perform these operations proactively or as a follow-up without being asked.

## Required Workflow

- Before making changes: read AGENTS.md and the relevant skill files.
- Before executing any command that modifies the system: state what you are about to do and why.
- Never commit, push, or tag unless the user explicitly asks.
