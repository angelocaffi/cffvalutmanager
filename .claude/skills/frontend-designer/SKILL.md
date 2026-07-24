---
name: frontend-designer
description: Delegate a UI/UX/visual-design task in CffVaultManager.Web.Client (new page or component, layout/CSS change, branding/theme polish, responsive fix) to the frontend-designer subagent, running in the background so work continues in parallel.
---

Use this skill whenever the user asks for frontend/UI/visual work on CffVaultManager: a new page or component, styling or layout changes, branding/theme adjustments, visual polish, empty states, responsive fixes, or anything else scoped to `src/CffVaultManager.Web.Client` and the shared theme assets in `src/CffVaultManager.Web/wwwroot`.

**This skill never does the design work itself.** Its entire job is to formalize the handoff to the `frontend-designer` subagent (defined in `.claude/agents/frontend-designer.md`) and dispatch it **in the background**, so the main conversation stays free to keep working on other things while the design task runs in parallel.

## What to do when this skill is invoked

1. Read the arguments passed to the skill (`$ARGUMENTS`, or the free-text request that triggered it) — that is the task description.
2. Gather only the context the subagent cannot derive on its own: exact file paths already known from the current conversation, any constraint the user already stated (colors, copy, pages affected), and whether this is a brand-new page/component or a change to an existing one. Do not re-explore the whole repo yourself — the subagent has its own read access and its own project-context brief baked into its agent definition.
3. Call the `Agent` tool with:
   - `subagent_type: "frontend-designer"`
   - `description`: a short 3-5 word label for the task
   - `prompt`: a self-contained brief — the task itself, the relevant context gathered in step 2, and an explicit reminder that it must verify the result live in a browser before considering the task done (its own agent definition already covers the mechanics of that, so you don't need to repeat the how — just make sure the *what* is unambiguous).
   - Leave `run_in_background` at its default (**do not set it to `false`**) — the whole point of this skill is that the design work proceeds in parallel, not blocking the current turn.
4. Tell the user, in one or two sentences, that the frontend-designer subagent has been dispatched in the background and will report back when done. Do not narrate what you expect it to produce, and do not fabricate or predict its results — the completion notification arrives later, as a separate turn.
5. If the user's request is ambiguous in a way that would materially change the design (e.g. "make the vault page nicer" with no indication of *what* about it), ask a brief clarifying question yourself before dispatching — don't hand an underspecified brief to the subagent and let it guess.

## When not to use this skill

- Backend, API, crypto, or data-model tasks — those are out of the frontend-designer subagent's scope by design (see its agent definition).
- Trivial one-line copy or class-name tweaks the user explicitly asks you to "just do quickly" inline — use judgment; this skill is for design tasks substantial enough to benefit from a dedicated, verified pass, not a rubber stamp for every CSS edit.
