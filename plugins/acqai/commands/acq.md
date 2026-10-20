---
description: Get ready for ACQ AI (sign in when needed), or ask it a question with your docs as the context.
---

Run the acq skill.

With a task, a question is one tool call: the `acqai` tool `ask`, with the
whole question and `yes: true`. It gets ready itself (Playwright, the login,
the route, the chat the send continues; it opens the sign-in window when the
login is out, and no browser at all while the saved login is fresh), sends
over HTTP with the saved login, and returns the answer. Do not call `ready`
first, and do not dry-run first: the live send stops itself on a private name
or a chat from the other app and says so. When a result says the job is still
running, call `wait` with that job until it ends.

With no task (bare `/acq`, or only flags after stripping `-y` / `--yes`), call
`ready`, show its result, and stop.

Call the `acqai` tools, not the shell: in Cowork the shell runs in a VM that
cannot reach the browser. When the tools are missing, say the plugin's
connector did not start, and stop.

With a task, run the loop:

- Shape the task into one question ACQ AI can answer with mechanics.
- Show the person what is about to go out.
- `ask` it, read the answer, and refine it with a follow-up question or two in the same conversation, each one another `ask`, each bringing in what the person's docs add.
- Report what ACQ AI said and what you added, and sort the result: adopt, later, or drop.

Before you shape the question, look for `ACQ-CONTEXT.md` in the working
folder. When it exists, include it in whole as the standing business context
of every question (the skill says how).

Flags in `$ARGUMENTS`:
- `-y` / `--yes`: this flag is the yes for the whole run. Show the first question once, then `ask` it and up to two follow-ups with `yes: true` on each. Do not wait for another yes in chat. Do not ask "Send it?" or "Reply yes." When the loop ends, write every Adopt change into the files now (including a new offer or page when the task calls for one), record the outcome, and stop. Do not ask which pile to keep or whether to edit.
- No task (bare `/acq`, or only flags): run `ready` and stop.

Without `-y`, wait for a yes before each `ask`, and wait again before file edits or recording the outcome. The exception is the plugin's auto_send install option: when `${user_config.auto_send}` reads `true`, every run is a `-y` run, with no wait in chat.

Rules:
- One `ask` per question. A question argument never skips the ready step: `ask` runs it.
- Nothing is sent without a yes. On a plain `/acq <task>`, that is one yes in chat per send. On `/acq -y <task>`, the `-y` is that yes for the sends and the Adopt edits.
- Client names and transcripts stay home, and so does anything the person calls private.
- Never present your own analysis as ACQ AI's. If the send fails, stop and say why.

Arguments pass through: $ARGUMENTS
