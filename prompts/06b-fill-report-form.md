# Phase 4d: Fill the Report Form

Put a READY report into the platform's report form in the human's own Chrome, with the Claude in
Chrome extension, and stop there. The human reads the form and presses submit. The agent never
submits.

## Before you start
1. **READY only.** The latest pre-submit review (06) of this ID must be READY, in
   `notes/case-file.md` or earlier in this session. If it isn't, run the review first and stop.
2. **One at a time.** On a program's first report, or with 1-2 reports already open, fill only the
   strongest one (`CLAUDE.md`, one report before feedback).
3. **The extension.** Load its tools in one ToolSearch call:
   `select:mcp__claude-in-chrome__tabs_context_mcp,mcp__claude-in-chrome__tabs_create_mcp,mcp__claude-in-chrome__navigate,mcp__claude-in-chrome__read_page,mcp__claude-in-chrome__find,mcp__claude-in-chrome__form_input,mcp__claude-in-chrome__computer,mcp__claude-in-chrome__file_upload,mcp__claude-in-chrome__browser_batch`.
   If none load, Claude in Chrome isn't connected. Tell the human to install the extension from the
   Chrome Web Store and run `/chrome` in Claude Code (or start it with `claude --chrome`), hand over
   `reports/<ID>-v2.md` to paste by hand, and stop.
4. **Read** `reports/<ID>-v2.md`, the platform's fields in `reference/form-reference.md` (without
   it, the platform's file in the plugin's `reference/`), the program URL in `STRATEGY.md`, any
   required report template or AI disclosure line in `notes/program-rules.md`, and the evidence
   files the report cites.
5. **No secrets in the form.** If the report carries a live session cookie, a bearer token, a
   password or another person's data, stop: redact it in the report and run the review again.

## Fill
6. Call `tabs_context_mcp`, then open a new tab with `tabs_create_mcp`. Leave the human's other tabs
   alone.
7. Go to the program page and open its new-report form. Claude in Chrome is for the platform only:
   the scope guard blocks it from the target, which is tested in the Playwright browser. If the
   form only opens from a "Submit report" button, tell the human first that this click opens the
   empty form: the scope guard will ask them to allow it.
8. If the platform asks for a login, a captcha or 2FA, ask the human to do it in that tab and wait.
   Never type credentials.
9. Fill every field the form reference lists, from the report and nothing else:
   - **Asset** and **weakness / CWE** from the dropdowns. If no option matches the report, leave the
     field empty and say so.
   - **Severity**: the report's CVSS vector, metric by metric when the platform has a calculator.
   - **Title, description and steps, impact**: each in its own field, exactly as v2 has them. Don't
     rewrite, shorten or add claims. If a text doesn't fit a field's limit, stop and say which.
   - **Program template**: if the program pre-fills a field with a template, replace it with the
     report text, keeping the headings the program requires.
   - **Attachments**: upload the evidence files the report cites with `file_upload`. If an upload
     is refused, list those files for the human to attach.

   Use `form_input` with refs from `read_page` or `find` for plain fields; click into markdown
   editors and type. Never press Enter in a one-line field: it can send the form.
10. **Leave alone**: submit, send, save or publish buttons; consent and terms checkboxes (disclosure
    policy, "I agree"); collaborator and bounty-split settings. Those are the human's. Describe
    every click as what it does: the scope guard asks the human before a click described as a submit.
11. **Check.** Read the page back and compare every field with the report: title, asset, weakness,
    severity, text, attachments. Fix whatever differs.

## Hand over
12. Leave the tab open on the filled form and tell the human, briefly:
    - which tab and platform;
    - each field and what it holds (one line each; long texts by their first words);
    - the attachments uploaded, and any they must attach themselves;
    - what is left for them: the consent boxes, anything you couldn't fill, then read the form and
      press submit.
13. Once they've submitted, ask for the report's URL or ID. Record it in `notes/submissions-log.md`
    and mark the finding REPORTED in `notes/case-file.md`.
