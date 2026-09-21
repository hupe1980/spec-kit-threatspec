---
description: "ThreatSpec companion: inventory SR-### and defer evidence judgment to ThreatSpec converge"
strategy: append
---

## ThreatSpec: Security Requirements in Convergence

When `spec.md` contains `SR-###` requirements or `FEATURE_DIR/threat-model.yaml` exists:

- Include every `SR-###` in the intent inventory alongside `FR-###` and `SC-###`.
- Do not judge whether an `SR-###` is satisfied from task checkboxes or code comments. If `FEATURE_DIR/security/convergence-report.json` exists and is newer than the last change to `tasks.md`, take each requirement's verdict from it (`verified` means met; anything else is unmet). Otherwise, recommend running `__SPECKIT_COMMAND_THREATSPEC_CONVERGE__` first and treat unverified `SR-###` as unmet.
- When ThreatSpec has already appended a `## Phase N: Security Convergence` section to `tasks.md` for the same gaps, do not duplicate those tasks; reference them instead.
- Trace any convergence task you append for an `SR-###` with the `[SR-###]` tag so ThreatSpec can find it.
