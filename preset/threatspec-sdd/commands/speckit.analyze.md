---
description: "ThreatSpec companion: inventory SR-### in the coverage analysis"
strategy: append
---

## ThreatSpec: Security Requirements Coverage

When `spec.md` contains `SR-###` requirements (the ThreatSpec-managed `### Security Requirements` block) or `FEATURE_DIR/threat-model.yaml` exists:

- Add every `SR-###` to the requirements inventory with the same stable-key treatment as `FR-###` and `SC-###`.
- In Coverage Gaps, report each `SR-###` with zero tasks (a task counts when it carries the `[SR-###]` tag or is listed under `requirements[].tasks` in `threat-model.yaml`). Severity: HIGH, or CRITICAL when the requirement mitigates a threat whose `attributes.severity` is `high` or `critical`.
- In Ambiguity Detection, flag `SR-###` statements without a measurable object or without a Given/When/Then acceptance scenario.
- Include `SR-###` rows in the Coverage Summary Table.
- For structural gaps inside the threat model itself (dangling references, threats without mitigation, expired decisions), do not re-derive them here; recommend `__SPECKIT_COMMAND_THREATSPEC_CHECK__`, which computes them deterministically.
