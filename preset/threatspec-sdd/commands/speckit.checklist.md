---
description: "ThreatSpec companion: offer a security checklist built from SR acceptance criteria"
strategy: append
---

## ThreatSpec: Security Checklist Type

If the user asks for a `security` checklist (or the feature has `SR-###` requirements and no checklist type was specified, offer it):

- Source items from `FEATURE_DIR/threat-model.yaml`: one item per `SR-###` acceptance scenario ("Is the Given/When/Then scenario for SR-003 covered by a test? [Completeness, Spec §SR-003]"), one item per mitigation touchpoint ("Does src/agent/prompt_builder.py delimit retrieved content as untrusted? [Traceability, threat-model.yaml#mitigation.context-isolation]"), and one item per open threat without a decision ("Has threat.model-extraction been mitigated or explicitly accepted with an owner and expiry? [Risk, threat-model.yaml#threat.model-extraction]").
- Keep the checklist's purpose: it validates that the security requirements are complete, unambiguous, and traceable; it does not execute tests.
- Name the file `checklists/security.md`.
