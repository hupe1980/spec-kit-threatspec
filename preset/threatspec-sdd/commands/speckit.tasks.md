---
description: "ThreatSpec companion: tag tasks with [SR-###] for every security requirement"
strategy: append
---

## ThreatSpec: Security Requirements

If `spec.md` contains a `### Security Requirements` section (between `<!-- threatspec:begin -->` and `<!-- threatspec:end -->`) or `FEATURE_DIR/threat-model.yaml` exists, treat every `SR-###` there as a requirement that needs buildable work:

- Generate at least one task per `SR-###` that implements the mitigation at the touchpoints named in `threat-model.yaml` (`mitigations[].attributes.touchpoints`), and one test task that implements its Given/When/Then acceptance scenario.
- Tag those tasks with `[SR-###]` immediately after the story tag (a task serving several requirements uses one tag with a comma list, `[SR-001, SR-003]`); only bracket tags count, a prose mention such as "SR-001 through SR-016" links nothing, e.g. `- [ ] T031 [P] [US1] [SR-003] Delimit retrieved documents as untrusted in src/agent/prompt_builder.py`.
- Place security tasks in the phase of the user story they protect; put cross-cutting ones (rate limiting, logging, secrets) in the Foundational phase.
- Do not invent `SR-###` ids; use only those present in the spec or model. If a security requirement cannot be mapped to any story, add it to the Foundational phase and say so in the completion report.
