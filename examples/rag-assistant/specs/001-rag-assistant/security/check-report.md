## ThreatSpec Check Report

Feature: `001-rag-assistant` · Model: `threat-model.yaml` · Enforcement: `warn`

| ID | Check | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| F1 | C12 | MEDIUM | `threat-model.yaml#threat.needs-clarification-document-visibility` | Threat 'threat.needs-clarification-document-visibility' needs clarification: [NEEDS CLARIFICATION: what visibility levels does Document have, which principals may read each, and is visibility enforced per user, per group, or org-wide?] | Resolve the question in the spec (clarify command), then re-run the model command |
| F2 | C12 | MEDIUM | `threat-model.yaml#threat.needs-clarification-model-hosting` | Threat 'threat.needs-clarification-model-hosting' needs clarification: [NEEDS CLARIFICATION: where is the language model hosted (in-house or third-party provider), and do documents and conversations leave the corporate boundary?] | Resolve the question in the spec (clarify command), then re-run the model command |
| F3 | C12 | MEDIUM | `threat-model.yaml#threat.needs-clarification-retention` | Threat 'threat.needs-clarification-retention' needs clarification: [NEEDS CLARIFICATION: how long are Conversations and ticket-creation logs retained, and who may read them?] | Resolve the question in the spec (clarify command), then re-run the model command |
| F4 | C12 | MEDIUM | `threat-model.yaml#threat.needs-clarification-ticket-api-identity` | Threat 'threat.needs-clarification-ticket-api-identity' needs clarification: [NEEDS CLARIFICATION: how does the assistant authenticate to the ticket API, and is the reporter asserted by the assistant's service identity or derived from a delegated user token?] | Resolve the question in the spec (clarify command), then re-run the model command |
| F5 | C6 | LOW | `threat-model.yaml#requirements` | 16 requirements have no verification entry yet (implementation not started): SR-001, SR-002, SR-003, SR-004, SR-005, SR-006, SR-007, SR-008, SR-009, SR-010, SR-011, SR-012, SR-013, SR-014, SR-015, SR-016 | Expected before implementation; run the converge command afterwards |

**Metrics**

- threats: 19
- mitigations: 16
- requirements: 16
- requirements with tasks: 0
- requirements verified: 0
- decisions: 0
- threats by severity: critical 1, high 6, low 1, medium 11
- findings: medium 4, low 1

**Next actions**

- Resolve HIGH findings before implementation; MEDIUM may proceed with a note.
