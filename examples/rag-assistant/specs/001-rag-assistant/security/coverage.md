## ThreatSpec Coverage — 001-rag-assistant

Surfaces present: agent-autonomy, audit-relevant, authentication, authorization, delegated-identity, external-input, human-in-loop, llm-inference, network-boundary, persistent-model-input, persistent-store, retrieval-path, untrusted-content-to-model, user-facing-generation, write-capable-tool

### Techniques

| Profile | Technique | Category | Surfaces | Present | State | Threats | Reason |
|---|---|---|---|---|---|---|---|
| stride | credential-theft | Spoofing | authentication | yes | **threat** | `threat.sso-session-replay` |  |
| stride | identity-spoofing | Spoofing | authentication, network-boundary | yes | **uncovered** | — |  |
| stride | data-tampering-in-transit | Tampering | network-boundary | yes | **threat** | `threat.in-transit-tampering` |  |
| stride | data-tampering-at-rest | Tampering | persistent-store | yes | **threat** | `threat.kb-out-of-band-tamper` |  |
| stride | injection | Tampering | external-input | yes | **threat** | `threat.question-backend-injection` |  |
| stride | missing-audit-trail | Repudiation | audit-relevant | yes | **threat** | `threat.ticket-log-unattributable` |  |
| stride | sensitive-data-exposure | Information Disclosure | — | yes | **threat** | `threat.conversation-log-exposure` |  |
| stride | cross-tenant-leak | Information Disclosure | shared-tenant | no | **not-applicable** | — | no shared-tenant surface: spec.md describes one internal assistant over 'our knowledge base'; no tenants are named |
| stride | resource-exhaustion | Denial of Service | external-input | yes | **threat** | `threat.question-flood` |  |
| stride | broken-access-control | Elevation of Privilege | authorization | yes | **threat** | `threat.kb-unauthorized-publish` |  |
| stride | privilege-escalation-via-config | Elevation of Privilege | persistent-store | yes | **no-threat-detected** | — | persistent-store surface present, but spec.md names no runtime configuration or secret store written by the feature; the ticket API credential is covered by threat.needs-clarification-ticket-api-identity and threat.ticket-tool-overprivileged |
| llm | prompt-injection-direct | Tampering | llm-inference | yes | **threat** | `threat.direct-prompt-injection` |  |
| llm | prompt-injection-indirect | Tampering | untrusted-content-to-model | yes | **threat** | `threat.corpus-prompt-injection` |  |
| llm | sensitive-information-disclosure | Information Disclosure | llm-inference | yes | **threat** | `threat.ticket-content-overshare` |  |
| llm | excessive-agency | Elevation of Privilege | llm-inference | yes | **threat** | `threat.ticket-tool-overprivileged` |  |
| llm | model-supply-chain | Tampering | model-supply-chain | no | **not-applicable** | — | no model-supply-chain surface: spec.md names no model, adapter, or dataset that is downloaded or pinned (model hosting itself is unclarified, see threat.needs-clarification-model-hosting) |
| llm | training-data-poisoning | Tampering | persistent-model-input | yes | **no-threat-detected** | — | persistent-model-input surface present (authors publish to the knowledge base), but spec.md names no training, fine-tuning, or evaluation dataset; corpus poisoning of the retrieval path is recorded under threat.corpus-prompt-injection |
| llm | unbounded-consumption | Denial of Service | cost-bearing-inference | no | **not-applicable** | — | no cost-bearing-inference surface recorded: spec.md does not state where the model is hosted or whether inference is metered; request-volume exhaustion is recorded under threat.question-flood (stride/resource-exhaustion) |
| llm | misinformation | Tampering | user-facing-generation | yes | **threat** | `threat.fabricated-citation` |  |
| llm | hidden-context-exposure | Information Disclosure | llm-inference | yes | **no-threat-detected** | — | llm-inference surface present, but spec.md names no system prompt, memory, or user profile in the model context; retrieved documents are the only hidden context and their exposure is recorded under threat.visibility-bypass-via-retrieval |
| llm | vector-embedding-weakness | Information Disclosure | retrieval-path | yes | **threat** | `threat.visibility-bypass-via-retrieval` |  |
| llm | improper-output-handling | Tampering | output-to-sink | no | **not-applicable** | — | no output-to-sink surface: spec.md names no shell, SQL, path, template, or HTML sink for model output; ticket fields written through the ticket API are covered by threat.ticket-tool-misuse |
| llm | model-extraction | Information Disclosure | llm-inference | yes | **no-threat-detected** | — | llm-inference surface present, but the model and its instructions are not assets named in spec.md; users are SSO-authenticated employees and query volume is bounded by threat.question-flood mitigations |
| agent | goal-hijack | Tampering | agent-autonomy | yes | **threat** | `threat.goal-hijack-ticket` |  |
| agent | tool-misuse | Elevation of Privilege | write-capable-tool | yes | **threat** | `threat.ticket-tool-misuse`, `threat.unconfirmed-ticket` |  |
| agent | identity-privilege-abuse | Elevation of Privilege | delegated-identity | yes | **threat** | `threat.reporter-spoofing` |  |
| agent | agentic-supply-chain | Tampering | external-skill-supply | no | **not-applicable** | — | no external-skill-supply surface: the only tool named in spec.md is the organisation's own ticket API (FR-004); no skills, plugins, or MCP servers are installed from external sources |
| agent | unexpected-code-execution | Elevation of Privilege | code-execution | no | **not-applicable** | — | no code-execution surface: spec.md gives the assistant no ability to run code or commands; its only action is ticket creation (FR-004) |
| agent | memory-context-poisoning | Tampering | agent-memory | no | **not-applicable** | — | no agent-memory surface: Conversation is defined as the user's session (spec.md#Key-Entities); no memory persisted across sessions is named |
| agent | insecure-inter-agent-communication | Spoofing | multi-agent | no | **not-applicable** | — | no multi-agent surface: spec.md names a single assistant and no agent-to-agent communication |
| agent | cascading-failure | Denial of Service | multi-agent, agent-autonomy | no | **no-threat-detected** | — | agent-autonomy surface present, but spec.md names a single assistant with one write action (ticket creation) gated per ticket by confirmation (FR-004); there is no agent-to-agent propagation path |
| agent | human-agent-trust-exploitation | Repudiation | human-in-loop | yes | **threat** | `threat.blind-confirmation` |  |
| agent | rogue-agent | Elevation of Privilege | agent-autonomy | yes | **no-threat-detected** | — | agent-autonomy surface present, but the assistant's only side effect is ticket creation gated by human confirmation (FR-004), so a deviating assistant cannot act without a human step |

### Requirements

| Requirement | Priority | Threats | Mitigations | Tasks | Verified? |
|---|---|---|---|---|---|
| SR-001 | P1 | `threat.corpus-prompt-injection`, `threat.direct-prompt-injection`, `threat.goal-hijack-ticket` | `mitigation.untrusted-context-delimiting` | — (no tasks.md) | no |
| SR-002 | P1 | `threat.corpus-prompt-injection`, `threat.direct-prompt-injection`, `threat.goal-hijack-ticket`, `threat.unconfirmed-ticket` | `mitigation.ticket-confirmation` | — (no tasks.md) | no |
| SR-003 | P2 | `threat.blind-confirmation`, `threat.ticket-content-overshare` | `mitigation.confirmation-shows-exact-fields` | — (no tasks.md) | no |
| SR-004 | P2 | `threat.reporter-spoofing` | `mitigation.reporter-from-session` | — (no tasks.md) | no |
| SR-005 | P1 | `threat.ticket-tool-overprivileged` | `mitigation.ticket-tool-least-privilege` | — (no tasks.md) | no |
| SR-006 | P2 | `threat.ticket-tool-misuse` | `mitigation.ticket-parameter-validation` | — (no tasks.md) | no |
| SR-007 | P1 | `threat.visibility-bypass-via-retrieval` | `mitigation.visibility-filtered-retrieval` | — (no tasks.md) | no |
| SR-008 | P2 | `threat.fabricated-citation` | `mitigation.verified-citations` | — (no tasks.md) | no |
| SR-009 | P1 | `threat.kb-unauthorized-publish` | `mitigation.author-only-publish` | — (no tasks.md) | no |
| SR-010 | P2 | `threat.kb-out-of-band-tamper` | `mitigation.least-privilege-kb-storage` | — (no tasks.md) | no |
| SR-011 | P2 | `threat.ticket-log-unattributable` | `mitigation.ticket-audit-record` | — (no tasks.md) | no |
| SR-012 | P2 | `threat.conversation-log-exposure` | `mitigation.log-redaction` | — (no tasks.md) | no |
| SR-013 | P2 | `threat.question-flood` | `mitigation.ask-rate-and-size-limits` | — (no tasks.md) | no |
| SR-014 | P2 | `threat.sso-session-replay` | `mitigation.validate-sso-per-request` | — (no tasks.md) | no |
| SR-015 | P3 | `threat.in-transit-tampering` | `mitigation.tls-everywhere` | — (no tasks.md) | no |
| SR-016 | P2 | `threat.question-backend-injection` | `mitigation.parameterized-backend-queries` | — (no tasks.md) | no |

Needs clarification (no requirement expected): `threat.needs-clarification-document-visibility`, `threat.needs-clarification-model-hosting`, `threat.needs-clarification-retention`, `threat.needs-clarification-ticket-api-identity`

**Uncovered techniques** (surfaces present, no threat, no disposition): identity-spoofing
