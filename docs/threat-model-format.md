# `threat-model.yaml` reference

`threat-model.yaml` is the canonical, machine-readable threat model of one feature. It is a valid [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) 0.2 document extended with four ThreatSpec keys. The JSON Schema is `schemas/threat-model.schema.json`; the engine validates against it and against the reference rules below on every write.

## Top level

| Key | Origin | Purpose |
|---|---|---|
| `otmVersion` | OTM | `"0.2.0"` |
| `project` | OTM | `id`, `name`, optional `description`, `attributes` |
| `threatspec` | ThreatSpec | `version`, `generated`, `profiles`, `extends`, `sources`, `actors`, `surfaces`, `dispositions`, `exclusions` |
| `trustZones` | OTM | zones with `risk.trustRating` 0–100 |
| `assets` | OTM | data and capabilities with `risk.{confidentiality,integrity,availability}` and `attributes.{type,classification,source,capabilities}` |
| `components` | OTM | `type`, `parent.trustZone`, optional `threats[]` with `state` and `mitigations[]` |
| `dataflows` | OTM | `source`, `destination` (component, actor, or trust zone id), `assets`, `attributes.crosses` |
| `threats` | OTM + attributes | see below |
| `mitigations` | OTM + attributes | see below |
| `requirements` | ThreatSpec | `SR-###` security requirements |
| `verification` | ThreatSpec | append-only evidence history |
| `decisions` | ThreatSpec | accepted or transferred risks |

## Identifiers

| Entity | Pattern | Example |
|---|---|---|
| actor | `actor.<slug>` | `actor.content-author` |
| trust zone | `tz.<slug>` | `tz.internal` |
| asset | `asset.<slug>` | `asset.rag-corpus` |
| component | `component.<slug>` | `component.agent` |
| data flow | `flow.<slug>` | `flow.retrieved-context` |
| threat | `threat.<slug>` | `threat.rag-poisoning` |
| mitigation | `mitigation.<slug>` | `mitigation.context-isolation` |
| requirement | `SR-###` | `SR-003` |
| verification | `verification.<slug>` | `verification.sr-003.2026-09-21` |
| decision | `decision.<slug>` | `decision.model-extraction` |

Ids are immutable. A renamed or superseded threat keeps its entry with `attributes.status: retired` and `attributes.superseded_by`.

## `threats[]`

```yaml
- id: threat.rag-poisoning
  name: A content author plants instructions in a document that steer the agent
  categories: [Tampering]                 # STRIDE or LINDDUN
  cwes: [CWE-1427]
  risk: { likelihood: 75, impact: 90 }    # 0–100; severity derived by the engine
  attributes:
    technique: prompt-injection-indirect  # profile technique id
    profile: llm
    mappings: { owasp-llm-2026: [LLM01, LLM08], owasp-asi-2026: [ASI01] }
    disposition: threat                   # threat | needs-clarification
    actor: actor.content-author
    assets: [asset.document]
    elements: [flow.retrieved-context]
    severity: critical                    # computed; override with severity_override {level, reason}; 'unrated' for needs-clarification
    constitution: "Principle III"         # optional: MUST principle at stake
    source: "spec.md#FR-003"              # evidence
    status: open                          # open | mitigated | accepted | transferred | retired
```

A threat with `attributes.disposition: needs-clarification` is a question, not a rated threat: give it `risk: {likelihood: 0, impact: 0}`, the engine sets `severity: unrated`, excludes it from severity counts and from C3/C10, and reports it as C12.

`status` is human- and engine-owned: the model command never sets `mitigated`; the converge command does when every linked requirement is verified.

## `mitigations[]`

```yaml
- id: mitigation.context-isolation
  name: Isolate retrieved content from instructions
  riskReduction: 60
  attributes:
    threats: [threat.rag-poisoning]       # required, ≥1
    kind: preventive                      # preventive | detective | corrective | deterrent
    touchpoints: [src/agent/prompt_builder.py]
    requirements: [SR-001]
    status: required                      # required | planned | implemented | verified | rejected
```

## `requirements[]`

```yaml
- id: SR-001
  statement: Retrieved documents MUST be delimited as untrusted data and MUST NOT alter tool-call policy.
  priority: P1
  mitigations: [mitigation.context-isolation]
  acceptance:
    - given: a corpus document containing an injected instruction
      when: the user asks an unrelated question
      then: no tool call is issued and the attempt is logged
  tasks: [T011, T012]                     # optional; tasks tagged [SR-001] (or [SR-001, SR-002]) in tasks.md count too; prose mentions do not
```

## `verification[]` (append-only)

```yaml
- id: verification.sr-001.2026-09-21
  requirement: SR-001
  method: test                            # test | review | scan | manual | evidence
  evidence: tests/agent/test_prompt_injection.py::test_corpus_injection_blocked
  result: pass                            # pass | fail | partial | inconclusive
  verdict: verified                       # verified | implemented-unverified | partial | missing
  justification: Test asserts no tool call on injected corpus content.
  verified_at: "2026-09-21T14:03:00Z"
  commit: a1b2c3d
```

## `decisions[]`

```yaml
- id: decision.model-extraction
  threat: threat.model-extraction
  status: accepted                        # accepted | transferred
  owner: "@hupe"
  rationale: Hosted third-party model; low impact
  expires: 2027-03-01
```

## Reference rules (check C2)

- `components[].parent.trustZone` → `trustZones[]`
- `dataflows[].source/destination` → a component, actor, or trust zone
- `dataflows[].assets`, `threats[].attributes.assets`, `components[].attributes.tools` → `assets[]`
- `threats[].attributes.elements` → components, actors, trust zones, or dataflows
- `mitigations[].attributes.threats` → `threats[]`; `mitigations[].attributes.requirements` → `requirements[]`
- `requirements[].mitigations` → `mitigations[]`
- `verification[].requirement` → `requirements[]`; `decisions[].threat` → `threats[]`

## Exclusions

```yaml
threatspec:
  exclusions:
    - entity: Open Event
      reason: Folded into a counter column on Link; no separate asset
```

A spec key entity listed here is deliberately out of the model, and check C8 skips it. The reason is mandatory.

## Baseline inheritance

`threatspec.extends` may point at a project-level model (by convention `.specify/memory/threat-model.yaml`). Entities from the baseline are visible for reference resolution and rendering; the feature model wins on id clashes. The baseline is never written by feature commands.

## Drift hashes

`threatspec.sources[]` records a SHA-256 per source file. The hash is computed on universal-newline text with trailing newlines trimmed, so a CRLF checkout on Windows produces the same digest as an LF one. For `spec.md` the ThreatSpec-managed block (between `<!-- threatspec:begin -->` and `<!-- threatspec:end -->`) is removed first, so rendering the SR block never counts as drift; any edit outside the markers does.

## Determinism

The engine writes entities sorted by id with a fixed key order, so regenerating an unchanged model yields a byte-identical file and diffs stay reviewable.
