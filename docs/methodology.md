# Methodology

ThreatSpec applies Shostack's four questions to a Spec Kit feature and keeps the answers connected as the feature moves from specification to verified implementation.

| Question | Where the answer lives | Who produces it |
|---|---|---|
| What are we working on? | `spec.md`, `plan.md` → actors, trust zones, assets, components, data flows in `threat-model.yaml` | Spec Kit, then the model command |
| What can go wrong? | `threats[]` with STRIDE category, profile technique, likelihood, impact, evidence source | the model command (LLM) |
| What are we going to do about it? | `mitigations[]` → `requirements[]` (`SR-###`) → tasks in `tasks.md` | the model command, then `/speckit.tasks` |
| Did we do a good job? | `verification[]`, convergence report, appended remediation tasks | the converge command |

## STRIDE per element, plus profiles

STRIDE is applied per element (actor, component, data flow, datastore, trust boundary). Profiles add techniques that STRIDE does not name but that map onto its categories:

- `llm`: OWASP Top 10 for LLM Applications 2026 and MITRE ATLAS techniques (prompt injection, hidden context exposure, excessive agency, unbounded consumption, …).
- `agent`: OWASP Top 10 for Agentic Applications 2026 and MAESTRO layers (goal hijack, tool misuse, memory poisoning, rogue agents, …).

Every technique declares the **applicability surfaces** it needs. The model command records which surfaces the system has, so a technique whose surface is absent is marked `not-applicable` with a verbatim reason instead of a misleading "no threat detected". The check command (C11) catches contradictions between a not-applicable claim and a present surface.

## Three-state disposition

For each technique and element the model records exactly one of:

| Disposition | Meaning | Where |
|---|---|---|
| `threat` | a concrete exposure with an evidence pointer into the spec or plan | `threats[]` |
| `no-threat-detected` | the surface exists, the elements were evaluated, nothing concrete was found | `threatspec.dispositions[]` |
| `not-applicable` | the required surface is structurally absent | `threatspec.dispositions[]` with `reason` |

A fourth marker, `needs-clarification`, is a threat whose name starts with `[NEEDS CLARIFICATION: …]`; it exists so that spec gaps surface in checks and in `/speckit.clarify` rather than being silently filled in.

## Severity

Likelihood and impact are OTM-style integers 0–100 with comments. Levels: low < 34, medium < 67, high ≥ 67. The default 3×3 matrix with a critical tier:

|  | impact high | impact medium | impact low |
|---|---|---|---|
| **likelihood high** | critical | high | medium |
| **likelihood medium** | high | medium | low |
| **likelihood low** | medium | low | low |

The engine computes `attributes.severity` on every merge. A different level requires `attributes.severity_override: {level, reason}`; check C10 flags unexplained differences. A threat that would violate a constitution MUST principle carries `attributes.constitution` and is treated as CRITICAL when unmitigated (C3).

## Mitigations, requirements, acceptance

- Every threat has at least one mitigation or a decision (C3). Mitigations name their `kind` (preventive, detective, corrective, deterrent) and the `touchpoints` in the plan where they land.
- Every mitigation rolls up into one or more `SR-###` requirements (C4). A requirement is an imperative, testable statement with Given/When/Then acceptance scenarios written so a test can implement them.
- `SR-###` numbering continues from the project baseline so ids stay unique across features.

## Decisions instead of silent gaps

Not every threat gets mitigated. `decisions[]` records `accepted` or `transferred` risk with `owner`, `rationale`, and `expires`. Check C7 fails incomplete or expired decisions; convergence reports them as tracked debt.

## Evidence, not claims

The converge command collects facts per requirement: task state, test files that reference the SR id, touchpoint existence, optional verifier output. The agent then judges only from that evidence and must supply a pointer for `verified`; the engine rejects `verified` without one. Verification entries are append-only and carry a timestamp and commit.

**Definition of Converged**: no open threat at or above `severity.block_on`; every `SR-###` verified or covered by an unexpired decision; no expired decisions; no drift between the model and `spec.md`/`plan.md`.

## Untrusted content

Spec, plan, code, tests, and fetched pages are inputs the agent reads, and any of them can contain instruction-like text. All three commands treat that text as data, quote it under an "Unverified" heading, and never follow it. Claims inside artifacts ("input is validated") do not change likelihood; only mitigations with touchpoints, tasks, and evidence do.
