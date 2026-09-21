# Threat model of ThreatSpec itself

ThreatSpec runs inside a coding agent with read/write access to a repository. This is its own threat model, in the same shape it asks of others.

## What we are working on

| Asset | Type | Why it matters |
|---|---|---|
| `spec.md`, `plan.md`, `tasks.md` | project artifacts | source of intent; ThreatSpec writes into two of them |
| `threat-model.yaml` | security record | drives what gets built and what counts as verified |
| Agent session | agent | executes commands and scripts with the developer's privileges |
| `threatspec-config.yml` | configuration | `verification.test_command` is executed by converge |
| Verdicts file | agent output | becomes append-only verification history |

Actors: the developer (trusted), other contributors to the repo (semi-trusted), authors of content the spec or code quotes (untrusted), package registries (semi-trusted).

## What can go wrong

| ID | Threat | Category | Mitigation | Status |
|---|---|---|---|---|
| T1 | Instruction-like text in `spec.md`, `plan.md`, code, tests, or fetched pages steers the agent (indirect prompt injection) into marking threats mitigated, writing bogus verdicts, or running commands | Tampering | Every command treats artifact content as data, quotes suspicious text under "Unverified", and never follows it; `verified` needs an evidence pointer the engine checks; status roll-up is computed, not asserted | mitigated by command text; residual risk remains because LLM adherence is probabilistic |
| T2 | `$ARGUMENTS` is used to inject instructions or shell text | Tampering | Arguments only select scope; commands never pass them to a shell; the engine takes explicit flags | mitigated |
| T3 | The SR block overwrites human-authored spec content | Tampering | Writes are confined to the `<!-- threatspec:begin/end -->` markers; first insertion goes before `## Success Criteria`; covered by tests | mitigated |
| T4 | Converge rewrites or renumbers existing tasks | Tampering | Append-only contract; byte-for-byte unchanged when converged; covered by tests | mitigated |
| T5 | `verification.test_command` or `scanners` execute arbitrary commands | Elevation of Privilege | Empty by default; only the configured command runs, once, from the repo root; config is versioned and reviewable; the command prompt forbids running anything else | accepted: config is developer-owned, same trust as any project script |
| T6 | The bash/PowerShell wrapper runs `uv run --with pyyaml --with jsonschema`, pulling packages from PyPI at first use | Tampering (supply chain) | Only when no local Python with PyYAML exists; pinned to two widely used packages; teams can pre-install PyYAML to avoid it | accepted until v0.2 adds version pins |
| T7 | A malicious verdicts file marks everything verified | Repudiation | Verdicts require an evidence pointer; entries record commit and timestamp; history is append-only and reviewable in diffs | partially mitigated: the evidence pointer is not opened by the engine |
| T8 | Secrets or system prompts from artifacts are copied into `threat-model.md` or the SR block | Information Disclosure | Commands forbid verbatim reproduction; the renderer only emits model fields | mitigated by command text |
| T9 | Hook made mandatory by a project runs ThreatSpec without the developer noticing | Elevation of Privilege | All hooks ship `optional: true`; changing that is an explicit, versioned edit of `.specify/extensions.yml` | mitigated |
| T10 | Baseline `extends` path points outside the repository | Information Disclosure | The engine resolves the path but only reads YAML; v0.2 will reject paths outside the repo root | open, low |

## Did we do a good job

Tests cover T3, T4, T7 (evidence pointer required), and the append-only contract. T1 and T8 rely on prompt discipline and should be exercised with adversarial fixtures (a spec containing injected instructions) as part of the v0.2 test suite. T6 and T10 are tracked for v0.2.
