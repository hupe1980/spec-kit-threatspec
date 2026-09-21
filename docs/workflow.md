# Workflow integration

ThreatSpec adds three commands to the Spec Kit lifecycle. Nothing changes until you invoke one or enable a hook.

```text
/speckit.specify              spec.md
        ↓
/speckit.threatspec.model     threat-model.yaml + threat-model.md + SR-### block in spec.md
        ↓
/speckit.plan                 plan.md (sees the security requirements)
        ↓
/speckit.threatspec.model     --from-plan: components, data flows, trust zones
        ↓
/speckit.tasks                tasks.md (security tasks tagged [SR-###])
        ↓
/speckit.threatspec.check     gap report
        ↓
/speckit.implement            code + tests
        ↓
/speckit.threatspec.converge  evidence-based verification, remediation tasks
        ↓
/speckit.converge             core convergence completes the appended tasks
```

## Why two model passes

After `/speckit.specify` the model captures **what to protect**: actors, trust zones, assets, and the threats visible from user stories and requirements. After `/speckit.plan` the second pass attaches threats to **where attacks land**: components, data flows, boundary crossings, tools. Both passes are incremental; ids, statuses, decisions, and verification history survive.

## Hooks

Installed hooks are listed in `.specify/extensions.yml`. All are `optional: true` by default: the core command prints a prompt and you decide. To make one mandatory, set `optional: false` for that entry.

| Event | Command | Purpose |
|---|---|---|
| `after_specify` | model | first pass |
| `after_clarify` | model | refresh after spec changes |
| `after_plan` | model | plan pass |
| `after_tasks` | check | every SR has a task |
| `before_implement` | check | gate on CRITICAL when `enforcement: strict` |
| `after_implement` | converge | evidence-based verification |
| `before_converge` | converge | hand remediation tasks to core convergence |

ThreatSpec commands also dispatch their own hook points: `before_threatspec_model`, `after_threatspec_model`, `before_threatspec_check`, `after_threatspec_check`, `before_threatspec_converge`, `after_threatspec_converge`. Other extensions can register on them in their manifests (for example the `git` extension to auto-commit a refreshed model).

## Companion preset `threatspec-sdd`

```bash
specify preset add --dev ./spec-kit-threatspec/preset/threatspec-sdd
```

Appends one section to the core `tasks`, `analyze`, `converge`, and `checklist` commands so that `SR-###` requirements are tagged, inventoried, and offered as a checklist type. Without it, ThreatSpec `check` and `converge` remain the authoritative passes for security coverage.

## Workflow `secure-sdd`

```bash
specify workflow add --dev ./spec-kit-threatspec/workflow/secure-sdd
specify workflow run secure-sdd -i spec="An internal assistant that answers questions from our knowledge base"
```

Runs the full cycle with review gates after the threat model, after the plan pass, and after the security check.

## CI

The deterministic checks need no agent:

```bash
.specify/extensions/threatspec/scripts/bash/threatspec.sh check --feature-dir specs/007-rag-assistant --format sarif --output threatspec.sarif
```

Upload the SARIF file with `github/codeql-action/upload-sarif` to see findings in the Security tab. Exit codes: `0` nothing above MEDIUM, `1` HIGH (or MEDIUM with `--strict`), `2` CRITICAL.

The repository also ships a composite GitHub Action (`action.yml`) that runs the check, uploads SARIF under the `threatspec` category, and fails the job on HIGH/CRITICAL:

```yaml
- uses: hupe1980/spec-kit-threatspec@v0.1.0
  with:
    feature-dir: specs/007-rag-assistant
    strict: "false"          # "true" also fails on MEDIUM
    upload-sarif: "true"
    fail-on-findings: "true"
```

Check C6 (requirement without verification) is phase-aware: LOW while no task for the requirement is done, MEDIUM while implementation is in progress, HIGH/MEDIUM once all tasks are checked but nothing verifies the requirement. A pre-implementation run therefore does not fail CI on verification alone.

## Coverage tables

`threatspec.sh coverage --format md|json` prints, without an agent, every profile technique with its required surfaces and state (`threat`, `no-threat-detected`, `not-applicable`, `uncovered`, `surface-absent`) and every `SR-###` with threats, mitigations, tasks, and verification state. The check command uses it as the index for its semantic passes.

## Task linking

A task counts for a requirement only when it carries the bracket tag `[SR-###]` (comma lists such as `[SR-001, SR-003]` are allowed) or is listed under `requirements[].tasks`. A prose mention like "SR-001 through SR-016" does not count, so ranges cannot produce false coverage.

## Re-running converge

`converge-apply` is idempotent on the not-converged path: a gap that already has an unchecked task in a `Security Convergence` phase is not duplicated, and no new phase is appended when there is nothing to add. Once that task is checked off but the requirement still fails verification, the next run appends a fresh task.

## Partial convergence runs

`converge-apply --only SR-003,SR-007` re-judges only the named requirements. Every other requirement keeps its most recent recorded verdict; no synthetic "missing" entries are written for them.

## Files written

| Command | Writes |
|---|---|
| model | `threat-model.yaml`, `threat-model.md`, `security/incoming-threat-model.yaml`, the marked block in `spec.md` |
| check | `security/check-report.md` (with `--persist`) |
| converge | `threat-model.yaml` (verification, status roll-up), `threat-model.md`, `security/converge-scan.json`, `security/verdicts.yaml`, `security/convergence-report.{md,json}`, appended phase in `tasks.md` |

Nothing else is touched. `plan.md` is never written; `tasks.md` is append-only.
