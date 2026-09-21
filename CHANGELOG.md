# Changelog

All notable changes to the ThreatSpec extension are documented here. The format follows Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Added

- `speckit.threatspec.model`: create or incrementally update an OTM-compatible `threat-model.yaml` from `spec.md` and `plan.md`; publish `SR-###` security requirements into `spec.md` between managed markers.
- `speckit.threatspec.check`: deterministic checks C1–C11 (schema, references, coverage, decisions, drift, severity, applicability) with `md`, `json`, and `sarif` output, plus semantic passes.
- `speckit.threatspec.converge`: evidence-based verification of every `SR-###`, append-only verification history, convergence report, and appended `Security Convergence` tasks.
- Engine `scripts/python/threatspec.py` with bash and PowerShell wrappers; JSON Schema `schemas/threat-model.schema.json`.
- Profiles: `stride`, `llm` (OWASP LLM Top 10 2026), `agent` (OWASP Agentic Top 10 2026, MAESTRO layers).
- Optional lifecycle hooks (`after_specify`, `after_clarify`, `after_plan`, `after_tasks`, `before_implement`, `after_implement`, `before_converge`) and own hook points (`before/after_threatspec_*`).
- Companion preset `threatspec-sdd` (append overrides for `tasks`, `analyze`, `converge`, `checklist`) and workflow `secure-sdd`.
- Test suite with a golden `rag-assistant` fixture and a `broken` fixture.
- Fixes from an end-to-end run: coverage no longer lists retired clarification threats; `converge-apply` no longer duplicates convergence tasks on re-run; task linking requires `[SR-###]` bracket tags so prose ranges cannot inflate coverage; `threatspec.exclusions` records deliberately omitted spec entities and silences C8.
- Windows/CRLF correctness: source hashes are computed on universal-newline text so a CRLF checkout is not reported as drift, and every reported path (evidence, SARIF URIs) is POSIX-style. `.gitattributes` normalises checkouts to LF.
- `check --strict` now reports `Enforcement: strict` in the Markdown, JSON, SARIF-adjacent, and persisted outputs, matching the exit code it enforces.
- `catalog.json` at the repository root: an installable self-hosted catalog with a tag-pinned download URL; `docs/publishing.md` maps the Spec Kit publishing guide and submission template to this repository.
- `examples/rag-assistant`: a complete first-pass model produced by the model command from a bare spec, with rendered view, check report, and coverage table, kept valid by tests.
- Composite GitHub Action (`action.yml`) that runs the check and uploads SARIF to code scanning.
- GitHub workflows: CI (tests on Linux and Windows, manifest validation, scratch-project install) and Release (tag → version check → ZIP asset → GitHub Release).
- Phase-aware C6 severity (LOW before implementation starts, HIGH only when all tasks are done and nothing verifies the requirement).
- `converge-apply --only` for partial convergence runs; un-judged requirements keep their last recorded verdict.
- Needs-clarification threats get `severity: unrated`, are excluded from severity counts and C3/C10, and surface as check C12.
- `spec.md` is hashed without the managed SR block, so rendering never registers as drift; unhashed sources block convergence.
- YAML parse errors are reported with a quoting hint instead of a traceback.
- `coverage` subcommand: technique × surface × threat/disposition and SR → threats/mitigations/tasks/verification tables (md or json).
- Pre-implementation C6 findings are aggregated into one line.
- Check prompt: semantic passes S9 (dispositions) and S10 (wording/attribution), explicit severity→priority mapping, constitution-template fallback, unverified rule exempts quoted test payloads.
