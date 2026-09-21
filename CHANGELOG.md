# Changelog

All notable changes to the ThreatSpec extension are documented here. The format follows Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Added

**Commands**

- `speckit.threatspec.model`: create or incrementally update an OTM-compatible `threat-model.yaml` from `spec.md` and `plan.md`; publish `SR-###` security requirements into `spec.md` between managed markers. Existing ids, statuses, decisions, and verification history survive; threats that disappear are retired, not deleted.
- `speckit.threatspec.check`: deterministic checks C1–C12 (schema, dangling references, coverage, decisions, drift, severity, applicability, open questions) with `md`, `json`, and `sarif` output, plus ten semantic passes.
- `speckit.threatspec.converge`: evidence-based verification of every `SR-###`, append-only verification history, convergence report, and appended `Security Convergence` tasks. `verified` requires an inspectable evidence pointer; re-running does not duplicate tasks.

**Engine**

- `scripts/python/threatspec.py` with bash and PowerShell wrappers; subcommands `paths`, `init`, `validate`, `merge`, `render`, `check`, `coverage`, `converge-scan`, `converge-apply`. PyYAML is the only requirement; `jsonschema` enables full schema validation.
- JSON Schema `schemas/threat-model.schema.json`, an Open Threat Model superset with `threatspec`, `requirements`, `verification`, and `decisions` keys.
- `coverage`: technique × surface × threat/disposition and `SR-###` → threats/mitigations/tasks/verification tables.
- Runs without an agent: exit codes reflect severity, output is CI-ready, and hashes and reported paths are stable across Linux, macOS, and Windows.

**Model semantics**

- Three-state dispositions per technique, plus `needs-clarification` threats that carry `severity: unrated`, stay out of severity counts, and surface as check C12.
- `threatspec.exclusions` records spec entities deliberately left out of the model, with a mandatory reason, and silences C8 for them.
- Risk decisions (`accepted`, `transferred`) require owner, rationale, and expiry.
- Drift detection hashes `spec.md` without the ThreatSpec-managed block, so rendering is never mistaken for a spec change.
- Tasks link to requirements through `[SR-###]` bracket tags only, so prose ranges cannot inflate coverage.

**Profiles**

- `stride` (STRIDE per element), `llm` (OWASP Top 10 for LLM Applications 2026, MITRE ATLAS), `agent` (OWASP Top 10 for Agentic Applications 2026, MAESTRO layers), each with applicability surfaces and edition-pinned framework mappings.

**Integration**

- Seven optional lifecycle hooks (`after_specify` through `before_converge`) and own hook points (`before/after_threatspec_*`) for other extensions to chain on.
- Companion preset `threatspec-sdd` (append overrides for `tasks`, `analyze`, `converge`, `checklist`) and workflow `secure-sdd`.
- Composite GitHub Action (`action.yml`) that runs the check and uploads SARIF to code scanning.
- `catalog.json` at the repository root: an installable self-hosted catalog with a tag-pinned download URL.

**Documentation and tests**

- `docs/`: methodology, threat-model format reference, workflow integration, design and roadmap, publishing checklist, and ThreatSpec's own threat model.
- `examples/rag-assistant`: a complete first-pass model produced by the model command from a bare spec, with rendered view, check report, and coverage table, kept valid by tests.
- Test suite covering the manifest, schema, checks, merge, render, convergence, and the shipped example; CI on Linux and Windows across Python 3.11 and 3.13.
