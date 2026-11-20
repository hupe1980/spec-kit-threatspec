# Changelog

All notable changes to the ThreatSpec extension are documented here. The format follows Keep a Changelog; versions follow SemVer.

## [Unreleased]

## [0.3.1] - 2026-11-20

Field feedback from updating to 0.3.0 and converging two features of a service with a daemon, a database, and web screens.

### Changed

- `merge --patch` keeps the recorded `spec.md`/`plan.md` hashes. A patch that only changed a technique or a touchpoint used to re-record them and silently clear pending C9 drift, which made every patch an implicit `rehash`. `--record-sources` re-records them when the patch is the answer to the edit (the model command passes it for the `--from-plan` pass and for changes derived from a spec edit). When hashes are kept although a source changed, the merge prints a `note:`. A full merge records them as before.
- `verification.evidence_markers: []` turns marker evidence off instead of falling back to `["SR-"]`: no file is tied to a requirement by marker, `evidence.marker` is `null`, remediation tasks no longer say "mark its test", and the converge and preset tasks prompts find tests from touchpoints and acceptance scenarios. Omitting the key keeps the default.
- The model command asks every rate-limit, lockout, quota, or throttle requirement to name its key and whom that key can lock out; the check command's S4 pass flags one that does not.
- The workflow guide recommends running converge as an independent judge, in a session that did not write the code.

### Fixed

- `converge-scan` listed and stat'ed every file under `test_dirs`, including `node_modules`, before filtering, which took minutes on a web project. In a git work tree it now lists files with `git ls-files` and skips whatever a `.gitignore` excludes; elsewhere it prunes skipped and hidden directories while walking.
- The README's troubleshooting row and the 0.3.0 changelog showed `merge --patch` without the required `--incoming`.
- The CI example in the workflow guide pinned the action to `v0.2.3`.
- SARIF output reports tool version `0.3.1`.

### Documentation

- README troubleshooting: updating a `--dev` install (remove, add, restore `threatspec-config.yml` from `.specify/extensions/.backup/threatspec/`), and C9 still pending after a patch.

## [0.3.0] - 2026-11-19

Field feedback from a full model → plan pass → check → converge cycle on a library project.

### Added

- `merge --patch --incoming <file>`: a partial document keyed by id, so a plan pass or a single correction no longer re-sends the whole model. Each listed entry is merged into the existing one by JSON Merge Patch (RFC 7396): mappings merge, lists and scalars replace, `null` removes a key; an unknown id is added. `threatspec.actors`, `dispositions`, and `exclusions` are upserted by key and `surfaces` are added. Nothing the patch does not name is retired or dropped. A `remove:` list deletes structure entries, mitigations, requirements, and actors, retires threats, and drops `surface:<id>`, `disposition:<technique>`, `exclusion:<entity>`. `verification[]` and `decisions[]` stay append-only. The patched model is validated as a whole; a rejected patch writes nothing.
- `rehash`: re-records the `spec.md`/`plan.md` hashes without touching the model, for a reviewed edit that changes no asset, flow, surface, or trust boundary. `--dry-run` lists what changed. The C9 finding and the check command's S1 pass recommend it; the agent does not run it.
- `techniques [--profiles a,b] [--format md|json]`: prints each profile's asset types, surfaces, techniques, and mitigation patterns. It needs no feature directory. The model command uses it instead of reading the profile YAML.
- `stride` profile 0.2: technique `dependency-compromise` (Tampering, surface `third-party-code`, CWE-1357/1395/494/829, OWASP Top 10:2025 A03) with the patterns `dependency-pinning`, `dependency-gate`, `provenance-verification`, and `sbom-monitoring`. Existing models are unaffected until they record the `third-party-code` surface; `coverage` lists the technique as `surface-absent` until then.

### Changed

- The `authorization` surface now reads as any decision that permits or denies an action, including a rule-based eligibility or entitlement decision without an authenticated principal, so `broken-access-control` applies to such library functions.
- A full `merge` reports what it did on its own: a `note:` line names structure entries it dropped because the incoming model omitted them, and mitigations or requirements it kept although the incoming model omitted them. The stats line gained `removed`.
- The model command chooses the merge mode by run type: complete model for an initial or update run, patch for `--from-plan` and targeted changes.

### Fixed

- `specify extension add --dev` copied the checkout's `.git` directory (and would have copied `.venv`, editor folders, and tool caches) into `.specify/extensions/threatspec/`, because Spec Kit excludes only what `.extensionignore` names. They are now listed, and CI asserts the install is clean.
- Command prompts repeated the user input: agents substitute `$ARGUMENTS` textually, and each command named it two to four times, once inside a sentence. Each prompt now expands it once.
- A full `merge` could never delete a stale mitigation or requirement: one missing from the incoming model was silently re-added. The carry-over is kept as a safeguard, is now reported, and `merge --patch` with `remove:` deletes explicitly.
- SARIF output reports tool version `0.3.0`.

## [0.2.3] - 2026-11-18

### Fixed

- Evidence collection mixed up features. `SR-###` ids are feature-local (features are built on parallel branches, so no project-wide sequence exists), but `converge-scan` counted every test file mentioning `SR-001` as evidence, including tests written for another feature's `SR-001`. A bare marker now counts only while no other feature defines the same id; otherwise the file is listed under the new `evidence.ambiguous_test_files` (with `also_defined_in`). A qualified marker always counts for the feature it names and never for another: `rag-assistant/SR-001`, `007-rag-assistant/SR-001`, or the identifier form `test_rag_assistant_sr_001`. A slug shared by two features does not qualify; the full directory name does. Timestamp-prefixed feature directories are supported. Repositories whose SR numbers are not shared see no change.
- `converge-apply` rejects a `verified` verdict whose evidence is an ambiguous test file or a file marked for another feature, and names the marker to use. Evidence pointers are matched in `path::test`, `path:line`, and `path#L…` form.
- The docs claimed `SR-###` ids are unique across features. They are now documented as feature-local, with `<feature-dir>/SR-###` as the cross-feature reference form (methodology, format reference, configuration, design decisions), a new "Tagging tests" section in the workflow guide, a README troubleshooting entry, and threat T11 in ThreatSpec's own threat model. The baseline rule is unchanged: a feature must not reuse a baseline id.
- SARIF output reports tool version `0.2.3`.

### Added

- `converge-scan` reports `evidence.other_feature_test_files` and `evidence.marker`, the qualified form tests should use. Remediation tasks name it, and the companion preset's tasks instruction asks for it on every new security test, so new tests are unambiguous from the start.

### Changed

- `converge-scan` reads sibling feature models once per run instead of once per requirement.

## [0.2.2] - 2026-11-17

### Fixed

- Task parsing missed bold task ids (`- [ ] **T001** …`), in-progress checkboxes (`- [~]`), and inserted ids with a letter suffix (`T006a`). When ids were bold, no `[SR-###]` tag was seen, so every requirement got a false C5 ("no task"). These forms are now recognised; `[~]` counts as open.
- `converge-apply` computes the next task number from the leading digits, so a suffixed id such as `T006a` counts as 6 and cannot crash the append.
- `converge-apply` writes `threat-model.yaml` after appending remediation tasks, so a failure while appending leaves the model untouched instead of half-applied.
- A feature requirement that reuses an `SR-###` id from the baseline silently replaced the baseline requirement in the merged view. `validate`, `merge`, and `check` (as C2, critical) now reject the clash and name the baseline's highest id to continue from.
- SARIF output reports tool version `0.2.2`.

## [0.2.1] - 2026-11-09

### Fixed

- `converge-apply` ignored risk decisions for security requirements: an unverified `SR-###` always blocked convergence and got a remediation task, contrary to the documented Definition of Converged. An `SR-###` whose linked threats all carry an unexpired `accepted`/`transferred` decision no longer blocks, gets no task, and is listed under `requirements.risk_accepted` (shown as "covered by decision" in the report and scoreboard). Partial coverage and expired decisions still block.
- SARIF output reports tool version `0.2.1`.

## [0.2.0] - 2026-09-27

### Added

- `site/`: a [Zola](https://www.getzola.org/) static site (landing page + docs) published to GitHub Pages at https://hupe1980.github.io/spec-kit-threatspec/ by a new `pages.yml` workflow. It replaces the unstyled `docs/` folder and carries the same pages: methodology, the threat-model format reference, workflow integration, design and roadmap, the publishing checklist, and ThreatSpec's own threat model.
- Configuration reference page: every key, its default, what reads it, and the merge order.

### Changed

- Documentation shows commands in the hyphenated skills form (`/speckit-threatspec-model`) used by Claude Code, Copilot, Cursor and most other agents; the README explains the dotted form (`/speckit.threatspec.model`) that opencode, gemini and qwen use. Command bodies still use `__SPECKIT_COMMAND_*__` tokens, and a test now rejects either literal form in them.
- README, `config-template.yml`, and `examples/README.md` link to the documentation site instead of `docs/`, and the `documentation` URL in `catalog.json` points to the site instead of the README.
- `.extensionignore` excludes `site/` from installs, in place of `docs/`.
- SARIF output reports tool version `0.2.0`.

### Fixed

- `config-template.yml` said any `SPECKIT_THREATSPEC_<SECTION>_<KEY>` variable overrides config. Only `SPECKIT_THREATSPEC_ENFORCEMENT` and `SPECKIT_THREATSPEC_PROFILES` are read, and the comment now says so.

## [0.1.0] - 2026-09-21

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

[Unreleased]: https://github.com/hupe1980/spec-kit-threatspec/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/hupe1980/spec-kit-threatspec/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/hupe1980/spec-kit-threatspec/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/hupe1980/spec-kit-threatspec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/spec-kit-threatspec/releases/tag/v0.1.0
