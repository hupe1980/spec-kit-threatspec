# 🛡️ ThreatSpec — Threat Modeling & Security Traceability for Spec Kit

**ThreatSpec is a [Spec Kit](https://github.com/github/spec-kit) extension that makes threat modeling and security traceability a first-class part of Spec-Driven Development.**

It generates a machine-readable, [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)-compatible threat model from your Spec Kit artifacts, derives testable security requirements (`SR-###`) from it, feeds them into `/speckit.plan` and `/speckit.tasks`, checks the whole chain for gaps deterministically, and verifies after implementation that every threat has been mitigated, implemented, and tested.

```text
Asset ─▶ Threat ─▶ Mitigation ─▶ Security Requirement (SR-###)
                                        ├──▶ Task (T###)      tasks.md
                                        ├──▶ Verification     test | review | scan | evidence
                                        └──▶ Convergence      every link resolved, every SR verified
```

## 🔁 Workflow

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
/speckit.threatspec.check     gap report: threats → mitigations → SR-### → tasks → verification
        ↓
/speckit.implement            code + tests
        ↓
/speckit.threatspec.converge  evidence-based verification, convergence report, remediation tasks
        ↓
/speckit.converge             core convergence completes the appended tasks
```

🔌 Every ThreatSpec hook is optional by default. Nothing in the core workflow changes unless you opt in.

## 📦 Installation

```bash
# From a release archive (the CLI asks you to confirm the untrusted URL)
specify extension add threatspec --from https://github.com/hupe1980/spec-kit-threatspec/archive/refs/tags/v0.1.0.zip

# Or register this repository's catalog once, then install by name
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-threatspec/main/catalog.json --name threatspec --install-allowed
specify extension add threatspec

# From a local checkout (development)
specify extension add --dev ./spec-kit-threatspec

# Optional companions
specify preset add --dev ./spec-kit-threatspec/preset/threatspec-sdd      # SR-### awareness in tasks/analyze/converge/checklist
specify workflow add --dev ./spec-kit-threatspec/workflow/secure-sdd       # one-shot secure SDD cycle with review gates
```

Requirements: Spec Kit ≥ 1.0.0, Python 3 with PyYAML (or [uv](https://docs.astral.sh/uv/), which the wrappers use to fetch PyYAML and jsonschema on the fly).

## 🧭 Commands

| Command | What it does | Writes |
|---|---|---|
| 🧠 `/speckit.threatspec.model` | Builds or incrementally updates `threat-model.yaml` from `spec.md` (assets, actors, trust zones, threats, mitigations, `SR-###`) and, with `--from-plan`, from `plan.md` (components, data flows). | `threat-model.yaml`, `threat-model.md`, the marked block in `spec.md` |
| 🔍 `/speckit.threatspec.check` | Deterministic checks C1–C12 and coverage tables from the engine, plus ten semantic passes; report in the `/speckit.analyze` shape; `--format sarif` for GitHub code scanning. | optional `security/check-report.md` |
| ✅ `/speckit.threatspec.converge` | Collects evidence per `SR-###`, has the agent judge only from that evidence, records append-only verification history, reports convergence, appends remediation tasks. | `threat-model.yaml`, `security/convergence-report.{md,json}`, appended phase in `tasks.md` |

### ⚙️ Deterministic checks

| ID | Check | Severity |
|---|---|---|
| C1 | Schema validation | 🔴 CRITICAL |
| C2 | Dangling references | 🔴 CRITICAL |
| C3 | Threat with neither mitigation nor decision | 🟠 HIGH / 🔴 CRITICAL |
| C4 | Mitigation without `SR-###` | 🟠 HIGH |
| C5 | `SR-###` without a task | 🟠 HIGH |
| C6 | `SR-###` without verification | 🟡 MEDIUM / 🟠 HIGH |
| C7 | Decision missing owner, rationale, expiry, or expired | 🟠 HIGH |
| C8 | Key entity in `spec.md` missing from the model | 🟡 MEDIUM |
| C9 | `spec.md`/`plan.md` changed since the model was generated | 🟡 MEDIUM |
| C10 | Severity differs from the matrix without an override reason | 🟢 LOW |
| C11 | Technique marked not-applicable while its surfaces are present | 🟡 MEDIUM |
| C12 | Threat marked needs-clarification | 🟡 MEDIUM |

The engine also prints mechanical coverage tables (`threatspec.sh coverage`: technique × surface × threat/disposition, and SR → threats/mitigations/tasks/verification). It runs without an agent, so the same checks work in CI:

```bash
.specify/extensions/threatspec/scripts/bash/threatspec.sh check --feature-dir specs/007-rag-assistant --format sarif --output threatspec.sarif
```

Exit codes: `0` nothing above MEDIUM, `1` HIGH (or MEDIUM in strict mode), `2` CRITICAL.

🤖 Or use the bundled GitHub Action, which runs the check and uploads SARIF to code scanning:

```yaml
# .github/workflows/threatspec.yml
name: ThreatSpec
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hupe1980/spec-kit-threatspec@v0.1.0
        with:
          feature-dir: specs/007-rag-assistant   # optional; auto-detected from SPECIFY_FEATURE or the branch
          strict: "false"
```

## 🧪 Example

[examples/rag-assistant](examples/rag-assistant/) holds a complete first-pass output for an internal RAG assistant: the spec with its generated `SR-###` block, a 23-threat `threat-model.yaml` produced by the model command from that spec alone, the rendered `threat-model.md` with a Mermaid data-flow diagram, and the persisted check and coverage reports. See [examples/README.md](examples/README.md) for how it was produced and how to reproduce it.

## 🗂️ The model

`threat-model.yaml` is a valid OTM document with ThreatSpec keys (`threatspec`, `requirements`, `verification`, `decisions`), validated by `schemas/threat-model.schema.json`. See `templates/threat-model.yaml` for the annotated skeleton and `docs/threat-model-format.md` for the reference.

Profiles supply techniques, applicability surfaces, and edition-pinned mappings:

| Profile | Foundation |
|---|---|
| `stride` | STRIDE per element (default) |
| `llm` | OWASP Top 10 for LLM Applications 2026, MITRE ATLAS |
| `agent` | OWASP Top 10 for Agentic Applications 2026, MAESTRO layers |

## 🎛️ Configuration

`.specify/extensions/threatspec/threatspec-config.yml` (see `config-template.yml`):

```yaml
profiles: [stride, llm, agent]
enforcement: warn            # strict → CRITICAL findings block /speckit.implement
severity: { matrix: default, block_on: [critical] }
risk_acceptance: { require_owner: true, max_duration_days: 180 }
model: { baseline: .specify/memory/threat-model.yaml, write_requirements_to_spec: true, render_markdown: true, diagram: mermaid }
verification: { test_command: "", scanners: [], evidence_markers: ["SR-"], test_dirs: [tests, test, spec, __tests__] }
```

## 🧱 Design principles

♻️ Reusable · 🤝 agent-agnostic · 🔗 traceable · 🎯 deterministic where possible · 🪶 non-intrusive · 📈 incremental · 🧾 evidence over claims · 🙋 honest about uncertainty · 🔄 interoperable (OTM, SARIF) · 🔒 secure by construction (artifact content is untrusted data).

📚 Positioning, design bets, roadmap, and the landscape of related extensions: [docs/design.md](docs/design.md). Methodology: [docs/methodology.md](docs/methodology.md). Model reference: [docs/threat-model-format.md](docs/threat-model-format.md). Lifecycle and CI: [docs/workflow.md](docs/workflow.md). ThreatSpec's own threat model: [docs/threat-model.md](docs/threat-model.md).

## 🩺 Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `threatspec: no Python runtime with PyYAML found` | Install PyYAML (`pip install pyyaml`) or [uv](https://docs.astral.sh/uv/); the wrappers try `python3`, `python`, then `uv run --with pyyaml --with jsonschema`. |
| `threatspec: no feature directory found` | Pass `--feature-dir specs/<feature>` before the subcommand, or set `SPECIFY_FEATURE`. Resolution order: flag, `SPECIFY_FEATURE`, git branch name, newest `specs/*/spec.md`. |
| `YAML parse error … quote any scalar` | A `[NEEDS CLARIFICATION: …]` name or a value containing `: ` is unquoted in the incoming model. Quote it and re-run `merge`. |
| `merge rejected, N validation error(s)` | The incoming model references an id that does not exist. The errors name the entity and field; fix the file, do not bypass. |
| Commands do not appear in the agent | Run `specify extension list`; if installed, restart the agent so it reloads `.claude/commands` or `.claude/skills`. |
| C9 drift right after editing `spec.md` | Expected: re-run the model command so the hashes match. Rendering the SR block does not count as drift. |
| Convergence keeps reporting `never hashed` | The model predates source hashing; run the model command once to record hashes. |

## 🤝 Contributing

Issues and pull requests are welcome at [github.com/hupe1980/spec-kit-threatspec](https://github.com/hupe1980/spec-kit-threatspec). Run the test suite before opening a PR, keep `CHANGELOG.md` current, and bump `extension.version` and `catalog.json` together on every content change (the tests enforce that they agree). New threat profiles go in `profiles/` and need surfaces, techniques, and mitigation patterns that the profile consistency test accepts. Release and catalog submission steps are in [docs/publishing.md](docs/publishing.md).

## 🛠️ Development

```bash
uv run --with pytest --with pyyaml --with jsonschema pytest -q
python3 scripts/python/threatspec.py --help
```

## 📄 License

MIT
