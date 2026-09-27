+++
title = "Configuration reference"
description = "Every threatspec-config.yml key, its default, what reads it, the four-layer precedence order, and the two known documentation inconsistencies."
weight = 40
template = "docs-page.html"
+++

ThreatSpec reads one configuration object per repository. Every key is optional; the engine falls back to a documented default for each. `config-template.yml` at the repository root is the annotated copy to start from.

## Where the file lives

```bash
cp .specify/extensions/threatspec/threatspec-config.template.yml \
   .specify/extensions/threatspec/threatspec-config.yml
```

`specify extension add threatspec` installs the template into `.specify/extensions/threatspec/`. Commit `threatspec-config.yml`; keep machine-specific values in `threatspec-config.local.yml`, which Spec Kit gitignores.

## Precedence

`load_config()` merges four layers, each overriding the one above it:

| # | Layer | Source |
|---|---|---|
| 1 | Extension defaults | `config.defaults` in `extension.yml` |
| 2 | Project config | `.specify/extensions/threatspec/threatspec-config.yml` |
| 3 | Local overrides | `.specify/extensions/threatspec/threatspec-config.local.yml` |
| 4 | Environment | `SPECKIT_THREATSPEC_*` |

Merging is recursive: a mapping in a later layer is merged key by key into the earlier one rather than replacing it wholesale. A scalar or a list, by contrast, is replaced outright — setting `profiles: [llm]` in the project config discards the default `[stride]`, it does not append to it.

## Environment variables

Exactly two are recognised:

| Variable | Effect |
|---|---|
| `SPECKIT_THREATSPEC_ENFORCEMENT` | Replaces `enforcement`. |
| `SPECKIT_THREATSPEC_PROFILES` | Replaces `profiles`; comma-separated, whitespace trimmed. |

```bash
SPECKIT_THREATSPEC_PROFILES=stride,llm SPECKIT_THREATSPEC_ENFORCEMENT=strict \
  .specify/extensions/threatspec/scripts/bash/threatspec.sh check
```

There is no general `SPECKIT_THREATSPEC_<SECTION>_<KEY>` form. Nested keys such as `verification.test_command` cannot be set from the environment; use the local override file.

## Keys

### `profiles`

```yaml
profiles: [stride, llm, agent]
```

Threat catalogs applied when generating and checking a model. Default `[stride]`. Each name resolves to `profiles/<name>.yaml`, which supplies surfaces, techniques, and mitigation patterns.

A feature's own `threat-model.yaml` wins over this setting. The engine reads `threatspec.profiles` from the model first and only falls back to the configured value when the model does not pin one, so an existing feature keeps the profiles it was generated with even after the repository default changes.

| Profile | Catalog |
|---|---|
| `stride` | STRIDE per element. Also supplies the severity matrix. |
| `llm` | OWASP Top 10 for LLM Applications 2026, MITRE ATLAS |
| `agent` | OWASP Top 10 for Agentic Applications 2026, MAESTRO layers |

### `enforcement`

```yaml
enforcement: warn   # warn | strict
```

Controls the exit code of the check command and the advice the agent gives. Default `warn`.

| Worst finding | `warn` | `strict` |
|---|---|---|
| critical | 2 | 2 |
| high | 1 | 1 |
| medium | 0 | 1 |
| low or none | 0 | 0 |

Under `strict` the check command also states that implementation must not proceed while a CRITICAL finding is open. The `--enforcement` flag overrides the configured value for one run, and `--strict` forces `strict` regardless of both.

### `severity`

```yaml
severity:
  block_on: [critical]
```

`block_on` lists the severities that prevent convergence while a threat of that severity is still `open`. Default `[critical]`. Compared against the threat's `severity_override.level` when present, otherwise its computed `severity`.

> **`severity.matrix` is inert.** `config-template.yml` ships `matrix: default`, but nothing reads it. The likelihood × impact matrix comes from the first loaded profile that declares `severity_matrix` — in practice `profiles/stride.yaml`, which defines the levels (`low: 0, medium: 34, high: 67`, OTM's 0–100 scale) and the 3×3 grid. To change the matrix, edit or add a profile.

### `risk_acceptance`

```yaml
risk_acceptance:
  require_owner: true
  max_duration_days: 180
```

Governs check C7 over `decisions[]`. A decision must carry `owner`, `rationale`, and `expires`; anything missing is a **high** finding. Setting `require_owner: false` drops `owner` from that required set. `max_duration_days` (default 180) caps how far ahead `expires` may sit; exceeding it is a **medium** finding. An expiry already in the past, or one that is not `YYYY-MM-DD`, is **high**.

### `model`

```yaml
model:
  baseline: .specify/memory/threat-model.yaml
  write_requirements_to_spec: true
  render_markdown: true
  diagram: mermaid
```

| Key | Default | Effect |
|---|---|---|
| `baseline` | `.specify/memory/threat-model.yaml` | Project-level model inherited by each new feature model, for trust zones, assets, actors, and decisions shared across features. Read at `init` only, and silently skipped when the path does not exist. Recorded in the feature model as a path relative to the feature directory. |
| `write_requirements_to_spec` | `true` | Publishes the `SR-###` block into `spec.md` between `<!-- threatspec:begin -->` and `<!-- threatspec:end -->`. `render --no-spec` overrides it for one run. |
| `render_markdown` | `true` | Writes the human-readable `threat-model.md`. `render --no-markdown` overrides it for one run. |
| `diagram` | `mermaid` | `mermaid` embeds a data-flow diagram in `threat-model.md`; `none` omits it. |

### `verification`

```yaml
verification:
  test_command: ""
  scanners: []
  evidence_markers: ["SR-"]
  test_dirs: [tests, test, spec, __tests__]
```

| Key | Default | Consumed by | Effect |
|---|---|---|---|
| `test_dirs` | `[tests, test, spec, __tests__]` | engine | Directories walked when collecting evidence. |
| `evidence_markers` | `["SR-"]` | engine | Substrings searched in those files to tie a test to a requirement. |
| `test_command` | `""` (none) | agent | When non-empty, converge runs exactly this command once from the repository root and treats per-test results as evidence. Empty means evidence is located but nothing is executed. `--run-tests` in `$ARGUMENTS` also triggers it, but only if a command is configured. |
| `scanners` | `[]` | agent | Scanner outputs converge may cite as evidence, recorded with `method: scan`. Never as a verdict on its own. |

The engine does not execute `test_command` or `scanners` itself. `converge-scan` echoes both back under `config.verification` in its output, and the converge command prompt decides what to run. Running anything is opt-in: with no `test_command` set and no `--run-tests`, converge reads artifacts and runs nothing.

## Known inconsistencies

Two defaults disagree between files. Neither changes behaviour, because the engine hard-codes the same fallbacks, but the manifest is the thinner of the two:

- `verification.test_dirs` appears in `config-template.yml` and in the engine, but not in `extension.yml`'s `config.defaults`.
- `severity.matrix` appears in `config-template.yml`, `extension.yml`, and the README, but no code path reads it.
