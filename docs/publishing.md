# Publishing checklist

Mapped to Spec Kit's `extensions/EXTENSION-PUBLISHING-GUIDE.md` and the Extension Submission issue template.

## Before tagging

| Guide requirement | Where it is satisfied |
|---|---|
| `extension.yml` with valid id, semver, description under 100 characters, public repository URL, 2–5 lowercase tags | `extension.yml`; enforced by `tests/test_manifest.py` |
| `README.md` with overview, installation, configuration, usage, troubleshooting, contributing | `README.md` |
| `LICENSE` (permissive) and `CHANGELOG.md` | both at the root |
| Command files exist for every declared command | `commands/`; enforced by tests |
| Config template with documented options and defaults | `config-template.yml`, `config.defaults` in the manifest |
| No hardcoded secrets, validated inputs, trusted dependencies | PyYAML only; jsonschema optional; `$ARGUMENTS` never reaches a shell |
| Version bumped on every content change | Release workflow refuses a tag whose version differs from the manifest |

## Release

1. Bump `extension.version` in `extension.yml`, update `CHANGELOG.md`, and update `version` and `download_url` in `catalog.json` (the test suite checks they agree).
2. Tag and push:

   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

3. The Release workflow runs the tests, builds `threatspec-v0.1.0.zip`, smoke-installs it with the Spec Kit CLI, and publishes a GitHub Release whose notes include the archive's SHA-256.
4. Verify the two install paths the guide expects:

   ```bash
   specify extension add threatspec --from https://github.com/hupe1980/spec-kit-threatspec/archive/refs/tags/v0.1.0.zip
   specify extension add --dev /path/to/spec-kit-threatspec
   ```

## Submit to the community catalog

File an issue with the [Extension Submission](https://github.com/github/spec-kit/issues/new?template=extension_submission.yml) template. Do not open a pull request against `catalog.community.json`. Field values:

| Field | Value |
|---|---|
| Extension ID | `threatspec` |
| Extension Name | ThreatSpec — Threat Modeling & Security Traceability |
| Version | from `extension.yml` |
| Description | STRIDE and AI/ML threat modeling with threat-to-test traceability and security convergence |
| Author | hupe1980 |
| Repository URL | https://github.com/hupe1980/spec-kit-threatspec |
| Download URL | https://github.com/hupe1980/spec-kit-threatspec/archive/refs/tags/vX.Y.Z.zip |
| License | MIT |
| Documentation URL | https://github.com/hupe1980/spec-kit-threatspec/blob/main/README.md |
| Changelog URL | https://github.com/hupe1980/spec-kit-threatspec/blob/main/CHANGELOG.md |
| Required Spec Kit Version | `>=1.0.0` |
| Required Tools | Python 3 with PyYAML, or uv |
| Number of Commands | 3 |
| Number of Hooks | 7 |
| Tags | security, threat-modeling, llm, agentic, traceability |
| Key Features | OTM-compatible `threat-model.yaml`; `SR-###` requirements published into `spec.md`; deterministic checks C1–C12 with SARIF output; evidence-based convergence with append-only verification history; profiles for STRIDE, OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026 |
| Testing checklist | installs from the download URL (release workflow smoke test); commands executed on real projects; docs complete; no known vulnerabilities (see `docs/threat-model.md`) |

The community catalog is discovery-only. Users either copy the entry into a catalog they trust or use the `--from` URL. The ready-made entry in `catalog.json` at the repository root is what a maintainer would paste.

## Self-hosted catalog

`catalog.json` is also a complete installable catalog. Teams can register it and install by name:

```bash
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-threatspec/main/catalog.json --name threatspec --install-allowed
specify extension add threatspec
```

Spec Kit ≥ 1.0.7 requires tag-pinned download URLs in catalogs, which is why `download_url` names a release tag rather than `main`.
