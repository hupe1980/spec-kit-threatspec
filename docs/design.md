# Design: positioning, bets, roadmap

## Positioning

Existing Spec Kit security extensions produce one-shot reports. None maintains a stable, machine-readable threat model with typed cross-references that survives the lifecycle and can be validated without an LLM. ThreatSpec's value is the closed, verifiable traceability loop from asset to threat to mitigation to `SR-###` to task to verification evidence, with a convergence verdict at the end.

Shostack's four questions map onto the SDD lifecycle. Spec Kit answers the first; ThreatSpec answers the other three.

| Question | Spec Kit | ThreatSpec |
|---|---|---|
| What are we working on? | `spec.md`, `plan.md` | actors, trust zones, assets, components, data flows |
| What can go wrong? | — | `threat-model.yaml` (STRIDE + AI/ML profiles) |
| What are we going to do about it? | `tasks.md` | mitigations → `SR-###` → tasks |
| Did we do a good job? | `/speckit.converge` (functional) | security convergence with evidence |

## Design bets

| Bet | Meaning |
|---|---|
| **Threat model as code, OTM-compatible** | `threat-model.yaml` is a valid Open Threat Model document plus ThreatSpec keys. OTM consumers read it unchanged; Markdown is a rendered view. |
| **Deterministic core, semantic edge** | Schema, references, coverage, drift, expiry, severity, and evidence collection run in scripts. The LLM enumerates threats, proposes mitigations, and judges evidence it opened. |
| **Native IDs** | `SR-###` sits next to `FR-###`/`SC-###` in `spec.md`. The companion preset appends one paragraph to core commands so `tasks`, `analyze`, `converge`, and `checklist` treat them natively. |
| **Evidence, not checkboxes** | `verified` requires an inspectable pointer; the engine rejects it otherwise. Claims in tasks, comments, or docstrings never upgrade a verdict. |
| **Profiles pinned to editions** | Mapping keys carry the edition (`owasp-llm-2026`, `owasp-asi-2026`) so future editions do not silently renumber. |
| **Three-state dispositions** | Every technique is `threat`, `no-threat-detected`, or `not-applicable` with a checkable reason; missing information becomes a `needs-clarification` question, never a rated threat. |
| **Risk acceptance is an outcome** | `accepted` and `transferred` need owner, rationale, expiry, and show up in convergence as tracked debt. |
| **Runs without an agent** | Checks and coverage are plain scripts with `md`, `json`, and `sarif` output, usable in CI and code scanning. |
| **Secure by construction** | Artifact content is untrusted data; commands never reproduce secrets or instruction blocks; the extension ships its own threat model. |

## Decisions taken

- The companion preset ships in v0.1 rather than later; it is small and removes the only ambiguity in core integration.
- The project baseline model lives in `.specify/memory/threat-model.yaml`, mirroring the constitution.
- The default severity matrix is 3×3 with a critical tier; likelihood and impact are OTM-style 0–100 integers.
- Convergence locates evidence by default and runs tests only when `verification.test_command` is configured.
- `spec.md` is hashed with the managed SR block removed, so ThreatSpec's own render never counts as drift, while unhashed sources block convergence.
- Command prompts are self-contained (hook procedure repeated in each) and reference siblings only through `__SPECKIT_COMMAND_*__` tokens.

## Roadmap

**v0.2**: `ml` (MITRE ATLAS), `rag`, `privacy` (LINDDUN), `supply-chain` (SLSA) profiles; `bundle.yml` installing extension, preset, and workflow together; exporters (OTM file, Threat Dragon, STIX 2.1, Gherkin `.feature` files from SR acceptance); `review` (facilitated sign-off recorded in the model), `diff` (semantic diff of two model versions for PR review), `report` (cross-feature roll-up); agent runtime `events` guard mode; adversarial fixtures with injected instructions inside spec and code; version pins for the `uv run` fallback; rejection of `extends` paths outside the repository.

**v0.3 ideas**: convergence report as an in-toto/SLSA attestation predicate; OSCAL control mapping for teams that need compliance cross-references.

**Out of scope**: penetration testing, scanning engines, compliance management, dashboards, SaaS. Scanner output may be consumed as evidence; ThreatSpec does not become a scanner.

## Landscape (September 2026)

| Extension | What it does | What it lacks |
|---|---|---|
| `threatmodel` (NaviaSamal, v2.1.2) | OWASP LLM Top 10 2026 scan of the **agent's skill files**; date-sequenced Markdown reports; one `after_implement` hook. Strong prompt discipline: three-state disposition, "documentation is not mitigation", no verbatim quoting, single blocking definition. | Models the tooling, not the product; no machine-readable model, mitigation status, requirement/task/test links, convergence, or scripts. |
| `tekimax-security` (v0.3.1) | Seven gates, STRIDE table, secret/prompt audit, dependency CVEs, hash-chained gate log. | Threat-model gate underspecified; no model file; no evidence chain. |
| `security-review` (DyanGalih, v2.0.0) | OWASP-categorised whitebox audits of diffs, branches, plans; remediation tasks. | Review-time only; no threat model. |
| `spec-kit-cyber` | Fork of Spec Kit with mandatory ASVS-style security in every command. | Not an extension. |

ThreatSpec adopts the `threatmodel` prompt rules and targets the product feature instead of the agent's skill files. Prior art for the format: OWASP pytm, Threagile, Threat Dragon, Open Threat Model, grokify/threat-model-spec; ASOS threat-model-automation for Gherkin security tests.

## References

Spec Kit `extensions/EXTENSION-{API-REFERENCE,DEVELOPMENT-GUIDE,PUBLISHING-GUIDE}.md`, `presets/README.md`, `docs/reference/{workflows,bundles}.md`; iriusrisk/OpenThreatModel; OWASP Top 10 for LLM Applications 2026; OWASP Top 10 for Agentic Applications 2026; OWASP MAESTRO; MITRE ATLAS; LINDDUN; Threat Modeling Manifesto and Capabilities; SARIF 2.1.0; in-toto/SLSA.
