+++
title = "ThreatSpec"
description = "ThreatSpec brings deterministic, evidence-based threat modeling and security traceability to Spec Kit's Spec-Driven Development lifecycle."
template = "index.html"

[extra]
hero_kicker = "A Spec Kit extension"
install_cmd = """
# From a release archive (the CLI asks you to confirm the untrusted URL)
specify extension add threatspec --from https://github.com/hupe1980/spec-kit-threatspec/archive/refs/tags/v0.2.0.zip

# Or register this repository's catalog once, then install by name
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-threatspec/main/catalog.json --name threatspec --install-allowed
specify extension add threatspec
"""
chain = """Asset ─▶ Threat ─▶ Mitigation ─▶ Security Requirement (SR-###)
                                      ├──▶ Task (T###)      tasks.md
                                      ├──▶ Verification     test | review | scan | evidence
                                      └──▶ Convergence      every link resolved, every SR verified"""

[[extra.workflow]]
cmd = "/speckit-specify"
output = "spec.md"

[[extra.workflow]]
cmd = "/speckit-threatspec-model"
output = "threat-model.yaml + threat-model.md + SR-### block in spec.md"

[[extra.workflow]]
cmd = "/speckit-plan"
output = "plan.md (sees the security requirements)"

[[extra.workflow]]
cmd = "/speckit-threatspec-model --from-plan"
output = "components, data flows, trust zones"

[[extra.workflow]]
cmd = "/speckit-tasks"
output = "tasks.md (security tasks tagged [SR-###])"

[[extra.workflow]]
cmd = "/speckit-threatspec-check"
output = "gap report: threats → mitigations → SR-### → tasks → verification"

[[extra.workflow]]
cmd = "/speckit-implement"
output = "code + tests"

[[extra.workflow]]
cmd = "/speckit-threatspec-converge"
output = "evidence-based verification, convergence report, remediation tasks"

[[extra.workflow]]
cmd = "/speckit-converge"
output = "core convergence completes the appended tasks"

[[extra.commands]]
name = "/speckit-threatspec-model"
does = "Builds or incrementally updates threat-model.yaml from spec.md (assets, actors, trust zones, threats, mitigations, SR-###) and, with --from-plan, from plan.md (components, data flows)."
writes = "threat-model.yaml, threat-model.md, the marked block in spec.md"

[[extra.commands]]
name = "/speckit-threatspec-check"
does = "Deterministic checks C1–C12 and coverage tables from the engine, plus ten semantic passes; report in the /speckit-analyze shape; --format sarif for GitHub code scanning."
writes = "optional security/check-report.md"

[[extra.commands]]
name = "/speckit-threatspec-converge"
does = "Collects evidence per SR-###, has the agent judge only from that evidence, records append-only verification history, reports convergence, appends remediation tasks."
writes = "threat-model.yaml, security/convergence-report.{md,json}, appended phase in tasks.md"

[[extra.profiles]]
id = "stride"
foundation = "STRIDE per element (default)"

[[extra.profiles]]
id = "llm"
foundation = "OWASP Top 10 for LLM Applications 2026, MITRE ATLAS"

[[extra.profiles]]
id = "agent"
foundation = "OWASP Top 10 for Agentic Applications 2026, MAESTRO layers"

[[extra.principles]]
emoji = "♻️"
label = "Reusable"

[[extra.principles]]
emoji = "🤝"
label = "Agent-agnostic"

[[extra.principles]]
emoji = "🔗"
label = "Traceable"

[[extra.principles]]
emoji = "🎯"
label = "Deterministic where possible"

[[extra.principles]]
emoji = "🪶"
label = "Non-intrusive"

[[extra.principles]]
emoji = "📈"
label = "Incremental"

[[extra.principles]]
emoji = "🧾"
label = "Evidence over claims"

[[extra.principles]]
emoji = "🙋"
label = "Honest about uncertainty"

[[extra.principles]]
emoji = "🔄"
label = "Interoperable (OTM, SARIF)"

[[extra.principles]]
emoji = "🔒"
label = "Secure by construction"
+++

ThreatSpec is a [Spec Kit](https://github.com/github/spec-kit) extension that makes threat modeling and security traceability a first-class part of Spec-Driven Development.

It generates a machine-readable, [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)-compatible threat model from your Spec Kit artifacts, derives testable security requirements (`SR-###`) from it, feeds them into `/speckit-plan` and `/speckit-tasks`, checks the whole chain for gaps deterministically, and verifies after implementation that every threat has been mitigated, implemented, and tested.

Every ThreatSpec hook is optional by default — nothing in the core workflow changes unless you opt in.
