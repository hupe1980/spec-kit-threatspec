import json
from pathlib import Path

import yaml


def run_check(engine, repo: Path, feature: Path):
    paths = engine.Paths(repo, feature)
    cfg = engine.load_config(repo)
    findings, metrics = engine.run_checks(paths, cfg)
    return findings, metrics, paths


def checks(findings):
    return {f.check for f in findings}


def test_good_fixture_only_reports_expected_gaps(engine, rag_repo, rag_feature):
    findings, metrics, _ = run_check(engine, rag_repo, rag_feature)
    ids = checks(findings)
    # No structural problems
    assert "C1" not in ids and "C2" not in ids and "C3" not in ids and "C4" not in ids
    # Every SR has a task in the fixture tasks.md
    assert "C5" not in ids
    # No verification yet → C6 for each requirement
    assert sum(1 for f in findings if f.check == "C6") == 3
    # The golden fixture records real source hashes → no drift
    assert "C9" not in ids
    assert metrics["requirements"] == 3 and metrics["requirements_with_tasks"] == 3
    assert engine.worst_severity(findings) == "high"  # SR-001/SR-003 mitigate high/critical threats


def test_broken_fixture_reports_c2_c3_c4_c7_c10_c11(engine, tmp_path):
    repo = tmp_path / "repo"
    feature = repo / "specs" / "001-broken"
    feature.mkdir(parents=True)
    (repo / ".specify").mkdir()
    src = Path(__file__).parent / "fixtures" / "broken" / "threat-model.yaml"
    (feature / "threat-model.yaml").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    findings, _, paths = run_check(engine, repo, feature)
    ids = checks(findings)
    assert {"C2", "C3", "C4", "C7", "C10", "C11"} <= ids
    assert engine.worst_severity(findings) == "critical"
    assert engine.exit_code_for(findings, strict=False) == 2
    sarif = json.loads(engine.report_sarif(findings, paths))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


def test_drift_detected_after_spec_change(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    model = engine.load_model(paths.model)
    model["threatspec"]["sources"] = engine.sources_for(paths)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert "C9" not in checks(findings)
    paths.spec.write_text(paths.spec.read_text(encoding="utf-8") + "\n- **FR-009**: New requirement.\n", encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert any(f.check == "C9" and f.severity == "medium" for f in findings)


def test_c6_severity_follows_implementation_state(engine, rag_repo, rag_feature):
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    c6 = {f.location.split("#")[1]: f for f in findings if f.check == "C6"}
    assert c6["SR-001"].severity == "high"      # tasks done, mitigates a critical threat
    assert c6["SR-003"].severity == "high"      # tasks done, mitigates a high threat
    assert c6["SR-002"].severity == "low"       # T013 still open → implementation not started
    assert "not started" in c6["SR-002"].summary


def test_missing_task_is_c5(engine, rag_repo, rag_feature):
    tasks = rag_feature / "tasks.md"
    tasks.write_text(tasks.read_text(encoding="utf-8").replace("[SR-002]", ""), encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert any(f.check == "C5" and "SR-002" in f.summary for f in findings)


def test_report_md_has_table_and_next_actions(engine, rag_repo, rag_feature):
    findings, metrics, paths = run_check(engine, rag_repo, rag_feature)
    md = engine.report_md(findings, metrics, paths, "warn")
    assert "| ID | Check | Severity |" in md and "**Next actions**" in md


def test_dump_is_deterministic(engine, rag_feature):
    model = engine.load_yaml(rag_feature / "threat-model.yaml")
    a = engine.dump_yaml(model)
    shuffled = dict(reversed(list(model.items())))
    shuffled["threats"] = list(reversed(shuffled["threats"]))
    assert engine.dump_yaml(shuffled) == a


def test_needs_clarification_threats_are_c12_not_c3(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    model = engine.load_model(paths.model)
    model["threats"].append({"id": "threat.nc-auth", "name": "[NEEDS CLARIFICATION: auth method for ticket API]",
                             "categories": ["Spoofing"], "risk": {"likelihood": 0, "impact": 0},
                             "attributes": {"disposition": "needs-clarification", "status": "open", "source": "spec.md#FR-004"}})
    profiles = engine.load_profiles(["stride"])
    merged, _ = engine.merge_models(model, model, paths, profiles)
    nc = next(t for t in merged["threats"] if t["id"] == "threat.nc-auth")
    assert nc["attributes"]["severity"] == "unrated"
    assert engine.schema_validate(merged) == []
    paths.model.write_text(engine.dump_yaml(merged), encoding="utf-8")
    findings, metrics, _ = run_check(engine, rag_repo, rag_feature)
    assert any(f.check == "C12" and "threat.nc-auth" in f.location for f in findings)
    assert not any(f.check in ("C3", "C10") and "threat.nc-auth" in f.location for f in findings)
    assert metrics["needs_clarification"] == 1 and metrics["threats"] == 4
    md = engine.render_markdown(merged, merged, paths, engine.load_config(rag_repo))
    assert "| Needs clarification |" in md and "### Needs clarification" in md


def test_yaml_parse_error_is_reported_cleanly(engine, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("threats:\n  - name: [NEEDS CLARIFICATION: unquoted marker\n", encoding="utf-8")
    import pytest
    with pytest.raises(SystemExit) as exc:
        engine.load_yaml(bad)
    assert "YAML parse error" in str(exc.value) and "quote" in str(exc.value)


def test_rendering_sr_block_is_not_drift(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    model = engine.load_model(paths.model)
    model["threatspec"]["sources"] = engine.sources_for(paths)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    engine.upsert_sr_block(paths.spec, engine.sr_block(model))
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert "C9" not in checks(findings)
    # a human edit outside the block is still drift
    paths.spec.write_text(paths.spec.read_text(encoding="utf-8").replace("FR-005", "FR-005 (changed)"), encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert any(f.check == "C9" and f.location == "spec.md" for f in findings)


def test_coverage_tables(engine, rag_repo, rag_feature):
    cov = engine.coverage(engine.Paths(rag_repo, rag_feature), engine.load_config(rag_repo))
    by_tech = {t["technique"]: t for t in cov["techniques"]}
    assert by_tech["prompt-injection-indirect"]["state"] == "threat" and by_tech["prompt-injection-indirect"]["threats"] == ["threat.rag-poisoning"]
    assert by_tech["model-supply-chain"]["state"] == "not-applicable"
    assert by_tech["unbounded-consumption"]["state"] == "no-threat-detected"
    assert by_tech["injection"]["state"] == "uncovered"          # external-input present, nothing recorded
    assert by_tech["cross-tenant-leak"]["state"] == "surface-absent"
    reqs = {r["id"]: r for r in cov["requirements"]}
    assert reqs["SR-001"]["tasks"] == ["T011*", "T012*"] and reqs["SR-002"]["tasks"] == ["T013"]
    md = engine.coverage_md(cov)
    assert "### Techniques" in md and "### Requirements" in md and "Uncovered techniques" in md


def test_c6_low_findings_are_aggregated(engine, tmp_path, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    paths.tasks.unlink()  # no tasks → every SR "not started"
    model = engine.load_model(paths.model)
    for i in range(4, 9):
        model["requirements"].append({"id": f"SR-00{i}", "statement": "x MUST y", "mitigations": ["mitigation.rate-limit-ask"]})
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    c6 = [f for f in findings if f.check == "C6"]
    assert len(c6) == 1 and "8 requirements" in c6[0].summary


def test_coverage_footer_omits_retired_clarifications(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    model = engine.load_model(paths.model)
    for slug, status in (("open-q", "open"), ("answered-q", "retired")):
        model["threats"].append({"id": f"threat.{slug}", "name": f"[NEEDS CLARIFICATION: {slug}]", "categories": ["Spoofing"],
                                 "risk": {"likelihood": 0, "impact": 0},
                                 "attributes": {"disposition": "needs-clarification", "status": status, "severity": "unrated"}})
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    cov = engine.coverage(paths, engine.load_config(rag_repo))
    assert cov["needs_clarification"] == ["threat.open-q"]
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert [f for f in findings if f.check == "C12" and "answered-q" in f.location] == []


def test_c8_respects_recorded_exclusions(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    spec = paths.spec
    spec.write_text(spec.read_text(encoding="utf-8").replace("- **Conversation**:", "- **Open Event**: A counter of opens.\n- **Conversation**:"), encoding="utf-8")
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert any(f.check == "C8" and "Open Event" in f.summary for f in findings)
    model = engine.load_model(paths.model)
    model["threatspec"]["exclusions"] = [{"entity": "Open Event", "reason": "Folded into a counter column; no separate asset"}]
    model["threatspec"]["sources"] = engine.sources_for(paths)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    assert engine.schema_validate(model) == []
    findings, _, _ = run_check(engine, rag_repo, rag_feature)
    assert not any(f.check == "C8" for f in findings)


def test_strict_flag_is_reflected_in_report_and_exit_code(engine, rag_repo, rag_feature, capsys):
    # fixture state: worst finding is HIGH (C6 on done-but-unverified SRs) → exit 1 either way; header must match the gate
    rc = engine.main(["--repo", str(rag_repo), "--feature-dir", str(rag_feature), "check", "--format", "json", "--strict"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["enforcement"] == "strict"
    rc = engine.main(["--repo", str(rag_repo), "--feature-dir", str(rag_feature), "check", "--format", "md", "--strict", "--persist"])
    md = capsys.readouterr().out
    assert "Enforcement: `strict`" in md
    assert "Enforcement: `strict`" in (rag_feature / "security" / "check-report.md").read_text(encoding="utf-8")
    rc = engine.main(["--repo", str(rag_repo), "--feature-dir", str(rag_feature), "check", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["enforcement"] == "warn"
