import json
from pathlib import Path

import yaml


def test_converge_scan_finds_tasks_and_evidence(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    data = engine.converge_scan(paths, engine.load_config(rag_repo))
    assert data["config"]["verification"]["test_command"] == ""
    assert data["config"]["config_file"].endswith("threatspec-config.yml")
    by_id = {r["id"]: r for r in data["requirements"]}
    assert by_id["SR-001"]["all_tasks_done"] is True
    assert "tests/agent/test_prompt_injection.py" in by_id["SR-001"]["evidence"]["test_files"]
    assert by_id["SR-001"]["evidence"]["touchpoints"][0]["exists"] is True
    assert by_id["SR-002"]["all_tasks_done"] is False
    assert by_id["SR-002"]["evidence"]["test_files"] == []


def test_evidence_scan_skips_caches_and_binaries(engine, rag_repo):
    cache = rag_repo / "tests" / "agent" / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "test_prompt_injection.cpython-313.pyc").write_text("SR-001 SR-", encoding="utf-8")
    (rag_repo / "tests" / "agent" / "notes.pdf").write_text("SR-001 SR-", encoding="utf-8")
    (rag_repo / "tests" / ".hidden").mkdir()
    (rag_repo / "tests" / ".hidden" / "x.py").write_text("SR-001 SR-", encoding="utf-8")
    ev = engine.find_evidence(rag_repo, "SR-001", engine.load_config(rag_repo), [])
    assert ev["test_files"] == ["tests/agent/test_prompt_injection.py"]


def test_evidence_scan_accepts_id_spellings(engine, rag_repo):
    (rag_repo / "tests" / "agent" / "test_underscore.py").write_text("def test_sr_001_blocks(): pass\n", encoding="utf-8")
    (rag_repo / "tests" / "agent" / "test_compact.py").write_text("# covers SR001\n", encoding="utf-8")
    (rag_repo / "tests" / "agent" / "test_other.py").write_text("# covers SR-0010 only\n", encoding="utf-8")
    ev = engine.find_evidence(rag_repo, "SR-001", engine.load_config(rag_repo), [])
    assert ev["test_files"] == ["tests/agent/test_compact.py", "tests/agent/test_prompt_injection.py",
                                "tests/agent/test_underscore.py"]


def test_converge_only_scope_carries_previous_verdicts_forward(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    # run 1: judge everything
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": "SR-001", "verdict": "verified", "method": "test", "evidence": "tests/a.py::t", "result": "pass"},
        {"requirement": "SR-002", "verdict": "missing", "method": "review", "evidence": "none", "result": "fail"},
        {"requirement": "SR-003", "verdict": "verified", "method": "test", "evidence": "tests/b.py::t", "result": "pass"},
    ]}), encoding="utf-8")
    engine.converge_apply(paths, cfg, vf, commit="c1")
    # run 2: only SR-002 re-judged; SR-001/SR-003 must keep 'verified', no new history for them
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": "SR-002", "verdict": "verified", "method": "test", "evidence": "tests/c.py::t", "result": "pass"},
    ]}), encoding="utf-8")
    summary = engine.converge_apply(paths, cfg, vf, commit="c2", only=["SR-002"])
    assert summary["requirements"]["verified"] == ["SR-001", "SR-002", "SR-003"]
    model = engine.load_model(paths.model)
    assert len(model["verification"]) == 4
    assert summary["verdicts"]["SR-001"]["evidence"] == "tests/a.py::t"
    # a verdict outside --only scope is rejected
    import pytest
    vf.write_text(yaml.safe_dump({"verdicts": [{"requirement": "SR-001", "verdict": "missing", "evidence": "none"}]}), encoding="utf-8")
    with pytest.raises(SystemExit):
        engine.converge_apply(paths, cfg, vf, commit="c3", only=["SR-002"])


def test_converge_apply_records_and_appends_tasks(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    verdicts = {"verdicts": [
        {"requirement": "SR-001", "verdict": "verified", "method": "test",
         "evidence": "tests/agent/test_prompt_injection.py::test_corpus_injection_blocked", "result": "pass",
         "justification": "Test asserts no tool call on injected corpus content."},
        {"requirement": "SR-003", "verdict": "implemented-unverified", "method": "review",
         "evidence": "src/agent/tools.py:12", "justification": "Confirmation gate present, no test."},
    ]}
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    vf.write_text(yaml.safe_dump(verdicts), encoding="utf-8")
    tasks_before = paths.tasks.read_text(encoding="utf-8")

    summary = engine.converge_apply(paths, cfg, vf, commit="abc1234")

    assert summary["status"] == "NOT CONVERGED"
    assert summary["requirements"]["verified"] == ["SR-001"]
    assert summary["requirements"]["missing"] == ["SR-002"]  # no verdict supplied → missing
    assert summary["requirements"]["implemented_unverified"] == ["SR-003"]
    assert summary["threats"]["open_blocking"] == ["threat.rag-poisoning"]  # SR-003 also mitigates it and is unverified
    assert summary["drift"] == []
    by_req = {v["requirement"]: v for v in engine.load_model(paths.model)["verification"]}
    assert by_req["SR-003"]["result"] == "inconclusive"  # default result for implemented-unverified

    model = engine.load_model(paths.model)
    assert len(model["verification"]) == 2
    assert all(v["commit"] == "abc1234" for v in model["verification"])

    tasks_after = paths.tasks.read_text(encoding="utf-8")
    assert tasks_after.startswith(tasks_before)  # append-only
    assert "## Phase 4: Security Convergence" in tasks_after
    assert "[SR-002]" in tasks_after and "[SR-003]" in tasks_after
    assert "T022" in tasks_after  # continues numbering after T021
    assert (rag_feature / "security" / "convergence-report.json").exists()
    assert (rag_feature / "security" / "convergence-report.md").exists()


def test_converge_apply_converges_when_everything_verified(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    model = engine.load_model(paths.model)
    model["threatspec"]["sources"] = engine.sources_for(paths)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    verdicts = {"verdicts": [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/x.py::{rid}", "result": "pass",
         "justification": "ok"} for rid in ("SR-001", "SR-002", "SR-003")]}
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    vf.write_text(yaml.safe_dump(verdicts), encoding="utf-8")
    tasks_before = paths.tasks.read_text(encoding="utf-8")
    summary = engine.converge_apply(paths, cfg, vf, commit="abc1234")
    assert summary["status"] == "CONVERGED"
    assert paths.tasks.read_text(encoding="utf-8") == tasks_before  # byte-for-byte unchanged
    model = engine.load_model(paths.model)
    statuses = {t["id"]: t["attributes"]["status"] for t in model["threats"]}
    assert statuses["threat.rag-poisoning"] == "mitigated"
    assert statuses["threat.model-extraction"] == "accepted"


def test_verified_without_evidence_is_rejected(engine, rag_repo, rag_feature):
    import pytest
    paths = engine.Paths(rag_repo, rag_feature)
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    vf.write_text(yaml.safe_dump({"verdicts": [{"requirement": "SR-001", "verdict": "verified"}]}), encoding="utf-8")
    with pytest.raises(SystemExit):
        engine.converge_apply(paths, engine.load_config(rag_repo), vf, commit="x")


def test_render_writes_markdown_and_sr_block(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    model = engine.load_model(paths.model)
    md = engine.render_markdown(model, model, paths, cfg)
    assert "```mermaid" in md and "threat.rag-poisoning" in md and "### SR-001" in md
    action = engine.upsert_sr_block(paths.spec, engine.sr_block(model))
    spec = paths.spec.read_text(encoding="utf-8")
    assert action == "inserted"
    assert spec.index(engine.BEGIN_MARK) < spec.index("## Success Criteria")
    assert "**SR-002**" in spec
    # second run updates in place, nothing outside the markers changes
    action = engine.upsert_sr_block(paths.spec, engine.sr_block(model))
    assert action == "updated"
    assert spec == paths.spec.read_text(encoding="utf-8")


def test_merge_preserves_human_fields_and_retires(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    existing = engine.load_model(paths.model)
    incoming = json.loads(json.dumps(existing))
    incoming["threats"] = [t for t in incoming["threats"] if t["id"] != "threat.inference-exhaustion"]
    incoming["threats"][0]["attributes"].pop("status")  # LLM forgot status
    incoming["threats"][0]["risk"] = {"likelihood": 90, "impact": 95}
    incoming["threats"].append({"id": "threat.new", "name": "New", "categories": ["Spoofing"],
                                "risk": {"likelihood": 10, "impact": 10}, "attributes": {}})
    profiles = engine.load_profiles(["stride"])
    merged, stats = engine.merge_models(existing, incoming, paths, profiles)
    by_id = {t["id"]: t for t in merged["threats"]}
    assert by_id["threat.inference-exhaustion"]["attributes"]["status"] == "retired"
    assert by_id["threat.model-extraction"]["attributes"]["status"] == "accepted"
    assert by_id["threat.new"]["attributes"]["status"] == "open" and by_id["threat.new"]["attributes"]["severity"] == "low"
    assert by_id["threat.rag-poisoning"]["attributes"]["severity"] == "critical"
    assert stats["added"] == 1 and stats["retired"] == 1
    assert merged["decisions"] == existing["decisions"]
    assert merged["threatspec"]["sources"], "sources must be hashed on merge"


def test_unhashed_sources_block_convergence(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    model = engine.load_model(paths.model)
    model["threatspec"]["sources"] = []
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/x.py::{rid}", "result": "pass"}
        for rid in ("SR-001", "SR-002", "SR-003")]}), encoding="utf-8")
    summary = engine.converge_apply(paths, cfg, vf, commit="x")
    assert summary["status"] == "NOT CONVERGED"
    assert any("never hashed" in d for d in summary["drift"])


def test_converge_apply_is_idempotent_when_not_converged(engine, rag_repo, rag_feature):
    paths = engine.Paths(rag_repo, rag_feature)
    cfg = engine.load_config(rag_repo)
    vf = rag_feature / "security" / "verdicts.yaml"
    vf.parent.mkdir(parents=True)
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": "SR-001", "verdict": "verified", "method": "test", "evidence": "tests/a.py::t", "result": "pass"},
        {"requirement": "SR-002", "verdict": "missing", "method": "review", "evidence": "none", "result": "fail"},
        {"requirement": "SR-003", "verdict": "verified", "method": "test", "evidence": "tests/b.py::t", "result": "pass"},
    ]}), encoding="utf-8")
    first = engine.converge_apply(paths, cfg, vf, commit="c1")
    after_first = paths.tasks.read_text(encoding="utf-8")
    assert first["appended_tasks"] == ["T022"] and "[SR-002]" in after_first
    second = engine.converge_apply(paths, cfg, vf, commit="c2")
    assert second["appended_tasks"] == []
    assert second["already_open_tasks_for"] == ["SR-002"]
    assert paths.tasks.read_text(encoding="utf-8") == after_first  # no duplicate phase, no duplicate task
    assert after_first.count("## Phase 4: Security Convergence") == 1
    # once the task is checked off but the SR is still unverified, a fresh task is warranted
    paths.tasks.write_text(after_first.replace("- [ ] T022 [SR-002]", "- [x] T022 [SR-002]"), encoding="utf-8")
    third = engine.converge_apply(paths, cfg, vf, commit="c3")
    assert third["appended_tasks"] == ["T023"]


def test_task_linking_requires_bracket_tags(engine, rag_repo, rag_feature):
    tasks = rag_feature / "tasks.md"
    tasks.write_text(tasks.read_text(encoding="utf-8") + "\n- [ ] T030 One module for each of SR-001 through SR-003\n"
                     "- [ ] T031 [US1] [SR-001, SR-003] Shared helper for both\n", encoding="utf-8")
    parsed = {t["id"]: t for t in engine.parse_tasks(tasks)}
    assert parsed["T030"]["srs"] == [] and parsed["T030"]["mentions"] == ["SR-001", "SR-003"]
    assert parsed["T031"]["srs"] == ["SR-001", "SR-003"]
    cov = engine.coverage(engine.Paths(rag_repo, rag_feature), engine.load_config(rag_repo))
    reqs = {r["id"]: r for r in cov["requirements"]}
    assert "T030" not in " ".join(reqs["SR-001"]["tasks"]) and "T031" in " ".join(reqs["SR-001"]["tasks"])
