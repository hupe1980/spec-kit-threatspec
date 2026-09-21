"""The shipped example must stay valid and clean as the engine evolves."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEATURE = ROOT / "examples" / "rag-assistant" / "specs" / "001-rag-assistant"


def test_example_model_is_valid(engine):
    model = engine.load_model(FEATURE / "threat-model.yaml")
    assert engine.schema_validate(model) == []
    assert engine.reference_errors(model) == []
    assert len(model["requirements"]) >= 10 and len(model["threats"]) >= 15


def test_example_check_has_nothing_above_medium_and_no_drift(engine):
    paths = engine.Paths(ROOT, FEATURE)
    findings, metrics = engine.run_checks(paths, engine.load_config(ROOT))
    assert engine.worst_severity(findings) in ("none", "low", "medium")
    assert not any(f.check == "C9" for f in findings), "example sources must be hashed and current"
    assert metrics["needs_clarification"] >= 1


def test_example_spec_carries_sr_block_and_render_matches(engine):
    spec = (FEATURE / "spec.md").read_text(encoding="utf-8")
    assert engine.BEGIN_MARK in spec and engine.END_MARK in spec
    assert spec.index(engine.BEGIN_MARK) < spec.index("## Success Criteria")
    model = engine.load_model(FEATURE / "threat-model.yaml")
    assert engine.sr_block(model) in spec
    cov = engine.coverage(engine.Paths(ROOT, FEATURE), engine.load_config(ROOT))
    assert all(t["state"] != "surface-absent" or not t["surfaces_present"] for t in cov["techniques"])
