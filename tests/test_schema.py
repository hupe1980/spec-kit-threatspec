import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "threat-model.schema.json"
GOOD = ROOT / "tests" / "fixtures" / "rag-assistant" / "specs" / "007-rag-assistant" / "threat-model.yaml"
BROKEN = ROOT / "tests" / "fixtures" / "broken" / "threat-model.yaml"


def test_schema_is_valid_json_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"].endswith("2020-12/schema")
    assert set(schema["required"]) == {"otmVersion", "project", "threatspec"}


def test_good_fixture_passes_engine_validation(engine):
    model = engine.load_yaml(GOOD)
    assert engine.schema_validate(model) == []
    assert engine.reference_errors(model) == []


def test_broken_fixture_reports_dangling_reference(engine):
    model = engine.load_yaml(BROKEN)
    errs = engine.reference_errors(model)
    assert any("asset.missing" in e for e in errs)


def test_builtin_validation_catches_required_fields(engine):
    errs = engine.builtin_validate({"otmVersion": "0.2.0", "project": {"id": "x", "name": "x"}, "threatspec": {"version": "0.1"},
                                    "threats": [{"id": "threat.x", "name": "x", "categories": [], "risk": {"likelihood": 200}}]})
    assert any("categories" in e for e in errs)
    assert any("likelihood" in e for e in errs)
    assert any("status" in e for e in errs)


def test_jsonschema_validation_if_available(engine):
    pytest.importorskip("jsonschema")
    model = engine.load_yaml(GOOD)
    assert engine.schema_validate(model) == []
    bad = engine.load_yaml(BROKEN)
    bad["threats"][0]["attributes"]["status"] = "bogus"
    assert any("bogus" in e for e in engine.schema_validate(bad))


def test_template_skeleton_is_parseable_and_shaped():
    tpl = yaml.safe_load((ROOT / "templates" / "threat-model.yaml").read_text(encoding="utf-8"))
    for key in ("otmVersion", "project", "threatspec", "threats", "mitigations", "requirements", "verification", "decisions"):
        assert key in tpl


def test_profiles_are_consistent():
    for name in ("stride", "llm", "agent"):
        prof = yaml.safe_load((ROOT / "profiles" / f"{name}.yaml").read_text(encoding="utf-8"))
        assert prof["profile"]["id"] == name
        surfaces = {s["id"] for s in prof.get("surfaces", [])}
        patterns = {m["id"] for m in prof.get("mitigation_patterns", [])}
        for tech in prof["techniques"]:
            assert tech["category"] in {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
            for s in tech.get("surfaces", []):
                assert s in surfaces, f"{name}: technique {tech['id']} uses undeclared surface {s}"
            for m in tech.get("mitigations", []):
                assert m in patterns, f"{name}: technique {tech['id']} suggests undeclared mitigation {m}"
