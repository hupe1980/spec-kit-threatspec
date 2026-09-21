#!/usr/bin/env python3
"""ThreatSpec engine — deterministic core for the Spec Kit ThreatSpec extension.

Subcommands
  paths           Resolve repo root, feature directory and artifact paths
  init            Create an empty threat-model.yaml for a feature
  validate        Validate a model against the ThreatSpec schema and reference rules
  merge           Merge an LLM-produced model into the existing one (stable ids, human fields kept)
  render          Render threat-model.md and the SR block inside spec.md
  check           Run gap checks C1–C12 (md | json | sarif), exit code reflects severity
  coverage        Technique × surface × threat/disposition and SR → threat/mitigation/task tables
  converge-scan   Collect per-requirement evidence facts for the converge command
  converge-apply  Record verdicts, write the convergence report, append remediation tasks

Only the standard library plus PyYAML are required. `jsonschema` is used when
available; otherwise a built-in structural validation runs.
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("threatspec: PyYAML is required (pip install pyyaml, or run via uv: uv run --with pyyaml ...)\n")
    sys.exit(2)

EXT_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = EXT_ROOT / "schemas" / "threat-model.schema.json"
PROFILES_DIR = EXT_ROOT / "profiles"
TEMPLATES_DIR = EXT_ROOT / "templates"

MODEL_FILE = "threat-model.yaml"
RENDER_FILE = "threat-model.md"
SECURITY_DIR = "security"
BEGIN_MARK = "<!-- threatspec:begin -->"
END_MARK = "<!-- threatspec:end -->"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
LEVELS_DEFAULT = {"low": 0, "medium": 34, "high": 67}
MATRIX_DEFAULT = {
    "high": {"high": "critical", "medium": "high", "low": "medium"},
    "medium": {"high": "high", "medium": "medium", "low": "low"},
    "low": {"high": "medium", "medium": "low", "low": "low"},
}

TASK_RE = re.compile(r"^\s*-\s*\[( |x|X)\]\s*(T\d{3,})\b(.*)$")
SR_RE = re.compile(r"\bSR-\d{3,}\b")
SR_TAG_RE = re.compile(r"\[((?:SR-\d{3,})(?:\s*,\s*SR-\d{3,})*)\]")  # [SR-001] or [SR-001, SR-002]; prose mentions do not count
ENTITY_RE = re.compile(r"^\s*-\s*\*\*([^*]+)\*\*\s*:", re.MULTILINE)

KEY_ORDER = {
    "root": ["otmVersion", "project", "threatspec", "representations", "trustZones", "assets", "components",
             "dataflows", "threats", "mitigations", "requirements", "verification", "decisions"],
    "generic": ["id", "name", "type", "description", "statement", "priority", "categories", "cwes", "risk",
                "parent", "source", "destination", "bidirectional", "tags", "assets", "threats", "mitigations",
                "acceptance", "tasks", "riskReduction", "requirement", "method", "evidence", "result", "verdict",
                "justification", "verified_at", "verified_by", "commit", "threat", "status", "owner", "rationale",
                "expires", "decided_at", "attributes"],
}


# --------------------------------------------------------------------------- utilities

def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_dates(obj: Any) -> Any:
    """YAML parses bare dates into date objects; the model contract is ISO strings."""
    if isinstance(obj, dict):
        return {k: normalize_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_dates(i) for i in obj]
    if isinstance(obj, _dt.datetime):
        return obj.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    return obj


def load_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return normalize_dates(yaml.safe_load(fh) or {})
    except yaml.YAMLError as exc:
        raise SystemExit(
            f"threatspec: YAML parse error in {path}: {exc}\n"
            "Hint: quote any scalar that contains ': ', '#', or starts with '[' — e.g. "
            "name: \"[NEEDS CLARIFICATION: auth method]\"") from None


def order_keys(obj: Any, order: List[str]) -> Any:
    if isinstance(obj, dict):
        known = [k for k in order if k in obj]
        rest = sorted(k for k in obj if k not in order)
        return {k: order_keys(obj[k], KEY_ORDER["generic"]) for k in known + rest}
    if isinstance(obj, list):
        return [order_keys(i, KEY_ORDER["generic"]) for i in obj]
    return obj


def sort_entities(model: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("trustZones", "assets", "components", "dataflows", "threats", "mitigations", "requirements",
                "verification", "decisions"):
        items = model.get(key)
        if isinstance(items, list):
            model[key] = sorted(items, key=lambda i: str(i.get("id", "")))
    ts = model.get("threatspec") or {}
    if isinstance(ts.get("actors"), list):
        ts["actors"] = sorted(ts["actors"], key=lambda i: str(i.get("id", "")))
    if isinstance(ts.get("sources"), list):
        ts["sources"] = sorted(ts["sources"], key=lambda i: str(i.get("path", "")))
    return model


def dump_yaml(model: Dict[str, Any]) -> str:
    ordered = order_keys(sort_entities(copy.deepcopy(model)), KEY_ORDER["root"])
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=110, default_flow_style=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def git(args: List[str], cwd: Path) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False)
        return out.stdout.strip() if out.returncode == 0 else None
    except OSError:
        return None


# --------------------------------------------------------------------------- paths & config

def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / ".specify").is_dir() or (candidate / ".git").exists():
            return candidate
    return cur


FEATURE_SOURCE = {"how": "none"}


def resolve_feature_dir(repo: Path, explicit: Optional[str]) -> Optional[Path]:
    """Resolution order: --feature-dir, $SPECIFY_FEATURE, current git branch, newest specs/*/spec.md."""
    specs = repo / "specs"
    if explicit:
        p = Path(explicit)
        FEATURE_SOURCE["how"] = "--feature-dir"
        return p if p.is_absolute() else (repo / p)
    env = os.environ.get("SPECIFY_FEATURE")
    if env and (specs / env).is_dir():
        FEATURE_SOURCE["how"] = "SPECIFY_FEATURE"
        return specs / env
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
    if branch and (specs / branch).is_dir():
        FEATURE_SOURCE["how"] = "git-branch"
        return specs / branch
    if specs.is_dir():
        candidates = sorted((d for d in specs.iterdir() if d.is_dir() and (d / "spec.md").exists()),
                            key=lambda d: d.stat().st_mtime, reverse=True)
        if candidates:
            FEATURE_SOURCE["how"] = "newest-spec"
            return candidates[0]
    return None


def load_config(repo: Path) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    ext_manifest = EXT_ROOT / "extension.yml"
    if ext_manifest.exists():
        cfg = copy.deepcopy((load_yaml(ext_manifest).get("config") or {}).get("defaults") or {})
    ext_dir = repo / ".specify" / "extensions" / "threatspec"
    for name in ("threatspec-config.yml", "threatspec-config.local.yml"):
        p = ext_dir / name
        if p.exists():
            deep_update(cfg, load_yaml(p) or {})
    prefix = "SPECKIT_THREATSPEC_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            parts = key[len(prefix):].lower().split("_")
            if parts == ["enforcement"]:
                cfg["enforcement"] = value
            elif parts == ["profiles"]:
                cfg["profiles"] = [v.strip() for v in value.split(",") if v.strip()]
    return cfg


def deep_update(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in incoming.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v
    return base


def load_profiles(names: Iterable[str]) -> List[Dict[str, Any]]:
    out = []
    for n in names:
        p = PROFILES_DIR / f"{n}.yaml"
        if p.exists():
            out.append(load_yaml(p))
    return out


def severity_matrix(profiles: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, Dict[str, str]]]:
    for prof in profiles:
        sm = prof.get("severity_matrix")
        if sm:
            return sm.get("levels", LEVELS_DEFAULT), sm.get("matrix", MATRIX_DEFAULT)
    return LEVELS_DEFAULT, MATRIX_DEFAULT


def level_of(value: int, levels: Dict[str, int]) -> str:
    lvl = "low"
    for name in ("low", "medium", "high"):
        if value >= levels.get(name, LEVELS_DEFAULT[name]):
            lvl = name
    return lvl


def is_clarification(threat: Dict[str, Any]) -> bool:
    return (threat.get("attributes") or {}).get("disposition") == "needs-clarification"


def effective_severity(threat: Dict[str, Any], levels: Dict[str, int], matrix: Dict[str, Dict[str, str]]) -> str:
    at = threat.get("attributes") or {}
    if is_clarification(threat):
        return "unrated"
    return (at.get("severity_override") or {}).get("level") or at.get("severity") or compute_severity(threat, levels, matrix)


def compute_severity(threat: Dict[str, Any], levels: Dict[str, int], matrix: Dict[str, Dict[str, str]]) -> str:
    risk = threat.get("risk") or {}
    lk = level_of(int(risk.get("likelihood", 0)), levels)
    im = level_of(int(risk.get("impact", 0)), levels)
    return matrix.get(lk, {}).get(im, "low")


class Paths:
    def __init__(self, repo: Path, feature: Optional[Path]):
        self.repo = repo
        self.feature = feature
        self.spec = feature / "spec.md" if feature else None
        self.plan = feature / "plan.md" if feature else None
        self.tasks = feature / "tasks.md" if feature else None
        self.model = feature / MODEL_FILE if feature else None
        self.render = feature / RENDER_FILE if feature else None
        self.security = feature / SECURITY_DIR if feature else None
        self.constitution = repo / ".specify" / "memory" / "constitution.md"

    def as_dict(self) -> Dict[str, Any]:
        def s(p: Optional[Path]) -> Optional[str]:
            return str(p) if p else None
        return {
            "REPO_ROOT": str(self.repo),
            "FEATURE_DIR": s(self.feature),
            "SPEC": s(self.spec), "PLAN": s(self.plan), "TASKS": s(self.tasks),
            "MODEL": s(self.model), "RENDER": s(self.render), "SECURITY_DIR": s(self.security),
            "CONSTITUTION": s(self.constitution),
            "EXISTS": {k: bool(p and p.exists()) for k, p in
                       (("spec", self.spec), ("plan", self.plan), ("tasks", self.tasks), ("model", self.model),
                        ("constitution", self.constitution))},
            "FEATURE_SOURCE": FEATURE_SOURCE["how"],
            "EXTENSION_ROOT": str(EXT_ROOT),
        }


def get_paths(args: argparse.Namespace) -> Paths:
    repo = find_repo_root(Path(getattr(args, "repo", None) or os.getcwd()))
    feature = resolve_feature_dir(repo, getattr(args, "feature_dir", None))
    return Paths(repo, feature)


# --------------------------------------------------------------------------- model helpers

def empty_model(project_id: str, name: str, profiles: List[str], baseline: Optional[str]) -> Dict[str, Any]:
    return {
        "otmVersion": "0.2.0",
        "project": {"id": project_id, "name": name},
        "threatspec": {
            "version": "0.1",
            "generated": now_iso(),
            "profiles": list(profiles),
            "extends": baseline,
            "sources": [],
            "actors": [],
            "surfaces": [],
            "dispositions": [],
        },
        "trustZones": [], "assets": [], "components": [], "dataflows": [],
        "threats": [], "mitigations": [], "requirements": [], "verification": [], "decisions": [],
    }


def load_model(path: Path) -> Dict[str, Any]:
    model = load_yaml(path)
    if not isinstance(model, dict):
        raise SystemExit(f"threatspec: {path} is not a mapping")
    return model


def load_baseline(model: Dict[str, Any], model_path: Path) -> Optional[Dict[str, Any]]:
    ext = (model.get("threatspec") or {}).get("extends")
    if not ext:
        return None
    p = Path(ext)
    if not p.is_absolute():
        p = (model_path.parent / p).resolve()
    if not p.exists():
        return None
    return load_yaml(p)


def merged_view(model: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Union of baseline and feature model for reference resolution; the feature wins on id clash."""
    if not baseline:
        return model
    view = copy.deepcopy(model)
    for key in ("trustZones", "assets", "components", "dataflows", "threats", "mitigations", "requirements",
                "verification", "decisions"):
        ids = {i.get("id") for i in view.get(key) or []}
        for item in baseline.get(key) or []:
            if item.get("id") not in ids:
                view.setdefault(key, []).append(item)
    bts = baseline.get("threatspec") or {}
    vts = view.setdefault("threatspec", {})
    ids = {a.get("id") for a in vts.get("actors") or []}
    for a in bts.get("actors") or []:
        if a.get("id") not in ids:
            vts.setdefault("actors", []).append(a)
    return view


def index_by_id(items: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    return {i["id"]: i for i in (items or []) if isinstance(i, dict) and "id" in i}


def strip_managed_block(text: str) -> str:
    """Remove the ThreatSpec-managed SR block (and the blank lines it brought) so our own render never counts as drift."""
    pattern = re.escape(BEGIN_MARK) + r".*?" + re.escape(END_MARK) + r"\n*"
    return re.sub(pattern, "", text, flags=re.S)


def source_hash(path: Path) -> str:
    """Content hash used for drift detection. spec.md is normalised: managed block removed, trailing newlines trimmed."""
    if path.name == "spec.md":
        normalised = strip_managed_block(path.read_text(encoding="utf-8")).rstrip("\n")
        return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
    return sha256_file(path)


def sources_for(paths: Paths) -> List[Dict[str, str]]:
    out = []
    for p in (paths.spec, paths.plan):
        if p and p.exists():
            out.append({"path": p.name, "sha256": source_hash(p)})
    return out


# --------------------------------------------------------------------------- validation

def builtin_validate(model: Dict[str, Any]) -> List[str]:
    """Structural validation used when jsonschema is unavailable."""
    errors: List[str] = []
    for key in ("otmVersion", "project", "threatspec"):
        if key not in model:
            errors.append(f"missing required key '{key}'")
    patterns = {
        "trustZones": r"^tz\.", "assets": r"^asset\.", "components": r"^component\.", "dataflows": r"^flow\.",
        "threats": r"^threat\.", "mitigations": r"^mitigation\.", "requirements": r"^SR-\d{3,}$",
        "verification": r"^verification\.", "decisions": r"^decision\.",
    }
    for key, pat in patterns.items():
        for i, item in enumerate(model.get(key) or []):
            if not isinstance(item, dict) or "id" not in item:
                errors.append(f"{key}[{i}] has no id")
                continue
            if not re.match(pat, str(item["id"])):
                errors.append(f"{key}[{i}] id '{item['id']}' does not match {pat}")
    for t in model.get("threats") or []:
        if not isinstance(t, dict):
            continue
        if not t.get("categories"):
            errors.append(f"threat {t.get('id')} has no categories")
        risk = t.get("risk") or {}
        for k in ("likelihood", "impact"):
            v = risk.get(k)
            if not isinstance(v, int) or not 0 <= v <= 100:
                errors.append(f"threat {t.get('id')} risk.{k} must be an integer 0–100")
        if not (t.get("attributes") or {}).get("status"):
            errors.append(f"threat {t.get('id')} attributes.status is required")
    for m in model.get("mitigations") or []:
        if isinstance(m, dict) and not (m.get("attributes") or {}).get("threats"):
            errors.append(f"mitigation {m.get('id')} attributes.threats is required")
    for r in model.get("requirements") or []:
        if isinstance(r, dict) and not r.get("mitigations"):
            errors.append(f"requirement {r.get('id')} mitigations is required")
    for d in model.get("decisions") or []:
        if isinstance(d, dict):
            for k in ("threat", "status", "owner", "rationale", "expires"):
                if not d.get(k):
                    errors.append(f"decision {d.get('id')} missing '{k}'")
    return errors


def schema_validate(model: Dict[str, Any]) -> List[str]:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return builtin_validate(model)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = []
    for err in sorted(validator.iter_errors(model), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        errors.append(f"{loc}: {err.message}")
    return errors + builtin_validate(model)


def reference_errors(view: Dict[str, Any]) -> List[str]:
    errs: List[str] = []
    ts = view.get("threatspec") or {}
    actors = index_by_id(ts.get("actors"))
    tzs = index_by_id(view.get("trustZones"))
    assets = index_by_id(view.get("assets"))
    comps = index_by_id(view.get("components"))
    threats = index_by_id(view.get("threats"))
    mits = index_by_id(view.get("mitigations"))
    reqs = index_by_id(view.get("requirements"))
    nodes = set(actors) | set(comps) | set(tzs)

    def need(ref: Any, table: Dict[str, Any], where: str, kind: str) -> None:
        if ref is not None and ref not in table:
            errs.append(f"{where} references unknown {kind} '{ref}'")

    def threat_refs(refs: List[Dict[str, Any]], where: str) -> None:
        for tr in refs or []:
            need(tr.get("threat"), threats, where, "threat")
            for mr in tr.get("mitigations") or []:
                need(mr.get("mitigation"), mits, where, "mitigation")

    for c in view.get("components") or []:
        where = f"component {c.get('id')}"
        parent = c.get("parent") or {}
        if "trustZone" in parent:
            need(parent["trustZone"], tzs, where, "trust zone")
        if "component" in parent:
            need(parent["component"], comps, where, "component")
        for a in c.get("assets") or []:
            need(a, assets, where, "asset")
        threat_refs(c.get("threats"), where)
        for tool in (c.get("attributes") or {}).get("tools") or []:
            need(tool, assets, where, "asset (tool)")
    for f in view.get("dataflows") or []:
        where = f"dataflow {f.get('id')}"
        for end in ("source", "destination"):
            if f.get(end) not in nodes:
                errs.append(f"{where} {end} '{f.get(end)}' is not a known component, actor, or trust zone")
        for a in f.get("assets") or []:
            need(a, assets, where, "asset")
        for tz in (f.get("attributes") or {}).get("crosses") or []:
            need(tz, tzs, where, "trust zone")
        threat_refs(f.get("threats"), where)
    for t in view.get("threats") or []:
        where = f"threat {t.get('id')}"
        at = t.get("attributes") or {}
        if at.get("actor"):
            need(at["actor"], actors, where, "actor")
        for a in at.get("assets") or []:
            need(a, assets, where, "asset")
        for el in at.get("elements") or []:
            if el not in nodes and el not in index_by_id(view.get("dataflows")):
                errs.append(f"{where} element '{el}' is not a known component, actor, trust zone, or dataflow")
        if at.get("superseded_by"):
            need(at["superseded_by"], threats, where, "threat")
    for m in view.get("mitigations") or []:
        where = f"mitigation {m.get('id')}"
        at = m.get("attributes") or {}
        for t in at.get("threats") or []:
            need(t, threats, where, "threat")
        for r in at.get("requirements") or []:
            need(r, reqs, where, "requirement")
    for r in view.get("requirements") or []:
        where = f"requirement {r.get('id')}"
        for m in r.get("mitigations") or []:
            need(m, mits, where, "mitigation")
    for v in view.get("verification") or []:
        need(v.get("requirement"), reqs, f"verification {v.get('id')}", "requirement")
    for d in view.get("decisions") or []:
        need(d.get("threat"), threats, f"decision {d.get('id')}", "threat")
    return errs


# --------------------------------------------------------------------------- tasks & spec parsing

def parse_tasks(path: Optional[Path]) -> List[Dict[str, Any]]:
    if not path or not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = TASK_RE.match(line)
        if not m:
            continue
        done, tid, rest = m.group(1).lower() == "x", m.group(2), m.group(3)
        tagged = {sr for group in SR_TAG_RE.findall(rest) for sr in SR_RE.findall(group)}
        out.append({"id": tid, "done": done, "line": n, "text": rest.strip(), "srs": sorted(tagged),
                    "mentions": sorted(set(SR_RE.findall(rest)) - tagged)})
    return out


def tasks_for_requirement(tasks: List[Dict[str, Any]], req: Dict[str, Any]) -> List[Dict[str, Any]]:
    declared = set(req.get("tasks") or [])
    rid = req.get("id")
    return [t for t in tasks if t["id"] in declared or rid in t["srs"]]


def spec_entities(spec: Optional[Path]) -> List[str]:
    if not spec or not spec.exists():
        return []
    text = spec.read_text(encoding="utf-8")
    m = re.search(r"###\s*Key Entities.*?(?=\n##\s|\Z)", text, re.S)
    if not m:
        return []
    return [e.strip() for e in ENTITY_RE.findall(m.group(0)) if not e.strip().startswith("[")]


# --------------------------------------------------------------------------- checks

class Finding:
    def __init__(self, check: str, severity: str, location: str, summary: str, recommendation: str):
        self.check, self.severity, self.location, self.summary, self.recommendation = (
            check, severity, location, summary, recommendation)

    def as_dict(self) -> Dict[str, str]:
        return {"check": self.check, "severity": self.severity, "location": self.location,
                "summary": self.summary, "recommendation": self.recommendation}


def run_checks(paths: Paths, cfg: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any]]:
    findings: List[Finding] = []
    model_path = paths.model
    if not model_path or not model_path.exists():
        findings.append(Finding("C1", "critical", MODEL_FILE, "threat-model.yaml is missing",
                                "Run the model command first"))
        return findings, {}
    model = load_model(model_path)
    loc = MODEL_FILE

    for e in schema_validate(model):
        findings.append(Finding("C1", "critical", loc, f"Schema: {e}", "Fix the model structure"))
    baseline = load_baseline(model, model_path)
    view = merged_view(model, baseline)
    for e in reference_errors(view):
        findings.append(Finding("C2", "critical", loc, e, "Point the reference at an existing id or add the entity"))

    profiles = load_profiles((model.get("threatspec") or {}).get("profiles") or cfg.get("profiles") or ["stride"])
    levels, matrix = severity_matrix(profiles)
    mits_by_threat: Dict[str, List[str]] = {}
    for m in view.get("mitigations") or []:
        for t in (m.get("attributes") or {}).get("threats") or []:
            mits_by_threat.setdefault(t, []).append(m["id"])
    decisions_by_threat = {d.get("threat"): d for d in view.get("decisions") or []}
    reqs_by_mit: Dict[str, List[str]] = {}
    for r in view.get("requirements") or []:
        for m in r.get("mitigations") or []:
            reqs_by_mit.setdefault(m, []).append(r["id"])
    for m in view.get("mitigations") or []:
        for r in (m.get("attributes") or {}).get("requirements") or []:
            reqs_by_mit.setdefault(m["id"], []).append(r)

    # C3 threats without mitigation or decision; C10 severity consistency
    for t in model.get("threats") or []:
        at = t.get("attributes") or {}
        tid = t.get("id")
        if at.get("status") == "retired":
            continue
        if is_clarification(t):
            findings.append(Finding("C12", "medium", f"{loc}#{tid}",
                                    f"Threat '{tid}' needs clarification: {t.get('name', '')}",
                                    "Resolve the question in the spec (clarify command), then re-run the model command"))
            continue
        computed = compute_severity(t, levels, matrix)
        stated = at.get("severity")
        override = at.get("severity_override") or {}
        if stated and stated != computed and not override.get("reason"):
            findings.append(Finding("C10", "low", f"{loc}#{tid}",
                                    f"Stated severity '{stated}' differs from matrix result '{computed}'",
                                    "Adjust likelihood/impact or add severity_override.reason"))
        effective = override.get("level") or stated or computed
        if not mits_by_threat.get(tid) and tid not in decisions_by_threat:
            sev = "critical" if SEVERITY_ORDER.get(effective, 0) >= 2 or at.get("constitution") else "high"
            findings.append(Finding("C3", sev, f"{loc}#{tid}",
                                    f"Threat '{tid}' ({effective}) has no mitigation and no accepted/transferred decision",
                                    "Add a mitigation with an SR-### or record a decision with owner and expiry"))

    # C4 mitigations without requirement
    for m in model.get("mitigations") or []:
        if (m.get("attributes") or {}).get("status") == "rejected":
            continue
        if not reqs_by_mit.get(m["id"]):
            findings.append(Finding("C4", "high", f"{loc}#{m['id']}",
                                    f"Mitigation '{m['id']}' has no security requirement",
                                    "Derive an SR-### with acceptance criteria"))

    # C5 requirements without task; C6 without verification
    tasks = parse_tasks(paths.tasks)
    verifications: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        verifications.setdefault(v.get("requirement"), []).append(v)
    threat_sev: Dict[str, str] = {t["id"]: effective_severity(t, levels, matrix) for t in view.get("threats") or []}
    mit_index = index_by_id(view.get("mitigations"))
    for r in model.get("requirements") or []:
        rid = r["id"]
        linked_threats = [t for m in r.get("mitigations") or [] for t in (mit_index.get(m, {}).get("attributes") or {}).get("threats") or []]
        worst = max((SEVERITY_ORDER.get(threat_sev.get(t, "low"), 0) for t in linked_threats), default=0)
        if paths.tasks and paths.tasks.exists() and not tasks_for_requirement(tasks, r):
            findings.append(Finding("C5", "high", f"{loc}#{rid}", f"Requirement '{rid}' has no task in tasks.md",
                                    f"Add a task tagged [{rid}] or list task ids under requirements[].tasks"))
        if not verifications.get(rid):
            # Phase-aware: unverified is only urgent once implementation claims to be done.
            rtasks = tasks_for_requirement(tasks, r)
            if rtasks and all(t["done"] for t in rtasks):
                sev, note = ("high" if worst >= 2 else "medium"), "all tasks are done but nothing verifies it"
            elif rtasks and any(t["done"] for t in rtasks):
                sev, note = "medium", "implementation in progress"
            else:
                sev, note = "low", "implementation not started"
            findings.append(Finding("C6", sev, f"{loc}#{rid}",
                                    f"Requirement '{rid}' has no verification entry ({note})",
                                    "Run the converge command after implementation or record evidence"))

    # C7 decisions
    max_days = int((cfg.get("risk_acceptance") or {}).get("max_duration_days", 180))
    require_owner = bool((cfg.get("risk_acceptance") or {}).get("require_owner", True))
    for d in model.get("decisions") or []:
        did = d.get("id")
        missing = [k for k in ("owner", "rationale", "expires") if not d.get(k)]
        if not require_owner and "owner" in missing:
            missing.remove("owner")
        if missing:
            findings.append(Finding("C7", "high", f"{loc}#{did}", f"Decision '{did}' is missing {', '.join(missing)}",
                                    "Complete the decision record"))
            continue
        try:
            exp = _dt.date.fromisoformat(str(d["expires"]))
        except ValueError:
            findings.append(Finding("C7", "high", f"{loc}#{did}", f"Decision '{did}' has an invalid expiry", "Use YYYY-MM-DD"))
            continue
        if exp < today():
            findings.append(Finding("C7", "high", f"{loc}#{did}", f"Decision '{did}' expired on {exp}",
                                    "Re-decide, mitigate, or extend with a new rationale"))
        elif (exp - today()).days > max_days:
            findings.append(Finding("C7", "medium", f"{loc}#{did}",
                                    f"Decision '{did}' exceeds max_duration_days ({max_days})",
                                    "Shorten the acceptance window"))

    # C8 spec entities absent from model
    names = " ".join(str(i.get("name", "")) + " " + str(i.get("id", "")) + " " + json.dumps(i.get("attributes") or {})
                     for k in ("assets", "components", "dataflows") for i in view.get(k) or []).lower()
    excluded = {str(e.get("entity", "")).lower(): e.get("reason", "") for e in (model.get("threatspec") or {}).get("exclusions") or []}
    for ent in spec_entities(paths.spec):
        if ent.lower() in excluded:
            continue  # deliberately out of scope, with a recorded reason
        if ent.lower() not in names and ent.lower().replace(" ", "-") not in names:
            findings.append(Finding("C8", "medium", "spec.md#Key-Entities",
                                    f"Key entity '{ent}' is not represented in the threat model",
                                    "Add it as an asset or component, or note why it is out of scope"))

    # C9 drift
    recorded = {s.get("path"): s.get("sha256") for s in (model.get("threatspec") or {}).get("sources") or []}
    for src in sources_for(paths):
        if recorded.get(src["path"]) and recorded[src["path"]] != src["sha256"]:
            findings.append(Finding("C9", "medium", src["path"], f"{src['path']} changed since the model was generated",
                                    "Re-run the model command to refresh the threat model"))
        elif not recorded.get(src["path"]):
            findings.append(Finding("C9", "low", src["path"], f"{src['path']} was not hashed when the model was generated",
                                    "Re-run the model command"))

    # C11 not-applicable dispositions whose surface exists
    surfaces = set((model.get("threatspec") or {}).get("surfaces") or [])
    tech_surfaces: Dict[str, List[str]] = {}
    for prof in profiles:
        for tech in prof.get("techniques") or []:
            tech_surfaces[tech["id"]] = tech.get("surfaces") or []
    for disp in (model.get("threatspec") or {}).get("dispositions") or []:
        if disp.get("disposition") != "not-applicable":
            continue
        needed = tech_surfaces.get(disp.get("technique"), [])
        if needed and all(s in surfaces for s in needed):
            findings.append(Finding("C11", "medium", f"{loc}#dispositions/{disp.get('technique')}",
                                    f"Technique '{disp.get('technique')}' is marked not-applicable but its surfaces {needed} are present",
                                    "Evaluate the technique or remove the surface"))

    findings = aggregate_c6(findings, loc)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.check, f.location))
    metrics = summarize(view, model, tasks, verifications, findings)
    return findings, metrics


def aggregate_c6(findings: List[Finding], loc: str) -> List[Finding]:
    """Collapse the pre-implementation 'not started' C6 rows into one line so the report stays readable."""
    pending = [f for f in findings if f.check == "C6" and f.severity == "low"]
    if len(pending) <= 3:
        return findings
    ids = [f.location.split("#", 1)[1] for f in pending]
    rest = [f for f in findings if f not in pending]
    rest.append(Finding("C6", "low", f"{loc}#requirements",
                        f"{len(ids)} requirements have no verification entry yet (implementation not started): {', '.join(ids)}",
                        "Expected before implementation; run the converge command afterwards"))
    return rest


def summarize(view: Dict[str, Any], model: Dict[str, Any], tasks: List[Dict[str, Any]],
              verifications: Dict[str, List[Dict[str, Any]]], findings: List[Finding]) -> Dict[str, Any]:
    active = [t for t in model.get("threats") or [] if (t.get("attributes") or {}).get("status") != "retired"]
    threats = [t for t in active if not is_clarification(t)]
    clarifications = [t for t in active if is_clarification(t)]
    by_status: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for t in threats:
        at = t.get("attributes") or {}
        by_status[at.get("status", "open")] = by_status.get(at.get("status", "open"), 0) + 1
        sev = (at.get("severity_override") or {}).get("level") or at.get("severity") or "unknown"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    reqs = model.get("requirements") or []
    with_tasks = sum(1 for r in reqs if tasks_for_requirement(tasks, r))
    verified = sum(1 for r in reqs if any(v.get("verdict") == "verified" or v.get("result") == "pass"
                                          for v in verifications.get(r["id"], [])))
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "threats": len(threats), "needs_clarification": len(clarifications),
        "threats_by_status": by_status, "threats_by_severity": by_sev,
        "mitigations": len(model.get("mitigations") or []),
        "requirements": len(reqs), "requirements_with_tasks": with_tasks, "requirements_verified": verified,
        "decisions": len(model.get("decisions") or []),
        "findings": counts,
    }


def worst_severity(findings: List[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="none")


def exit_code_for(findings: List[Finding], strict: bool) -> int:
    worst = worst_severity(findings)
    if worst == "critical":
        return 2
    if worst == "high" or (strict and worst == "medium"):
        return 1
    return 0


def report_md(findings: List[Finding], metrics: Dict[str, Any], paths: Paths, enforcement: str) -> str:
    lines = ["## ThreatSpec Check Report", ""]
    lines.append(f"Feature: `{paths.feature.name if paths.feature else '?'}` · Model: `{MODEL_FILE}` · Enforcement: `{enforcement}`")
    lines.append("")
    if findings:
        lines += ["| ID | Check | Severity | Location | Summary | Recommendation |", "|---|---|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            lines.append(f"| F{i} | {f.check} | {f.severity.upper()} | `{f.location}` | {f.summary} | {f.recommendation} |")
    else:
        lines.append("No findings. The security chain is structurally complete.")
    lines += ["", "**Metrics**", ""]
    for k in ("threats", "mitigations", "requirements", "requirements_with_tasks", "requirements_verified", "decisions"):
        lines.append(f"- {k.replace('_', ' ')}: {metrics.get(k, 0)}")
    if metrics.get("threats_by_severity"):
        lines.append("- threats by severity: " + ", ".join(f"{k} {v}" for k, v in sorted(metrics["threats_by_severity"].items())))
    if metrics.get("findings"):
        lines.append("- findings: " + ", ".join(f"{k} {v}" for k, v in sorted(metrics["findings"].items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))))
    worst = worst_severity(findings)
    lines += ["", "**Next actions**", ""]
    if worst == "critical":
        lines.append("- CRITICAL findings exist. " + ("Do NOT proceed to implement until resolved (enforcement: strict)." if enforcement == "strict" else "Resolve before implementing."))
    elif worst in ("high", "medium"):
        lines.append("- Resolve HIGH findings before implementation; MEDIUM may proceed with a note.")
    else:
        lines.append("- Proceed.")
    return "\n".join(lines) + "\n"


def report_sarif(findings: List[Finding], paths: Paths) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f.check, {"id": f.check, "name": f"threatspec/{f.check}",
                                   "shortDescription": {"text": CHECK_NAMES.get(f.check, f.check)}})
        uri = f.location.split("#", 1)[0]
        if paths.feature:
            uri = str((paths.feature / uri).relative_to(paths.repo)) if (paths.feature / uri).exists() else uri
        results.append({
            "ruleId": f.check, "level": level.get(f.severity, "warning"),
            "message": {"text": f"{f.summary}. {f.recommendation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri.replace(os.sep, "/")}}}],
            "properties": {"severity": f.severity, "fragment": f.location.split("#", 1)[1] if "#" in f.location else ""},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "threatspec", "version": "0.1.0",
                                       "informationUri": "https://github.com/hupe1980/spec-kit-threatspec",
                                       "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2) + "\n"


CHECK_NAMES = {
    "C1": "Schema validation", "C2": "Dangling reference", "C3": "Threat without mitigation or decision",
    "C4": "Mitigation without requirement", "C5": "Requirement without task", "C6": "Requirement without verification",
    "C7": "Incomplete or expired decision", "C8": "Spec entity missing from model", "C9": "Source drift",
    "C10": "Severity inconsistent with matrix", "C11": "Not-applicable disposition with surface present",
    "C12": "Threat needs clarification",
}


# --------------------------------------------------------------------------- coverage

def coverage(paths: Paths, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Mechanical cross-reference: technique × surface × threat/disposition, and SR → threats/mitigations/tasks/verification."""
    model = load_model(paths.model)
    view = merged_view(model, load_baseline(model, paths.model))
    ts = model.get("threatspec") or {}
    profiles = load_profiles(ts.get("profiles") or cfg.get("profiles") or ["stride"])
    present = set(ts.get("surfaces") or [])
    dispositions = {d.get("technique"): d for d in ts.get("dispositions") or []}
    by_tech: Dict[str, List[str]] = {}
    for t in view.get("threats") or []:
        at = t.get("attributes") or {}
        if at.get("status") != "retired" and not is_clarification(t):
            by_tech.setdefault(at.get("technique", ""), []).append(t["id"])
    techniques = []
    for prof in profiles:
        for tech in prof.get("techniques") or []:
            needed = tech.get("surfaces") or []
            applicable = all(sf in present for sf in needed)
            threats = by_tech.get(tech["id"], [])
            disp = dispositions.get(tech["id"])
            if threats:
                state = "threat"
            elif disp:
                state = disp.get("disposition")
            else:
                state = "uncovered" if applicable else "surface-absent"
            techniques.append({"profile": prof["profile"]["id"], "technique": tech["id"], "category": tech.get("category"),
                               "surfaces": needed, "surfaces_present": applicable, "state": state,
                               "threats": threats, "reason": (disp or {}).get("reason", "")})
    mits = index_by_id(view.get("mitigations"))
    tasks = parse_tasks(paths.tasks)
    ver: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        ver.setdefault(v.get("requirement"), []).append(v)
    reqs = []
    for r in sorted(model.get("requirements") or [], key=lambda x: x["id"]):
        threats = sorted({t for m in r.get("mitigations") or [] for t in (mits.get(m, {}).get("attributes") or {}).get("threats") or []})
        rt = tasks_for_requirement(tasks, r)
        latest = max(ver.get(r["id"], []), key=lambda v: str(v.get("verified_at", "")), default=None)
        reqs.append({"id": r["id"], "priority": r.get("priority", "P2"), "threats": threats,
                     "mitigations": r.get("mitigations") or [],
                     "tasks": [t["id"] + ("*" if t["done"] else "") for t in rt],
                     "verified": (latest or {}).get("verdict") == "verified" or (latest or {}).get("result") == "pass",
                     "latest_verdict": (latest or {}).get("verdict")})
    clar = [t["id"] for t in model.get("threats") or []
            if is_clarification(t) and (t.get("attributes") or {}).get("status") != "retired"]
    return {"feature": paths.feature.name if paths.feature else None, "tasks_file": bool(paths.tasks and paths.tasks.exists()),
            "surfaces_present": sorted(present), "techniques": techniques, "requirements": reqs, "needs_clarification": clar,
            "uncovered": [t["technique"] for t in techniques if t["state"] == "uncovered"]}


def coverage_md(c: Dict[str, Any]) -> str:
    L = [f"## ThreatSpec Coverage — {c.get('feature')}", "", f"Surfaces present: {', '.join(c['surfaces_present']) or 'none recorded'}", "",
         "### Techniques", "", "| Profile | Technique | Category | Surfaces | Present | State | Threats | Reason |", "|---|---|---|---|---|---|---|---|"]
    for t in c["techniques"]:
        L.append(f"| {t['profile']} | {t['technique']} | {t['category']} | {', '.join(t['surfaces']) or '—'} | {'yes' if t['surfaces_present'] else 'no'} | "
                 f"**{t['state']}** | {', '.join(f'`{x}`' for x in t['threats']) or '—'} | {md_escape(t['reason'])} |")
    L += ["", "### Requirements", "", "| Requirement | Priority | Threats | Mitigations | Tasks | Verified? |", "|---|---|---|---|---|---|"]
    for r in c["requirements"]:
        tasks = ", ".join(r["tasks"]) if r["tasks"] else ("— (no tasks.md)" if not c["tasks_file"] else "— none —")
        L.append(f"| {r['id']} | {r['priority']} | {', '.join(f'`{x}`' for x in r['threats'])} | {', '.join(f'`{x}`' for x in r['mitigations'])} | {tasks} | "
                 f"{'yes' if r['verified'] else ('no (' + r['latest_verdict'] + ')' if r['latest_verdict'] else 'no')} |")
    if c["needs_clarification"]:
        L += ["", "Needs clarification (no requirement expected): " + ", ".join(f"`{x}`" for x in c["needs_clarification"])]
    if c["uncovered"]:
        L += ["", "**Uncovered techniques** (surfaces present, no threat, no disposition): " + ", ".join(c["uncovered"])]
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- merge

HUMAN_THREAT_FIELDS = ("status", "severity_override", "notes", "superseded_by", "retired_reason")


def merge_models(existing: Dict[str, Any], incoming: Dict[str, Any], paths: Paths,
                 profiles: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    stats = {"added": 0, "updated": 0, "retired": 0, "kept": 0}
    result = copy.deepcopy(incoming)
    result["otmVersion"] = existing.get("otmVersion") or incoming.get("otmVersion") or "0.2.0"
    result["project"] = deep_update(copy.deepcopy(existing.get("project") or {}), incoming.get("project") or {})
    ts_old = existing.get("threatspec") or {}
    ts_new = result.setdefault("threatspec", {})
    ts_new["version"] = "0.1"
    ts_new["generated"] = now_iso()
    ts_new["profiles"] = ts_new.get("profiles") or ts_old.get("profiles") or ["stride"]
    ts_new["extends"] = ts_new.get("extends", ts_old.get("extends"))
    ts_new["sources"] = sources_for(paths)
    for key in ("surfaces", "dispositions", "actors", "exclusions"):
        ts_new.setdefault(key, ts_old.get(key) or [])

    levels, matrix = severity_matrix(profiles)

    # threats: keep human fields, retire missing
    old_threats = index_by_id(existing.get("threats"))
    new_threats = index_by_id(result.get("threats"))
    for tid, old in old_threats.items():
        oat = old.get("attributes") or {}
        if tid in new_threats:
            nat = new_threats[tid].setdefault("attributes", {})
            for f in HUMAN_THREAT_FIELDS:
                if f in oat and f not in nat:
                    nat[f] = oat[f]
            if oat.get("status") in ("accepted", "transferred", "mitigated", "retired"):
                nat["status"] = oat["status"]
            stats["updated" if new_threats[tid] != old else "kept"] += 1
        else:
            retired = copy.deepcopy(old)
            rat = retired.setdefault("attributes", {})
            if rat.get("status") != "retired":
                rat["status"] = "retired"
                rat.setdefault("retired_reason", "Not present in the regenerated model")
                stats["retired"] += 1
            result.setdefault("threats", []).append(retired)
    stats["added"] += sum(1 for tid in new_threats if tid not in old_threats)
    for t in result.get("threats") or []:
        at = t.setdefault("attributes", {})
        at.setdefault("status", "open")
        if is_clarification(t):
            at["severity"] = "unrated"          # a question, not a rated threat
        elif not (at.get("severity_override") or {}).get("reason"):
            at["severity"] = compute_severity(t, levels, matrix)

    # mitigations: keep status; requirements: keep tasks; verification/decisions: union by id (existing wins)
    old_m = index_by_id(existing.get("mitigations"))
    for m in result.get("mitigations") or []:
        o = old_m.get(m["id"])
        if o:
            oat = o.get("attributes") or {}
            nat = m.setdefault("attributes", {})
            if "status" in oat and "status" not in nat:
                nat["status"] = oat["status"]
    for m in old_m.values():
        if m["id"] not in index_by_id(result.get("mitigations")):
            result.setdefault("mitigations", []).append(m)
    old_r = index_by_id(existing.get("requirements"))
    for r in result.get("requirements") or []:
        o = old_r.get(r["id"])
        if o and o.get("tasks") and not r.get("tasks"):
            r["tasks"] = o["tasks"]
    for r in old_r.values():
        if r["id"] not in index_by_id(result.get("requirements")):
            result.setdefault("requirements", []).append(r)
    for key in ("verification", "decisions"):
        merged = index_by_id(existing.get(key))
        for item in result.get(key) or []:
            merged.setdefault(item["id"], item)
        result[key] = list(merged.values())
    for key in ("trustZones", "assets", "components", "dataflows"):
        result.setdefault(key, [])
    return result, stats


# --------------------------------------------------------------------------- render

def md_escape(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def mermaid(view: Dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    comps = view.get("components") or []
    by_tz: Dict[str, List[Dict[str, Any]]] = {}
    for c in comps:
        by_tz.setdefault((c.get("parent") or {}).get("trustZone", ""), []).append(c)

    def node_id(i: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]", "_", i)

    for a in (view.get("threatspec") or {}).get("actors") or []:
        lines.append(f'    {node_id(a["id"])}(["{md_escape(a.get("name", a["id"]))}"])')
    for tz in view.get("trustZones") or []:
        lines.append(f'    subgraph {node_id(tz["id"])}["{md_escape(tz.get("name", tz["id"]))}"]')
        for c in by_tz.get(tz["id"], []):
            shape = "[(" if c.get("type") in ("datastore", "database", "vector-store") else "["
            close = ")]" if shape == "[(" else "]"
            lines.append(f'        {node_id(c["id"])}{shape}"{md_escape(c.get("name", c["id"]))}"{close}')
        lines.append("    end")
    for c in by_tz.get("", []):
        lines.append(f'    {node_id(c["id"])}["{md_escape(c.get("name", c["id"]))}"]')
    for f in view.get("dataflows") or []:
        arrow = "<-->" if f.get("bidirectional") else "-->"
        lines.append(f'    {node_id(f["source"])} {arrow}|"{md_escape(f.get("name", f["id"]))}"| {node_id(f["destination"])}')
    return "\n".join(lines)


def render_markdown(model: Dict[str, Any], view: Dict[str, Any], paths: Paths, cfg: Dict[str, Any]) -> str:
    ts = model.get("threatspec") or {}
    proj = model.get("project") or {}
    mits = index_by_id(view.get("mitigations"))
    reqs = view.get("requirements") or []
    tasks = parse_tasks(paths.tasks)
    ver: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        ver.setdefault(v.get("requirement"), []).append(v)
    decisions = {d.get("threat"): d for d in view.get("decisions") or []}

    L: List[str] = []
    L.append(f"# Threat Model: {proj.get('name', proj.get('id', ''))}")
    L.append("")
    L.append(f"**Feature**: `{paths.feature.name if paths.feature else proj.get('id', '')}` · **Generated**: {ts.get('generated', '')} · "
             f"**Profiles**: {', '.join(ts.get('profiles') or [])} · **Canonical**: `{MODEL_FILE}`")
    L.append("")
    L.append("> Rendered by ThreatSpec. Edit `threat-model.yaml`, not this file.")
    L.append("")
    active = [t for t in view.get("threats") or [] if (t.get("attributes") or {}).get("status") != "retired"]
    threats = [t for t in active if not is_clarification(t)]
    clarifications = [t for t in active if is_clarification(t)]
    sev_counts: Dict[str, int] = {}
    for t in threats:
        s = ((t.get("attributes") or {}).get("severity_override") or {}).get("level") or (t.get("attributes") or {}).get("severity", "?")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    L.append("## Summary")
    L.append("")
    L.append("| Threats | Critical | High | Medium | Low | Needs clarification | Not applicable | Mitigations | Requirements | Decisions |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    na = sum(1 for d in ts.get("dispositions") or [] if d.get("disposition") == "not-applicable")
    L.append(f"| {len(threats)} | {sev_counts.get('critical', 0)} | {sev_counts.get('high', 0)} | {sev_counts.get('medium', 0)} | "
             f"{sev_counts.get('low', 0)} | {len(clarifications)} | {na} | {len(view.get('mitigations') or [])} | {len(reqs)} | {len(view.get('decisions') or [])} |")
    L.append("")
    if clarifications:
        L += ["### Needs clarification", ""]
        for t in clarifications:
            L.append(f"- `{t['id']}` — {md_escape(t.get('name'))} ({md_escape((t.get('attributes') or {}).get('source', ''))})")
        L.append("")

    actors = ts.get("actors") or (view.get("threatspec") or {}).get("actors") or []
    if actors:
        L += ["## Actors", "", "| ID | Name | Trust | Description |", "|---|---|---|---|"]
        for a in actors:
            L.append(f"| `{a['id']}` | {md_escape(a.get('name'))} | {a.get('trust', '')} | {md_escape(a.get('description', ''))} |")
        L.append("")
    if view.get("trustZones"):
        L += ["## Trust Zones", "", "| ID | Name | Trust rating | Description |", "|---|---|---|---|"]
        for z in view["trustZones"]:
            L.append(f"| `{z['id']}` | {md_escape(z.get('name'))} | {(z.get('risk') or {}).get('trustRating', '')} | {md_escape(z.get('description', ''))} |")
        L.append("")
    if view.get("assets"):
        L += ["## Assets", "", "| ID | Name | Type | Classification | C / I / A | Source |", "|---|---|---|---|---|---|"]
        for a in view["assets"]:
            at, r = a.get("attributes") or {}, a.get("risk") or {}
            L.append(f"| `{a['id']}` | {md_escape(a.get('name'))} | {at.get('type', '')} | {at.get('classification', '')} | "
                     f"{r.get('confidentiality', '-')} / {r.get('integrity', '-')} / {r.get('availability', '-')} | {md_escape(at.get('source', ''))} |")
        L.append("")
    if view.get("components"):
        L += ["## Components", "", "| ID | Name | Type | Trust zone | Source |", "|---|---|---|---|---|"]
        for c in view["components"]:
            L.append(f"| `{c['id']}` | {md_escape(c.get('name'))} | {c.get('type', '')} | `{(c.get('parent') or {}).get('trustZone', '')}` | "
                     f"{md_escape((c.get('attributes') or {}).get('source', ''))} |")
        L.append("")
    if view.get("dataflows"):
        L += ["## Data Flows", "", "| ID | Name | From | To | Assets | Crosses |", "|---|---|---|---|---|---|"]
        for f in view["dataflows"]:
            L.append(f"| `{f['id']}` | {md_escape(f.get('name'))} | `{f['source']}` | `{f['destination']}` | "
                     f"{', '.join(f'`{a}`' for a in f.get('assets') or [])} | {', '.join(f'`{z}`' for z in (f.get('attributes') or {}).get('crosses') or [])} |")
        L.append("")
        if (cfg.get("model") or {}).get("diagram", "mermaid") == "mermaid":
            L += ["```mermaid", mermaid(view), "```", ""]

    L += ["## Threats", ""]
    if threats:
        L += ["| ID | Threat | Category | Technique | Severity | Status | Mitigations | Mappings | Source |", "|---|---|---|---|---|---|---|---|---|"]
        for t in sorted(threats, key=lambda x: (-SEVERITY_ORDER.get(((x.get('attributes') or {}).get('severity_override') or {}).get('level') or (x.get('attributes') or {}).get('severity', 'low'), 0), x['id'])):
            at = t.get("attributes") or {}
            sev = (at.get("severity_override") or {}).get("level") or at.get("severity", "")
            tm = [m["id"] for m in view.get("mitigations") or [] if t["id"] in ((m.get("attributes") or {}).get("threats") or [])]
            status = at.get("status", "open")
            if t["id"] in decisions:
                status = f"{decisions[t['id']].get('status')} (until {decisions[t['id']].get('expires')})"
            maps = "; ".join(f"{k}: {', '.join(v)}" for k, v in (at.get("mappings") or {}).items())
            L.append(f"| `{t['id']}` | {md_escape(t.get('name'))} | {', '.join(t.get('categories') or [])} | {at.get('technique', '')} | "
                     f"**{sev}** | {status} | {', '.join(f'`{m}`' for m in tm) or '—'} | {md_escape(maps)} | {md_escape(at.get('source', ''))} |")
    else:
        L.append("No threats recorded yet.")
    L.append("")
    dispositions = ts.get("dispositions") or []
    if dispositions:
        L += ["### Techniques evaluated without findings", "", "| Technique | Disposition | Reason |", "|---|---|---|"]
        for d in dispositions:
            L.append(f"| {d.get('technique')} | {d.get('disposition')} | {md_escape(d.get('reason', ''))} |")
        L.append("")

    if view.get("mitigations"):
        L += ["## Mitigations", "", "| ID | Mitigation | Kind | Threats | Requirements | Touchpoints | Status |", "|---|---|---|---|---|---|---|"]
        for m in view["mitigations"]:
            at = m.get("attributes") or {}
            rs = sorted(set((at.get("requirements") or []) + [r["id"] for r in reqs if m["id"] in (r.get("mitigations") or [])]))
            L.append(f"| `{m['id']}` | {md_escape(m.get('name'))} | {at.get('kind', '')} | {', '.join(f'`{t}`' for t in at.get('threats') or [])} | "
                     f"{', '.join(rs)} | {', '.join(f'`{p}`' for p in at.get('touchpoints') or [])} | {at.get('status', '')} |")
        L.append("")

    L += ["## Security Requirements", ""]
    if reqs:
        for r in sorted(reqs, key=lambda x: x["id"]):
            rt = tasks_for_requirement(tasks, r)
            vs = ver.get(r["id"], [])
            state = "verified" if any(v.get("verdict") == "verified" or v.get("result") == "pass" for v in vs) else ("has-evidence" if vs else "unverified")
            L.append(f"### {r['id']} ({r.get('priority', 'P2')}) — {state}")
            L.append("")
            L.append(r.get("statement", ""))
            L.append("")
            for ac in r.get("acceptance") or []:
                L.append(f"- **Given** {ac.get('given')}, **when** {ac.get('when')}, **then** {ac.get('then')}")
            L.append(f"- Mitigations: {', '.join(f'`{m}`' for m in r.get('mitigations') or [])}")
            task_labels = ", ".join(t["id"] + (" ✓" if t["done"] else "") for t in rt) or "— none —"
            L.append(f"- Tasks: {task_labels}")
            for v in vs:
                L.append(f"- Verification `{v.get('id')}`: {v.get('method')} → {v.get('result')} ({v.get('verdict', '')}) — `{v.get('evidence')}`")
            L.append("")
    else:
        L.append("No security requirements yet.")
        L.append("")

    if view.get("decisions"):
        L += ["## Risk Decisions", "", "| ID | Threat | Status | Owner | Expires | Rationale |", "|---|---|---|---|---|---|"]
        for d in view["decisions"]:
            L.append(f"| `{d['id']}` | `{d.get('threat')}` | {d.get('status')} | {d.get('owner')} | {d.get('expires')} | {md_escape(d.get('rationale'))} |")
        L.append("")
    return "\n".join(L)


def sr_block(model: Dict[str, Any]) -> str:
    reqs = sorted(model.get("requirements") or [], key=lambda r: r["id"])
    mits = index_by_id(model.get("mitigations"))
    L = [BEGIN_MARK, "### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*", ""]
    if not reqs:
        L.append("- No security requirements derived yet. Run the ThreatSpec model command.")
    for r in reqs:
        L.append(f"- **{r['id']}** ({r.get('priority', 'P2')}): {r.get('statement', '')}")
        threats = sorted({t for m in r.get("mitigations") or [] for t in (mits.get(m, {}).get("attributes") or {}).get("threats") or []})
        if threats:
            L.append(f"  - Mitigates: {', '.join(f'`{t}`' for t in threats)} via {', '.join(f'`{m}`' for m in r.get('mitigations') or [])}")
        for ac in r.get("acceptance") or []:
            L.append(f"  - Given {ac.get('given')}, when {ac.get('when')}, then {ac.get('then')}")
    L.append(END_MARK)
    return "\n".join(L)


def upsert_sr_block(spec_path: Path, block: str) -> str:
    text = spec_path.read_text(encoding="utf-8")
    if BEGIN_MARK in text and END_MARK in text:
        start, end = text.index(BEGIN_MARK), text.index(END_MARK) + len(END_MARK)
        new = text[:start] + block + text[end:]
        action = "updated"
    else:
        anchor = re.search(r"^## Success Criteria.*$", text, re.M) or re.search(r"^## Assumptions.*$", text, re.M)
        if anchor:
            new = text[:anchor.start()] + block + "\n\n" + text[anchor.start():]
        else:
            new = text.rstrip("\n") + "\n\n" + block + "\n"
        action = "inserted"
    if new != text:
        spec_path.write_text(new, encoding="utf-8")
    return action


# --------------------------------------------------------------------------- converge

EVIDENCE_SKIP_DIRS = {"__pycache__", "node_modules", "dist", "build", "target", "vendor", "coverage"}
EVIDENCE_SKIP_SUFFIXES = {".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".bin", ".so", ".dylib", ".dll",
                          ".zip", ".gz", ".tar", ".class", ".jar", ".wasm", ".lock"}


def find_evidence(repo: Path, rid: str, cfg: Dict[str, Any], touchpoints: List[str]) -> Dict[str, Any]:
    dirs = (cfg.get("verification") or {}).get("test_dirs") or ["tests", "test", "spec", "__tests__"]
    markers = (cfg.get("verification") or {}).get("evidence_markers") or ["SR-"]
    hits: List[str] = []
    number = rid.split("-", 1)[1]
    # Accept every configured spelling of the id: SR-001, SR_001, SR001, sr-001 …
    pat = re.compile("|".join(re.escape(m.rstrip("-_")) + r"[-_]?" + re.escape(number) + r"(?!\d)" for m in markers), re.I)
    for d in dirs:
        base = repo / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.stat().st_size > 2_000_000 or p.suffix in EVIDENCE_SKIP_SUFFIXES:
                continue
            if any(part in EVIDENCE_SKIP_DIRS or part.startswith(".") for part in p.relative_to(base).parts[:-1]):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pat.search(content):
                hits.append(str(p.relative_to(repo)))
    tp = [{"path": t, "exists": (repo / t).exists()} for t in touchpoints]
    return {"test_files": sorted(hits), "touchpoints": tp}


def converge_scan(paths: Paths, cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not paths.model or not paths.model.exists():
        raise SystemExit("threatspec: threat-model.yaml not found; run the model command first")
    model = load_model(paths.model)
    view = merged_view(model, load_baseline(model, paths.model))
    tasks = parse_tasks(paths.tasks)
    mits = index_by_id(view.get("mitigations"))
    ver: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        ver.setdefault(v.get("requirement"), []).append(v)
    items = []
    for r in sorted(model.get("requirements") or [], key=lambda x: x["id"]):
        touch = sorted({t for m in r.get("mitigations") or [] for t in (mits.get(m, {}).get("attributes") or {}).get("touchpoints") or []})
        rt = tasks_for_requirement(tasks, r)
        items.append({
            "id": r["id"], "statement": r.get("statement"), "priority": r.get("priority", "P2"),
            "acceptance": r.get("acceptance") or [], "mitigations": r.get("mitigations") or [],
            "tasks": [{"id": t["id"], "done": t["done"], "text": t["text"]} for t in rt],
            "all_tasks_done": bool(rt) and all(t["done"] for t in rt),
            "existing_verification": ver.get(r["id"], []),
            "evidence": find_evidence(paths.repo, r["id"], cfg, touch),
        })
    findings, metrics = run_checks(paths, cfg)
    return {
        "feature": paths.feature.name if paths.feature else None,
        "commit": git(["rev-parse", "--short", "HEAD"], paths.repo),
        "requirements": items,
        "open_threats": [t["id"] for t in model.get("threats") or [] if (t.get("attributes") or {}).get("status") == "open"],
        "decisions": model.get("decisions") or [],
        "check_findings": [f.as_dict() for f in findings],
        "metrics": metrics,
        "config": {"verification": cfg.get("verification") or {}, "enforcement": cfg.get("enforcement", "warn"),
                   "config_file": str(paths.repo / ".specify" / "extensions" / "threatspec" / "threatspec-config.yml")},
        "verdict_schema": {"requirement": "SR-###", "verdict": "verified | implemented-unverified | partial | missing",
                            "method": "test | review | scan | manual | evidence", "evidence": "path::test or record",
                            "result": "pass | fail | partial | inconclusive", "justification": "one sentence"},
    }


def open_convergence_tasks(tasks_text: str) -> Dict[str, List[str]]:
    """Unchecked tasks inside any '## Phase N: Security Convergence' section, keyed by SR id and threat id."""
    reqs: List[str] = []
    threats: List[str] = []
    in_section = False
    for line in tasks_text.splitlines():
        if line.startswith("## "):
            in_section = "Security Convergence" in line
            continue
        if not in_section:
            continue
        m = TASK_RE.match(line)
        if not m or m.group(1).lower() == "x":
            continue
        rest = m.group(3)
        reqs += [sr for group in SR_TAG_RE.findall(rest) for sr in SR_RE.findall(group)]
        threats += re.findall(r"`(threat\.[a-z0-9.-]+)`", rest)
    return {"requirements": sorted(set(reqs)), "threats": sorted(set(threats))}


def next_phase_number(tasks_text: str) -> int:
    nums = [int(n) for n in re.findall(r"^## Phase (\d+)", tasks_text, re.M)]
    return (max(nums) + 1) if nums else 1


def next_task_id(tasks: List[Dict[str, Any]], tasks_text: str) -> int:
    ids = [int(t["id"][1:]) for t in tasks] + [int(n) for n in re.findall(r"\bT(\d{3,})\b", tasks_text)]
    return (max(ids) + 1) if ids else 1


RESULT_FOR_VERDICT = {"verified": "pass", "implemented-unverified": "inconclusive", "partial": "partial", "missing": "fail"}


def latest_verification(model: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Most recent verification entry per requirement (by verified_at, then file order)."""
    latest: Dict[str, Dict[str, Any]] = {}
    for v in model.get("verification") or []:
        rid = v.get("requirement")
        if rid and (rid not in latest or str(v.get("verified_at", "")) >= str(latest[rid].get("verified_at", ""))):
            latest[rid] = v
    return latest


def converge_apply(paths: Paths, cfg: Dict[str, Any], verdicts_path: Path, commit: Optional[str],
                   only: Optional[List[str]] = None) -> Dict[str, Any]:
    model = load_model(paths.model)
    verdicts_raw = load_yaml(verdicts_path)
    verdicts = verdicts_raw.get("verdicts") if isinstance(verdicts_raw, dict) else verdicts_raw
    if not isinstance(verdicts, list):
        raise SystemExit("threatspec: verdicts file must be a list or {verdicts: [...]}")
    reqs = index_by_id(model.get("requirements"))
    if only:
        unknown = [r for r in only if r not in reqs]
        if unknown:
            raise SystemExit(f"threatspec: --only names unknown requirement(s): {', '.join(unknown)}")
        outside = [v.get("requirement") for v in verdicts if v.get("requirement") not in only]
        if outside:
            raise SystemExit(f"threatspec: verdicts outside --only scope: {', '.join(outside)}")
    previous = latest_verification(model)
    commit = commit or git(["rev-parse", "--short", "HEAD"], paths.repo) or "unknown"
    stamp = now_iso()
    existing_ids = {v.get("id") for v in model.get("verification") or []}
    results: Dict[str, Dict[str, Any]] = {}
    for v in verdicts:
        rid = v.get("requirement")
        if rid not in reqs:
            raise SystemExit(f"threatspec: verdict references unknown requirement {rid}")
        verdict = v.get("verdict")
        if verdict not in ("verified", "implemented-unverified", "partial", "missing"):
            raise SystemExit(f"threatspec: invalid verdict '{verdict}' for {rid}")
        if verdict == "verified" and not v.get("evidence"):
            raise SystemExit(f"threatspec: {rid} cannot be 'verified' without an evidence pointer")
        n = 1
        vid = f"verification.{rid.lower()}.{stamp[:10]}"
        while vid in existing_ids:
            n += 1
            vid = f"verification.{rid.lower()}.{stamp[:10]}-{n}"
        existing_ids.add(vid)
        entry = {
            "id": vid, "requirement": rid, "method": v.get("method", "evidence"),
            "evidence": v.get("evidence") or "none", "result": v.get("result") or RESULT_FOR_VERDICT[verdict],
            "verdict": verdict, "justification": v.get("justification", ""), "verified_at": stamp, "commit": commit,
        }
        model.setdefault("verification", []).append(entry)
        results[rid] = entry
    for rid in reqs:
        if rid in results:
            continue
        prev = previous.get(rid)
        if prev and prev.get("verdict"):
            # Keep the last recorded verdict for requirements not re-judged in this run (e.g. --only scope).
            results[rid] = {**prev, "carried_forward": True}
        else:
            results[rid] = {"requirement": rid, "verdict": "missing", "evidence": "none",
                            "justification": "No verdict supplied", "synthetic": True}

    # threat status roll-up: a threat is mitigated when all its mitigations' requirements are verified
    mits = model.get("mitigations") or []
    req_by_mit: Dict[str, List[str]] = {}
    for r in model.get("requirements") or []:
        for m in r.get("mitigations") or []:
            req_by_mit.setdefault(m, []).append(r["id"])
    decided = {d.get("threat") for d in model.get("decisions") or []}
    for t in model.get("threats") or []:
        at = t.setdefault("attributes", {})
        if at.get("status") in ("retired", "accepted", "transferred"):
            continue
        tm = [m for m in mits if t["id"] in ((m.get("attributes") or {}).get("threats") or [])]
        rids = [r for m in tm for r in req_by_mit.get(m["id"], [])]
        if tm and rids and all(results.get(r, {}).get("verdict") == "verified" for r in rids):
            at["status"] = "mitigated"
            for m in tm:
                m.setdefault("attributes", {})["status"] = "verified"
        elif t["id"] in decided:
            at["status"] = next(d.get("status") for d in model["decisions"] if d.get("threat") == t["id"])
        else:
            at["status"] = "open"

    block_on = set((cfg.get("severity") or {}).get("block_on") or ["critical"])
    open_blocking = [t["id"] for t in model.get("threats") or []
                     if (t.get("attributes") or {}).get("status") == "open"
                     and (((t.get("attributes") or {}).get("severity_override") or {}).get("level") or (t.get("attributes") or {}).get("severity")) in block_on]
    expired = [d["id"] for d in model.get("decisions") or [] if str(d.get("expires", "9999")) < str(today())]
    unverified = [r for r, v in results.items() if v.get("verdict") != "verified"]
    recorded_hashes = {x.get("path"): x.get("sha256") for x in (model.get("threatspec") or {}).get("sources") or []}
    drift = [s["path"] + ("" if recorded_hashes.get(s["path"]) else " (never hashed: re-run the model command)")
             for s in sources_for(paths) if recorded_hashes.get(s["path"]) != s["sha256"]]
    converged = not open_blocking and not unverified and not expired and not drift

    write_text(paths.model, dump_yaml(model))

    # append remediation tasks — idempotent: a gap that already has an open convergence task is not duplicated
    appended: List[str] = []
    already_open: List[str] = []
    if paths.tasks and paths.tasks.exists() and (unverified or open_blocking):
        text = paths.tasks.read_text(encoding="utf-8")
        tasks = parse_tasks(paths.tasks)
        open_conv = open_convergence_tasks(text)
        pending_reqs = [rid for rid in sorted(unverified) if rid not in open_conv["requirements"]]
        pending_threats = [t_id for t_id in open_blocking if t_id not in open_conv["threats"]]
        already_open = sorted(set(unverified) & set(open_conv["requirements"])) + [t for t in open_blocking if t in open_conv["threats"]]
        unverified_to_append, open_blocking = pending_reqs, pending_threats
        tid = next_task_id(tasks, text)
        phase = next_phase_number(text)
        lines = ["", f"## Phase {phase}: Security Convergence", "",
                 f"**Purpose**: Close security gaps found by ThreatSpec converge on {stamp[:10]} (commit {commit}).", ""]
        for rid in unverified_to_append:
            v = results[rid]
            req = reqs[rid]
            touch = sorted({p for m in req.get("mitigations") or [] for p in (index_by_id(mits).get(m, {}).get("attributes") or {}).get("touchpoints") or []})
            what = {"missing": "Implement", "partial": "Complete", "implemented-unverified": "Add a test for"}.get(v.get("verdict"), "Address")
            where = f" — touchpoints: {', '.join(touch)}" if touch else ""
            why = f"; {v.get('justification')}" if v.get("justification") else ""
            statement = str(req.get("statement", "")).rstrip(".")
            lines.append(f"- [ ] T{tid:03d} [{rid}] {what} {rid} ({statement}){where} [converge: {v.get('verdict')}{why}]")
            appended.append(f"T{tid:03d}")
            tid += 1
        for t_id in open_blocking:
            lines.append(f"- [ ] T{tid:03d} [threatspec] Mitigate or decide open blocking threat `{t_id}` in threat-model.yaml")
            appended.append(f"T{tid:03d}")
            tid += 1
        if appended:
            paths.tasks.write_text(text.rstrip("\n") + "\n" + "\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "feature": paths.feature.name if paths.feature else None, "commit": commit, "timestamp": stamp,
        "status": "CONVERGED" if converged else "NOT CONVERGED",
        "threats": {"total": len([t for t in model.get("threats") or [] if (t.get("attributes") or {}).get("status") != "retired"]),
                    "open_blocking": open_blocking},
        "requirements": {"total": len(reqs),
                         "verified": sorted(r for r, v in results.items() if v.get("verdict") == "verified"),
                         "implemented_unverified": sorted(r for r, v in results.items() if v.get("verdict") == "implemented-unverified"),
                         "partial": sorted(r for r, v in results.items() if v.get("verdict") == "partial"),
                         "missing": sorted(r for r, v in results.items() if v.get("verdict") == "missing")},
        "expired_decisions": expired, "drift": drift, "appended_tasks": appended, "already_open_tasks_for": already_open,
        "verdicts": {r: {k: v.get(k) for k in ("verdict", "method", "evidence", "justification")} for r, v in results.items()},
    }
    if paths.security:
        write_text(paths.security / "convergence-report.json", json.dumps(summary, indent=2) + "\n")
        write_text(paths.security / "convergence-report.md", convergence_md(summary))
    return summary


def convergence_md(s: Dict[str, Any]) -> str:
    r = s["requirements"]
    L = [f"## Security Convergence — {s.get('feature')}", "",
         f"Commit `{s.get('commit')}` · {s.get('timestamp')}", "",
         "| Metric | Value |", "|---|---|",
         f"| Threats (active) | {s['threats']['total']} |",
         f"| Open blocking threats | {len(s['threats']['open_blocking'])} {', '.join(s['threats']['open_blocking'])} |",
         f"| Security requirements | {r['total']} |",
         f"| verified | {len(r['verified'])} |",
         f"| implemented, unverified | {len(r['implemented_unverified'])} {', '.join(r['implemented_unverified'])} |",
         f"| partial | {len(r['partial'])} {', '.join(r['partial'])} |",
         f"| missing | {len(r['missing'])} {', '.join(r['missing'])} |",
         f"| Expired decisions | {len(s['expired_decisions'])} {', '.join(s['expired_decisions'])} |",
         f"| Source drift | {', '.join(s['drift']) or 'none'} |",
         "", f"**Status: {s['status']}**", ""]
    if s["appended_tasks"]:
        L.append(f"Appended tasks: {', '.join(s['appended_tasks'])}")
        L.append("")
    L += ["| Requirement | Verdict | Method | Evidence | Justification |", "|---|---|---|---|---|"]
    for rid, v in sorted(s["verdicts"].items()):
        L.append(f"| {rid} | {v.get('verdict')} | {v.get('method') or ''} | `{v.get('evidence') or ''}` | {md_escape(v.get('justification') or '')} |")
    return "\n".join(L) + "\n"


def scoreboard(s: Dict[str, Any]) -> str:
    r = s["requirements"]
    lines = [f"Security Convergence — {s.get('feature')}", "",
             f"Threats (active)               {s['threats']['total']:>4}",
             f"  open blocking                {len(s['threats']['open_blocking']):>4}   {' '.join(s['threats']['open_blocking'])}".rstrip(),
             f"Security requirements          {r['total']:>4}",
             f"  verified                     {len(r['verified']):>4}",
             f"  implemented, unverified      {len(r['implemented_unverified']):>4}   {' '.join(r['implemented_unverified'])}".rstrip(),
             f"  partial                      {len(r['partial']):>4}   {' '.join(r['partial'])}".rstrip(),
             f"  missing                      {len(r['missing']):>4}   {' '.join(r['missing'])}".rstrip(),
             f"Expired decisions              {len(s['expired_decisions']):>4}",
             f"Source drift                   {'yes' if s['drift'] else 'no':>4}", "",
             f"Status: {s['status']}"]
    if s["appended_tasks"]:
        lines.append(f"Appended {len(s['appended_tasks'])} task(s) to tasks.md: {', '.join(s['appended_tasks'])}")
    if s.get("already_open_tasks_for"):
        lines.append(f"Open convergence tasks already exist for: {', '.join(s['already_open_tasks_for'])} (not duplicated)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI

def cmd_paths(args: argparse.Namespace) -> int:
    p = get_paths(args)
    d = p.as_dict()
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        for k, v in d.items():
            print(f"{k}: {v}")
    return 0 if p.feature else 1


def cmd_init(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("threatspec: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    if p.model.exists() and not args.force:
        print(f"exists: {p.model}")
        return 0
    baseline_cfg = (cfg.get("model") or {}).get("baseline")
    baseline = None
    if baseline_cfg and (p.repo / baseline_cfg).exists():
        baseline = os.path.relpath(p.repo / baseline_cfg, p.feature)
    model = empty_model(args.project_id or p.feature.name, args.name or p.feature.name, cfg.get("profiles") or ["stride"], baseline)
    model["threatspec"]["sources"] = sources_for(p)
    write_text(p.model, dump_yaml(model))
    print(f"created: {p.model}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.model)
    model = load_model(path)
    errors = schema_validate(model)
    errors += reference_errors(merged_view(model, load_baseline(model, path)))
    if args.json:
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
    else:
        for e in errors:
            print(f"ERROR: {e}")
        print("valid" if not errors else f"{len(errors)} error(s)")
    return 0 if not errors else 1


def cmd_merge(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("threatspec: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    incoming = load_model(Path(args.incoming))
    existing = load_model(p.model) if p.model.exists() else empty_model(p.feature.name, p.feature.name, cfg.get("profiles") or ["stride"], None)
    profiles = load_profiles((incoming.get("threatspec") or {}).get("profiles") or (existing.get("threatspec") or {}).get("profiles") or cfg.get("profiles") or ["stride"])
    merged, stats = merge_models(existing, incoming, p, profiles)
    errors = schema_validate(merged) + reference_errors(merged_view(merged, load_baseline(merged, p.model)))
    if errors and not args.allow_invalid:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print(f"threatspec: merge rejected, {len(errors)} validation error(s); fix the incoming model", file=sys.stderr)
        return 1
    if args.dry_run:
        print(dump_yaml(merged))
    else:
        write_text(p.model, dump_yaml(merged))
        print(f"merged: {p.model}")
    print(json.dumps(stats))
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("threatspec: threat-model.yaml not found; run init or merge first")
    cfg = load_config(p.repo)
    model = load_model(p.model)
    view = merged_view(model, load_baseline(model, p.model))
    out = []
    if (cfg.get("model") or {}).get("render_markdown", True) and not args.no_markdown:
        write_text(p.render, render_markdown(model, view, p, cfg))
        out.append(str(p.render))
    if (cfg.get("model") or {}).get("write_requirements_to_spec", True) and not args.no_spec and p.spec.exists():
        action = upsert_sr_block(p.spec, sr_block(model))
        out.append(f"{p.spec} ({action} SR block)")
    for o in out:
        print(f"rendered: {o}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("threatspec: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    enforcement = args.enforcement or cfg.get("enforcement", "warn")
    if args.strict:
        enforcement = "strict"  # the report must say what the exit code enforces
    findings, metrics = run_checks(p, cfg)
    if args.format == "json":
        text = json.dumps({"findings": [f.as_dict() for f in findings], "metrics": metrics,
                           "worst": worst_severity(findings), "enforcement": enforcement}, indent=2) + "\n"
    elif args.format == "sarif":
        text = report_sarif(findings, p)
    else:
        text = report_md(findings, metrics, p, enforcement)
    if args.output:
        write_text(Path(args.output), text)
        print(f"written: {args.output}")
    else:
        sys.stdout.write(text)
    if args.persist and p.security:
        write_text(p.security / "check-report.md", report_md(findings, metrics, p, enforcement))
    return exit_code_for(findings, strict=(enforcement == "strict") or args.strict)


def cmd_coverage(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("threatspec: threat-model.yaml not found; run the model command first")
    c = coverage(p, load_config(p.repo))
    text = json.dumps(c, indent=2) + "\n" if args.format == "json" else coverage_md(c)
    if args.output:
        write_text(Path(args.output), text)
        print(f"written: {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_converge_scan(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("threatspec: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    data = converge_scan(p, cfg)
    if args.output:
        write_text(Path(args.output), json.dumps(data, indent=2) + "\n")
        print(f"written: {args.output}")
    else:
        print(json.dumps(data, indent=2))
    return 0


def cmd_converge_apply(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("threatspec: threat-model.yaml not found")
    cfg = load_config(p.repo)
    only = [s.strip() for s in args.only.split(",") if s.strip()] if args.only else None
    summary = converge_apply(p, cfg, Path(args.verdicts), args.commit, only)
    if not args.no_render:
        model = load_model(p.model)
        write_text(p.render, render_markdown(model, merged_view(model, load_baseline(model, p.model)), p, cfg))
    print(scoreboard(summary))
    return 0 if summary["status"] == "CONVERGED" else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="threatspec", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", help="Repository root (default: auto-detect from cwd)")
    ap.add_argument("--feature-dir", help="Feature directory (default: SPECIFY_FEATURE, current branch, or newest spec)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("paths", help="Resolve artifact paths"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_paths)
    s = sub.add_parser("init", help="Create an empty threat model"); s.add_argument("--project-id"); s.add_argument("--name")
    s.add_argument("--force", action="store_true"); s.set_defaults(fn=cmd_init)
    s = sub.add_parser("validate", help="Validate a model file"); s.add_argument("model"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("merge", help="Merge an incoming model into the feature model"); s.add_argument("--incoming", required=True)
    s.add_argument("--dry-run", action="store_true"); s.add_argument("--allow-invalid", action="store_true"); s.set_defaults(fn=cmd_merge)
    s = sub.add_parser("render", help="Render Markdown and the SR block"); s.add_argument("--no-spec", action="store_true")
    s.add_argument("--no-markdown", action="store_true"); s.set_defaults(fn=cmd_render)
    s = sub.add_parser("check", help="Run gap checks"); s.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    s.add_argument("--output"); s.add_argument("--persist", action="store_true"); s.add_argument("--strict", action="store_true")
    s.add_argument("--enforcement", choices=["warn", "strict"]); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("coverage", help="Technique × surface × threat/disposition and SR → threat/mitigation/task tables")
    s.add_argument("--format", choices=["md", "json"], default="md"); s.add_argument("--output"); s.set_defaults(fn=cmd_coverage)
    s = sub.add_parser("converge-scan", help="Collect evidence facts per requirement"); s.add_argument("--output"); s.set_defaults(fn=cmd_converge_scan)
    s = sub.add_parser("converge-apply", help="Record verdicts and write the convergence report"); s.add_argument("--verdicts", required=True)
    s.add_argument("--commit"); s.add_argument("--no-render", action="store_true")
    s.add_argument("--only", help="Comma-separated SR ids judged in this run; others keep their last verdict"); s.set_defaults(fn=cmd_converge_apply)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
