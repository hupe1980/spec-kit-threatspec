import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

# Fixture repos contain their own test files; never collect them as part of this suite.
collect_ignore_glob = ["fixtures/*"]


def _load_engine():
    spec = importlib.util.spec_from_file_location("threatspec", ROOT / "scripts" / "python" / "threatspec.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["threatspec"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture(scope="session")
def engine():
    return _load_engine()


@pytest.fixture
def rag_repo(tmp_path: Path) -> Path:
    """A throwaway copy of the rag-assistant fixture repo with a .specify marker."""
    dst = tmp_path / "rag"
    shutil.copytree(FIXTURES / "rag-assistant", dst)
    (dst / ".specify").mkdir()
    return dst


@pytest.fixture
def rag_feature(rag_repo: Path) -> Path:
    return rag_repo / "specs" / "007-rag-assistant"
