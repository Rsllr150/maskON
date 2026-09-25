"""The public API: `import maskon` and the names in `maskon.__all__`.

This is the semver-covered surface. Everything else is internal, so these
tests pin behaviour a consumer relies on, including what importing costs.
"""

import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path

import pytest

import maskon
from maskon.service.redaction import RedactionService

TEXT = "IBAN FR7630006000011234567890189, mail jean.dupont@example.com"
FRAMEWORKS = ["fastapi", "starlette", "pydantic", "prometheus_client", "uvicorn"]


def _run(code: str) -> subprocess.CompletedProcess[str]:
    # Fresh interpreter: the test process has already imported FastAPI.
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )


def _blocking(modules: list[str]) -> str:
    # A None entry in sys.modules makes `import x` raise ImportError.
    return f"import sys\nfor m in {modules!r}: sys.modules[m] = None\n"


def test_all_is_exactly_the_public_surface():
    assert sorted(maskon.__all__) == [
        "Finding",
        "__version__",
        "detect",
        "redact",
        "redact_stream",
    ]


def test_redact_returns_the_masked_string():
    assert maskon.redact(TEXT) == "IBAN [IBAN], mail [EMAIL]"


def test_detect_agrees_with_the_service():
    assert maskon.detect(TEXT) == RedactionService().detect(TEXT)
    assert [f.type for f in maskon.detect(TEXT)] == ["IBAN", "EMAIL"]


def test_unknown_mask_is_a_clear_error():
    with pytest.raises(ValueError, match="unknown mask"):
        maskon.redact(TEXT, mask="banana")  # type: ignore[arg-type]


def test_hash_key_parameter_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("MASKON_HASH_KEY", "env-key")
    from_env = maskon.redact(TEXT, mask="hash")
    from_param = maskon.redact(TEXT, mask="hash", hash_key=b"param-key")
    assert from_param != from_env
    assert from_param == maskon.redact(TEXT, mask="hash", hash_key=b"param-key")


def test_environment_key_is_read_on_each_call(monkeypatch):
    monkeypatch.setenv("MASKON_HASH_KEY", "first")
    first = maskon.redact(TEXT, mask="hash")
    monkeypatch.setenv("MASKON_HASH_KEY", "second")
    assert maskon.redact(TEXT, mask="hash") != first


def test_redact_stream_matches_redact_across_chunks():
    chunks = [TEXT[:10], TEXT[10:30], TEXT[30:]]  # the IBAN is cut in two
    assert "".join(maskon.redact_stream(chunks)) == maskon.redact(TEXT)


def test_redact_stream_rejects_a_bad_mask_at_call_time():
    with pytest.raises(ValueError, match="unknown mask"):
        maskon.redact_stream(["x"], mask="banana")  # type: ignore[arg-type]


def test_hash_without_any_key_is_refused(monkeypatch):
    monkeypatch.delenv("MASKON_HASH_KEY", raising=False)
    with pytest.raises(ValueError, match="needs a key"):
        maskon.redact(TEXT, mask="hash")
    with pytest.raises(ValueError, match="needs a key"):
        maskon.redact_stream([TEXT], mask="hash")


def test_readme_lists_exactly_the_public_names():
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    line = next(x for x in readme.splitlines() if "exactly `maskon.__all__`" in x)
    rule = line + readme.split(line, 1)[1].split("\n\n", 1)[0]
    assert sorted(re.findall(r"`(\w+)`", rule)) == sorted(maskon.__all__)


def test_redact_stream_uses_the_hash_key():
    chunks = [TEXT]
    keyed = "".join(maskon.redact_stream(chunks, mask="hash", hash_key=b"k"))
    assert keyed == maskon.redact(TEXT, mask="hash", hash_key=b"k")


def test_version_is_the_installed_metadata():
    assert maskon.__version__ == importlib.metadata.version("maskon")


def test_api_reports_the_same_version():
    from maskon.api.app import app

    assert app.version == maskon.__version__


def test_import_maskon_imports_no_framework():
    # The frameworks ARE installed here: an optional `try: import x` in the
    # core would load them and show up in sys.modules.
    code = (
        "import sys, maskon\n"
        "maskon.redact('mail a@b.com')\n"
        f"print([m for m in {FRAMEWORKS!r} if m in sys.modules])\n"
    )
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_maskon_works_with_no_framework_installed():
    code = _blocking(FRAMEWORKS) + "import maskon\nprint(maskon.redact('a@b.com'))\n"
    result = _run(code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[EMAIL]"


def test_api_without_the_extra_says_how_to_install_it():
    result = _run(_blocking(["fastapi"]) + "import maskon.api\n")
    assert result.returncode != 0
    assert 'pip install "maskon[api]"' in result.stderr
