"""A consumer of the public API, as a user would write it.

CI copies this file out of the repo, installs the built wheel (no extras) in a
fresh venv, then runs `mypy --strict` on it and executes it. That checks the
wheel ships `py.typed`, that the core needs no dependency, and that the public
names are typed well enough for a strict consumer.
"""

import importlib.metadata

import maskon


def main() -> None:
    text = "IBAN FR7630006000011234567890189"
    redacted: str = maskon.redact(text, mask="partial", hash_key=None)
    findings: list[maskon.Finding] = maskon.detect(text)
    streamed: str = "".join(maskon.redact_stream([text[:8], text[8:]]))
    assert redacted != text
    assert [f.type for f in findings] == ["IBAN"]
    assert streamed == maskon.redact(text)
    # The wheel's metadata and the code agree: the version has one source.
    assert importlib.metadata.version("maskon") == maskon.__version__
    print(f"maskon {maskon.__version__}: {redacted}")


if __name__ == "__main__":
    main()
