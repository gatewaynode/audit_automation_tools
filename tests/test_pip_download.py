import pytest
import sys

# Support importing pip_audit as an absolute import
from pathlib import Path

file = Path(__file__).resolve()
parent, root = file.parent, file.parents[1]
sys.path.append(str(root))

# Additionally remove the current file's directory from sys.path
try:
    sys.path.remove(str(parent))
except ValueError:  # Already removed
    pass

from pip_audit import _pip_download as app


def test_pip_download_error():
    output = app(
        raw_input="no_such_package",
        output_dir="local_files",
        verbose=False,
        debug=False,
        output_json=False,
    )
    assert output.stderr


def test_pip_download_success():
    output = app(
        raw_input="six",
        output_dir="local_files",
        verbose=False,
        debug=False,
        output_json=False,
    )
    assert "Saved" in output.stdout.decode("utf-8")
