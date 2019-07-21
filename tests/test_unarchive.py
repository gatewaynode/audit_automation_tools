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

from pip_audit import _extract_archives as app


def test_pip_download_error():
    test_output = app(
        output="",
        output_dir="local_files",
        package_meta={},
        verbose=False,
        debug=False,
        output_json=False,
    )
    assert test_output
