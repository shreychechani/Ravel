"""Enable ``python -m ravel``.

This is the deterministic entry point: run from the repo root and the ``ravel``
package is found via the current directory, independent of the editable install.
"""

from ravel.cli.main import run

if __name__ == "__main__":
    run()
