"""Entry point so the package can be run as `python -m phishing_triage`.

Python executes this file when the package is run with -m. We delegate to
cli.main() and use its return value as the process exit code (0 = success,
non-zero = error), which is the convention command-line tools follow.
"""

import sys

from phishing_triage.cli import main

if __name__ == "__main__":
    sys.exit(main())
