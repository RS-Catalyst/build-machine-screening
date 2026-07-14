"""Enable ``python -m packet_assembler``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
