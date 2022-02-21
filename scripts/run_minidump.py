import logging
import sys

import forsee
from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump

log = logging.getLogger(__name__)


def main():
    if len(sys.argv) != 2:
        raise ValueError("Usage: python run_minidump.py /path/to/mini.dmp")
    logging.getLogger(forsee.__name__).setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)

    proj = ForseeProjectMinidump(sys.argv[1], loop_bound=5)
    explorer = Explorer(proj)
    explorer.run()


if __name__ == "__main__":
    main()
