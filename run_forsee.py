import logging

import forsee
from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump

log = logging.getLogger(__name__)


def main():
    logging.getLogger(forsee.__name__).setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)

    # proj = ForseeProjectMinidump("../memdump/larger_dump.dmp")
    proj = ForseeProjectMinidump("../memdump/memdump_at_start.dmp")
    # proj = ForseeProjectBinary("../binaries/6bbd10ac20782542f40f78471c30c52f0619b91639840e60831dd665f9396365.bin", use_entry_state=True)
    explorer = Explorer(proj)
    explorer.run()


if __name__ == "__main__":
    main()
