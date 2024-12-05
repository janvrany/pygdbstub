"""
General debugging support.

See https://stackoverflow.com/a/242531
"""

import os
import sys

try:
    import ipdb

    debugger = ipdb
except ImportError:
    import pdb

    debugger = pdb


def excepthook(type, value, tb):
    if hasattr(sys, "ps1") or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import traceback

        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        # ...then start the debugger in post-mortem mode.
        debugger.post_mortem(tb)


def breakpointhook(*args, **kws):
    if os.getenv("PYTHONBREAKPOINT") is not None:
        # Use specified her own preferred debugger, defer to
        # default handling.
        sys.__breakpointhook__(*args, **kws)
    else:
        print("breakpoint() hit!")
        debugger.set_trace()
