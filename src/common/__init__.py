"""Common utilities package."""

import sys as _sys

# Expose legacy top-level package name ``common`` for compatibility.
_sys.modules.setdefault("common", _sys.modules[__name__])
