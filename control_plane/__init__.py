"""Firmbatch v1 control plane.

Built beside the frozen v0 prototype per ADR 0003: nothing in this package imports or
modifies ``control/``, ``controller.py``, ``worker/``, ``providers/`` or ``fb.py``.

Imported as a package from the repository's PARENT directory, exactly like v0:

    cd "$(git rev-parse --show-toplevel)/.."
    python3 -m firmbatch.control_plane.migrate upgrade

PostgreSQL is the only v1 metadata authority (target architecture section 3.1). There is
no SQLite fallback in this package and none may be added.
"""
