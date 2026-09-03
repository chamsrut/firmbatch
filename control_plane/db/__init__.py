"""PostgreSQL persistence for the Firmbatch v1 control plane.

PostgreSQL is the only metadata authority (target architecture 3.1). There is no SQLite
fallback here and none may be added: a fallback backend is how a single authority decays
into "PostgreSQL unless something else is configured".
"""
