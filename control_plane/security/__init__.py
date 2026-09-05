"""Authorization and secret-handling model for the v1 control plane.

Two modules, deliberately separate from ``db/``:

* :mod:`~firmbatch.control_plane.security.authorization` -- the closed permission
  catalogue. What scopes exist, what each one permits, and which table each rule is
  enforced on. It is data plus a small refusal helper; it opens no connection.
* :mod:`~firmbatch.control_plane.security.secrets` -- the four kinds of secret this
  system has, as types that cannot be rendered, logged, or serialized by accident.

Neither imports SQLAlchemy. The database half of authorization -- the policies that
actually enforce the catalogue -- lives in migration ``0003`` and in
``db/auth.py``; this package is what names it in one place so that the migration, the
runtime and the tests cannot each carry a slightly different idea of what a scope is.
"""
