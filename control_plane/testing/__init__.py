"""Test-only helpers.

Nothing in here may be imported by a production code path. Every helper refuses to run
unless ``FIRMBATCH_ENV=test`` and the database it is pointed at is unmistakably
disposable.
"""
