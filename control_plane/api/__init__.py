"""The native v1 HTTP boundary (Milestone 3.1).

Built beside the frozen v0 prototype (ADR 0003): nothing here imports ``control/``,
``fb.py`` or the v0 FastAPI application. ``create_app`` in :mod:`.app` builds an ASGI
application on Starlette from the runtime database engine, the API settings and an
email-delivery adapter; ``python3 -m firmbatch.control_plane.api`` serves it under uvicorn
on loopback.

Two authentication boundaries live here and never overlap: browser sessions
(``fb_session`` cookie plus a CSRF header on mutations) for ``/v1/account`` and
``/v1/workspace``, and API credentials (``Authorization: Bearer fbk_...``) for ``/v1/api``.
"""
