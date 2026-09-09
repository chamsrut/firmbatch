"""Serve the native v1 API under uvicorn, on loopback unless told otherwise.

    cd "$(git rev-parse --show-toplevel)/.."
    FIRMBATCH_ENV=test FIRMBATCH_DATABASE_URL=... FIRMBATCH_API_ALLOWED_ORIGINS=... \\
        python3 -m firmbatch.control_plane.api --port 8081

Loads the **application** settings only -- the restricted runtime URL -- and the API
settings. It cannot load the migration or bootstrap credential: neither loader is named
here, and the static import gate says so. In the ``test`` environment the email adapter is
the in-memory capture double, which delivers nothing anywhere; in every other environment
it is the adapter that raises, because no provider is configured at this milestone.

This entry point exists so the application can be run and reviewed locally. The hosted
shape -- TLS, the ALB, the service roles, real secrets delivery -- is Milestone 3.3's.
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m firmbatch.control_plane.api")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args(argv)

    from .. import config
    from ..db.engine import create_application_engine
    from .app import create_app
    from .email import CapturingEmailDelivery, UnavailableEmailDelivery
    from .settings import load_api_settings

    try:
        application_settings = config.load_application_settings(os.environ)
        authenticator_url = config.load_authenticator_url(os.environ)
        api_settings = load_api_settings(os.environ)
    except config.ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    email = (
        CapturingEmailDelivery(api_settings.environment)
        if api_settings.is_test
        else UnavailableEmailDelivery()
    )
    engine = create_application_engine(application_settings)
    # The trusted-issuer engine (Milestone 3.1 security correction): a distinct restricted
    # role holding login, session opening and recovery, which the application engine does not.
    authenticator_engine = create_application_engine(authenticator_url)
    app = create_app(
        settings=api_settings, engine=engine, email=email, authenticator_engine=authenticator_engine
    )

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", server_header=False)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
