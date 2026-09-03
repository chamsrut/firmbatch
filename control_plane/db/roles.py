"""Grants that separate application access from privileged provisioning.

Deliberately **not** part of the Alembic migration. Role names differ per environment
(and per disposable test database), so putting them in a migration would either hard-code
an environment into the schema history or make that history non-deterministic. The schema
migration is role-agnostic; role wiring is an explicit admin action, run here by the test
bootstrap and by an operator runbook in production.

Three roles, three jobs:

``owner``
    Owns the schema and runs migrations. Privileged by definition. Not used at runtime.

``application``
    What the API, controller and validator connect as. Non-owner, ``NOSUPERUSER``,
    ``NOBYPASSRLS``, no DDL, **no TEMP**. It gets DML on tenant-scoped tables and is fully
    subject to the isolation policies -- including on ``tenants``, where it may read only
    its own row and may not INSERT at all.

``provisioning``
    Creates tenants. Also non-owner, non-superuser and non-``BYPASSRLS``: it is
    privileged only in the narrow sense that it holds INSERT on ``tenants``, and it holds
    no privilege whatsoever on tenant data. Creating tenant X still requires the context
    of tenant X, so even this role cannot write a row into somebody else's scope.

Both runtime roles remain under RLS. Nothing here hands out ``BYPASSRLS``, and nothing
may: the point of forcing row security is that no runtime role can turn it off.

**Nothing is inherited from a PostgreSQL default.** PUBLIC loses ``CREATE`` on every
schema, ``TEMP`` on the database, ``EXECUTE`` on the tenant-context helper, and all table
privileges; each runtime role is then granted back only what it needs. Defaults change
between major versions and differ between a stock server and a hardened one, so a grant
that is only correct because of a default is a grant that is only correct here.
"""

from __future__ import annotations

import re

from sqlalchemy import Connection, text

from .base import SCHEMA
from .models import TENANT_SCOPED_TABLES

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

#: The helper every isolation policy calls. Policies are evaluated with the privileges of
#: the querying role, so a role without EXECUTE here cannot read a tenant-scoped table at
#: all -- which is the correct failure direction.
TENANT_CONTEXT_FUNCTION = f"{SCHEMA}.app_current_tenant_id()"


def quote_identifier(name: str) -> str:
    """Validate then quote a SQL identifier.

    Role names reach this module from the environment, and ``GRANT`` takes no bind
    parameters. Validating against a strict pattern before quoting is what keeps that
    from being an injection point.
    """
    if not _IDENTIFIER.match(name or ""):
        raise ValueError(f"{name!r} is not an acceptable SQL identifier for a role or table")
    return f'"{name}"'


def harden_database(connection: Connection, database: str) -> None:
    """Remove the implicit rights every role gets just by being able to connect.

    ``TEMP`` is the one that matters most. PostgreSQL grants it to PUBLIC by default, and
    a role holding it can ``CREATE TEMP TABLE workspaces (...)``; because the temporary
    schema is searched before ``search_path``, every later unqualified reference on that
    connection resolves to the forgery -- for the life of a pooled connection, and with
    row-level security attached to a table the query no longer reaches.

    ``CREATE`` on ``public`` is revoked for the same family of reasons. PostgreSQL 15+
    already does it; doing it explicitly means the guarantee does not depend on which
    server version an environment happens to run.
    """
    connection.execute(text(f"REVOKE TEMPORARY ON DATABASE {quote_identifier(database)} FROM PUBLIC"))
    connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    connection.execute(text(f"REVOKE ALL ON SCHEMA {quote_identifier(SCHEMA)} FROM PUBLIC"))
    connection.execute(text(f"REVOKE ALL ON FUNCTION {TENANT_CONTEXT_FUNCTION} FROM PUBLIC"))


def revoke_public_table_privileges(connection: Connection) -> None:
    """Belt and braces: no tenant-scoped table is reachable by PUBLIC."""
    for table in TENANT_SCOPED_TABLES:
        connection.execute(
            text(f"REVOKE ALL ON TABLE {quote_identifier(SCHEMA)}.{quote_identifier(table)} FROM PUBLIC")
        )


def _grant_common(connection: Connection, quoted: str) -> None:
    connection.execute(text(f"GRANT USAGE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}"))
    # Required to evaluate the isolation policies at all; granted explicitly because
    # harden_database took it away from PUBLIC.
    connection.execute(text(f"GRANT EXECUTE ON FUNCTION {TENANT_CONTEXT_FUNCTION} TO {quoted}"))
    # No GRANT TEMPORARY, and no GRANT CREATE. A runtime role creates nothing.


def grant_application_role(connection: Connection, role: str) -> None:
    """Give ``role`` exactly what a tenant-scoped application needs, and nothing more."""
    quoted = quote_identifier(role)
    _grant_common(connection, quoted)
    schema = quote_identifier(SCHEMA)
    # Read-only on tenants: an application resolves its own tenant, it never creates one.
    connection.execute(text(f"GRANT SELECT ON TABLE {schema}.tenants TO {quoted}"))
    connection.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {schema}.workspaces TO {quoted}"))
    # No privilege on alembic_version: the schema history is not application data.


def grant_provisioning_role(connection: Connection, role: str) -> None:
    """Give ``role`` tenant provisioning, and no access to tenant data."""
    quoted = quote_identifier(role)
    _grant_common(connection, quoted)
    schema = quote_identifier(SCHEMA)
    connection.execute(text(f"GRANT SELECT, INSERT, UPDATE ON TABLE {schema}.tenants TO {quoted}"))
    # Intentionally no grant on workspaces. Provisioning creates the scope; it does not
    # get to look inside it.
