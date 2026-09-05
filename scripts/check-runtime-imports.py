#!/usr/bin/env python3
"""Prove the runtime dependency lock is sufficient for the production code.

Two modes, and they close different halves of the same gap. Installing the runtime lock
and importing ``sqlalchemy`` proves the *lock* resolves; it says nothing about whether
Firmbatch itself can run on it. A production module that grows an import satisfied only by
the development lock -- ``pytest``, ``ruff``, or anything they drag in -- would install
cleanly, import cleanly in CI's development environment, and fail on first use in
production.

``--static`` (run by ``verify-repository.sh``, no virtual environment needed)
    Parse every production module and check that each third-party top-level import it
    makes is provided by a distribution pinned in ``requirements-v1-lock.txt``. This is
    the assertion that fails the moment production code reaches for a development-only
    package, wherever it is run.

``--dynamic`` (run by CI inside the clean runtime virtual environment)
    Actually import every production module on an interpreter that has *only* the runtime
    lock installed, run a real entry point, and confirm every third-party module resolved
    from this environment rather than leaking in from the development one. Static analysis
    cannot see a conditional or deferred import; this does.

Production code is everything under ``control_plane/`` except the test package. Alembic
migration scripts are included: they run in production too.

``--static`` also enforces a second boundary, for the same reason in a different currency.
The **runtime** modules -- the ones an API server, controller or validator imports -- must
not reach the migration entry point or the test bootstrap, and must not read the privileged
environment variables. A credential that reaches a process is a credential that can leak
from it, so the cheapest way not to leak the owner password from the runtime is for the
runtime never to have been able to ask for it.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "control_plane"
RUNTIME_LOCK = REPO_ROOT / "requirements-v1-lock.txt"

#: Directory names under the package that are not production code.
EXCLUDED = {"tests", "__pycache__"}

#: Files that are production code but cannot be *imported* as modules. Alembic execs
#: ``env.py`` inside a context it establishes first, so importing it directly raises
#: before it does anything. It is still parsed by ``--static``, which is where its imports
#: get checked; only the dynamic import skips it.
NOT_IMPORTABLE = {PACKAGE / "db" / "migrations" / "env.py"}

#: A real production entry point that needs no database and no development package.
#: ``migrate heads`` reads the migration history off disk and prints the single head, so
#: it exercises Alembic's script directory, the package layout and the config loader.
SMOKE_ENTRY_POINT = ("firmbatch.control_plane.migrate", ["heads"])

_PIN = re.compile(r"^([A-Za-z0-9_.\-]+)==")

#: The modules a runtime process imports. Everything else under ``control_plane/`` is
#: migration tooling, test tooling, or an Alembic script.
RUNTIME_MODULES = (
    "__init__.py",
    "config.py",
    "db/__init__.py",
    "db/audit.py",
    "db/auth.py",
    "db/base.py",
    "db/engine.py",
    "db/identity.py",
    "db/idempotency.py",
    "db/metadata.py",
    "db/models.py",
    "db/principal.py",
    "db/repositories.py",
    "db/roles.py",
    "security/__init__.py",
    "security/authorization.py",
    "security/secrets.py",
)

#: What a runtime module may not import. ``migrate`` holds the owner credential path and
#: ``testing`` holds the disposable-cluster administrator; neither belongs in an API
#: server's import graph.
FORBIDDEN_RUNTIME_IMPORTS = ("migrate", "testing", "alembic")

#: What a runtime module may not *use*. Reading one of these is how a runtime process
#: comes to hold a credential it has no business holding.
#:
#: Checked as attribute access and bare names in the AST -- ``config.MIGRATION_URL_VAR``,
#: ``load_migration_settings(...)`` -- and deliberately **not** as a substring of the
#: source. ``db/principal.py`` tells an operator to "use FIRMBATCH_MIGRATION_DATABASE_URL
#: for privileged work", which is advice in an error message and exactly the sort of thing
#: this rule must not make worse. Prose about a credential is not access to it.
PRIVILEGED_NAMES = frozenset(
    {
        "MIGRATION_URL_VAR",
        "TEST_ADMIN_URL_VAR",
        "load_migration_settings",
        "load_migration_url",
        "load_test_bootstrap_settings",
        "load_test_admin_url",
        "MigrationSettings",
        "TestBootstrapSettings",
    }
)

#: ``config.py`` defines the privileged loaders, so it necessarily uses their names. It is
#: still a runtime module for the *import* rule -- it must not reach migrate or testing.
NAME_RULE_EXEMPT = ("config.py",)


def production_modules() -> list[pathlib.Path]:
    return sorted(
        path
        for path in PACKAGE.rglob("*.py")
        if not EXCLUDED & set(path.relative_to(PACKAGE).parts)
    )


def locked_distributions(path: pathlib.Path) -> set[str]:
    return {
        _PIN.match(line).group(1).lower().replace("_", "-")
        for line in path.read_text().splitlines()
        if _PIN.match(line)
    }


def _module_to_distribution() -> dict[str, set[str]]:
    """Top-level import name -> distributions providing it, from the live environment."""
    from importlib.metadata import packages_distributions

    return {name: {d.lower().replace("_", "-") for d in dists} for name, dists in packages_distributions().items()}


def top_level_imports(path: pathlib.Path) -> set[str]:
    """Every top-level module name this file imports, including inside functions.

    Deferred imports count. ``bootstrap.py`` imports ``psycopg.sql`` inside a function
    precisely so the module stays import-light, and a check that only looked at the top of
    the file would miss exactly the imports most likely to be added casually.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def check_static() -> int:
    locked = locked_distributions(RUNTIME_LOCK)
    provided = _module_to_distribution()
    stdlib = set(sys.stdlib_module_names)

    problems: list[str] = []
    checked = 0
    for path in production_modules():
        relative = path.relative_to(REPO_ROOT)
        for name in sorted(top_level_imports(path)):
            if name in stdlib or name in ("firmbatch", "control_plane", "__future__"):
                continue
            checked += 1
            distributions = provided.get(name)
            if distributions is None:
                problems.append(
                    f"{relative}: imports {name!r}, which no installed distribution provides -- "
                    "cannot tell whether the runtime lock covers it"
                )
            elif not distributions & locked:
                problems.append(
                    f"{relative}: imports {name!r}, provided by {sorted(distributions)}, which is "
                    f"NOT pinned in {RUNTIME_LOCK.name}. Production code may only import what a "
                    "production install has; add the distribution to the runtime requirements or "
                    "move the code into the test package."
                )

    problems.extend(check_runtime_boundary())

    if problems:
        print("runtime import closure: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        f"runtime import closure: {checked} third-party imports across "
        f"{len(production_modules())} production modules, all covered by {RUNTIME_LOCK.name} "
        f"({len(locked)} pins)"
    )
    print(
        f"runtime module boundary: {len(RUNTIME_MODULES)} runtime modules import no migration "
        "or test tooling and read no privileged credential"
    )
    return 0


def check_runtime_boundary() -> list[str]:
    """Runtime modules import no privileged tooling and name no privileged credential.

    Static rather than dynamic on purpose: the property is "an API server cannot even ask
    for the owner URL", and that is a fact about the import graph, not about what happened
    to run.
    """
    problems: list[str] = []
    for relative in RUNTIME_MODULES:
        path = PACKAGE / relative
        if not path.exists():
            problems.append(f"control_plane/{relative}: listed as a runtime module but missing")
            continue
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))

        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # Relative imports carry the module in `.module`; `from . import x` puts
                # the interesting name in `.names`.
                targets = [node.module or ""] + [alias.name for alias in node.names]
            for target in targets:
                head = target.split(".")[0]
                if head in FORBIDDEN_RUNTIME_IMPORTS:
                    problems.append(
                        f"control_plane/{relative}: imports {target!r}. Runtime modules may not "
                        "reach the migration entry point or the test bootstrap -- a credential "
                        "that reaches a process is a credential that can leak from it."
                    )

        if relative in NAME_RULE_EXEMPT:
            continue
        for node in ast.walk(tree):
            used = None
            if isinstance(node, ast.Attribute) and node.attr in PRIVILEGED_NAMES:
                used = node.attr
            elif isinstance(node, ast.Name) and node.id in PRIVILEGED_NAMES:
                used = node.id
            if used is not None:
                problems.append(
                    f"control_plane/{relative}: uses {used!r}. A runtime module has no use for a "
                    "migration or bootstrap credential, and reaching for one is how it comes to "
                    "hold it."
                )
    return problems


def _pytest_available() -> bool:
    """The runtime environment must not carry a development-only package."""
    import importlib.util

    return importlib.util.find_spec("pytest") is not None


def check_dynamic() -> int:
    import importlib

    parent = str(REPO_ROOT.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)

    # Where this interpreter's own third-party packages live.
    roots = tuple(
        pathlib.Path(p).resolve()
        for p in sys.path
        if p and pathlib.Path(p).name in ("site-packages", "dist-packages")
    )
    if not roots:
        print("could not identify this environment's site-packages", file=sys.stderr)
        return 1

    stdlib = set(sys.stdlib_module_names)
    imported: list[str] = []
    for path in production_modules():
        if path in NOT_IMPORTABLE:
            continue
        relative = path.relative_to(REPO_ROOT).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join(["firmbatch"] + parts)
        importlib.import_module(module)
        imported.append(module)

    # The question is not "did this come from the base interpreter" -- a virtual
    # environment shares the base stdlib by design, and flagging that produced a false
    # positive on a private ``_sysconfigdata`` module. The question is whether any
    # *third-party* package was served out of a different environment's site-packages,
    # which is what a leaking PYTHONPATH looks like.
    problems = []
    for name, module in sorted(sys.modules.items()):
        if "." in name or name in stdlib or module is None:
            continue
        origin = getattr(module, "__file__", None)
        if not origin:
            continue
        resolved = pathlib.Path(origin).resolve()
        packages_dir = next(
            (
                parent
                for parent in resolved.parents
                if parent.name in ("site-packages", "dist-packages")
            ),
            None,
        )
        if packages_dir is not None and packages_dir not in roots:
            problems.append(
                f"{name} resolved from {resolved}, which is another environment's "
                f"{packages_dir.name} -- this environment must stand on its own"
            )

    if problems:
        print("runtime environment provenance: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    if _pytest_available():
        print(
            "pytest is importable in the runtime environment, so this check cannot show "
            "that production code stands on the runtime lock alone",
            file=sys.stderr,
        )
        return 1

    # A real entry point, on this interpreter, with no development package available.
    module_name, argv = SMOKE_ENTRY_POINT
    entry = importlib.import_module(module_name)
    code = entry.main(argv)
    if code != 0:
        print(f"{module_name} {' '.join(argv)} exited {code}", file=sys.stderr)
        return 1

    skipped = len(NOT_IMPORTABLE)
    print(
        f"imported {len(imported)} production modules "
        f"({skipped} exec-only, parsed by --static instead) and ran "
        f"{module_name} {' '.join(argv)}"
    )
    print(f"every third-party module resolved from {roots[0]}")
    print(f"pytest importable here: {_pytest_available()} (must be False)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--static", action="store_true", help="check imports against the lock file")
    group.add_argument("--dynamic", action="store_true", help="import everything in this environment")
    args = parser.parse_args()
    return check_static() if args.static else check_dynamic()


if __name__ == "__main__":
    raise SystemExit(main())
