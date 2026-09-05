"""Finding 8: every hardened ``Session`` bind form, across every transaction outcome.

The identity-map guard is the defence that stops SQLAlchemy answering ``session.get()``
from memory after the tenant context has changed or gone. It is installed once, class-wide,
and finds its state through whatever a ``Session`` happens to be bound to -- so "does it
work" is not one question, it is *bind form* x *transaction outcome*, and the two defects
found so far were each in one cell of that grid rather than in the guard itself:

* ``Session(bind=engine.connect())`` was not recognised as hardened at all, so a
  cross-tenant object survived a savepoint rollback;
* the listener fired only on savepoints, so a committed outer transaction left the map
  populated and a later context-free transaction returned tenant A's object from memory
  while the same row read through SQL returned nothing.

So the grid is enumerated rather than sampled. Three **supported** bind forms:

* ``Session(bind=engine)`` -- the ordinary case;
* ``Session(bind=engine.execution_options(...))`` -- an ``OptionEngine``, a *different*
  object that shares the pool;
* ``Session(bind=engine, binds={Model: engine})`` -- mapper-specific binds, where
  ``get_bind()`` rather than the ``bind`` attribute is what resolves a mapped class.

And one **rejected** form: ``Session(bind=engine.connect())``.

That rejection replaced an earlier attempt to support it. Every protection here is
anchored to a pool *checkout* -- the principal is re-verified there, ``search_path`` is
re-pinned there, and whatever session state the previous holder left is what the next one
inherits. A Connection
handed to a ``Session`` was checked out earlier by somebody else and may have been used in
between, so the Session inherits whatever session state that caller left behind and none of
the checkout hardening re-runs. Teaching the identity-map guard to recognise the form
closed one half of that and left the other open, which is worse than refusing it: a bind
form that looks supported and is not. Nothing in this package needs it.

  A mapper-bind-*only* session (no default ``bind``) is covered by the recognition test but
  not by the behavioural matrix, and that is a property of SQLAlchemy rather than an
  omission: ``session.execute(text(...))`` on such a session raises
  ``UnboundExecutionError`` because a raw statement has no mapper to resolve a bind from.
  A context is acquired by calling ``firmbatch.bind_authenticated_context(...)``, which is
  a raw statement -- so a session with no default bind cannot carry a context at all, and
  there is no cached-object scenario to test. The recognition test still covers the ``get_bind()`` resolution path, which is
  the part of the guard that mapper binds actually exercise.

Eight outcomes each: outer commit, outer rollback, outer exception, nested commit, nested
rollback, nested exception, an explicit context clear, and a tenant A -> B transition.

``expire_on_commit=False`` throughout, and a strong reference is held to every object that
must not come back -- with expiry on, SQLAlchemy would refresh from the database anyway and
the test would pass without the guard existing. The control at the end proves the class-wide
listener does not reach into ordinary SQLAlchemy sessions on unrelated engines.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.models import Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository

#: The forms that work, and keep every protection.
BIND_FORMS = ("engine", "option_engine", "mapper_binds")


@pytest.fixture()
def isolated_engine(disposable_database):
    """A private application engine, so one test's pool state cannot reach another."""
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=2, max_overflow=0
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def make_session(isolated_engine, request):
    """Build a ``Session`` for the requested bind form, and close everything afterwards."""
    opened = []

    def build(form: str) -> Session:
        if form == "engine":
            session = Session(bind=isolated_engine, expire_on_commit=False)
        elif form == "option_engine":
            session = Session(
                bind=isolated_engine.execution_options(stream_results=False),
                expire_on_commit=False,
            )
        elif form == "connection":
            connection = isolated_engine.connect()
            opened.append(connection)
            session = Session(bind=connection, expire_on_commit=False)
        elif form == "option_connection":
            connection = isolated_engine.execution_options(stream_results=False).connect()
            opened.append(connection)
            session = Session(bind=connection, expire_on_commit=False)
        elif form == "mapper_binds":
            # Mapper binds present, plus a default: the shape a real application uses when
            # it routes one model elsewhere. Resolution for Workspace goes through
            # get_bind(); the default is what raw set_config() statements travel over.
            session = Session(
                bind=isolated_engine,
                binds={Workspace: isolated_engine},
                expire_on_commit=False,
            )
        elif form == "mapper_binds_only":
            # No default bind at all. Recognition only -- see the module docstring.
            session = Session(binds={Workspace: isolated_engine}, expire_on_commit=False)
        else:  # pragma: no cover - guarded by the parametrisation
            raise AssertionError(form)
        opened.append(session)
        return session

    try:
        yield build
    finally:
        for item in reversed(opened):
            item.close()


def _seed(engine, principal, slug):
    """One workspace for ``principal``'s tenant, returning its id."""
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return WorkspaceRepository(session).create(slug=slug, name=f"W {slug}").id


@pytest.fixture()
def workspaces(isolated_engine, principal_a, principal_b):
    import uuid

    suffix = uuid.uuid4().hex[:8]
    return {
        principal_a.id: _seed(isolated_engine, principal_a, f"bind-a-{suffix}"),
        principal_b.id: _seed(isolated_engine, principal_b, f"bind-b-{suffix}"),
    }


# --------------------------------------------------------------------------- recognition


@pytest.mark.parametrize("form", BIND_FORMS + ("mapper_binds_only",))
def test_every_supported_bind_form_is_recognised_as_hardened(make_session, form):
    """The guard has to find the pool through whatever the Session was bound to."""
    assert db_engine._is_hardened(make_session(form)) is True


# ------------------------------------------------------------------ the rejected form


@pytest.mark.parametrize("form", ["connection", "option_connection"])
def test_a_hardened_connection_bound_session_is_refused(make_session, form):
    """Refused on first use, with a specific exception rather than a generic failure.

    The ``option_connection`` case matters separately: a ``Connection`` obtained from an
    ``OptionEngine`` is a different object from one obtained from the Engine, and shares
    the same pool. Recognising only the first would leave the derivative supported.
    """
    session = make_session(form)
    with pytest.raises(db_engine.UnsupportedSessionBindError) as exc:
        session.begin()
    assert "not supported" in str(exc.value)
    assert "pool checkout" in str(exc.value)


def test_the_refusal_precedes_any_cached_object_being_returned(
    isolated_engine, workspaces, tenant_a
):
    """The failure mode that matters: ``session.get()`` answered from the identity map.

    A Session bound to a live Connection is asked for an object directly, with no explicit
    transaction. Autobegin fires first, so the refusal lands before the identity map can
    be consulted -- and before any SQL is emitted either.
    """
    connection = isolated_engine.connect()
    try:
        session = Session(bind=connection, expire_on_commit=False)
        try:
            with pytest.raises(db_engine.UnsupportedSessionBindError):
                session.get(Workspace, workspaces[tenant_a])
            assert session.identity_map.keys() == set() if hasattr(
                session.identity_map, "keys"
            ) else True
        finally:
            session.close()
    finally:
        connection.close()


def test_a_session_joining_an_active_external_transaction_is_refused(isolated_engine):
    """Joining a transaction somebody else began is the same bind form, and the same risk."""
    connection = isolated_engine.connect()
    try:
        connection.begin()
        session = Session(bind=connection, expire_on_commit=False)
        try:
            with pytest.raises(db_engine.UnsupportedSessionBindError):
                session.execute(text("SELECT 1"))
        finally:
            session.close()
    finally:
        connection.close()


def test_the_session_factories_refuse_a_checked_out_connection(isolated_engine, principal_a):
    """The official factories take an Engine and say so at the door."""
    connection = isolated_engine.connect()
    try:
        for factory, args in (
            (auth.authenticated_transaction, (connection, principal_a.credential)),
            (auth.provisioning_transaction, (connection,)),
            (db_engine.transaction, (connection,)),
        ):
            with pytest.raises(db_engine.UnsupportedSessionBindError) as exc:
                with factory(*args):
                    pass  # pragma: no cover - the factory must not yield
            assert "takes an Engine" in str(exc.value)
    finally:
        connection.close()


def test_an_unrelated_connection_bound_session_still_works(disposable_database):
    """The rejection is about *our* pool, not about the bind form in general.

    An ordinary SQLAlchemy application binding a Session to a Connection is none of this
    package's business, and must keep working.
    """
    plain = create_engine(disposable_database.application_url, future=True)
    try:
        with plain.connect() as connection:
            session = Session(bind=connection)
            try:
                assert session.execute(text("SELECT 1")).scalar() == 1
            finally:
                session.close()
    finally:
        plain.dispose()


# --------------------------------------------------------------- outer transaction outcomes


@pytest.mark.parametrize("form", BIND_FORMS)
@pytest.mark.parametrize("outcome", ["commit", "rollback", "exception"])
def test_no_object_survives_an_outer_transaction(
    make_session, workspaces, principal_a, form, outcome
):
    """After the outermost transaction ends, the map must be empty however it ended.

    Reproduced before the fix, for ``commit``: with ``expire_on_commit=False`` the Session
    kept its cache, and a later context-free transaction returned tenant A's object from
    memory while the same row read through SQL returned ``[]``.
    """
    session = make_session(form)
    workspace_id = workspaces[principal_a.id]

    if outcome == "exception":
        with pytest.raises(RuntimeError):
            with session.begin():
                auth.bind_authenticated_context(session, principal_a.credential)
                held = session.get(Workspace, workspace_id)
                assert held is not None
                raise RuntimeError("unwinding on purpose")
    else:
        with session.begin():
            auth.bind_authenticated_context(session, principal_a.credential)
            held = session.get(Workspace, workspace_id)
            assert held is not None
            if outcome == "rollback":
                session.rollback()

    # A strong reference is deliberately still held; only the map being cleared can help.
    assert held is not None

    with session.begin():
        leaked = session.get(Workspace, workspace_id)
    assert leaked is None, (
        f"{form}/{outcome}: a cached object was returned in a transaction with no tenant "
        "context, so PostgreSQL never evaluated the policy"
    )
    session.close()


# -------------------------------------------------------------- nested transaction outcomes


@pytest.mark.parametrize("form", BIND_FORMS)
@pytest.mark.parametrize("outcome", ["commit", "rollback", "exception"])
def test_the_map_is_emptied_however_a_savepoint_ends(
    make_session, workspaces, principal_a, principal_b, form, outcome
):
    """Every savepoint outcome empties the identity map, in every bind form.

    This cell of the grid used to test something stronger and sadder: a **raw** context
    switch inside a savepoint, because at Milestone 2.1 one worked. ``set_config`` could
    change the effective tenant, so the guard was what stood between a savepoint rollback
    and tenant B's object being served under tenant A.

    Milestone 2.3 removed the switch rather than defending against it -- no policy reads a
    setting, and the function that writes a context is executable by no runtime role -- so
    the first thing asserted here is that the raw route now changes nothing. The guard
    itself remains, and is asserted directly: after a savepoint ends by any route, nothing
    is served from memory. It is defence in depth now rather than the primary fix, which
    is exactly the kind of guard that gets refactored away when nothing pins it.
    """
    session = make_session(form)
    a_id, b_id = workspaces[principal_a.id], workspaces[principal_b.id]

    with session.begin():
        auth.bind_authenticated_context(session, principal_a.credential)
        mine = session.get(Workspace, a_id)
        assert mine is not None

        nested = session.begin_nested()
        # Deliberately raw, and deliberately futile.
        session.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(principal_b.id)}
        )
        assert db_engine.current_tenant_context(session) == principal_a.id
        assert session.get(Workspace, b_id) is None, (
            f"{form}/{outcome}: a raw setting change reached tenant B's row"
        )

        if outcome == "commit":
            nested.commit()
        elif outcome == "rollback":
            nested.rollback()
        else:
            try:
                with session.begin_nested():
                    raise RuntimeError("unwinding through a savepoint")
            except RuntimeError:
                pass
            nested.rollback()

        assert mine is not None  # strong reference retained on purpose
        assert session.identity_map.keys() == set(), (
            f"{form}/{outcome}: the identity map survived the end of a savepoint"
        )
        # And the outer context is untouched, so legitimate work continues.
        assert db_engine.current_tenant_context(session) == principal_a.id
        reread = session.get(Workspace, a_id)
        assert reread is not None and reread is not mine, (
            f"{form}/{outcome}: the object was served from memory rather than re-read"
        )
    session.close()


# ------------------------------------------------------------ clearing and switching tenants


@pytest.mark.parametrize("form", BIND_FORMS)
def test_the_map_is_dropped_when_a_transaction_starts_unauthenticated(
    make_session, workspaces, principal_a, form
):
    """A new transaction is a context change like any other, in every bind form.

    This cell used to clear the context part-way through a transaction and check the map
    emptied. That operation no longer exists -- it was a route to binding a second identity
    -- so the unauthenticated state is reached the way a request reaches it, and what is
    asserted is unchanged: nothing is served from memory once the context that loaded it
    is gone.
    """
    session = make_session(form)
    workspace_id = workspaces[principal_a.id]
    with session.begin():
        auth.bind_authenticated_context(session, principal_a.credential)
        held = session.get(Workspace, workspace_id)
        assert held is not None

    with session.begin():
        db_engine.require_no_inherited_context(session)
        assert held is not None  # strong reference retained on purpose
        assert session.get(Workspace, workspace_id) is None, (
            f"{form}: the object survived into an unauthenticated transaction"
        )
    session.close()


@pytest.mark.parametrize("form", BIND_FORMS)
def test_a_tenant_transition_re_evaluates_in_postgresql(
    make_session, workspaces, principal_a, principal_b, form
):
    """A -> B: B must not see A's object, and must see its own."""
    session = make_session(form)
    a_id, b_id = workspaces[principal_a.id], workspaces[principal_b.id]

    with session.begin():
        auth.bind_authenticated_context(session, principal_a.credential)
        a_object = session.get(Workspace, a_id)
        assert a_object is not None

    with session.begin():
        auth.bind_authenticated_context(session, principal_b.credential)
        assert a_object is not None  # still strongly referenced
        assert session.get(Workspace, a_id) is None, (
            f"{form}: tenant B was served tenant A's object out of the identity map"
        )
        assert session.get(Workspace, b_id) is not None, (
            f"{form}: tenant B could not read its own row, so the clear was too aggressive"
        )
    session.close()


# --------------------------------------------------------------------------------- control


def test_an_unrelated_engine_is_not_claimed(disposable_database):
    """The listener is class-wide, so it must be inert for sessions it does not own.

    Without this, "the guard works" could be true because the guard fires for *every*
    SQLAlchemy session in the process, which would be a different and much worse property.
    """
    plain = create_engine(disposable_database.application_url, future=True)
    try:
        session = Session(bind=plain)
        try:
            assert db_engine._is_hardened(session) is False
        finally:
            session.close()
    finally:
        plain.dispose()


def test_the_guard_survives_many_engines(disposable_database):
    """Registration is module-level, so engines must not accumulate listeners.

    An earlier design registered per engine, which retained dead engines and grew the
    listener list with every fixture.
    """
    from sqlalchemy.orm import Session as PlainSession

    engines = [
        db_engine.create_application_engine(disposable_database.application_url, pool_size=1)
        for _ in range(3)
    ]
    try:
        for engine in engines:
            session = PlainSession(bind=engine)
            try:
                assert db_engine._is_hardened(session) is True
            finally:
                session.close()
    finally:
        for engine in engines:
            engine.dispose()
