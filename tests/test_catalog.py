from typing import cast

import pytest
import sqlalchemy as sa
from conftest import CatalogConnection
from conftest import CockroachCatalogConnection
from conftest import RecordingConnection
from conftest import catalog_rows
from conftest import make_catalog
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

import rls


def test_declarations_compile_onto_tables_and_install_typed_ddl() -> None:
    """A catalog compiles declarations onto protected tables and installs typed DDL."""
    base, catalog = make_catalog()
    items = base.metadata.tables["items"]
    plain = base.metadata.tables["plain"]
    state = rls.Catalog.state(items)
    assert state is not None and state.enabled and state.forced
    assert [policy.name for policy in state.policies] == [
        "rls_select",
        "rls_insert",
        "rls_update",
        "rls_delete",
    ]
    assert rls.Catalog.state(plain) is None
    assert catalog.protected == (items,)
    assert set(catalog.tables) == {items, plain}
    assert rls.Catalog.managed(()) == ()
    assert rls.Catalog.managed(sa.MetaData()) == ()
    assert catalog.reflect(cast(Connection, CatalogConnection([])), ()) == {}

    connection = RecordingConnection()
    catalog.create_all(cast(Connection, connection))
    compiled = [
        str(cast(sa.ExecutableDDLElement, statement).compile(dialect=postgresql.dialect()))
        for statement, _ in connection.calls
    ]
    assert compiled[0] == "ALTER TABLE items ENABLE ROW LEVEL SECURITY"
    assert compiled[1] == "ALTER TABLE items FORCE ROW LEVEL SECURITY"
    assert len(compiled) == 6


def test_open_singleton_and_invalid_declarations() -> None:
    """Every table needs policies or the singleton `Open`; bad declarations are rejected."""

    class StrictBase(DeclarativeBase):
        pass

    class Silent(StrictBase):
        __tablename__ = "silent"
        id: Mapped[int] = mapped_column(primary_key=True)

    with pytest.raises(rls.DeclarationError, match="silent"):
        rls.Catalog(StrictBase.registry)

    class OpenBase(DeclarativeBase):
        pass

    class Declared(OpenBase):
        __tablename__ = "declared"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = (rls.Policy.select(sa.true()),)

    class Excused(OpenBase):
        __tablename__ = "excused"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = rls.Open()

    catalog = rls.Catalog(OpenBase.registry)
    assert [table.name for table in catalog.protected] == ["declared"]
    assert rls.Open() is rls.Open()
    assert repr(rls.Open()) == "rls.Open()"

    class EmptyBase(DeclarativeBase):
        pass

    class Empty(EmptyBase):
        __tablename__ = "empty"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = ()

    with pytest.raises(rls.DeclarationError, match="declares no RLS policies"):
        rls.Catalog(EmptyBase.registry)

    class DuplicateBase(DeclarativeBase):
        pass

    class Duplicate(DuplicateBase):
        __tablename__ = "duplicate"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = (
            rls.Policy.select(sa.true()),
            rls.Policy.select(sa.true()),
        )

    with pytest.raises(rls.DeclarationError, match="duplicate policy"):
        rls.Catalog(DuplicateBase.registry)

    class Detached:
        __rls__ = (rls.Policy.select(sa.true()),)

    with pytest.raises(TypeError, match="mapped table"):
        rls.Catalog().declare(Detached, sa.select(sa.literal(1)).subquery())


def test_verify_reports_drift_and_passes_when_matched() -> None:
    """Verification names every divergence and stays silent when live matches the declaration."""
    _, catalog = make_catalog()
    drift = CatalogConnection(
        [
            (
                "public",
                "items",
                True,
                True,
                "rls_select",
                "PERMISSIVE",
                ["public"],
                "SELECT",
                "false",
                None,
            ),
            (
                "public",
                "items",
                True,
                True,
                "extra",
                "PERMISSIVE",
                ["public"],
                "SELECT",
                "true",
                None,
            ),
            ("public", "plain", False, True, None, None, None, None, None, None),
        ]
    )
    violations = catalog.verify(cast(Connection, drift))
    assert "items policy rls_select has drifted" in violations
    assert "items is missing policy rls_insert" in violations
    assert "items has undeclared policy extra" in violations
    assert "plain has undeclared row level security" in violations

    items = catalog.protected[0]
    state = rls.Catalog.state(items)
    assert state is not None
    rows = catalog_rows(state, "items")
    rows.append(("public", "plain", False, False, None, None, None, None, None, None))
    rows.append(
        ("public", "ghost", True, True, "loose", "PERMISSIVE", ["public"], "SELECT", "true", None)
    )
    matched = cast(Connection, CatalogConnection(rows))
    assert catalog.verify(matched) == []
    assert state.matches(catalog.inspect(matched)[items], "items")

    lowercase = rows.copy()
    first = lowercase[0]
    lowercase[0] = (*first[:5], "permissive", *first[6:])
    assert catalog.verify(cast(Connection, CatalogConnection(lowercase))) == []


def test_cockroach_reflection_uses_show_policies_and_shared_table_flags() -> None:
    """CockroachDB reflects its empty compatibility view through structured commands."""
    metadata = sa.MetaData()
    items = sa.Table("items", metadata, sa.Column("id", sa.Integer()), schema="tenant")
    plain = sa.Table("plain", metadata, sa.Column("id", sa.Integer()))
    connection = CockroachCatalogConnection(
        flags=[("tenant", "items", True, True), ("public", "plain", False, False)],
        policies={
            "SHOW POLICIES FOR tenant.items": [
                ("rls_select", "SELECT", "permissive", ["reader"], "id > 0:::INT8", "")
            ],
            "SHOW POLICIES FOR public.plain": [],
        },
    )

    states = rls.Catalog.reflect(cast(Connection, connection), (items, plain))

    assert states[items] == rls.RLSState(
        policies=(
            rls.CompiledPolicy(
                name="rls_select",
                command=rls.Command.select,
                using="id > 0:::INT8",
                roles=("reader",),
            ),
        )
    )
    assert states[plain] == rls.RLSState(enabled=False, forced=False)
    assert connection.statements == [
        "SHOW POLICIES FOR public.plain",
        "SHOW POLICIES FOR tenant.items",
    ]
