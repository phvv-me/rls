from typing import cast

import pytest
import sqlalchemy as sa
from conftest import CatalogConnection
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
        "scope_read",
        "scope_insert",
        "scope_update",
        "scope_delete",
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

    with pytest.raises(ValueError, match="silent"):
        rls.Catalog(StrictBase.registry)

    class OpenBase(DeclarativeBase):
        pass

    class Declared(OpenBase):
        __tablename__ = "declared"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = (rls.Policy.select("read", sa.true()),)

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

    with pytest.raises(ValueError, match="declares no RLS policies"):
        rls.Catalog(EmptyBase.registry)

    class DuplicateBase(DeclarativeBase):
        pass

    class Duplicate(DuplicateBase):
        __tablename__ = "duplicate"
        id: Mapped[int] = mapped_column(primary_key=True)
        __rls__ = (
            rls.Policy.select("same", sa.true()),
            rls.Policy.select("same", sa.true()),
        )

    with pytest.raises(ValueError, match="duplicate policy"):
        rls.Catalog(DuplicateBase.registry)

    class Detached:
        __rls__ = (rls.Policy.select("read", sa.true()),)

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
                "scope_read",
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
    assert "items policy scope_read has drifted" in violations
    assert "items is missing policy scope_insert" in violations
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
