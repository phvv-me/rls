from collections.abc import Callable
from collections.abc import Iterable
from typing import cast

from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy.engine import Connection
from sqlalchemy.orm import registry as MapperRegistry
from sqlalchemy.sql.selectable import FromClause

from ..ddl import apply_statements
from ..policy import Policy
from ..state import RLSState
from .open import Open
from .reflection import reflect_rls
from .table_key import TableKey

_INFO_KEY = "rls"

type PolicyDeclaration = Iterable[Policy] | Callable[[], Iterable[Policy]]


class Catalog:
    """The registered row security catalog over one or more mapper registries.

    Registration compiles every mapped `__rls__` declaration onto its table, refuses mapped
    tables without a declaration, and answers installation, reflection, and verification over
    the complete catalog.
    """

    def __init__(self, *registries: MapperRegistry) -> None:
        self.metadata = tuple(dict.fromkeys(registry.metadata for registry in registries))
        for metadata in self.metadata:
            metadata.info[_INFO_KEY] = self
        for mapper_registry in registries:
            for mapper in mapper_registry.mappers:
                self.declare(mapper.class_, mapper.local_table)
        self.tables = tuple(
            table for metadata in self.metadata for table in metadata.tables.values()
        )
        self.protected = tuple(table for table in self.tables if self.state(table) is not None)

    @staticmethod
    def state(table: Table) -> RLSState | None:
        """Return a table's compiled row security declaration."""
        state = table.info.get(_INFO_KEY)
        return state if isinstance(state, RLSState) else None

    @classmethod
    def managed(cls, metadata: MetaData | Iterable[MetaData]) -> tuple[Table, ...]:
        """Return tables attached to the RLS catalogs in `metadata`."""
        catalogs = (metadata,) if isinstance(metadata, MetaData) else metadata
        tables: list[Table] = []
        for catalog in catalogs:
            attached = catalog.info.get(_INFO_KEY)
            if isinstance(attached, cls):
                tables.extend(attached.tables)
        return tuple(dict.fromkeys(tables))

    def declare(self, mapped: type, local_table: FromClause) -> None:
        """Compile one mapped class's declaration onto its table."""
        found = cast(PolicyDeclaration | Open | None, getattr(mapped, "__rls__", None))
        if not isinstance(local_table, Table):
            raise TypeError("RLS requires a mapped table")
        table = local_table
        if isinstance(found, Open):
            return
        if found is None:
            raise ValueError(
                f"{table.fullname} declares no RLS policies; declare `__rls__` "
                "or mark it `rls.Open()`"
            )
        policies = tuple(found() if callable(found) else found)
        if not policies:
            raise ValueError(f"{table.fullname} declares no RLS policies")
        names = [policy.name for policy in policies]
        if len(set(names)) != len(names):
            raise ValueError(f"{table.fullname} declares duplicate policy names")
        table.info[_INFO_KEY] = RLSState.declared(policies)

    def create_all(self, connection: Connection) -> None:
        """Install every declared policy through typed SQLAlchemy DDL."""
        for table in self.protected:
            state = self.state(table)
            assert state is not None
            for statement in apply_statements(table, state):
                connection.execute(statement)

    @staticmethod
    def reflect(connection: Connection, tables: Iterable[Table]) -> dict[Table, RLSState]:
        """Reflect live row security keyed by the requested tables."""
        requested = tuple(tables)
        states = reflect_rls(connection, requested)
        return {table: states[TableKey.of(table, connection)] for table in requested}

    def inspect(self, connection: Connection) -> dict[Table, RLSState]:
        """Reflect live row security for every managed table."""
        return self.reflect(connection, self.tables)

    def verify(self, connection: Connection) -> list[str]:
        """Report every table whose live row security differs from its declaration."""
        live = self.inspect(connection)
        violations: list[str] = []
        for table in self.tables:
            state = live[table]
            declared = self.state(table)
            if declared is None:
                if state.exists:
                    violations.append(f"{table.fullname} has undeclared row level security")
                continue
            violations.extend(declared.diff(state, table.name))
        return violations
