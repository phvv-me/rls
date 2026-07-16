import datetime
import io
import uuid
from dataclasses import dataclass
from dataclasses import field

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations.ops import MigrateOperation
from hypothesis import strategies as st
from sqlalchemy import MetaData
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.sql.elements import ColumnElement

import rls
from rls.alembic import AlterRLSOp
from rls.policy import Command
from rls.policy import CompiledPolicy
from rls.state import RLSState

type CatalogRow = tuple[
    str,
    str,
    bool,
    bool,
    str | None,
    str | None,
    list[str] | None,
    str | None,
    str | None,
    str | None,
]


class Standing(rls.Context, prefix="app"):
    uid: uuid.UUID | None = None
    orgs: tuple[uuid.UUID, ...] = ()
    active: bool = False
    expires: datetime.date | None = None
    lens: tuple[uuid.UUID, ...] | None = None


class TenantGate(rls.Context):
    tenant: str = ""


@dataclass
class CatalogConnection:
    """Fake connection whose `execute` replays canned `pg_catalog` rows."""

    rows: list[CatalogRow]
    dialect: Dialect = field(default_factory=postgresql.dialect)

    def execute(self, statement: sa.Executable) -> list[CatalogRow]:
        del statement
        return self.rows


@dataclass
class RecordingConnection:
    """Fake connection that records every `execute` call for later assertions."""

    dialect: Dialect = field(default_factory=postgresql.dialect)
    calls: list[tuple[sa.Executable, dict[str, str] | None]] = field(default_factory=list)

    def execute(
        self,
        statement: sa.Executable,
        parameters: dict[str, str] | None = None,
    ) -> None:
        self.calls.append((statement, parameters))


@dataclass
class FakeAutogenContext:
    """Stand-in for `AutogenContext` exposing only the fields the comparator reads."""

    connection: Connection | None
    metadata: MetaData | None


@dataclass
class FakeUpgradeOps:
    """Stand-in for `UpgradeOps` collecting the operations the comparator appends."""

    ops: list[MigrateOperation] = field(default_factory=list)


def predicate() -> rls.Predicate:
    """A simple compilable boolean column expression."""
    return sa.column("owner_id", sa.Integer()) == 1


def configured() -> RLSState:
    """The one-policy declared state reused across DDL and alembic tests."""
    return RLSState(
        policies=(CompiledPolicy(name="read", command=Command.select, using="owner_id = 1"),)
    )


def catalog_rows(state: RLSState, table: str, schema: str = "public") -> list[CatalogRow]:
    """Render a declared state as the `pg_catalog` rows reflection would read back."""
    if not state.policies:
        return [(schema, table, state.forced, state.enabled, None, None, None, None, None, None)]
    return [
        (
            schema,
            table,
            state.forced,
            state.enabled,
            policy.name,
            "PERMISSIVE" if policy.permissive else "RESTRICTIVE",
            list(policy.roles),
            policy.command.sql,
            policy.using,
            policy.check,
        )
        for policy in state.policies
    ]


def make_catalog() -> tuple[type[DeclarativeBase], rls.Catalog]:
    """A fresh mapper base with one protected `items` table and one open `plain` table."""

    class Base(DeclarativeBase):
        pass

    class Item(Base):
        __tablename__ = "items"

        id: Mapped[int] = mapped_column(primary_key=True)
        owner_id: Mapped[int] = mapped_column()

        @classmethod
        def __rls__(cls) -> tuple[rls.Policy, ...]:
            return rls.crud(cls.owner_id == 1, cls.owner_id == 1)

    class Plain(Base):
        __tablename__ = "plain"
        __rls__ = rls.Open()

        id: Mapped[int] = mapped_column(primary_key=True)

    return Base, rls.Catalog(Base.registry)


def compile_ddl(statement: sa.ExecutableDDLElement) -> str:
    """Compile one DDL element against the PostgreSQL dialect."""
    return str(statement.compile(dialect=postgresql.dialect()))


def capture(operation: AlterRLSOp) -> list[str]:
    """Invoke an alembic operation offline and return its emitted SQL statements."""
    output = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    Operations(context).invoke(operation)
    return [line.strip() for line in output.getvalue().split(";\n") if line.strip()]


def projected(expression: object) -> ColumnElement[object]:
    """Cast a class-level projection back to the column element it is at runtime."""
    assert isinstance(expression, ColumnElement)
    return expression


_CLAUSES = st.sampled_from(
    (None, "true", "false", "owner_id = 1", "tenant = current_setting('app.t', true)")
)
_ROLE_TUPLES = st.lists(
    st.sampled_from(("public", "reader", "writer", "admin")), min_size=1, unique=True
).map(tuple)
_NAMES = st.sampled_from(("read", "insert", "update", "delete", "alpha", "beta"))


def compiled_policies() -> st.SearchStrategy[CompiledPolicy]:
    """Compiled policies over the full attribute space, with parseable clauses."""
    return st.builds(
        CompiledPolicy,
        name=_NAMES,
        command=st.sampled_from(Command),
        using=_CLAUSES,
        check=_CLAUSES,
        roles=_ROLE_TUPLES,
        permissive=st.booleans(),
    )


def rls_states(min_policies: int = 0) -> st.SearchStrategy[RLSState]:
    """Whole-table states with both flags free and uniquely named policies."""
    return st.builds(
        RLSState,
        enabled=st.booleans(),
        forced=st.booleans(),
        policies=st.lists(
            compiled_policies(),
            min_size=min_policies,
            max_size=4,
            unique_by=lambda policy: policy.name,
        ).map(tuple),
    )
