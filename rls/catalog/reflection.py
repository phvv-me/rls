import abc
from collections import defaultdict
from collections.abc import Iterable
from typing import cast

import sqlalchemy as sa
from sqlalchemy import Table
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.engine import Connection

from ..policy import Command
from ..policy import CompiledPolicy
from ..state import RLSState
from .table_key import TableKey

_PG_CLASS = sa.table(
    "pg_class",
    sa.column("oid", sa.BigInteger()),
    sa.column("relnamespace", sa.BigInteger()),
    sa.column("relname", sa.Text()),
    sa.column("relforcerowsecurity", sa.Boolean()),
    sa.column("relrowsecurity", sa.Boolean()),
    schema="pg_catalog",
)
_PG_NAMESPACE = sa.table(
    "pg_namespace",
    sa.column("oid", sa.BigInteger()),
    sa.column("nspname", sa.Text()),
    schema="pg_catalog",
)
_PG_POLICIES = sa.table(
    "pg_policies",
    sa.column("schemaname", sa.Text()),
    sa.column("tablename", sa.Text()),
    sa.column("policyname", sa.Text()),
    sa.column("permissive", sa.Text()),
    sa.column("roles", ARRAY(sa.Text())),
    sa.column("cmd", sa.Text()),
    sa.column("qual", sa.Text()),
    sa.column("with_check", sa.Text()),
    schema="pg_catalog",
)

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
type FlagRow = tuple[str, str, bool, bool]
type CockroachPolicyRow = tuple[str, str, str, list[str], str, str]


class _CatalogReflection(abc.ABC):
    """Reflect one database's row security catalog into portable state."""

    def __init__(self, connection: Connection, keys: set[TableKey]) -> None:
        self.connection = connection
        self.keys = keys

    @property
    def qualified_names(self) -> list[tuple[str, str]]:
        """Return deterministic schema and table pairs for the catalog query."""
        return sorted((key.schema_name, key.table_name) for key in self.keys)

    @classmethod
    def for_connection(cls, connection: Connection, keys: set[TableKey]) -> "_CatalogReflection":
        """Choose the catalog surface implemented by the connected database."""
        if connection.dialect.name == "cockroachdb":
            return _CockroachDBReflection(connection, keys)
        return _PostgreSQLReflection(connection, keys)

    def flags_statement(self) -> sa.Select[tuple[str, str, bool, bool]]:
        """Build the shared PostgreSQL-compatible table flag query."""
        return cast(
            sa.Select[tuple[str, str, bool, bool]],
            sa.select(
                _PG_NAMESPACE.c.nspname,
                _PG_CLASS.c.relname,
                _PG_CLASS.c.relforcerowsecurity,
                _PG_CLASS.c.relrowsecurity,
            )
            .select_from(
                _PG_CLASS.join(_PG_NAMESPACE, _PG_NAMESPACE.c.oid == _PG_CLASS.c.relnamespace)
            )
            .where(
                sa.tuple_(_PG_NAMESPACE.c.nspname, _PG_CLASS.c.relname).in_(self.qualified_names)
            ),
        )

    @abc.abstractmethod
    def reflect(self) -> dict[TableKey, RLSState]:
        """Read every requested table into a portable row security state."""

    def states(
        self,
        flags: dict[TableKey, tuple[bool, bool]],
        policies: dict[TableKey, list[CompiledPolicy]],
    ) -> dict[TableKey, RLSState]:
        """Assemble reflected flags and policies for every requested table."""
        return {
            key: RLSState(
                enabled=flags.get(key, (False, False))[0],
                forced=flags.get(key, (False, False))[1],
                policies=tuple(sorted(policies[key], key=lambda policy: policy.name)),
            )
            for key in self.keys
        }


class _PostgreSQLReflection(_CatalogReflection):
    """Reflect PostgreSQL through its populated `pg_policies` compatibility view."""

    def reflect(self) -> dict[TableKey, RLSState]:
        """Read all flags and policies through one joined catalog query."""
        statement = (
            sa.select(
                _PG_NAMESPACE.c.nspname,
                _PG_CLASS.c.relname,
                _PG_CLASS.c.relforcerowsecurity,
                _PG_CLASS.c.relrowsecurity,
                _PG_POLICIES.c.policyname,
                _PG_POLICIES.c.permissive,
                _PG_POLICIES.c.roles,
                _PG_POLICIES.c.cmd,
                _PG_POLICIES.c.qual,
                _PG_POLICIES.c.with_check,
            )
            .select_from(
                _PG_CLASS.join(
                    _PG_NAMESPACE, _PG_NAMESPACE.c.oid == _PG_CLASS.c.relnamespace
                ).outerjoin(
                    _PG_POLICIES,
                    sa.and_(
                        _PG_POLICIES.c.schemaname == _PG_NAMESPACE.c.nspname,
                        _PG_POLICIES.c.tablename == _PG_CLASS.c.relname,
                    ),
                )
            )
            .where(
                sa.tuple_(_PG_NAMESPACE.c.nspname, _PG_CLASS.c.relname).in_(self.qualified_names)
            )
        )
        flags: dict[TableKey, tuple[bool, bool]] = {}
        policies: defaultdict[TableKey, list[CompiledPolicy]] = defaultdict(list)
        for row in cast(Iterable[CatalogRow], self.connection.execute(statement)):
            schema_name, table_name, forced, enabled = row[:4]
            name, permissive, roles, command, using, check = row[4:]
            key = TableKey(schema_name=schema_name, table_name=table_name)
            flags[key] = enabled, forced
            if name is not None:
                assert permissive is not None and roles is not None and command is not None
                policies[key].append(
                    CompiledPolicy(
                        name=name,
                        command=Command[command.lower()],
                        using=using,
                        check=check,
                        roles=tuple(roles),
                        permissive=permissive.casefold() == "permissive",
                    )
                )
        return self.states(flags, policies)


class _CockroachDBReflection(_CatalogReflection):
    """Reflect CockroachDB through `SHOW POLICIES` and PostgreSQL table flags."""

    def reflect(self) -> dict[TableKey, RLSState]:
        """Read flags once and each table's structured policy rows."""
        flags = {
            TableKey(schema_name=schema, table_name=table): (enabled, forced)
            for schema, table, forced, enabled in cast(
                Iterable[FlagRow], self.connection.execute(self.flags_statement())
            )
        }
        policies: defaultdict[TableKey, list[CompiledPolicy]] = defaultdict(list)
        preparer = self.connection.dialect.identifier_preparer
        for key in sorted(self.keys, key=lambda item: (item.schema_name, item.table_name)):
            table = preparer.format_table(key.table())
            rows = cast(
                Iterable[CockroachPolicyRow],
                self.connection.exec_driver_sql(f"SHOW POLICIES FOR {table}"),
            )
            policies[key].extend(
                CompiledPolicy(
                    name=name,
                    command=Command[command.lower()],
                    using=using or None,
                    check=check or None,
                    roles=tuple(roles),
                    permissive=mode.casefold() == "permissive",
                )
                for name, command, mode, roles, using, check in rows
            )
        return self.states(flags, policies)


def reflect_rls(connection: Connection, tables: Iterable[Table]) -> dict[TableKey, RLSState]:
    """Reflect flags and policies for all requested tables through the active dialect."""
    keys = {TableKey.of(table, connection) for table in tables}
    if not keys:
        return {}
    return _CatalogReflection.for_connection(connection, keys).reflect()
