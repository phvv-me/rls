from collections import defaultdict
from collections.abc import Collection
from collections.abc import Iterable
from collections.abc import Sequence
from typing import Protocol
from typing import cast

from sqlalchemy import Table
from sqlalchemy.dialects.postgresql.base import ReflectedPolicy
from sqlalchemy.dialects.postgresql.base import ReflectedRowSecurity
from sqlalchemy.engine import Connection
from sqlalchemy.engine.reflection import ObjectKind
from sqlalchemy.engine.reflection import ObjectScope

from ..policy import Command
from ..policy import CompiledPolicy
from ..state import RLSState
from .table_key import TableKey


class _RowSecurityDialect(Protocol):
    """The PostgreSQL-compatible bulk row security reflection surface: the table flags and the
    policies are two reflections, as SQLAlchemy reflects indexes apart from constraints."""

    def get_multi_row_security(
        self,
        connection: Connection,
        schema: str,
        filter_names: Sequence[str],
        scope: ObjectScope,
        kind: ObjectKind,
    ) -> Iterable[tuple[tuple[str | None, str], ReflectedRowSecurity]]:
        """Return the enabled and forced flags of the requested tables."""

    def get_multi_policies(
        self,
        connection: Connection,
        schema: str,
        filter_names: Sequence[str],
        scope: ObjectScope,
        kind: ObjectKind,
    ) -> Iterable[tuple[tuple[str | None, str], list[ReflectedPolicy]]]:
        """Return the policies of the requested tables."""


class _CatalogReflection:
    """Reflect PostgreSQL-compatible row security into portable state."""

    def __init__(self, connection: Connection, keys: Collection[TableKey]) -> None:
        self.connection = connection
        self.keys = keys

    def reflect(self) -> dict[TableKey, RLSState]:
        """Read each requested schema's flags and policies through SQLAlchemy's bulk API."""
        dialect = cast(_RowSecurityDialect, self.connection.dialect)
        flags: dict[TableKey, tuple[bool, bool]] = {}
        policies: defaultdict[TableKey, list[CompiledPolicy]] = defaultdict(list)
        for schema_name in sorted({key.schema_name for key in self.keys}):
            names = sorted(key.table_name for key in self.keys if key.schema_name == schema_name)
            for reflected_key, state in dialect.get_multi_row_security(
                self.connection,
                schema=schema_name,
                filter_names=names,
                scope=ObjectScope.DEFAULT,
                kind=ObjectKind.TABLE,
            ):
                flags[self._key(reflected_key)] = state["enabled"], state["forced"]
            for reflected_key, declared in dialect.get_multi_policies(
                self.connection,
                schema=schema_name,
                filter_names=names,
                scope=ObjectScope.DEFAULT,
                kind=ObjectKind.TABLE,
            ):
                policies[self._key(reflected_key)].extend(
                    CompiledPolicy(
                        name=policy["name"],
                        command=Command[policy["command"].lower()],
                        using=policy["using"],
                        check=policy["check"],
                        roles=tuple(policy["roles"]),
                        permissive=policy["permissive"],
                    )
                    for policy in declared
                )
        return {
            key: RLSState(
                enabled=flags.get(key, (False, False))[0],
                forced=flags.get(key, (False, False))[1],
                policies=tuple(sorted(policies.get(key, ()), key=lambda policy: policy.name)),
            )
            for key in self.keys
        }

    @staticmethod
    def _key(reflected: tuple[str | None, str]) -> TableKey:
        """The table key of a reflected `(schema, table)`; a bulk reflection always names its
        schema, since it was asked for one."""
        schema_name, table_name = reflected
        assert schema_name is not None
        return TableKey(schema_name=schema_name, table_name=table_name)


def reflect_rls(connection: Connection, tables: Iterable[Table]) -> dict[TableKey, RLSState]:
    """Reflect flags and policies for all requested tables through the active dialect."""
    keys = {TableKey.of(table, connection) for table in tables}
    if not keys:
        return {}
    return _CatalogReflection(connection, keys).reflect()
