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


def reflect_rls(connection: Connection, tables: Iterable[Table]) -> dict[TableKey, RLSState]:
    """Reflect flags and policies for all requested tables in one catalog query."""
    keys = {TableKey.of(table, connection) for table in tables}
    if not keys:
        return {}
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
            sa.tuple_(_PG_NAMESPACE.c.nspname, _PG_CLASS.c.relname).in_(
                sorted((key.schema_name, key.table_name) for key in keys)
            )
        )
    )
    flags: dict[TableKey, tuple[bool, bool]] = {}
    policies: defaultdict[TableKey, list[CompiledPolicy]] = defaultdict(list)
    for (
        schema_name,
        table_name,
        forced,
        enabled,
        name,
        permissive,
        roles,
        command,
        using,
        check,
    ) in cast(Iterable[CatalogRow], connection.execute(statement)):
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
                    permissive=permissive == "PERMISSIVE",
                )
            )
    return {
        key: RLSState(
            enabled=flags.get(key, (False, False))[0],
            forced=flags.get(key, (False, False))[1],
            policies=tuple(sorted(policies[key], key=lambda policy: policy.name)),
        )
        for key in keys
    }
