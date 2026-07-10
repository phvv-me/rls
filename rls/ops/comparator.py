"""Make Alembic autogenerate close the gap between declared policies and the live catalog.

Plugs into `alembic.autogenerate.comparators.dispatch_for("table")`, the per-table hook autogenerate
calls once for every table in the target metadata, already handed `metadata_table` (the table as
declared) directly, so the declared policies for this comparator call come from
`metadata_table.metadata.info["rls_policies"]`, whatever metadata the caller's `env.py` set as
`target_metadata`, never a module-level import. Ported from DelfinaCare/rls (MIT,
https://github.com/DelfinaCare/rls)'s `alembic_ops.py::compare_table_level`, which read
`metadata_table.metadata.info` the same way but never checked `FORCE`, so a table that had `ENABLE`
without `FORCE` read as already protected and was never fixed.

A table with no `FORCE` or no row security enabled at all gets the whole-table `ApplyRlsOp`
bootstrap, the shape a brand-new declared table and a force-stripped one both need. A table already
protected gets the fine-grained differ instead: each declared policy's compiled, normalized clause
is compared against the live catalog's, so only the policies that actually changed are dropped and
recreated, and any live policy no longer declared is dropped on its own. A table with no declared
policies but live row security is torn down entirely, `DropRlsOp` reading the live policies to
reverse cleanly.
"""

from alembic.autogenerate import comparators
from alembic.autogenerate.api import AutogenContext
from alembic.operations.ops import ModifyTableOps
from sqlalchemy import Table

from ..policy import Command
from ..policy import CompiledPolicy
from ..policy import Policy
from ..policy import compile_policy
from ..schema import drifted_policies
from ..schema import live_policies
from ..schema import live_security
from .operations import ApplyRlsOp
from .operations import CreatePolicyOp
from .operations import DropPolicyOp
from .operations import DropRlsOp


def _live_policies_for(connection, table: str) -> list[CompiledPolicy]:
    """Every policy `pg_policies` currently reports for `table`, compiled for a `DropRlsOp`."""
    return [
        CompiledPolicy(name=name, command=Command(cmd), using=qual, check=with_check)
        for (tbl, name), (cmd, qual, with_check) in live_policies(connection, {table}).items()
        if tbl == table
    ]


@comparators.dispatch_for("table")
def compare_rls(
    autogen_context: AutogenContext,
    modify_ops: ModifyTableOps,
    schemaname: str | None,
    tablename: str,
    conn_table: Table | None,
    metadata_table: Table | None,
) -> None:
    """Queue whatever ops close the gap between one table's declared and live row-level-security.

    autogen_context: alembic's autogenerate context, carrying the connection.
    modify_ops: the operation list this pass appends to.
    schemaname: unused, part of the comparator hook's fixed signature; every query here reads the
        `public` schema.
    tablename: table being compared.
    conn_table: the table as it exists live, `None` for a table not yet created.
    metadata_table: the table as declared, `None` for a table Alembic is dropping outright.
    """
    connection = autogen_context.connection
    if connection is None or metadata_table is None:
        return
    declared: list[Policy] = metadata_table.metadata.info.get("rls_policies", {}).get(
        tablename, []
    )
    force, enabled = live_security(connection, {tablename}).get(tablename, (False, False))

    if not declared:
        if force or enabled:
            modify_ops.ops.append(DropRlsOp(tablename, _live_policies_for(connection, tablename)))
        return

    if not (force and enabled):
        modify_ops.ops.append(
            ApplyRlsOp(tablename, [compile_policy(policy) for policy in declared])
        )
        return

    changed, stale = drifted_policies(connection, tablename, declared)
    for compiled in stale:
        modify_ops.ops.append(DropPolicyOp(tablename, compiled))
    for policy in changed:
        modify_ops.ops.append(CreatePolicyOp(tablename, compile_policy(policy)))
