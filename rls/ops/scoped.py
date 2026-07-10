"""Table-name-only Alembic ops that read a registered metadata's policies at invoke time.

Where `operations.py`'s `ApplyRlsOp` embeds its compiled policies in the migration text, an
`op.apply_scoped_rls("table")` op carries only a table name and recovers that table's declared
policies and grant role from the live model metadata `register()` opted in (`rls.registry`), the
call shape a migration written before the inline ops existed already uses. The emitted DDL is the
identical `enable_statements`/`disable_statements` output, only the policy source differs.

The schema-level `compare_scoped_rls` closes the same declared-vs-live gap `comparator.compare_rls`
does, but emits the table-name-only bootstrap op rather than the inline one, so the migration it
writes stays as small as a hand-written one and re-reads the current policies at apply time. It
reuses the fine-grained `CreatePolicyOp`/`DropPolicyOp` from `operations.py` for a single drifted
policy, since those carry one compiled policy inline and need no registry lookup.
"""

from alembic.autogenerate import comparators
from alembic.autogenerate import renderers
from alembic.autogenerate.api import AutogenContext
from alembic.operations import MigrateOperation
from alembic.operations import Operations
from alembic.operations.ops import UpgradeOps
from sqlalchemy.sql.schema import MetaData

from ..policy import compile_policy
from ..policy import disable_statements
from ..policy import enable_statements
from ..schema import drifted_policies
from ..schema import metadata_for_table
from ..schema import unprotected_tables
from .operations import CreatePolicyOp
from .operations import DropPolicyOp


def scoped_apply_statements(table: str, grant: bool = True) -> list[str]:
    """The enable, force, and per-policy DDL for `table`, its policies read from its metadata.

    table: table to protect, its declared policies recovered from the registered metadata.
    grant: also grant the metadata's `rls_grant_role` CRUD on `table`, skipped when that role does
        not exist yet during an early bootstrap migration.
    """
    metadata = metadata_for_table(table)
    compiled = [compile_policy(policy) for policy in metadata.info["rls_policies"][table]]
    grant_role = metadata.info.get("rls_grant_role") if grant else None
    return enable_statements(table, compiled, grant_role)


def scoped_drop_statements(table: str, grant: bool = True) -> list[str]:
    """Reverse `scoped_apply_statements` for `table`, dropping every declared policy in reverse.

    table: table to unprotect, its declared policies recovered from the registered metadata.
    grant: also revoke the metadata's `rls_grant_role` grant, matching how the apply granted it.
    """
    metadata = metadata_for_table(table)
    compiled = [compile_policy(policy) for policy in metadata.info["rls_policies"][table]]
    grant_role = metadata.info.get("rls_grant_role") if grant else None
    return disable_statements(table, compiled, grant_role)


@Operations.register_operation("apply_scoped_rls")
class ApplyScopedRlsOp(MigrateOperation):
    """Force every declared policy on one table, reading them from its registered metadata."""

    def __init__(self, table: str, grant: bool = True) -> None:
        self.table = table
        self.grant = grant

    @classmethod
    def apply_scoped_rls(cls, operations: Operations, table: str, grant: bool = True) -> None:
        """Invoke from a migration as `op.apply_scoped_rls(table)`."""
        operations.invoke(cls(table, grant))

    def reverse(self) -> "DropScopedRlsOp":
        return DropScopedRlsOp(self.table, self.grant)


@Operations.register_operation("drop_scoped_rls")
class DropScopedRlsOp(MigrateOperation):
    """Reverse `apply_scoped_rls`, dropping the declared policies and disabling row security."""

    def __init__(self, table: str, grant: bool = True) -> None:
        self.table = table
        self.grant = grant

    @classmethod
    def drop_scoped_rls(cls, operations: Operations, table: str, grant: bool = True) -> None:
        """Invoke from a migration as `op.drop_scoped_rls(table)`."""
        operations.invoke(cls(table, grant))

    def reverse(self) -> ApplyScopedRlsOp:
        return ApplyScopedRlsOp(self.table, self.grant)


@Operations.implementation_for(ApplyScopedRlsOp)
def run_apply_scoped_rls(operations: Operations, operation: ApplyScopedRlsOp) -> None:
    """Emit the enable, force, per-policy, and grant DDL when `apply_scoped_rls` is invoked."""
    for statement in scoped_apply_statements(operation.table, operation.grant):
        operations.execute(statement)


@Operations.implementation_for(DropScopedRlsOp)
def run_drop_scoped_rls(operations: Operations, operation: DropScopedRlsOp) -> None:
    """Emit the drop and disable DDL when a migration invokes `drop_scoped_rls`."""
    for statement in scoped_drop_statements(operation.table, operation.grant):
        operations.execute(statement)


@renderers.dispatch_for(ApplyScopedRlsOp)
def render_apply_scoped_rls(autogen_context: AutogenContext | None, op: ApplyScopedRlsOp) -> str:
    """Render an emitted apply op back into the table-name-only migration source."""
    return f"op.apply_scoped_rls({op.table!r})"


@renderers.dispatch_for(DropScopedRlsOp)
def render_drop_scoped_rls(autogen_context: AutogenContext | None, op: DropScopedRlsOp) -> str:
    """Render an emitted drop op back into the table-name-only migration source."""
    return f"op.drop_scoped_rls({op.table!r})"


@comparators.dispatch_for("schema")
def compare_scoped_rls(
    autogen_context: AutogenContext, upgrade_ops: UpgradeOps, schemas: set[str | None]
) -> None:
    """Make autogenerate close any gap between the declared policies and the live catalog.

    A table with no `FORCE` or no row security at all gets the whole-table `ApplyScopedRlsOp`
    bootstrap, the shape a brand-new declared table or a force-stripped one both need. A table
    already protected gets the fine-grained differ instead: `drifted_policies` compares each
    declared policy's compiled, normalized clause against the live catalog's, so only the policies
    that actually changed are dropped and recreated, and any live policy no longer declared is
    dropped on its own. The declared set is read from the autogenerate target metadata (whatever
    `env.py` set), a single `MetaData` or a sequence of them alike.

    autogen_context: alembic's autogenerate context, carrying the connection and target metadata.
    upgrade_ops: the operation list this pass appends to.
    schemas: unused, part of the comparator hook's fixed signature.
    """
    connection = autogen_context.connection
    metadata = autogen_context.metadata
    if connection is None or metadata is None:
        return
    catalogs = [metadata] if isinstance(metadata, MetaData) else metadata
    declared = {
        table: policies
        for catalog in catalogs
        for table, policies in catalog.info.get("rls_policies", {}).items()
    }
    if not declared:
        return
    bootstrap = set(unprotected_tables(connection, set(declared)))
    for table in sorted(bootstrap):
        upgrade_ops.ops.append(ApplyScopedRlsOp(table))
    for table in sorted(declared.keys() - bootstrap):
        changed, stale = drifted_policies(connection, table, declared[table])
        for compiled in stale:
            upgrade_ops.ops.append(DropPolicyOp(table, compiled))
        for policy in changed:
            upgrade_ops.ops.append(CreatePolicyOp(table, compile_policy(policy)))
