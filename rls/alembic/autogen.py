from collections.abc import Iterable
from typing import TYPE_CHECKING

from alembic.autogenerate.render import renderers
from alembic.operations.ops import CreateTableOp
from alembic.operations.ops import OpContainer
from alembic.util import PriorityDispatchResult

from ..catalog import Catalog
from .operation import AlterRLSOp

if TYPE_CHECKING:
    from alembic.autogenerate.api import AutogenContext
    from alembic.migration import MigrationContext
    from alembic.operations.ops import MigrationScript
    from alembic.operations.ops import UpgradeOps
def omit_runtime_table_info(
    context: MigrationContext,
    revision: Iterable[str | None] | Iterable[str] | str,
    directives: list[MigrationScript],
) -> None:
    """Remove runtime RLS state before Alembic renders new table operations.

    The RLS comparator has already read this state from SQLAlchemy metadata by
    the time this hook runs. Keeping it on `CreateTableOp` would make Alembic
    render Pydantic and enum representations that are neither migration state
    nor valid Python source.
    """
    del context, revision

    def clean(container: OpContainer) -> None:
        for operation in container.ops:
            if isinstance(operation, CreateTableOp):
                operation.info.pop("rls", None)
            if isinstance(operation, OpContainer):
                clean(operation)

    for directive in directives:
        for operations in (*directive.upgrade_ops_list, *directive.downgrade_ops_list):
            clean(operations)


def compare_rls(context: AutogenContext, upgrade_ops: UpgradeOps) -> PriorityDispatchResult:
    """Append one operation for every table whose row security drifted."""
    connection = context.connection
    metadata = context.metadata
    if connection is None or metadata is None:
        return PriorityDispatchResult.CONTINUE
    tables = Catalog.managed(metadata)
    reflected = Catalog.reflect(connection, tables)
    for table in sorted(tables, key=lambda candidate: candidate.fullname):
        live = reflected[table]
        declared = Catalog.state(table)
        if declared is not None and declared.matches(live, table.name):
            continue
        if declared is None and not live.exists:
            continue
        upgrade_ops.ops.append(
            AlterRLSOp(
                table_name=table.name,
                schema_name=table.schema,
                before=live if live.exists else None,
                after=declared,
            )
        )
    return PriorityDispatchResult.CONTINUE


@renderers.dispatch_for(AlterRLSOp)
def render_alter_rls(context: AutogenContext, operation: AlterRLSOp) -> str:
    """Render a self-contained row security transition."""
    context.imports.add("import rls")
    context.imports.add("from rls.alembic import AlterRLSOp")
    before, after = (
        "None"
        if state is None
        else f"rls.RLSState.model_validate({state.model_dump(mode='json')!r})"
        for state in (operation.before, operation.after)
    )
    return (
        f"op.invoke(AlterRLSOp({operation.table_name!r}, before={before}, after={after}, "
        f"schema_name={operation.schema_name!r}))"
    )
