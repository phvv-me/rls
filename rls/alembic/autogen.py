from typing import TYPE_CHECKING

from alembic.autogenerate.render import renderers
from alembic.util import PriorityDispatchResult

from ..catalog import Catalog
from .operation import AlterRLSOp

if TYPE_CHECKING:
    from alembic.autogenerate.api import AutogenContext
    from alembic.operations.ops import UpgradeOps


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
