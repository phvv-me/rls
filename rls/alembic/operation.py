from alembic.operations import MigrateOperation
from alembic.operations import Operations

from ..catalog.table_key import TableKey
from ..ddl import apply_statements
from ..ddl import drop_statements
from ..state import RLSState


class AlterRLSOp(MigrateOperation):
    """Replace one table's complete row security state."""

    def __init__(
        self,
        table_name: str,
        before: RLSState | None,
        after: RLSState | None,
        schema_name: str | None = None,
    ) -> None:
        self.table_name = table_name
        self.schema_name = schema_name
        self.before = before
        self.after = after

    @classmethod
    def alter_rls(
        cls,
        operations: Operations,
        table_name: str,
        before: RLSState | None,
        after: RLSState | None,
        schema_name: str | None = None,
    ) -> None:
        """Invoke the registered operation from a migration."""
        operations.invoke(cls(table_name, before, after, schema_name))

    def reverse(self) -> "AlterRLSOp":
        """Swap the complete before and after states."""
        return AlterRLSOp(self.table_name, self.after, self.before, self.schema_name)

    def to_diff_tuple(
        self,
    ) -> tuple[str, str, str | None, RLSState | None, RLSState | None]:
        """Describe the transition for Alembic diff reporting."""
        return "alter_rls", self.table_name, self.schema_name, self.before, self.after


def run_alter_rls(operations: Operations, operation: AlterRLSOp) -> None:
    """Execute one complete row security transition."""
    table = TableKey(
        schema_name=(
            operation.schema_name
            or operations.migration_context.dialect.default_schema_name
            or "public"
        ),
        table_name=operation.table_name,
    ).table()
    if operation.before is not None:
        for statement in drop_statements(table, operation.before):
            operations.execute(statement)
    if operation.after is not None:
        for statement in apply_statements(table, operation.after):
            operations.execute(statement)


def register_operations() -> None:
    """Register the Alembic operation and its implementation, idempotently."""
    if getattr(Operations, "alter_rls", None) is not None:
        return
    Operations.register_operation("alter_rls")(AlterRLSOp)
    Operations.implementation_for(AlterRLSOp)(run_alter_rls)
