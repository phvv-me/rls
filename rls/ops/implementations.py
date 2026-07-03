"""The DDL each operation in `operations.py` emits when a migration actually runs.

Plugs into Alembic's `Operations.implementation_for`, the hook that gives a registered operation a
body: what `operations.execute(...)` calls to make when `op.apply_rls(...)` (or any of its
siblings) is invoked, online against a real connection or offline into a `--sql` script. Every
statement comes from `policy.py`'s pure builders (`enable_statements`, `disable_statements`,
`create_statement`, `drop_statement`); this module's only job is threading each op's own fields
into those builders and executing the result.
"""

from alembic import operations as alembic_operations

from ..policy import create_statement
from ..policy import disable_statements
from ..policy import drop_statement
from ..policy import enable_statements
from .operations import ApplyRlsOp
from .operations import CreatePolicyOp
from .operations import DropPolicyOp
from .operations import DropRlsOp


@alembic_operations.Operations.implementation_for(ApplyRlsOp)
def run_apply_rls(operations: alembic_operations.Operations, operation: ApplyRlsOp) -> None:
    """Emit the enable, force, and per-policy DDL when a migration invokes `apply_rls`."""
    for statement in enable_statements(operation.table, operation.policies, operation.grant_role):
        operations.execute(statement)


@alembic_operations.Operations.implementation_for(DropRlsOp)
def run_drop_rls(operations: alembic_operations.Operations, operation: DropRlsOp) -> None:
    """Emit the drop and disable DDL when a migration invokes `drop_rls`."""
    for statement in disable_statements(operation.table, operation.policies, operation.grant_role):
        operations.execute(statement)


@alembic_operations.Operations.implementation_for(CreatePolicyOp)
def run_create_policy(
    operations: alembic_operations.Operations, operation: CreatePolicyOp
) -> None:
    """Drop any same-named policy then create the compiled definition, in one statement pair."""
    operations.execute(drop_statement(operation.table, operation.policy.name))
    operations.execute(create_statement(operation.table, operation.policy))


@alembic_operations.Operations.implementation_for(DropPolicyOp)
def run_drop_policy(operations: alembic_operations.Operations, operation: DropPolicyOp) -> None:
    """Drop the named policy."""
    operations.execute(drop_statement(operation.table, operation.policy.name))
