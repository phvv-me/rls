from sqlalchemy import Table
from sqlalchemy.schema import ExecutableDDLElement

from ..state import RLSState
from .action import RLSAction
from .statement import RLSStatement


def apply_statements(table: Table, state: RLSState) -> tuple[ExecutableDDLElement, ...]:
    """Build typed DDL that installs complete row security state."""
    enabled = RLSAction.enable if state.enabled else RLSAction.disable
    forced = RLSAction.force if state.forced else RLSAction.no_force
    return (
        RLSStatement(table, enabled),
        RLSStatement(table, forced),
        *(RLSStatement(table, RLSAction.create, policy=policy) for policy in state.policies),
    )


def drop_statements(table: Table, state: RLSState) -> tuple[ExecutableDDLElement, ...]:
    """Build typed DDL that removes complete row security state."""
    return (
        *(
            RLSStatement(table, RLSAction.drop, name=policy.name)
            for policy in reversed(state.policies)
        ),
        RLSStatement(table, RLSAction.no_force),
        RLSStatement(table, RLSAction.disable),
    )
