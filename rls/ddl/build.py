from sqlalchemy import Table
from sqlalchemy.dialects.postgresql import CreatePolicy
from sqlalchemy.dialects.postgresql import DisableRowLevelSecurity
from sqlalchemy.dialects.postgresql import DropPolicy
from sqlalchemy.dialects.postgresql import EnableRowLevelSecurity
from sqlalchemy.dialects.postgresql import ForceRowLevelSecurity
from sqlalchemy.dialects.postgresql import NoForceRowLevelSecurity
from sqlalchemy.dialects.postgresql import Policy
from sqlalchemy.schema import ExecutableDDLElement

from ..policy import CompiledPolicy
from ..state import RLSState


def _policy_ddl(table: Table, policy: CompiledPolicy) -> Policy:
    """Translate a compiled declaration to SQLAlchemy's PostgreSQL policy object."""
    return Policy(
        policy.name,
        table,
        command=policy.command.sql,
        roles=policy.roles,
        using=policy.using,
        check=policy.check,
        permissive=policy.permissive,
    )


def apply_statements(table: Table, state: RLSState) -> tuple[ExecutableDDLElement, ...]:
    """Build typed DDL that installs complete row security state."""
    enabled = EnableRowLevelSecurity if state.enabled else DisableRowLevelSecurity
    forced = ForceRowLevelSecurity if state.forced else NoForceRowLevelSecurity
    return (
        enabled(table),
        forced(table),
        *(CreatePolicy(_policy_ddl(table, policy)) for policy in state.policies),
    )


def drop_statements(table: Table, state: RLSState) -> tuple[ExecutableDDLElement, ...]:
    """Build typed DDL that removes complete row security state."""
    return (
        *(
            DropPolicy(Policy(policy.name, table), if_exists=True)
            for policy in reversed(state.policies)
        ),
        NoForceRowLevelSecurity(table),
        DisableRowLevelSecurity(table),
    )
