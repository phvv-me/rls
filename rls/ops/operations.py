"""The Alembic `MigrateOperation` subclasses a migration file actually calls.

Plugs into Alembic's `Operations.register_operation`, the hook that adds a new verb (`op.apply_rls`,
`op.create_rls_policy`, ...) to the `op` proxy every migration script receives. Two granularities:
`ApplyRlsOp`/`DropRlsOp` bootstrap or tear down a whole table (enable, force, and every policy, or
the reverse), and `CreatePolicyOp`/`DropPolicyOp` touch one named policy on an already-protected
table. Both granularities carry their compiled policies inline rather than looking them up from a
registry at invoke time, so no global metadata reference is needed anywhere in this module; a
rendered migration is self-contained the moment it is written, exactly like any other Alembic
operation. Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls)'s
`alembic_ops.py`, which split this same enable/disable + create/drop shape across four primitive
ops instead of two bootstrap ops plus two fine-grained ones.
"""

import typing

from alembic import operations as alembic_operations

from ..policy import CompiledPolicy


class RLSOp(typing.Protocol):
    """The RLS-specific operations this module adds to Alembic's `op` object.

    Use `typing.cast(RLSOp, op)` inside a generated migration file to get fully-typed access to
    these operations without a `# type: ignore` suppression.
    """

    def apply_rls(
        self, table: str, policies: list[CompiledPolicy], grant_role: str | None = None
    ) -> None: ...

    def drop_rls(
        self, table: str, policies: list[CompiledPolicy], grant_role: str | None = None
    ) -> None: ...

    def create_rls_policy(self, table: str, policy: CompiledPolicy) -> None: ...

    def drop_rls_policy(self, table: str, policy: CompiledPolicy) -> None: ...


@alembic_operations.Operations.register_operation("apply_rls")
class ApplyRlsOp(alembic_operations.MigrateOperation):
    """Force row level security on one table with its declared policies, in declaration order."""

    def __init__(
        self, table: str, policies: list[CompiledPolicy], grant_role: str | None = None
    ) -> None:
        self.table = table
        self.policies = policies
        self.grant_role = grant_role

    @classmethod
    def apply_rls(
        cls,
        operations: alembic_operations.Operations,
        table: str,
        policies: list[CompiledPolicy],
        grant_role: str | None = None,
    ) -> None:
        """Invoke from a migration as `op.apply_rls(table, policies)`."""
        operations.invoke(cls(table, policies, grant_role))

    def reverse(self) -> "DropRlsOp":
        return DropRlsOp(self.table, self.policies, self.grant_role)


@alembic_operations.Operations.register_operation("drop_rls")
class DropRlsOp(alembic_operations.MigrateOperation):
    """Reverse `ApplyRlsOp`: drop every policy and disable row level security on one table."""

    def __init__(
        self, table: str, policies: list[CompiledPolicy], grant_role: str | None = None
    ) -> None:
        self.table = table
        self.policies = policies
        self.grant_role = grant_role

    @classmethod
    def drop_rls(
        cls,
        operations: alembic_operations.Operations,
        table: str,
        policies: list[CompiledPolicy],
        grant_role: str | None = None,
    ) -> None:
        """Invoke from a migration as `op.drop_rls(table, policies)`."""
        operations.invoke(cls(table, policies, grant_role))

    def reverse(self) -> ApplyRlsOp:
        return ApplyRlsOp(self.table, self.policies, self.grant_role)


@alembic_operations.Operations.register_operation("create_rls_policy")
class CreatePolicyOp(alembic_operations.MigrateOperation):
    """Create or replace one compiled policy on an already-protected table.

    Idempotent: implemented as a drop-if-exists followed by the create, so it covers both a
    genuinely missing policy and one whose clause drifted from its declaration under the same op.
    """

    def __init__(self, table: str, policy: CompiledPolicy) -> None:
        self.table = table
        self.policy = policy

    @classmethod
    def create_rls_policy(
        cls,
        operations: alembic_operations.Operations,
        table: str,
        policy: CompiledPolicy,
    ) -> None:
        """Invoke from a migration as `op.create_rls_policy(table, policy)`."""
        operations.invoke(cls(table, policy))

    def reverse(self) -> "DropPolicyOp":
        return DropPolicyOp(self.table, self.policy)


@alembic_operations.Operations.register_operation("drop_rls_policy")
class DropPolicyOp(alembic_operations.MigrateOperation):
    """Drop one named policy, carrying its compiled definition so the op reverses cleanly."""

    def __init__(self, table: str, policy: CompiledPolicy) -> None:
        self.table = table
        self.policy = policy

    @classmethod
    def drop_rls_policy(
        cls,
        operations: alembic_operations.Operations,
        table: str,
        policy: CompiledPolicy,
    ) -> None:
        """Invoke from a migration as `op.drop_rls_policy(table, policy)`."""
        operations.invoke(cls(table, policy))

    def reverse(self) -> CreatePolicyOp:
        return CreatePolicyOp(self.table, self.policy)
