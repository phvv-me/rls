"""Render a queued operation back into the Python source `alembic revision --autogenerate` writes.

Plugs into `alembic.autogenerate.renderers.dispatch_for`, the hook that turns a `MigrateOperation`
instance the comparator queued into the literal `op.xxx(...)` line a generated migration file
contains. Every compiled policy an op carries is rendered as an `rls.CompiledPolicy(...)`
constructor call so the migration stays self-contained plain text, never a live reference back to
the model metadata that happened to be current when the migration was generated.
"""

from alembic.autogenerate import renderers
from alembic.autogenerate.api import AutogenContext

from ..policy import CompiledPolicy
from .operations import ApplyRlsOp
from .operations import CreatePolicyOp
from .operations import DropPolicyOp
from .operations import DropRlsOp


def _import_rls(autogen_context: AutogenContext | None) -> None:
    """Add the `rls` import a rendered migration needs to reference `rls.CompiledPolicy`."""
    if autogen_context is not None:
        autogen_context.imports.add("import rls")


def _render_compiled_policy(policy: CompiledPolicy) -> str:
    """The `rls.CompiledPolicy(...)` constructor call one op's rendering embeds."""
    return (
        f"rls.CompiledPolicy(name={policy.name!r}, command=rls.Command.{policy.command.name}, "
        f"using={policy.using!r}, check={policy.check!r})"
    )


def _render_compiled_policies(policies: list[CompiledPolicy]) -> str:
    return "[" + ", ".join(_render_compiled_policy(policy) for policy in policies) + "]"


@renderers.dispatch_for(ApplyRlsOp)
def render_apply_rls(autogen_context: AutogenContext | None, operation: ApplyRlsOp) -> str:
    """Render a queued whole-table bootstrap back into migration source."""
    _import_rls(autogen_context)
    return (
        f"op.apply_rls({operation.table!r}, {_render_compiled_policies(operation.policies)}, "
        f"grant_role={operation.grant_role!r})"
    )


@renderers.dispatch_for(DropRlsOp)
def render_drop_rls(autogen_context: AutogenContext | None, operation: DropRlsOp) -> str:
    """Render a queued whole-table teardown back into migration source."""
    _import_rls(autogen_context)
    return (
        f"op.drop_rls({operation.table!r}, {_render_compiled_policies(operation.policies)}, "
        f"grant_role={operation.grant_role!r})"
    )


@renderers.dispatch_for(CreatePolicyOp)
def render_create_policy(autogen_context: AutogenContext | None, operation: CreatePolicyOp) -> str:
    """Render a queued fine-grained create back into migration source."""
    _import_rls(autogen_context)
    return (
        f"op.create_rls_policy({operation.table!r}, {_render_compiled_policy(operation.policy)})"
    )


@renderers.dispatch_for(DropPolicyOp)
def render_drop_policy(autogen_context: AutogenContext | None, operation: DropPolicyOp) -> str:
    """Render a queued fine-grained drop back into migration source."""
    _import_rls(autogen_context)
    return f"op.drop_rls_policy({operation.table!r}, {_render_compiled_policy(operation.policy)})"
