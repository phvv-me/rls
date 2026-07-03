import io

import pytest
from alembic.autogenerate.api import AutogenContext
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations.ops import ModifyTableOps
from sqlalchemy import MetaData

import rls

READ = rls.CompiledPolicy(name="scope_read", command=rls.Command.select, using="true")
WRITE = rls.CompiledPolicy(name="scope_write", command=rls.Command.insert, check="true")
TABLE = "items"


def capture_offline(build) -> list[str]:
    """DDL an alembic op emits offline, driven through the real registered `Operations` proxy."""
    buffer = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buffer}
    )
    operations = Operations(context)
    build(operations)
    return [statement.strip() for statement in buffer.getvalue().split(";") if statement.strip()]


def test_apply_rls_emits_the_canonical_force_protected_ddl() -> None:
    emitted = capture_offline(lambda ops: rls.ops.ApplyRlsOp.apply_rls(ops, TABLE, [READ, WRITE]))
    assert emitted == rls.enable_statements(TABLE, [READ, WRITE])


def test_apply_rls_passes_the_grant_role_through() -> None:
    emitted = capture_offline(
        lambda ops: rls.ops.ApplyRlsOp.apply_rls(ops, TABLE, [READ], grant_role="app_role")
    )
    assert emitted == rls.enable_statements(TABLE, [READ], grant_role="app_role")


def test_drop_rls_reverses_apply_rls_ddl() -> None:
    emitted = capture_offline(lambda ops: rls.ops.DropRlsOp.drop_rls(ops, TABLE, [READ, WRITE]))
    assert emitted == rls.disable_statements(TABLE, [READ, WRITE])


def test_apply_and_drop_rls_ops_reverse_into_each_other() -> None:
    apply_op = rls.ops.ApplyRlsOp(TABLE, [READ], grant_role="app_role")
    drop_op = apply_op.reverse()
    assert isinstance(drop_op, rls.ops.DropRlsOp)
    assert (drop_op.table, drop_op.policies, drop_op.grant_role) == (TABLE, [READ], "app_role")

    mirror = drop_op.reverse()
    assert isinstance(mirror, rls.ops.ApplyRlsOp)
    assert (mirror.table, mirror.policies, mirror.grant_role) == (TABLE, [READ], "app_role")


def test_create_rls_policy_drops_any_same_named_policy_then_creates_it_offline() -> None:
    emitted = capture_offline(
        lambda ops: rls.ops.CreatePolicyOp.create_rls_policy(ops, TABLE, READ)
    )
    assert emitted == [
        rls.drop_statement(TABLE, READ.name),
        rls.create_statement(TABLE, READ),
    ]


def test_drop_rls_policy_emits_exactly_one_drop_statement_offline() -> None:
    emitted = capture_offline(lambda ops: rls.ops.DropPolicyOp.drop_rls_policy(ops, TABLE, READ))
    assert emitted == [rls.drop_statement(TABLE, READ.name)]


def test_create_and_drop_policy_ops_reverse_into_each_other() -> None:
    create_op = rls.ops.CreatePolicyOp(TABLE, READ)
    drop_op = create_op.reverse()
    assert isinstance(drop_op, rls.ops.DropPolicyOp)
    assert (drop_op.table, drop_op.policy) == (TABLE, READ)

    mirror = drop_op.reverse()
    assert isinstance(mirror, rls.ops.CreatePolicyOp)
    assert (mirror.table, mirror.policy) == (TABLE, READ)


def test_render_apply_and_drop_rls_add_the_rls_import_and_render_the_call() -> None:
    context = AutogenContext(MigrationContext.configure(dialect_name="postgresql"), MetaData())

    rendered = rls.ops.render_apply_rls(context, rls.ops.ApplyRlsOp(TABLE, [READ]))
    assert rendered == (
        f"op.apply_rls({TABLE!r}, [rls.CompiledPolicy(name='scope_read', "
        f"command=rls.Command.select, using='true', check=None)], grant_role=None)"
    )
    assert "import rls" in context.imports

    rendered = rls.ops.render_drop_rls(context, rls.ops.DropRlsOp(TABLE, [READ]))
    assert rendered == (
        f"op.drop_rls({TABLE!r}, [rls.CompiledPolicy(name='scope_read', "
        f"command=rls.Command.select, using='true', check=None)], grant_role=None)"
    )


def test_render_create_and_drop_policy_add_the_rls_import_and_render_the_call() -> None:
    context = AutogenContext(MigrationContext.configure(dialect_name="postgresql"), MetaData())

    created = rls.ops.render_create_policy(context, rls.ops.CreatePolicyOp(TABLE, READ))
    assert created == (
        f"op.create_rls_policy({TABLE!r}, rls.CompiledPolicy(name='scope_read', "
        f"command=rls.Command.select, using='true', check=None))"
    )

    dropped = rls.ops.render_drop_policy(context, rls.ops.DropPolicyOp(TABLE, READ))
    assert dropped == (
        f"op.drop_rls_policy({TABLE!r}, rls.CompiledPolicy(name='scope_read', "
        f"command=rls.Command.select, using='true', check=None))"
    )
    assert "import rls" in context.imports


def test_render_without_a_context_still_renders_no_import_add() -> None:
    """A `None` autogen_context (an offline `--sql` render) still renders the call, no import add."""
    op = rls.ops.CreatePolicyOp(TABLE, READ)
    assert rls.ops.render_create_policy(None, op) == (
        f"op.create_rls_policy({TABLE!r}, rls.CompiledPolicy(name='scope_read', "
        f"command=rls.Command.select, using='true', check=None))"
    )


def test_comparator_returns_early_without_a_connection() -> None:
    """An offline migration context carries no connection, so the comparator must skip, never
    query a catalog it cannot reach.
    """
    context = AutogenContext(MigrationContext.configure(dialect_name="postgresql"), MetaData())
    upgrade_ops = ModifyTableOps(TABLE, [])
    rls.ops.compare_rls(context, upgrade_ops, None, TABLE, None, None)
    assert upgrade_ops.ops == []


@pytest.mark.parametrize("connection", [object()])
def test_comparator_returns_early_without_declared_metadata(connection: object) -> None:
    """A `None` `metadata_table` (Alembic dropping a table outright) is also a no-op, connection
    or not, since there is nothing declared to diff against.
    """
    context = AutogenContext(MigrationContext.configure(dialect_name="postgresql"), MetaData())
    context.connection = connection  # type: ignore[assignment]
    upgrade_ops = ModifyTableOps(TABLE, [])
    rls.ops.compare_rls(context, upgrade_ops, None, TABLE, None, None)
    assert upgrade_ops.ops == []
