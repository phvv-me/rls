import io
import string
from types import SimpleNamespace
from typing import cast

from alembic.autogenerate.api import AutogenContext
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations.ops import CreateTableOp
from alembic.operations.ops import DowngradeOps
from alembic.operations.ops import MigrationScript
from alembic.operations.ops import ModifyTableOps
from alembic.operations.ops import UpgradeOps
from conftest import CatalogConnection
from conftest import CatalogRow
from conftest import FakeAutogenContext
from conftest import FakeUpgradeOps
from conftest import capture
from conftest import catalog_rows
from conftest import configured
from conftest import make_catalog
from conftest import rls_states
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import MetaData
from sqlalchemy.engine import Connection

import rls
from rls.alembic import AlterRLSOp
from rls.alembic import register_operations
from rls.alembic.autogen import compare_rls
from rls.alembic.autogen import omit_runtime_table_info
from rls.alembic.autogen import render_alter_rls


def _alter_ops() -> st.SearchStrategy[AlterRLSOp]:
    endpoints = st.none() | rls_states()
    return st.builds(
        AlterRLSOp,
        table_name=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=6),
        before=endpoints,
        after=endpoints,
        schema_name=st.none() | st.sampled_from(("public", "private", "tenant")),
    )


@given(operation=_alter_ops())
def test_operation_reverses_and_rendered_source_round_trips(operation: AlterRLSOp) -> None:
    """Reversal is an involution and rendered snapshots restore the same operation."""
    register_operations()  # idempotent: the entry point already registered on import
    reversed_once = operation.reverse()
    assert reversed_once.before == operation.after
    assert reversed_once.after == operation.before
    twice = reversed_once.reverse()
    assert (twice.table_name, twice.schema_name, twice.before, twice.after) == (
        operation.table_name,
        operation.schema_name,
        operation.before,
        operation.after,
    )
    assert operation.to_diff_tuple() == (
        "alter_rls",
        operation.table_name,
        operation.schema_name,
        operation.before,
        operation.after,
    )
    context = AutogenContext(MigrationContext.configure(dialect_name="postgresql"), MetaData())
    rendered = render_alter_rls(context, operation)
    restored: list[AlterRLSOp] = []
    namespace = {
        "AlterRLSOp": AlterRLSOp,
        "op": SimpleNamespace(invoke=restored.append),
        "rls": rls,
    }
    exec(rendered, namespace)
    assert restored[0].to_diff_tuple() == operation.to_diff_tuple()
    assert context.imports == {"import rls", "from rls.alembic import AlterRLSOp"}


def test_operation_executes_both_directions_and_renders_self_contained_source() -> None:
    """One operation tears down before, installs after, and renders standalone migration source."""
    before = rls.RLSState(enabled=True, forced=False, policies=configured().policies)
    operation = AlterRLSOp("items", before=before, after=configured())
    forward = capture(operation)
    assert forward[0].startswith("DROP POLICY IF EXISTS read ON public.items")
    assert forward[-3:] == [
        "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.items FORCE ROW LEVEL SECURITY",
        "CREATE POLICY read ON public.items AS PERMISSIVE FOR SELECT TO public USING (owner_id = 1)",
    ]
    assert capture(operation.reverse())[-3:] == [
        "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.items NO FORCE ROW LEVEL SECURITY",
        "CREATE POLICY read ON public.items AS PERMISSIVE FOR SELECT TO public USING (owner_id = 1)",
    ]
    install_only = capture(AlterRLSOp("items", before=None, after=configured()))
    assert len(install_only) == 3 and not any("DROP" in line for line in install_only)
    teardown_only = capture(AlterRLSOp("items", before=configured(), after=None))
    assert len(teardown_only) == 3 and all("CREATE" not in line for line in teardown_only)
    buffer = io.StringIO()
    migration = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buffer}
    )
    AlterRLSOp.alter_rls(Operations(migration), "items", None, configured())
    assert "CREATE POLICY read ON public.items" in buffer.getvalue()


def _compared(rows: list[CatalogRow], metadata: MetaData | None) -> list[AlterRLSOp]:
    ops = FakeUpgradeOps()
    connection = None if metadata is None else cast(Connection, CatalogConnection(rows))
    context = cast(AutogenContext, FakeAutogenContext(connection, metadata))
    compare_rls(context, cast(UpgradeOps, ops))
    return cast(list[AlterRLSOp], ops.ops)


def test_compare_rls_appends_one_operation_per_drifted_table() -> None:
    """The comparator returns early without a connection and otherwise emits complete drifts."""
    assert _compared([], None) == []
    base, catalog = make_catalog()
    declared = rls.Catalog.state(catalog.protected[0])
    assert declared is not None
    plain_absent: CatalogRow = (
        "public",
        "plain",
        False,
        False,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert _compared([*catalog_rows(declared, "items"), plain_absent], base.metadata) == []

    drift: list[CatalogRow] = [
        ("public", "items", False, False, None, None, None, None, None, None),
        ("public", "plain", True, True, "loose", "PERMISSIVE", ["public"], "SELECT", "true", None),
    ]
    operations = _compared(drift, base.metadata)
    assert [operation.table_name for operation in operations] == ["items", "plain"]
    assert operations[0].before is None and operations[0].after == declared
    assert operations[1].after is None and operations[1].before is not None


def test_runtime_rls_info_is_removed_from_nested_create_table_operations() -> None:
    """Autogenerated migrations keep ordinary table info but never runtime RLS models."""
    create = CreateTableOp("items", (), info={"rls": configured(), "purpose": "test"})
    nested = ModifyTableOps("items", ops=[create])
    script = MigrationScript(
        "revision",
        UpgradeOps([nested]),
        DowngradeOps([]),
    )

    omit_runtime_table_info(
        cast(MigrationContext, None),
        (),
        [script],
    )

    assert create.info == {"purpose": "test"}
