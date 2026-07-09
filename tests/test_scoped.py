import io

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

import rls


def make_registered_base(table: str, grant_role: str | None = None) -> type[DeclarativeBase]:
    """A fresh declarative base with one policy-declaring table, registered for row level security.

    table: the unique table name the model maps, kept per-test so the process-wide registry never
        collides one test's table with another's.
    grant_role: the CRUD grant role stored on the metadata, threaded into every emitted statement.
    """

    class Base(DeclarativeBase):
        pass

    class Item(Base):
        __tablename__ = table

        id: Mapped[int] = mapped_column(primary_key=True)
        owner_id: Mapped[int] = mapped_column()

        @classmethod
        def __rls_policies__(cls) -> list[rls.Policy]:
            return [
                rls.Policy(name="read", command=rls.Command.select, using=cls.owner_id == 1),
                rls.Policy(name="write", command=rls.Command.insert, check=cls.owner_id == 1),
            ]

    rls.register(Base, grant_role=grant_role)
    return Base


def capture_offline(build) -> list[str]:
    """DDL an alembic op emits offline, driven through the real registered `Operations` proxy."""
    buffer = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buffer}
    )
    operations = Operations(context)
    build(operations)
    return [statement.strip() for statement in buffer.getvalue().split(";") if statement.strip()]


def test_register_populates_the_rls_table_name_set() -> None:
    """`register` stamps every policy-declaring table into `metadata.info['rls']`, a plain set."""
    base = make_registered_base("scoped_set_probe")
    rls_set = base.metadata.info["rls"]
    assert isinstance(rls_set, set)
    assert "scoped_set_probe" in rls_set


def test_register_leaves_the_rls_set_empty_for_a_table_declaring_no_policies() -> None:
    """A plain mapped class with no `__rls_policies__` never joins the `info['rls']` set."""

    class Base(DeclarativeBase):
        pass

    class Plain(Base):
        __tablename__ = "scoped_plain_probe"

        id: Mapped[int] = mapped_column(primary_key=True)

    rls.register(Base)
    assert "scoped_plain_probe" not in Base.metadata.info["rls"]


def test_scoped_apply_op_emits_the_canonical_force_grant_ddl_from_the_registry() -> None:
    """The table-name-only op recovers its policies and grant role and emits the same DDL inline."""
    base = make_registered_base("scoped_apply_probe", grant_role="probe_role")
    compiled = [
        rls.compile_policy(p) for p in base.metadata.info["rls_policies"]["scoped_apply_probe"]
    ]
    expected = rls.enable_statements("scoped_apply_probe", compiled, grant_role="probe_role")

    emitted = capture_offline(
        lambda ops: rls.ApplyScopedRlsOp.apply_scoped_rls(ops, "scoped_apply_probe")
    )
    assert emitted == expected
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON scoped_apply_probe TO probe_role" in emitted


def test_scoped_drop_op_reverses_the_apply_ddl_from_the_registry() -> None:
    """`drop_scoped_rls` emits the reverse of `apply_scoped_rls`, revoking the same grant role."""
    base = make_registered_base("scoped_drop_probe", grant_role="probe_role")
    compiled = [
        rls.compile_policy(p) for p in base.metadata.info["rls_policies"]["scoped_drop_probe"]
    ]
    expected = rls.disable_statements("scoped_drop_probe", compiled, grant_role="probe_role")

    emitted = capture_offline(
        lambda ops: rls.DropScopedRlsOp.drop_scoped_rls(ops, "scoped_drop_probe")
    )
    assert emitted == expected


def test_scoped_apply_and_drop_ops_reverse_into_each_other() -> None:
    apply_op = rls.ApplyScopedRlsOp("t")
    drop_op = apply_op.reverse()
    assert isinstance(drop_op, rls.DropScopedRlsOp)
    assert isinstance(drop_op.reverse(), rls.ApplyScopedRlsOp)


def test_render_scoped_ops_stay_table_name_only() -> None:
    """A rendered scoped op carries only its table name, no inline compiled policies."""
    assert (
        rls.render_apply_scoped_rls(None, rls.ApplyScopedRlsOp("t")) == "op.apply_scoped_rls('t')"
    )
    assert rls.render_drop_scoped_rls(None, rls.DropScopedRlsOp("t")) == "op.drop_scoped_rls('t')"


def test_metadata_for_table_raises_for_an_unregistered_table() -> None:
    """A scoped op invoked for a table no registered metadata declares fails loud, never silent."""

    with pytest.raises(LookupError, match="never_registered_table"):
        rls.metadata_for_table("never_registered_table")


class FakeResult:
    """A stand-in for a SQLAlchemy result, iterable over the catalog rows a query would return."""

    def __init__(self, rows: list[tuple]) -> None:
        self.rows = rows

    def __iter__(self):
        return iter(self.rows)


class FakeConnection:
    """A stand-in connection routing the two catalog reads `verify_rls` makes to canned rows.

    security_rows: `(relname, relforcerowsecurity, relrowsecurity)` rows the `pg_class` read returns.
    policy_rows: `(tablename, policyname, cmd, qual, with_check)` rows the `pg_policies` read returns.
    """

    def __init__(self, security_rows: list[tuple], policy_rows: list[tuple]) -> None:
        self.security_rows = security_rows
        self.policy_rows = policy_rows

    def execute(self, statement, parameters=None) -> FakeResult:
        rows = self.security_rows if "relforcerowsecurity" in str(statement) else self.policy_rows
        return FakeResult(rows)


def test_verify_scoped_rls_reads_declared_policies_from_the_registry_by_default() -> None:
    """With no explicit `declared`, `verify_scoped_rls` diffs against the registered policy set."""
    make_registered_base("scoped_verify_probe")
    # the table is force-and-enabled live but carries no policy at all, so the declared `read`/
    # `write` policies read from the registry must both surface as missing.
    connection = FakeConnection(
        security_rows=[("scoped_verify_probe", True, True)], policy_rows=[]
    )
    violations = rls.verify_scoped_rls(connection, {"scoped_verify_probe"})
    assert "scoped_verify_probe: missing read policy" in violations
    assert "scoped_verify_probe: missing write policy" in violations


def test_verify_scoped_rls_flags_a_table_missing_force() -> None:
    """A table with neither force nor enable is reported as both, the coarse half of the check."""
    make_registered_base("scoped_force_probe")
    connection = FakeConnection(security_rows=[], policy_rows=[])
    violations = rls.verify_scoped_rls(connection, {"scoped_force_probe"})
    assert "scoped_force_probe: row level security not enabled" in violations
    assert "scoped_force_probe: row level security not forced" in violations
