import pydantic
import pytest
import sqlalchemy as sa

import rls


def owner_predicate() -> sa.ColumnElement:
    return sa.column("owner_id") == sa.literal(1)


def test_policy_and_compiled_policy_are_frozen() -> None:
    """Both model classes reject attribute mutation after construction."""
    policy = rls.Policy(name="p", command=rls.Command.select, using=owner_predicate())
    with pytest.raises(pydantic.ValidationError):
        policy.name = "other"

    compiled = rls.compile_policy(policy)
    with pytest.raises(pydantic.ValidationError):
        compiled.name = "other"


def test_compile_policy_compiles_using_and_check_independently() -> None:
    """A policy with only `using` compiles `check` to `None`, and vice versa."""
    read_only = rls.Policy(name="r", command=rls.Command.select, using=owner_predicate())
    compiled = rls.compile_policy(read_only)
    assert compiled.using == "owner_id = 1"
    assert compiled.check is None

    insert_only = rls.Policy(name="i", command=rls.Command.insert, check=owner_predicate())
    compiled = rls.compile_policy(insert_only)
    assert compiled.using is None
    assert compiled.check == "owner_id = 1"


def test_create_statement_emits_using_and_check_when_both_present() -> None:
    compiled = rls.CompiledPolicy(
        name="scope_update", command=rls.Command.update, using="a", check="b"
    )
    assert rls.create_statement("items", compiled) == (
        "CREATE POLICY scope_update ON items FOR UPDATE USING (a) WITH CHECK (b)"
    )


def test_drop_statement_is_idempotent() -> None:
    assert rls.drop_statement("items", "scope_read") == "DROP POLICY IF EXISTS scope_read ON items"


READ = rls.CompiledPolicy(name="scope_read", command=rls.Command.select, using="true")
WRITE = rls.CompiledPolicy(name="scope_write", command=rls.Command.insert, check="true")


def test_enable_statements_emit_enable_force_then_each_policy_then_optional_grant() -> None:
    assert rls.enable_statements("items", [READ, WRITE]) == [
        "ALTER TABLE items ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE items FORCE ROW LEVEL SECURITY",
        rls.create_statement("items", READ),
        rls.create_statement("items", WRITE),
    ]
    assert rls.enable_statements("items", [READ], grant_role="app_role") == [
        "ALTER TABLE items ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE items FORCE ROW LEVEL SECURITY",
        rls.create_statement("items", READ),
        "GRANT SELECT, INSERT, UPDATE, DELETE ON items TO app_role",
    ]


def test_disable_statements_reverse_enable_statements_in_order() -> None:
    assert rls.disable_statements("items", [READ, WRITE]) == [
        rls.drop_statement("items", WRITE.name),
        rls.drop_statement("items", READ.name),
        "ALTER TABLE items NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE items DISABLE ROW LEVEL SECURITY",
    ]
    assert rls.disable_statements("items", [READ], grant_role="app_role") == [
        "REVOKE ALL ON items FROM app_role",
        rls.drop_statement("items", READ.name),
        "ALTER TABLE items NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE items DISABLE ROW LEVEL SECURITY",
    ]
