import sqlalchemy as sa

import rls
from rls.verify import clause_matches
from rls.verify import policy_matches

OWNER_ID = sa.column("owner_id", sa.Uuid())
READ_USING = OWNER_ID == sa.literal("11111111-1111-1111-1111-111111111111")
COMPILED_READ_USING = rls.compile_expression(READ_USING)


def test_clause_matches_a_live_clause_normalized_equal_to_the_declared_one() -> None:
    """A live clause re-serialized with an `= ANY (ARRAY[...])` fold still matches its declaration."""
    assert clause_matches(READ_USING, COMPILED_READ_USING, table="items")


def test_clause_matches_rejects_a_live_clause_missing_where_one_is_declared() -> None:
    """A live row with no clause at all fails a declared clause, not a silent pass."""
    assert not clause_matches(READ_USING, None, table="items")


def test_clause_matches_rejects_an_unexpected_live_clause_where_none_is_declared() -> None:
    """A live clause present where the declared policy carries none also counts as drift."""
    assert not clause_matches(None, COMPILED_READ_USING, table="items")


def test_clause_matches_absent_both_sides_is_a_match() -> None:
    assert clause_matches(None, None, table="items")


def test_policy_matches_rejects_a_missing_live_policy() -> None:
    declared = rls.Policy(name="scope_read", command=rls.Command.select, using=READ_USING)
    assert not policy_matches(declared, None, table="items")


def test_policy_matches_rejects_a_live_check_missing_where_one_is_declared() -> None:
    """Postgres auto-copies USING into WITH CHECK for commands needing both; a truly missing
    WITH CHECK on a declared UPDATE still fails, the one `clause_matches` branch no canonical
    `enable_statements` output naturally reaches.
    """
    declared = rls.Policy(name="p", command=rls.Command.update, using=READ_USING, check=READ_USING)
    live = ("UPDATE", COMPILED_READ_USING, None)
    assert not policy_matches(declared, live, table="items")


def test_policy_matches_rejects_a_wrong_command() -> None:
    declared = rls.Policy(name="p", command=rls.Command.select, using=READ_USING)
    live = ("ALL", COMPILED_READ_USING, None)
    assert not policy_matches(declared, live, table="items")


def test_policy_matches_accepts_an_unchanged_policy() -> None:
    declared = rls.Policy(name="p", command=rls.Command.select, using=READ_USING)
    live = ("SELECT", COMPILED_READ_USING, None)
    assert policy_matches(declared, live, table="items")
